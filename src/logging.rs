use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLogs {
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct LogRotationPolicy {
    pub max_size_bytes: u64,
    pub max_files: u32,
    pub max_age_days: u64,
}

pub fn process_logs(log_dir: &Path, name: &str) -> ProcessLogs {
    ProcessLogs {
        stdout: log_dir.join(format!("{name}.out.log")),
        stderr: log_dir.join(format!("{name}.err.log")),
    }
}

pub fn open_log_writers(logs: &ProcessLogs, policy: LogRotationPolicy) -> Result<(File, File)> {
    if let Some(parent) = logs.stdout.parent() {
        ensure_private_dir(parent)?;
    }
    rotate_log_if_needed(&logs.stdout, policy)?;
    rotate_log_if_needed(&logs.stderr, policy)?;
    cleanup_rotated_logs(&logs.stdout, policy)?;
    cleanup_rotated_logs(&logs.stderr, policy)?;

    let mut stdout_options = OpenOptions::new();
    stdout_options
        .create(true)
        .append(true)
        .write(true)
        .read(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        stdout_options.mode(0o600);
    }
    let stdout = stdout_options
        .open(&logs.stdout)
        .with_context(|| format!("failed opening {}", logs.stdout.display()))?;
    set_private_file_permissions(&logs.stdout)?;

    let mut stderr_options = OpenOptions::new();
    stderr_options
        .create(true)
        .append(true)
        .write(true)
        .read(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        stderr_options.mode(0o600);
    }
    let stderr = stderr_options
        .open(&logs.stderr)
        .with_context(|| format!("failed opening {}", logs.stderr.display()))?;
    set_private_file_permissions(&logs.stderr)?;

    Ok((stdout, stderr))
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    let existed = path.exists();
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

fn rotate_log_if_needed(path: &Path, policy: LogRotationPolicy) -> Result<()> {
    if policy.max_size_bytes == 0 || policy.max_files == 0 {
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }

    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() < policy.max_size_bytes {
        return Ok(());
    }

    for idx in (1..=policy.max_files).rev() {
        let candidate = rotated_path(path, idx);
        if !candidate.exists() {
            continue;
        }
        if idx == policy.max_files {
            let _ = fs::remove_file(&candidate);
        } else {
            let next = rotated_path(path, idx + 1);
            let _ = fs::remove_file(&next);
            fs::rename(&candidate, &next).with_context(|| {
                format!(
                    "failed to rotate {} -> {}",
                    candidate.display(),
                    next.display()
                )
            })?;
        }
    }

    let first = rotated_path(path, 1);
    let _ = fs::remove_file(&first);
    fs::rename(path, &first)
        .with_context(|| format!("failed to rotate {} -> {}", path.display(), first.display()))?;
    Ok(())
}

fn cleanup_rotated_logs(path: &Path, policy: LogRotationPolicy) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let Some(base_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Ok(());
    };

    let max_age = Duration::from_secs(policy.max_age_days.saturating_mul(24 * 60 * 60));
    let now = std::time::SystemTime::now();

    let entries = fs::read_dir(parent)
        .with_context(|| format!("failed to read directory {}", parent.display()))?;
    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", parent.display()))?;
        let file_name = entry.file_name();
        let file_name = match file_name.to_str() {
            Some(value) => value,
            None => continue,
        };

        let Some(suffix) = file_name
            .strip_prefix(base_name)
            .and_then(|rest| rest.strip_prefix('.'))
        else {
            continue;
        };
        let Ok(index) = suffix.parse::<u32>() else {
            continue;
        };

        let path = entry.path();
        let mut remove = index > policy.max_files;

        if !remove && policy.max_age_days > 0 {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if now.duration_since(modified).unwrap_or(Duration::ZERO) > max_age {
                        remove = true;
                    }
                }
            }
        }

        if remove {
            let _ = fs::remove_file(path);
        }
    }

    Ok(())
}

fn rotated_path(path: &Path, index: u32) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

pub fn read_last_lines(path: &Path, max_lines: usize) -> Result<Vec<String>> {
    if max_lines == 0 || !path.exists() {
        return Ok(Vec::new());
    }

    let mut file =
        File::open(path).with_context(|| format!("failed opening {}", path.display()))?;
    let total_size = file
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len();
    if total_size == 0 {
        return Ok(Vec::new());
    }

    const CHUNK_SIZE: u64 = 16 * 1024;
    let mut offset = total_size;
    let mut newline_count = 0usize;
    let mut chunks: Vec<Vec<u8>> = Vec::new();

    while offset > 0 && newline_count <= max_lines {
        let read_len = CHUNK_SIZE.min(offset) as usize;
        offset -= read_len as u64;

        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed seeking {}", path.display()))?;

        let mut chunk = vec![0_u8; read_len];
        file.read_exact(&mut chunk)
            .with_context(|| format!("failed reading {}", path.display()))?;
        newline_count += chunk.iter().filter(|&&byte| byte == b'\n').count();
        chunks.push(chunk);
    }

    let total_bytes: usize = chunks.iter().map(Vec::len).sum();
    let mut bytes = Vec::with_capacity(total_bytes);
    for chunk in chunks.iter().rev() {
        bytes.extend_from_slice(chunk);
    }
    let text = String::from_utf8_lossy(&bytes);

    let mut ring = VecDeque::with_capacity(max_lines.saturating_add(1));
    for line in text.lines() {
        ring.push_back(line.to_string());
        if ring.len() > max_lines {
            ring.pop_front();
        }
    }

    Ok(ring.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{open_log_writers, process_logs, read_last_lines, LogRotationPolicy, ProcessLogs};

    #[test]
    fn open_log_writers_rotates_when_size_exceeded() {
        let tmp = temp_dir("rotate");
        let logs = ProcessLogs {
            stdout: tmp.join("app.out.log"),
            stderr: tmp.join("app.err.log"),
        };
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        fs::write(&logs.stdout, "1234567890").expect("failed to write stdout seed");
        fs::write(&logs.stderr, "1234567890").expect("failed to write stderr seed");

        let policy = LogRotationPolicy {
            max_size_bytes: 5,
            max_files: 3,
            max_age_days: 30,
        };
        let (mut out, mut err) = open_log_writers(&logs, policy).expect("failed opening logs");
        writeln!(out, "new").expect("failed writing stdout");
        writeln!(err, "new").expect("failed writing stderr");

        assert!(tmp.join("app.out.log.1").exists());
        assert!(tmp.join("app.err.log.1").exists());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn open_log_writers_does_not_rotate_when_size_is_below_threshold() {
        let tmp = temp_dir("no-rotate");
        let logs = ProcessLogs {
            stdout: tmp.join("app.out.log"),
            stderr: tmp.join("app.err.log"),
        };
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        fs::write(&logs.stdout, "1234").expect("failed to write stdout seed");
        fs::write(&logs.stderr, "1234").expect("failed to write stderr seed");

        let policy = LogRotationPolicy {
            max_size_bytes: 1024,
            max_files: 3,
            max_age_days: 30,
        };
        let _ = open_log_writers(&logs, policy).expect("failed opening logs");

        assert!(!tmp.join("app.out.log.1").exists());
        assert!(!tmp.join("app.err.log.1").exists());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn open_log_writers_prunes_rotated_files_by_count() {
        let tmp = temp_dir("prune-count");
        let logs = ProcessLogs {
            stdout: tmp.join("app.out.log"),
            stderr: tmp.join("app.err.log"),
        };
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        fs::write(&logs.stdout, "seed").expect("failed to write stdout seed");
        fs::write(&logs.stderr, "seed").expect("failed to write stderr seed");
        fs::write(tmp.join("app.out.log.1"), "r1").expect("failed to write out.1");
        fs::write(tmp.join("app.out.log.2"), "r2").expect("failed to write out.2");
        fs::write(tmp.join("app.out.log.3"), "r3").expect("failed to write out.3");

        let policy = LogRotationPolicy {
            max_size_bytes: 1024,
            max_files: 2,
            max_age_days: 30,
        };
        let _ = open_log_writers(&logs, policy).expect("failed opening logs");

        assert!(tmp.join("app.out.log.1").exists());
        assert!(tmp.join("app.out.log.2").exists());
        assert!(!tmp.join("app.out.log.3").exists());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn read_last_lines_returns_only_tail() {
        let tmp = temp_dir("read-tail");
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        let path = tmp.join("app.out.log");
        fs::write(&path, "line1\nline2\nline3\nline4\n").expect("failed to write test log file");

        let lines = read_last_lines(&path, 2).expect("failed reading tail lines");
        assert_eq!(lines, vec!["line3".to_string(), "line4".to_string()]);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn read_last_lines_returns_all_lines_without_trailing_newline() {
        let tmp = temp_dir("read-no-trailing-newline");
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        let path = tmp.join("app.out.log");
        fs::write(&path, "line1\nline2\nline3").expect("failed to write test log file");

        let lines = read_last_lines(&path, 10).expect("failed reading lines");
        assert_eq!(
            lines,
            vec![
                "line1".to_string(),
                "line2".to_string(),
                "line3".to_string()
            ]
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn read_last_lines_returns_empty_for_missing_or_empty_file() {
        let tmp = temp_dir("read-empty");
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        let missing = tmp.join("missing.log");
        let empty = tmp.join("empty.log");
        fs::write(&empty, "").expect("failed to create empty log file");

        assert!(read_last_lines(&missing, 5)
            .expect("missing file should be handled")
            .is_empty());
        assert!(read_last_lines(&empty, 5)
            .expect("empty file should be handled")
            .is_empty());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn read_last_lines_with_zero_limit_returns_empty() {
        let tmp = temp_dir("read-zero");
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        let path = tmp.join("app.out.log");
        fs::write(&path, "line1\nline2\n").expect("failed to write test log file");

        let lines = read_last_lines(&path, 0).expect("failed reading lines");
        assert!(lines.is_empty());

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn open_log_writers_creates_parent_directory_and_files() {
        let tmp = temp_dir("create-files");
        let logs = ProcessLogs {
            stdout: tmp.join("nested").join("app.out.log"),
            stderr: tmp.join("nested").join("app.err.log"),
        };

        let policy = LogRotationPolicy {
            max_size_bytes: 1024,
            max_files: 2,
            max_age_days: 30,
        };

        let _ = open_log_writers(&logs, policy).expect("failed opening logs");

        assert!(logs.stdout.exists(), "stdout log should be created");
        assert!(logs.stderr.exists(), "stderr log should be created");
        assert!(
            logs.stdout.parent().is_some_and(|parent| parent.exists()),
            "log directory should be created"
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn open_log_writers_rotates_existing_chain_forward() {
        let tmp = temp_dir("rotate-chain");
        let logs = ProcessLogs {
            stdout: tmp.join("app.out.log"),
            stderr: tmp.join("app.err.log"),
        };
        fs::create_dir_all(&tmp).expect("failed to create temp directory");
        fs::write(&logs.stdout, "current-out").expect("failed to write stdout seed");
        fs::write(&logs.stderr, "current-err").expect("failed to write stderr seed");
        fs::write(tmp.join("app.out.log.1"), "older-out-1").expect("failed to write out.1");
        fs::write(tmp.join("app.out.log.2"), "older-out-2").expect("failed to write out.2");
        fs::write(tmp.join("app.err.log.1"), "older-err-1").expect("failed to write err.1");
        fs::write(tmp.join("app.err.log.2"), "older-err-2").expect("failed to write err.2");

        let policy = LogRotationPolicy {
            max_size_bytes: 1,
            max_files: 3,
            max_age_days: 30,
        };
        let _ = open_log_writers(&logs, policy).expect("failed opening logs");

        assert_eq!(
            fs::read_to_string(tmp.join("app.out.log.1")).expect("failed to read out.1"),
            "current-out"
        );
        assert_eq!(
            fs::read_to_string(tmp.join("app.out.log.2")).expect("failed to read out.2"),
            "older-out-1"
        );
        assert_eq!(
            fs::read_to_string(tmp.join("app.out.log.3")).expect("failed to read out.3"),
            "older-out-2"
        );

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn process_logs_builds_expected_file_paths() {
        let logs = process_logs(Path::new("/tmp/oxmgr/logs"), "worker");
        assert_eq!(logs.stdout, Path::new("/tmp/oxmgr/logs/worker.out.log"));
        assert_eq!(logs.stderr, Path::new("/tmp/oxmgr/logs/worker.err.log"));
    }

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("oxmgr-{prefix}-{nonce}"))
    }
}
