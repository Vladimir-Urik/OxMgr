use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
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
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    rotate_log_if_needed(&logs.stdout, policy)?;
    rotate_log_if_needed(&logs.stderr, policy)?;
    cleanup_rotated_logs(&logs.stdout, policy)?;
    cleanup_rotated_logs(&logs.stderr, policy)?;

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logs.stdout)
        .with_context(|| format!("failed opening {}", logs.stdout.display()))?;

    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logs.stderr)
        .with_context(|| format!("failed opening {}", logs.stderr.display()))?;

    Ok((stdout, stderr))
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
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).with_context(|| format!("failed opening {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut ring = VecDeque::with_capacity(max_lines.saturating_add(1));
    for line in reader.lines() {
        let line = line.with_context(|| format!("failed reading {}", path.display()))?;
        ring.push_back(line);
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{open_log_writers, LogRotationPolicy, ProcessLogs};

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

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("oxmgr-{prefix}-{nonce}"))
    }
}
