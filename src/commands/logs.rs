use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time::{sleep, Duration};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::logging::{log_modified_at, read_last_lines, ProcessLogs};

use super::common::expect_ok;

pub(crate) async fn run(
    config: &AppConfig,
    target: String,
    follow: bool,
    lines: usize,
) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::Logs { target }).await?;
    let response = expect_ok(response)?;
    let logs = response
        .logs
        .context("daemon returned no log paths for logs command")?;

    print_last_logs(&logs, lines)?;
    if follow {
        follow_logs(logs).await?;
    }

    Ok(())
}

fn print_last_logs(logs: &ProcessLogs, lines: usize) -> Result<()> {
    for path in ordered_log_sections(logs) {
        println!("==> {} <==", path.display());
        for line in read_last_lines(path, lines)? {
            println!("{line}");
        }
    }

    Ok(())
}

fn ordered_log_sections(logs: &ProcessLogs) -> [&Path; 2] {
    let mut sections = [logs.stdout.as_path(), logs.stderr.as_path()];
    sections.sort_by(|left, right| {
        log_modified_at(left)
            .cmp(&log_modified_at(right))
            .then_with(|| left.as_os_str().cmp(right.as_os_str()))
    });
    sections
}

async fn follow_logs(logs: ProcessLogs) -> Result<()> {
    println!("Following logs (Ctrl-C to stop)...");

    let stdout_path = logs.stdout.clone();
    let stderr_path = logs.stderr.clone();

    let mut stdout_task = tokio::spawn(async move { follow_file(stdout_path, "stdout").await });
    let mut stderr_task = tokio::spawn(async move { follow_file(stderr_path, "stderr").await });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = &mut stdout_task => {}
        _ = &mut stderr_task => {}
    }

    stdout_task.abort();
    stderr_task.abort();
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    Ok(())
}

async fn follow_file(path: PathBuf, label: &'static str) -> Result<()> {
    if !path.exists() {
        std::fs::File::create(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .await
        .with_context(|| format!("failed to open {}", path.display()))?;

    file.seek(std::io::SeekFrom::End(0)).await?;

    loop {
        let mut buffer = Vec::new();
        let bytes_read = file.read_to_end(&mut buffer).await?;
        if bytes_read > 0 {
            let text = String::from_utf8_lossy(&buffer);
            for line in text.lines() {
                println!("[{label}] {line}");
            }
        } else {
            let current_pos = file.seek(std::io::SeekFrom::Current(0)).await?;
            if let Ok(meta) = tokio::fs::metadata(&path).await {
                if meta.len() < current_pos {
                    file = tokio::fs::OpenOptions::new()
                        .read(true)
                        .open(&path)
                        .await
                        .with_context(|| format!("failed to reopen {}", path.display()))?;
                }
            }
        }
        sleep(Duration::from_millis(300)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::logging::{log_modified_at, ProcessLogs};

    use super::ordered_log_sections;

    #[test]
    fn ordered_log_sections_keeps_newer_stream_last() {
        let tmp = temp_dir("ordered-sections");
        let stderr = tmp.join("stderr.log");
        let stdout = tmp.join("stdout.log");

        fs::write(&stderr, "older").expect("failed to seed stderr");
        let older_mtime = log_modified_at(&stderr);
        write_until_newer(&stdout, "newer", older_mtime);

        let logs = ProcessLogs {
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        };
        let sections = ordered_log_sections(&logs);

        assert_eq!(sections[0], stderr.as_path());
        assert_eq!(sections[1], stdout.as_path());

        let _ = fs::remove_dir_all(tmp);
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("oxmgr-logs-test-{prefix}-{nonce}"));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn write_until_newer(path: &Path, contents: &str, older_than: std::time::SystemTime) {
        for _ in 0..10 {
            fs::write(path, contents).expect("failed to write log test file");
            if log_modified_at(path) > older_than {
                return;
            }
            sleep(Duration::from_millis(20));
        }
        panic!("failed to produce a newer mtime for {}", path.display());
    }
}
