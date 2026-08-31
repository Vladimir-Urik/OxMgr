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
    target: Option<String>,
    follow: bool,
    lines: usize,
) -> Result<()> {
    let Some(target) = target else {
        print_logs_help();
        return Ok(());
    };

    if target == "all" {
        return run_all(config, follow, lines).await;
    }

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

async fn run_all(config: &AppConfig, follow: bool, lines: usize) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::List).await?;
    let response = expect_ok(response)?;

    if response.processes.is_empty() {
        println!("No managed processes found.");
        return Ok(());
    }

    for process in &response.processes {
        println!("\n=== {} ===", process.name);
        let logs = ProcessLogs {
            stdout: process.stdout_log.clone(),
            stderr: process.stderr_log.clone(),
        };
        if let Err(e) = print_last_logs(&logs, lines) {
            eprintln!("  (failed to read logs: {e})");
        }
    }

    if follow {
        let logs_list: Vec<ProcessLogs> = response
            .processes
            .iter()
            .map(|p| ProcessLogs {
                stdout: p.stdout_log.clone(),
                stderr: p.stderr_log.clone(),
            })
            .collect();
        follow_all(logs_list).await;
    }

    Ok(())
}

async fn follow_all(logs_list: Vec<ProcessLogs>) {
    println!("\nFollowing all logs (Ctrl-C to stop)...");
    let mut handles = Vec::new();

    for logs in logs_list {
        if logs.stdout == logs.stderr {
            let path = logs.stdout.clone();
            handles.push(tokio::spawn(async move {
                follow_file(path, "unified", false).await
            }));
        } else {
            let stdout_path = logs.stdout.clone();
            let stderr_path = logs.stderr.clone();
            handles.push(tokio::spawn(async move {
                follow_file(stdout_path, "stdout", true).await
            }));
            handles.push(tokio::spawn(async move {
                follow_file(stderr_path, "stderr", true).await
            }));
        }
    }

    let _ = tokio::signal::ctrl_c().await;

    for handle in handles {
        handle.abort();
        let _ = handle.await;
    }
}

fn print_logs_help() {
    eprintln!("Usage: oxmgr logs <TARGET>");
    eprintln!();
    eprintln!("Print recent logs for a managed process.");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <TARGET>  Process name, numeric id, or 'all' to print logs for every process");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -f, --follow     Follow log output");
    eprintln!("      --lines <N>  Number of lines to show [default: 100]");
}

fn print_last_logs(logs: &ProcessLogs, lines: usize) -> Result<()> {
    if logs.stdout == logs.stderr {
        println!("==> {} <==", logs.stdout.display());
        for line in read_last_lines(&logs.stdout, lines)? {
            println!("{line}");
        }
        return Ok(());
    }

    for path in ordered_log_sections(logs) {
        println!("==> {} <==", path.display());
        for line in read_last_lines(path, lines)? {
            println!("{line}");
        }
    }

    Ok(())
}

fn ordered_log_sections(logs: &ProcessLogs) -> Vec<&Path> {
    if logs.stdout == logs.stderr {
        return vec![logs.stdout.as_path()];
    }

    let mut sections = [logs.stdout.as_path(), logs.stderr.as_path()];
    sections.sort_by(|left, right| {
        log_modified_at(left)
            .cmp(&log_modified_at(right))
            .then_with(|| left.as_os_str().cmp(right.as_os_str()))
    });
    sections.to_vec()
}

async fn follow_logs(logs: ProcessLogs) -> Result<()> {
    println!("Following logs (Ctrl-C to stop)...");

    if logs.stdout == logs.stderr {
        let unified_path = logs.stdout.clone();
        let mut unified_task =
            tokio::spawn(async move { follow_file(unified_path, "unified", false).await });
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = &mut unified_task => {}
        }
        unified_task.abort();
        let _ = unified_task.await;
        return Ok(());
    }

    let stdout_path = logs.stdout.clone();
    let stderr_path = logs.stderr.clone();

    let mut stdout_task =
        tokio::spawn(async move { follow_file(stdout_path, "stdout", true).await });
    let mut stderr_task =
        tokio::spawn(async move { follow_file(stderr_path, "stderr", true).await });

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

async fn follow_file(path: PathBuf, label: &'static str, prefix_label: bool) -> Result<()> {
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
                if prefix_label {
                    println!("[{label}] {line}");
                } else {
                    println!("{line}");
                }
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

    #[test]
    fn ordered_log_sections_deduplicates_unified_path() {
        let log_path = PathBuf::from("/tmp/unified.log");
        let logs = ProcessLogs {
            stdout: log_path.clone(),
            stderr: log_path,
        };

        let sections = ordered_log_sections(&logs);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0], logs.stdout.as_path());
    }
}
