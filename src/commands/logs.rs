use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time::{sleep, Duration};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::logging::{read_last_lines, ProcessLogs};

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
    println!("==> {} <==", logs.stdout.display());
    for line in read_last_lines(&logs.stdout, lines)? {
        println!("{line}");
    }

    println!("==> {} <==", logs.stderr.display());
    for line in read_last_lines(&logs.stderr, lines)? {
        println!("{line}");
    }

    Ok(())
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
