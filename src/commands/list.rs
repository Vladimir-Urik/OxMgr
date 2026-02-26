use anyhow::Result;

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::ManagedProcess;

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::List).await?;
    let response = expect_ok(response)?;
    print_process_table(response.processes);

    Ok(())
}

fn print_process_table(mut processes: Vec<ManagedProcess>) {
    processes.sort_by_key(|process| process.id);

    if processes.is_empty() {
        println!("No managed processes.");
        return;
    }

    println!("ID   NAME              STATUS       PID      RESTARTS  CPU%    RAM(MB) HEALTH");
    for process in processes {
        let pid = process
            .pid
            .map_or_else(|| "-".to_string(), |value| value.to_string());
        println!(
            "{:<4} {:<17} {:<12} {:<8} {:<9} {:<7.1} {:<7} {}",
            process.id,
            process.name,
            process.status,
            pid,
            process.restart_count,
            process.cpu_percent,
            process.memory_bytes / (1024 * 1024),
            process.health_status
        );
    }
}
