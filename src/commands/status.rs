use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig, target: String) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::Status { target }).await?;
    let response = expect_ok(response)?;

    let process = response
        .process
        .context("daemon returned no process for status command")?;

    println!("ID:          {}", process.id);
    println!("Name:        {}", process.name);
    println!("Status:      {}", process.status);
    println!(
        "PID:         {}",
        process
            .pid
            .map_or_else(|| "-".to_string(), |pid| pid.to_string())
    );
    println!(
        "Restarts:    {}/{}",
        process.restart_count, process.max_restarts
    );
    println!("Policy:      {}", process.restart_policy);
    if let Some(namespace) = process.namespace.as_deref() {
        println!("Namespace:   {}", namespace);
    }
    println!("Health:      {}", process.health_status);
    if let Some(last_error) = process.last_health_error {
        println!("Health Last: {}", last_error);
    }
    println!("CPU:         {:.1}%", process.cpu_percent);
    println!("RAM:         {} MB", process.memory_bytes / (1024 * 1024));
    if let Some(limits) = process.resource_limits.as_ref() {
        println!(
            "Limits:      memory={} cpu={} cgroup_enforce={} deny_gpu={}",
            limits
                .max_memory_mb
                .map_or_else(|| "-".to_string(), |v| format!("{v} MB")),
            limits
                .max_cpu_percent
                .map_or_else(|| "-".to_string(), |v| format!("{v:.1}%")),
            limits.cgroup_enforce,
            limits.deny_gpu,
        );
    }
    if let Some(cgroup_path) = process.cgroup_path.as_deref() {
        println!("Cgroup:      {}", cgroup_path);
    }
    println!(
        "Command:     {} {}",
        process.command,
        process.args.join(" ")
    );
    println!(
        "Working Dir: {}",
        process
            .cwd
            .map_or_else(|| "-".to_string(), |cwd| cwd.display().to_string())
    );
    println!("Stdout Log:  {}", process.stdout_log.display());
    println!("Stderr Log:  {}", process.stderr_log.display());

    Ok(())
}
