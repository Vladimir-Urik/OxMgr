use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::ui;

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig, target: String) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::Status { target }).await?;
    let response = expect_ok(response)?;

    let process = response
        .process
        .context("daemon returned no process for status command")?;

    print_field("ID", process.id);
    print_field("Name", &process.name);
    print_field("Status", ui::status_value(&process.status));
    print_field(
        "PID",
        process
            .pid
            .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
    );
    print_field(
        "Uptime",
        ui::format_process_uptime(&process.status, process.last_started_at),
    );
    print_field(
        "Restarts",
        format!("{}/{}", process.restart_count, process.max_restarts),
    );
    print_field("Watch", if process.watch { "enabled" } else { "disabled" });
    print_field(
        "Cluster",
        if process.cluster_mode {
            process
                .cluster_instances
                .map(|instances| format!("enabled ({instances} workers)"))
                .unwrap_or_else(|| "enabled (auto workers)".to_string())
        } else {
            "disabled".to_string()
        },
    );
    print_field("Policy", process.restart_policy.to_string());
    if let Some(namespace) = process.namespace.as_deref() {
        print_field("Namespace", namespace);
    }
    print_field("Health", ui::health_value(&process.health_status));
    if let Some(last_error) = process.last_health_error.as_deref() {
        print_field("Health Last", last_error);
    }
    print_field("CPU", format!("{:.1}%", process.cpu_percent));
    print_field(
        "RAM",
        format!("{} MB", process.memory_bytes / (1024 * 1024)),
    );
    if let Some(limits) = process.resource_limits.as_ref() {
        print_field(
            "Limits",
            format!(
                "memory={} cpu={} cgroup_enforce={} deny_gpu={}",
                limits
                    .max_memory_mb
                    .map_or_else(|| "-".to_string(), |v| format!("{v} MB")),
                limits
                    .max_cpu_percent
                    .map_or_else(|| "-".to_string(), |v| format!("{v:.1}%")),
                limits.cgroup_enforce,
                limits.deny_gpu
            ),
        );
    }
    if let Some(cgroup_path) = process.cgroup_path.as_deref() {
        print_field("Cgroup", cgroup_path);
    }
    let command = if process.args.is_empty() {
        process.command.clone()
    } else {
        format!("{} {}", process.command, process.args.join(" "))
    };
    print_field("Command", command);
    print_field(
        "Working Dir",
        process
            .cwd
            .map_or_else(|| "-".to_string(), |cwd| cwd.display().to_string()),
    );
    print_field("Stdout Log", process.stdout_log.display().to_string());
    print_field("Stderr Log", process.stderr_log.display().to_string());

    Ok(())
}

fn print_field(label: &str, value: impl std::fmt::Display) {
    let left = format!("{label}:");
    println!("{} {}", ui::label(&format!("{left:<12}")), value);
}
