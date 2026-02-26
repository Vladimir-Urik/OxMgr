mod cli;
mod config;
mod daemon;
mod ecosystem;
mod errors;
mod ipc;
mod logging;
mod oxfile;
mod process;
mod process_manager;
mod storage;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

use crate::cli::{
    build_health_check, build_resource_limits, env_pairs_to_map, Cli, Commands, DaemonCommand,
    InitSystem,
};
use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest, IpcResponse};
use crate::logging::{read_last_lines, ProcessLogs};
use crate::process::{HealthCheck, ManagedProcess, ResourceLimits, RestartPolicy};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = AppConfig::load()?;

    match cli.command {
        Commands::Daemon {
            command: DaemonCommand::Run,
        } => daemon::run_foreground(config).await,
        command => run_cli_command(command, &config).await,
    }
}

async fn run_cli_command(command: Commands, config: &AppConfig) -> Result<()> {
    let needs_daemon = !matches!(
        command,
        Commands::Startup { .. } | Commands::Convert { .. } | Commands::Validate { .. }
    );
    if needs_daemon {
        daemon::ensure_daemon_running(config).await?;
    }

    match command {
        Commands::Start {
            command,
            name,
            restart,
            max_restarts,
            cwd,
            env,
            health_cmd,
            health_interval,
            health_timeout,
            health_max_failures,
            kill_signal,
            stop_timeout,
            restart_delay,
            start_delay,
            namespace,
            max_memory_mb,
            max_cpu_percent,
        } => {
            let health_check = build_health_check(
                health_cmd,
                health_interval,
                health_timeout,
                health_max_failures,
            );
            let resource_limits = build_resource_limits(max_memory_mb, max_cpu_percent);

            let response = send_request(
                &config.daemon_addr,
                &IpcRequest::Start {
                    command,
                    name,
                    restart_policy: restart.into(),
                    max_restarts,
                    cwd,
                    env: env_pairs_to_map(env),
                    health_check,
                    stop_signal: kill_signal,
                    stop_timeout_secs: stop_timeout.max(1),
                    restart_delay_secs: restart_delay,
                    start_delay_secs: start_delay,
                    namespace,
                    resource_limits,
                },
            )
            .await?;
            let response = expect_ok(response)?;
            println!("{}", response.message);
        }
        Commands::Stop { target } => {
            let response = send_request(&config.daemon_addr, &IpcRequest::Stop { target }).await?;
            let response = expect_ok(response)?;
            println!("{}", response.message);
        }
        Commands::Restart { target } => {
            let response =
                send_request(&config.daemon_addr, &IpcRequest::Restart { target }).await?;
            let response = expect_ok(response)?;
            println!("{}", response.message);
        }
        Commands::Reload { target } => {
            let response =
                send_request(&config.daemon_addr, &IpcRequest::Reload { target }).await?;
            let response = expect_ok(response)?;
            println!("{}", response.message);
        }
        Commands::Delete { target } => {
            let response =
                send_request(&config.daemon_addr, &IpcRequest::Delete { target }).await?;
            let response = expect_ok(response)?;
            println!("{}", response.message);
        }
        Commands::List => {
            let response = send_request(&config.daemon_addr, &IpcRequest::List).await?;
            let response = expect_ok(response)?;
            print_process_table(response.processes);
        }
        Commands::Status { target } => {
            let response =
                send_request(&config.daemon_addr, &IpcRequest::Status { target }).await?;
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
                    "Limits:      memory={} cpu={}",
                    limits
                        .max_memory_mb
                        .map_or_else(|| "-".to_string(), |v| format!("{v} MB")),
                    limits
                        .max_cpu_percent
                        .map_or_else(|| "-".to_string(), |v| format!("{v:.1}%")),
                );
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
        }
        Commands::Logs {
            target,
            follow,
            lines,
        } => {
            let response = send_request(&config.daemon_addr, &IpcRequest::Logs { target }).await?;
            let response = expect_ok(response)?;
            let logs = response
                .logs
                .context("daemon returned no log paths for logs command")?;

            print_last_logs(&logs, lines)?;
            if follow {
                follow_logs(logs).await?;
            }
        }
        Commands::Import { path, env, only } => {
            let mut specs = load_import_specs(&path, env.as_deref())?;
            if !only.is_empty() {
                specs.retain(|spec| {
                    spec.name
                        .as_ref()
                        .map(|name| only.iter().any(|selected| selected == name))
                        .unwrap_or(false)
                });
            }
            specs = order_specs_for_start(specs);

            if specs.is_empty() {
                println!("No apps found in {}", path.display());
                return Ok(());
            }

            let mut success = 0_usize;
            let mut failed = Vec::new();

            for spec in specs {
                let instances = spec.instances.max(1);
                for idx in 0..instances {
                    let mut env_vars = spec.env.clone();
                    if instances > 1 {
                        let key = spec
                            .instance_var
                            .clone()
                            .unwrap_or_else(|| "NODE_APP_INSTANCE".to_string());
                        env_vars.insert(key, idx.to_string());
                    }

                    let name = match (&spec.name, instances) {
                        (Some(base), count) if count > 1 => Some(format!("{base}-{idx}")),
                        (Some(base), _) => Some(base.clone()),
                        (None, _) => None,
                    };

                    let response = send_request(
                        &config.daemon_addr,
                        &IpcRequest::Start {
                            command: spec.command.clone(),
                            name,
                            restart_policy: spec.restart_policy.clone(),
                            max_restarts: spec.max_restarts,
                            cwd: spec.cwd.clone(),
                            env: env_vars,
                            health_check: spec.health_check.clone(),
                            stop_signal: spec.stop_signal.clone(),
                            stop_timeout_secs: spec.stop_timeout_secs.max(1),
                            restart_delay_secs: spec.restart_delay_secs,
                            start_delay_secs: spec.start_delay_secs,
                            namespace: spec.namespace.clone(),
                            resource_limits: spec.resource_limits.clone(),
                        },
                    )
                    .await?;

                    if response.ok {
                        success += 1;
                        println!("{}", response.message);
                    } else {
                        failed.push(response.message);
                    }
                }
            }

            println!("Imported: {} started, {} failed", success, failed.len());
            if !failed.is_empty() {
                for message in failed {
                    eprintln!("- {}", message);
                }
                anyhow::bail!("ecosystem import finished with failures");
            }
        }
        Commands::Apply {
            path,
            env,
            only,
            prune,
        } => {
            let mut specs = load_import_specs(&path, env.as_deref())?;
            if !only.is_empty() {
                specs.retain(|spec| {
                    spec.name
                        .as_ref()
                        .map(|name| only.iter().any(|selected| selected == name))
                        .unwrap_or(false)
                });
            }
            specs = order_specs_for_start(specs);

            let desired = expand_specs_for_apply(specs)?;
            if desired.is_empty() {
                println!("No apps found in {}", path.display());
                return Ok(());
            }

            let list_response = send_request(&config.daemon_addr, &IpcRequest::List).await?;
            let list_response = expect_ok(list_response)?;
            let current = list_response.processes;

            let plan = plan_apply_actions(&current, &desired, prune);
            let mut created = 0_usize;
            let mut restarted = 0_usize;
            let mut updated = 0_usize;
            let mut skipped = 0_usize;
            let mut pruned = 0_usize;
            let mut failures = Vec::new();

            for action in plan.actions {
                match action {
                    ApplyAction::Start(spec) => {
                        let response = send_request(
                            &config.daemon_addr,
                            &start_request_from_spec(spec.clone()),
                        )
                        .await?;
                        if response.ok {
                            created = created.saturating_add(1);
                        } else {
                            failures.push(format!("start {}: {}", spec.name, response.message));
                        }
                    }
                    ApplyAction::Restart(name) => {
                        let response = send_request(
                            &config.daemon_addr,
                            &IpcRequest::Restart {
                                target: name.clone(),
                            },
                        )
                        .await?;
                        if response.ok {
                            restarted = restarted.saturating_add(1);
                        } else {
                            failures.push(format!("restart {}: {}", name, response.message));
                        }
                    }
                    ApplyAction::Recreate(spec) => {
                        let delete = send_request(
                            &config.daemon_addr,
                            &IpcRequest::Delete {
                                target: spec.name.clone(),
                            },
                        )
                        .await?;
                        if !delete.ok {
                            failures.push(format!("delete {}: {}", spec.name, delete.message));
                            continue;
                        }

                        let start = send_request(
                            &config.daemon_addr,
                            &start_request_from_spec(spec.clone()),
                        )
                        .await?;
                        if start.ok {
                            updated = updated.saturating_add(1);
                        } else {
                            failures.push(format!("start {}: {}", spec.name, start.message));
                        }
                    }
                    ApplyAction::Delete(name) => {
                        let response = send_request(
                            &config.daemon_addr,
                            &IpcRequest::Delete {
                                target: name.clone(),
                            },
                        )
                        .await?;
                        if response.ok {
                            pruned = pruned.saturating_add(1);
                        } else {
                            failures.push(format!("delete {}: {}", name, response.message));
                        }
                    }
                    ApplyAction::Noop => {
                        skipped = skipped.saturating_add(1);
                    }
                }
            }

            println!(
                "Apply complete: {} created, {} restarted, {} updated, {} unchanged, {} pruned",
                created, restarted, updated, skipped, pruned
            );

            if !failures.is_empty() {
                for failure in failures {
                    eprintln!("- {}", failure);
                }
                anyhow::bail!("apply finished with failures");
            }
        }
        Commands::Convert { input, out, env } => {
            let specs = ecosystem::load_with_profile(&input, env.as_deref())?;
            oxfile::write_from_specs(&out, &specs)?;
            println!("Converted {} -> {}", input.display(), out.display());
        }
        Commands::Validate { path, env, only } => {
            validate_oxfile_command(&path, env.as_deref(), &only)?;
        }
        Commands::Startup { system } => {
            print_startup_instructions(system, config)?;
        }
        Commands::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("daemon mode is handled before CLI dispatch"),
    }

    Ok(())
}

fn expect_ok(response: IpcResponse) -> Result<IpcResponse> {
    if response.ok {
        Ok(response)
    } else {
        anyhow::bail!(response.message)
    }
}

fn load_import_specs(
    path: &Path,
    env: Option<&str>,
) -> Result<Vec<crate::ecosystem::EcosystemProcessSpec>> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    match extension.as_deref() {
        Some("toml") => oxfile::load_with_profile(path, env),
        _ => ecosystem::load_with_profile(path, env),
    }
}

fn order_specs_for_start(
    specs: Vec<crate::ecosystem::EcosystemProcessSpec>,
) -> Vec<crate::ecosystem::EcosystemProcessSpec> {
    let mut by_name = HashMap::new();
    for (idx, spec) in specs.iter().enumerate() {
        if let Some(name) = &spec.name {
            by_name.insert(name.clone(), idx);
        }
    }

    let mut indegree = vec![0_usize; specs.len()];
    let mut edges = vec![Vec::<usize>::new(); specs.len()];

    for (idx, spec) in specs.iter().enumerate() {
        for dependency in &spec.depends_on {
            if let Some(dep_idx) = by_name.get(dependency) {
                edges[*dep_idx].push(idx);
                indegree[idx] = indegree[idx].saturating_add(1);
            }
        }
    }

    let mut remaining: HashSet<usize> = (0..specs.len()).collect();
    let mut ordered_indices = Vec::with_capacity(specs.len());

    while !remaining.is_empty() {
        let mut ready: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|idx| indegree[*idx] == 0)
            .collect();

        if ready.is_empty() {
            let mut leftovers: Vec<usize> = remaining.iter().copied().collect();
            leftovers.sort_by(|left, right| {
                let left_spec = &specs[*left];
                let right_spec = &specs[*right];

                left_spec
                    .start_order
                    .cmp(&right_spec.start_order)
                    .then_with(|| left_spec.name.cmp(&right_spec.name))
                    .then_with(|| left.cmp(right))
            });
            ordered_indices.extend(leftovers);
            break;
        }

        ready.sort_by(|left, right| {
            let left_spec = &specs[*left];
            let right_spec = &specs[*right];

            left_spec
                .start_order
                .cmp(&right_spec.start_order)
                .then_with(|| left_spec.name.cmp(&right_spec.name))
                .then_with(|| left.cmp(right))
        });

        let current = ready[0];
        remaining.remove(&current);
        ordered_indices.push(current);
        for next in &edges[current] {
            indegree[*next] = indegree[*next].saturating_sub(1);
        }
    }

    let mut slots: Vec<Option<crate::ecosystem::EcosystemProcessSpec>> =
        specs.into_iter().map(Some).collect();
    let mut ordered = Vec::with_capacity(slots.len());
    for idx in ordered_indices {
        if let Some(spec) = slots[idx].take() {
            ordered.push(spec);
        }
    }

    ordered
}

#[derive(Debug, Clone)]
struct DesiredProcessSpec {
    name: String,
    command: String,
    restart_policy: RestartPolicy,
    max_restarts: u32,
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    health_check: Option<HealthCheck>,
    stop_signal: Option<String>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    namespace: Option<String>,
    resource_limits: Option<ResourceLimits>,
}

#[derive(Debug, Clone)]
enum ApplyAction {
    Start(DesiredProcessSpec),
    Restart(String),
    Recreate(DesiredProcessSpec),
    Delete(String),
    Noop,
}

#[derive(Debug, Clone)]
struct ApplyPlan {
    actions: Vec<ApplyAction>,
}

fn expand_specs_for_apply(
    specs: Vec<crate::ecosystem::EcosystemProcessSpec>,
) -> Result<Vec<DesiredProcessSpec>> {
    let mut desired = Vec::new();
    let mut seen_names = HashSet::new();

    for spec in specs {
        let instances = spec.instances.max(1);
        let base_name = spec.name.clone().with_context(|| {
            format!(
                "app command '{}' is missing 'name'; apply requires deterministic names",
                spec.command
            )
        })?;

        for idx in 0..instances {
            let mut env = spec.env.clone();
            let name = if instances > 1 {
                let key = spec
                    .instance_var
                    .clone()
                    .unwrap_or_else(|| "NODE_APP_INSTANCE".to_string());
                env.insert(key, idx.to_string());
                format!("{base_name}-{idx}")
            } else {
                base_name.clone()
            };

            if !seen_names.insert(name.clone()) {
                anyhow::bail!("duplicate app name in desired config: {}", name);
            }

            desired.push(DesiredProcessSpec {
                name,
                command: spec.command.clone(),
                restart_policy: spec.restart_policy.clone(),
                max_restarts: spec.max_restarts,
                cwd: spec.cwd.clone(),
                env,
                health_check: spec.health_check.clone(),
                stop_signal: spec.stop_signal.clone(),
                stop_timeout_secs: spec.stop_timeout_secs.max(1),
                restart_delay_secs: spec.restart_delay_secs,
                start_delay_secs: spec.start_delay_secs,
                namespace: spec.namespace.clone(),
                resource_limits: spec.resource_limits.clone(),
            });
        }
    }

    Ok(desired)
}

fn plan_apply_actions(
    current: &[ManagedProcess],
    desired: &[DesiredProcessSpec],
    prune: bool,
) -> ApplyPlan {
    let mut actions = Vec::new();
    let current_map: HashMap<String, ManagedProcess> = current
        .iter()
        .cloned()
        .map(|process| (process.name.clone(), process))
        .collect();

    let desired_names: HashSet<String> = desired.iter().map(|spec| spec.name.clone()).collect();

    for spec in desired {
        if let Some(existing) = current_map.get(&spec.name) {
            if process_matches_spec(existing, spec) {
                if existing.status == crate::process::ProcessStatus::Running
                    && existing.pid.is_some()
                {
                    actions.push(ApplyAction::Noop);
                } else {
                    actions.push(ApplyAction::Restart(spec.name.clone()));
                }
            } else {
                actions.push(ApplyAction::Recreate(spec.clone()));
            }
        } else {
            actions.push(ApplyAction::Start(spec.clone()));
        }
    }

    if prune {
        let mut stale: Vec<String> = current_map
            .keys()
            .filter(|name| !desired_names.contains(*name))
            .cloned()
            .collect();
        stale.sort();
        for name in stale {
            actions.push(ApplyAction::Delete(name));
        }
    }

    ApplyPlan { actions }
}

fn process_matches_spec(existing: &ManagedProcess, desired: &DesiredProcessSpec) -> bool {
    let desired_cmd = match split_command_line(&desired.command) {
        Ok(value) => value,
        Err(_) => return false,
    };

    existing.command == desired_cmd.0
        && existing.args == desired_cmd.1
        && existing.restart_policy == desired.restart_policy
        && existing.max_restarts == desired.max_restarts
        && existing.cwd == desired.cwd
        && existing.env == desired.env
        && existing.health_check == desired.health_check
        && existing.stop_signal == desired.stop_signal
        && existing.stop_timeout_secs == desired.stop_timeout_secs
        && existing.restart_delay_secs == desired.restart_delay_secs
        && existing.start_delay_secs == desired.start_delay_secs
        && existing.namespace == desired.namespace
        && existing.resource_limits == desired.resource_limits
}

fn split_command_line(command_line: &str) -> Result<(String, Vec<String>)> {
    let tokens = shell_words::split(command_line)
        .with_context(|| format!("invalid command syntax: {command_line}"))?;
    if tokens.is_empty() {
        anyhow::bail!("command cannot be empty");
    }

    Ok((tokens[0].clone(), tokens[1..].to_vec()))
}

fn start_request_from_spec(spec: DesiredProcessSpec) -> IpcRequest {
    IpcRequest::Start {
        command: spec.command,
        name: Some(spec.name),
        restart_policy: spec.restart_policy,
        max_restarts: spec.max_restarts,
        cwd: spec.cwd,
        env: spec.env,
        health_check: spec.health_check,
        stop_signal: spec.stop_signal,
        stop_timeout_secs: spec.stop_timeout_secs.max(1),
        restart_delay_secs: spec.restart_delay_secs,
        start_delay_secs: spec.start_delay_secs,
        namespace: spec.namespace,
        resource_limits: spec.resource_limits,
    }
}

#[derive(Debug, Clone)]
struct OxfileValidationReport {
    app_count: usize,
    expanded_process_count: usize,
    unnamed_count: usize,
}

fn validate_oxfile_command(path: &Path, env: Option<&str>, only: &[String]) -> Result<()> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    if extension.as_deref() != Some("toml") {
        anyhow::bail!(
            "validate expects oxfile.toml input (got: {})",
            path.display()
        );
    }

    let mut specs = oxfile::load_with_profile(path, env)?;
    if !only.is_empty() {
        specs.retain(|spec| {
            spec.name
                .as_ref()
                .map(|name| only.iter().any(|selected| selected == name))
                .unwrap_or(false)
        });
    }

    if specs.is_empty() {
        if only.is_empty() {
            anyhow::bail!("no apps resolved from {}", path.display());
        } else {
            anyhow::bail!(
                "no apps matched --only filter ({}) in {}",
                only.join(","),
                path.display()
            );
        }
    }

    let report = validate_resolved_specs(&specs)?;

    println!("Oxfile validation: OK");
    println!("Path: {}", path.display());
    println!("Profile: {}", env.unwrap_or("default"));
    println!("Apps: {}", report.app_count);
    println!("Expanded Processes: {}", report.expanded_process_count);
    if report.unnamed_count > 0 {
        println!(
            "Warning: {} app(s) have no name. Add `name` for deterministic `oxmgr apply`.",
            report.unnamed_count
        );
    }

    Ok(())
}

fn validate_resolved_specs(
    specs: &[crate::ecosystem::EcosystemProcessSpec],
) -> Result<OxfileValidationReport> {
    if specs.is_empty() {
        anyhow::bail!("empty app list");
    }

    let mut named_apps = HashSet::new();
    let mut unnamed_count = 0_usize;
    for spec in specs {
        let tokens = shell_words::split(&spec.command)
            .with_context(|| format!("invalid command syntax: {}", spec.command))?;
        if tokens.is_empty() {
            anyhow::bail!("app command cannot be empty");
        }

        if let Some(check) = &spec.health_check {
            let health_tokens = shell_words::split(&check.command)
                .with_context(|| format!("invalid health command syntax: {}", check.command))?;
            if health_tokens.is_empty() {
                anyhow::bail!("health command cannot be empty for app {:?}", spec.name);
            }
        }

        if let Some(name) = &spec.name {
            if !named_apps.insert(name.clone()) {
                anyhow::bail!("duplicate app name in oxfile: {}", name);
            }
        } else {
            unnamed_count = unnamed_count.saturating_add(1);
        }
    }

    for spec in specs {
        for dependency in &spec.depends_on {
            if !named_apps.contains(dependency) {
                anyhow::bail!(
                    "app {:?} depends_on unknown app '{}'",
                    spec.name,
                    dependency
                );
            }
        }
    }

    let mut expanded_names = HashSet::new();
    let mut expanded_process_count = 0_usize;
    for spec in specs {
        let instances = spec.instances.max(1) as usize;
        expanded_process_count = expanded_process_count.saturating_add(instances);

        let Some(base_name) = &spec.name else {
            continue;
        };

        if instances == 1 {
            if !expanded_names.insert(base_name.clone()) {
                anyhow::bail!("duplicate expanded process name: {}", base_name);
            }
            continue;
        }

        for idx in 0..instances {
            let expanded = format!("{base_name}-{idx}");
            if !expanded_names.insert(expanded.clone()) {
                anyhow::bail!("duplicate expanded process name: {}", expanded);
            }
        }
    }

    Ok(OxfileValidationReport {
        app_count: specs.len(),
        expanded_process_count,
        unnamed_count,
    })
}

fn print_process_table(mut processes: Vec<crate::process::ManagedProcess>) {
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
        }
        sleep(Duration::from_millis(300)).await;
    }
}

fn print_startup_instructions(system: InitSystem, config: &AppConfig) -> Result<()> {
    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let user = std::env::var("USER").unwrap_or_else(|_| "<user>".to_string());

    let resolved = match system {
        InitSystem::Auto => {
            if cfg!(target_os = "macos") {
                InitSystem::Launchd
            } else if cfg!(target_os = "windows") {
                InitSystem::TaskScheduler
            } else {
                InitSystem::Systemd
            }
        }
        other => other,
    };

    match resolved {
        InitSystem::Systemd => {
            println!("Create ~/.config/systemd/user/oxmgr.service with:");
            println!();
            println!("[Unit]");
            println!("Description=Oxmgr daemon");
            println!("After=network.target");
            println!();
            println!("[Service]");
            println!("Type=simple");
            println!("ExecStart={} daemon run", executable.display());
            println!("Restart=always");
            println!("RestartSec=2");
            println!();
            println!("[Install]");
            println!("WantedBy=default.target");
            println!();
            println!("Then run:");
            println!("systemctl --user daemon-reload");
            println!("systemctl --user enable --now oxmgr.service");
            println!("loginctl enable-linger {}", user);
        }
        InitSystem::Launchd => {
            let plist = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("~"))
                .join("Library/LaunchAgents/io.oxmgr.daemon.plist");
            println!("Create {} with:", plist.display());
            println!();
            println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            println!("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
            println!("<plist version=\"1.0\">");
            println!("<dict>");
            println!("  <key>Label</key><string>io.oxmgr.daemon</string>");
            println!("  <key>ProgramArguments</key>");
            println!("  <array>");
            println!("    <string>{}</string>", executable.display());
            println!("    <string>daemon</string>");
            println!("    <string>run</string>");
            println!("  </array>");
            println!("  <key>RunAtLoad</key><true/>");
            println!("  <key>KeepAlive</key><true/>");
            println!(
                "  <key>StandardOutPath</key><string>{}</string>",
                config.base_dir.join("daemon.out.log").display()
            );
            println!(
                "  <key>StandardErrorPath</key><string>{}</string>",
                config.base_dir.join("daemon.err.log").display()
            );
            println!("</dict>");
            println!("</plist>");
            println!();
            println!("Then run:");
            println!("launchctl bootstrap gui/$(id -u) {}", plist.display());
            println!("launchctl enable gui/$(id -u)/io.oxmgr.daemon");
            println!("launchctl kickstart -k gui/$(id -u)/io.oxmgr.daemon");
        }
        InitSystem::TaskScheduler => {
            let task_name = "OxmgrDaemon";
            println!("Create a scheduled task (at user logon) with:");
            println!();
            println!(
                "schtasks /Create /F /SC ONLOGON /TN {} /TR \"\\\"{}\\\" daemon run\"",
                task_name,
                executable.display()
            );
            println!();
            println!("Start it immediately:");
            println!("schtasks /Run /TN {}", task_name);
            println!();
            println!("Delete it later if needed:");
            println!("schtasks /Delete /F /TN {}", task_name);
        }
        InitSystem::Auto => unreachable!("auto should have been resolved"),
    }

    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

#[cfg(test)]
mod tests {
    use super::{plan_apply_actions, validate_resolved_specs, ApplyAction, DesiredProcessSpec};
    use crate::ecosystem::EcosystemProcessSpec;
    use crate::process::{
        DesiredState, HealthCheck, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy,
    };
    use std::collections::HashMap;

    #[test]
    fn apply_plan_is_noop_for_matching_running_process() {
        let desired = desired_spec("api", "node server.js");
        let existing = process_from_desired(&desired, ProcessStatus::Running, Some(1001));

        let plan = plan_apply_actions(&[existing], &[desired], false);
        assert_eq!(plan.actions.len(), 1);
        assert!(matches!(plan.actions[0], ApplyAction::Noop));
    }

    #[test]
    fn apply_plan_recreates_when_configuration_changes() {
        let desired = desired_spec("api", "node server.js --port 3000");
        let existing = process_from_desired(
            &desired_spec("api", "node server.js"),
            ProcessStatus::Running,
            Some(1002),
        );

        let plan = plan_apply_actions(&[existing], &[desired], false);
        assert_eq!(plan.actions.len(), 1);
        assert!(matches!(plan.actions[0], ApplyAction::Recreate(_)));
    }

    #[test]
    fn apply_plan_restarts_matching_stopped_process() {
        let desired = desired_spec("worker", "python worker.py");
        let existing = process_from_desired(&desired, ProcessStatus::Stopped, None);

        let plan = plan_apply_actions(&[existing], &[desired], false);
        assert_eq!(plan.actions.len(), 1);
        match &plan.actions[0] {
            ApplyAction::Restart(name) => assert_eq!(name, "worker"),
            other => panic!("unexpected action: {:?}", other),
        }
    }

    #[test]
    fn apply_plan_prunes_unmanaged_processes() {
        let desired = desired_spec("api", "node server.js");
        let api = process_from_desired(&desired, ProcessStatus::Running, Some(1003));
        let stale = process_from_desired(
            &desired_spec("old-worker", "python old.py"),
            ProcessStatus::Running,
            Some(1004),
        );

        let plan = plan_apply_actions(&[api, stale], &[desired], true);
        assert_eq!(plan.actions.len(), 2);
        assert!(matches!(plan.actions[0], ApplyAction::Noop));
        assert!(matches!(plan.actions[1], ApplyAction::Delete(_)));
    }

    #[test]
    fn validate_resolved_specs_accepts_valid_definitions() {
        let specs = vec![
            fixture_spec("db", "docker compose up db", vec![], 1),
            fixture_spec("api", "node server.js", vec!["db".to_string()], 2),
        ];

        let report = validate_resolved_specs(&specs).expect("validation should pass");
        assert_eq!(report.app_count, 2);
        assert_eq!(report.expanded_process_count, 3);
        assert_eq!(report.unnamed_count, 0);
    }

    #[test]
    fn validate_resolved_specs_rejects_unknown_dependency() {
        let specs = vec![fixture_spec(
            "api",
            "node server.js",
            vec!["missing-db".to_string()],
            1,
        )];

        let error = validate_resolved_specs(&specs).expect_err("validation should fail");
        assert!(
            error.to_string().contains("depends_on unknown app"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_duplicate_names() {
        let specs = vec![
            fixture_spec("api", "node server.js", vec![], 1),
            fixture_spec("api", "node worker.js", vec![], 1),
        ];

        let error = validate_resolved_specs(&specs).expect_err("validation should fail");
        assert!(
            error.to_string().contains("duplicate app name"),
            "unexpected error: {}",
            error
        );
    }

    fn desired_spec(name: &str, command: &str) -> DesiredProcessSpec {
        DesiredProcessSpec {
            name: name.to_string(),
            command: command.to_string(),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            cwd: None,
            env: HashMap::new(),
            health_check: None,
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            namespace: Some("default".to_string()),
            resource_limits: None,
        }
    }

    fn process_from_desired(
        desired: &DesiredProcessSpec,
        status: ProcessStatus,
        pid: Option<u32>,
    ) -> ManagedProcess {
        let mut tokens =
            shell_words::split(&desired.command).expect("invalid command in desired spec fixture");
        let command = tokens.remove(0);

        let tmp = std::env::temp_dir();
        ManagedProcess {
            id: 1,
            name: desired.name.clone(),
            command,
            args: tokens,
            cwd: desired.cwd.clone(),
            env: desired.env.clone(),
            restart_policy: desired.restart_policy.clone(),
            max_restarts: desired.max_restarts,
            restart_count: 0,
            namespace: desired.namespace.clone(),
            stop_signal: desired.stop_signal.clone(),
            stop_timeout_secs: desired.stop_timeout_secs,
            restart_delay_secs: desired.restart_delay_secs,
            start_delay_secs: desired.start_delay_secs,
            resource_limits: desired.resource_limits.clone(),
            pid,
            status,
            desired_state: DesiredState::Running,
            last_exit_code: None,
            stdout_log: tmp.join("oxmgr-test-stdout.log"),
            stderr_log: tmp.join("oxmgr-test-stderr.log"),
            health_check: desired.health_check.clone(),
            health_status: HealthStatus::Unknown,
            health_failures: 0,
            last_health_check: None,
            next_health_check: None,
            last_health_error: None,
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
        }
    }

    fn fixture_spec(
        name: &str,
        command: &str,
        depends_on: Vec<String>,
        instances: u32,
    ) -> EcosystemProcessSpec {
        EcosystemProcessSpec {
            command: command.to_string(),
            name: Some(name.to_string()),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            cwd: None,
            env: HashMap::new(),
            health_check: Some(HealthCheck {
                command: "echo ok".to_string(),
                interval_secs: 30,
                timeout_secs: 5,
                max_failures: 3,
            }),
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            namespace: None,
            resource_limits: None,
            start_order: 0,
            depends_on,
            instances,
            instance_var: Some("INSTANCE_ID".to_string()),
        }
    }
}
