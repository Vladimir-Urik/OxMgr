use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::{ManagedProcess, StartProcessSpec};

use super::common::{expand_specs_with_deterministic_names, expect_ok};
use super::import::{load_import_specs_from_paths, order_specs_for_start};

#[derive(Debug, Clone)]
enum ApplyAction {
    Start(StartProcessSpec),
    Restart(String),
    Recreate(StartProcessSpec),
    Delete(String),
    Noop,
}

#[derive(Debug, Clone)]
struct ApplyPlan {
    actions: Vec<ApplyAction>,
}

pub(crate) async fn run(
    config: &AppConfig,
    paths: Vec<PathBuf>,
    env: Option<String>,
    only: Vec<String>,
    prune: bool,
) -> Result<()> {
    let mut specs = load_import_specs_from_paths(&paths, env.as_deref())?;
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
        println!("No apps found in {}", display_paths(&paths));
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
                let name = spec_name_owned(&spec);
                let response =
                    send_request(&config.daemon_addr, &start_request_from_spec(spec.clone()))
                        .await?;
                if response.ok {
                    created = created.saturating_add(1);
                } else {
                    failures.push(format!("start {}: {}", name, response.message));
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
                let name = spec_name_owned(&spec);
                let delete = send_request(
                    &config.daemon_addr,
                    &IpcRequest::Delete {
                        target: name.clone(),
                    },
                )
                .await?;
                if !delete.ok {
                    failures.push(format!("delete {}: {}", name, delete.message));
                    continue;
                }

                let start =
                    send_request(&config.daemon_addr, &start_request_from_spec(spec.clone()))
                        .await?;
                if start.ok {
                    updated = updated.saturating_add(1);
                } else {
                    failures.push(format!("start {}: {}", name, start.message));
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

    Ok(())
}

fn display_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn expand_specs_for_apply(
    specs: Vec<crate::ecosystem::EcosystemProcessSpec>,
) -> Result<Vec<StartProcessSpec>> {
    let desired = expand_specs_with_deterministic_names(specs, "apply")?;
    let mut seen_names = HashSet::new();

    for spec in &desired {
        let name = spec
            .name
            .as_ref()
            .expect("apply expansion should always set a process name");
        if !seen_names.insert(name.clone()) {
            anyhow::bail!("duplicate app name in desired config: {}", name);
        }
    }

    Ok(desired)
}

fn plan_apply_actions(
    current: &[ManagedProcess],
    desired: &[StartProcessSpec],
    prune: bool,
) -> ApplyPlan {
    let mut actions = Vec::new();
    let current_map: HashMap<String, ManagedProcess> = current
        .iter()
        .cloned()
        .map(|process| (process.name.clone(), process))
        .collect();

    let desired_names: HashSet<String> = desired.iter().map(spec_name_owned).collect();

    for spec in desired {
        let name = spec_name(spec);
        if let Some(existing) = current_map.get(name) {
            if process_matches_spec(existing, spec) {
                if existing.status == crate::process::ProcessStatus::Running
                    && existing.pid.is_some()
                {
                    actions.push(ApplyAction::Noop);
                } else {
                    actions.push(ApplyAction::Restart(name.to_string()));
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

fn process_matches_spec(existing: &ManagedProcess, desired: &StartProcessSpec) -> bool {
    if !existing.config_fingerprint.is_empty() {
        return existing.config_fingerprint == desired.config_fingerprint();
    }

    let desired_cmd = match split_command_line(&desired.command) {
        Ok(value) => value,
        Err(_) => return false,
    };

    existing.command == desired_cmd.0
        && existing.args == desired_cmd.1
        && existing.restart_policy == desired.restart_policy
        && existing.max_restarts == desired.max_restarts
        && existing.crash_restart_limit == desired.crash_restart_limit
        && existing.cwd == desired.cwd
        && existing.health_check == desired.health_check
        && existing.stop_signal == desired.stop_signal
        && existing.stop_timeout_secs == desired.stop_timeout_secs
        && existing.restart_delay_secs == desired.restart_delay_secs
        && existing.start_delay_secs == desired.start_delay_secs
        && existing.watch == desired.watch
        && existing.watch_paths == desired.watch_paths
        && existing.ignore_watch == desired.ignore_watch
        && existing.watch_delay_secs == desired.watch_delay_secs
        && existing.cluster_mode == desired.cluster_mode
        && existing.cluster_instances == desired.cluster_instances
        && existing.namespace == desired.namespace
        && existing.resource_limits == desired.resource_limits
        && existing.git_repo == desired.git_repo
        && existing.git_ref == desired.git_ref
        && existing.pre_reload_cmd == desired.pre_reload_cmd
        && existing.reuse_port == desired.reuse_port
        && existing.wait_ready == desired.wait_ready
        && existing.ready_timeout_secs == desired.ready_timeout_secs
}

fn spec_name(spec: &StartProcessSpec) -> &str {
    spec.name
        .as_deref()
        .expect("apply specs should always have deterministic names")
}

fn spec_name_owned(spec: &StartProcessSpec) -> String {
    spec_name(spec).to_string()
}

fn split_command_line(command_line: &str) -> Result<(String, Vec<String>)> {
    let tokens = shell_words::split(command_line)
        .with_context(|| format!("invalid command syntax: {command_line}"))?;
    if tokens.is_empty() {
        anyhow::bail!("command cannot be empty");
    }

    Ok((tokens[0].clone(), tokens[1..].to_vec()))
}

fn start_request_from_spec(spec: StartProcessSpec) -> IpcRequest {
    IpcRequest::Start {
        spec: Box::new(spec),
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_apply_actions, ApplyAction};
    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy, StartProcessSpec,
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

    fn desired_spec(name: &str, command: &str) -> StartProcessSpec {
        StartProcessSpec {
            command: command.to_string(),
            name: Some(name.to_string()),
            pre_reload_cmd: None,
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: None,
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            watch_paths: Vec::new(),
            ignore_watch: Vec::new(),
            watch_delay_secs: 0,
            cluster_mode: false,
            cluster_instances: None,
            namespace: Some("default".to_string()),
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            reuse_port: false,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
            log_date_format: None,
            unified_logs: false,
            cron_restart: None,
        }
    }

    fn process_from_desired(
        desired: &StartProcessSpec,
        status: ProcessStatus,
        pid: Option<u32>,
    ) -> ManagedProcess {
        let mut tokens =
            shell_words::split(&desired.command).expect("invalid command in desired spec fixture");
        let command = tokens.remove(0);

        let tmp = std::env::temp_dir();
        ManagedProcess {
            id: 1,
            name: desired
                .name
                .clone()
                .expect("apply test spec should have a name"),
            command,
            args: tokens,
            pre_reload_cmd: desired.pre_reload_cmd.clone(),
            cwd: desired.cwd.clone(),
            env: desired.env.clone(),
            restart_policy: desired.restart_policy.clone(),
            max_restarts: desired.max_restarts,
            restart_count: 0,
            crash_restart_limit: desired.crash_restart_limit,
            auto_restart_history: Vec::new(),
            namespace: desired.namespace.clone(),
            git_repo: desired.git_repo.clone(),
            git_ref: desired.git_ref.clone(),
            pull_secret_hash: desired.pull_secret_hash.clone(),
            reuse_port: desired.reuse_port,
            stop_signal: desired.stop_signal.clone(),
            stop_timeout_secs: desired.stop_timeout_secs,
            restart_delay_secs: desired.restart_delay_secs,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs: desired.start_delay_secs,
            watch: desired.watch,
            watch_paths: desired.watch_paths.clone(),
            ignore_watch: desired.ignore_watch.clone(),
            watch_delay_secs: desired.watch_delay_secs,
            cluster_mode: desired.cluster_mode,
            cluster_instances: desired.cluster_instances,
            resource_limits: desired.resource_limits.clone(),
            cgroup_path: None,
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
            wait_ready: desired.wait_ready,
            ready_timeout_secs: desired.ready_timeout_secs,
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: None,
            last_stopped_at: None,
            config_fingerprint: String::new(),
            log_date_format: Some("%Y-%m-%d %H:%M:%S".to_string()),
            unified_logs: desired.unified_logs,
            cron_restart: None,
            next_cron_restart: None,
        }
    }
}
