use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::{
    HealthCheck, ManagedProcess, ResourceLimits, RestartPolicy, StartProcessSpec,
};

use super::common::expect_ok;
use super::import::{load_import_specs, order_specs_for_start};

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
    cluster_mode: bool,
    cluster_instances: Option<u32>,
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

pub(crate) async fn run(
    config: &AppConfig,
    path: PathBuf,
    env: Option<String>,
    only: Vec<String>,
    prune: bool,
) -> Result<()> {
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
                let response =
                    send_request(&config.daemon_addr, &start_request_from_spec(spec.clone()))
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

                let start =
                    send_request(&config.daemon_addr, &start_request_from_spec(spec.clone()))
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

    Ok(())
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
                cluster_mode: spec.cluster_mode,
                cluster_instances: spec.cluster_instances,
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
        && existing.cluster_mode == desired.cluster_mode
        && existing.cluster_instances == desired.cluster_instances
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
        spec: Box::new(StartProcessSpec {
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
            watch: false,
            cluster_mode: spec.cluster_mode,
            cluster_instances: spec.cluster_instances,
            namespace: spec.namespace,
            resource_limits: spec.resource_limits,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_apply_actions, ApplyAction, DesiredProcessSpec};
    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy,
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
            cluster_mode: false,
            cluster_instances: None,
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
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs: desired.start_delay_secs,
            watch: false,
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
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: None,
            last_stopped_at: None,
        }
    }
}
