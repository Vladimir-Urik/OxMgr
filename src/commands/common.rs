use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::ecosystem::EcosystemProcessSpec;
use crate::ipc::IpcResponse;
use crate::process::StartProcessSpec;

use super::import::{load_import_specs, order_specs_for_start};

pub(crate) fn expect_ok(response: IpcResponse) -> Result<IpcResponse> {
    if response.ok {
        Ok(response)
    } else {
        anyhow::bail!(response.message)
    }
}

pub(crate) fn maybe_load_named_targets_from_config(target: &str) -> Result<Option<Vec<String>>> {
    let path = PathBuf::from(target);
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() {
        anyhow::bail!("config target is not a file: {}", path.display());
    }

    let specs = order_specs_for_start(load_import_specs(&path, None)?);
    let expanded = expand_specs_with_deterministic_names(specs, "lifecycle commands")?;
    let names: Vec<String> = expanded
        .into_iter()
        .map(|spec| {
            spec.name
                .expect("deterministic lifecycle expansion should always set a name")
        })
        .collect();

    if names.is_empty() {
        anyhow::bail!("no apps resolved from {}", path.display());
    }

    Ok(Some(names))
}

pub(crate) fn expand_specs_with_deterministic_names(
    specs: Vec<EcosystemProcessSpec>,
    context: &str,
) -> Result<Vec<StartProcessSpec>> {
    let mut expanded = Vec::new();

    for spec in specs {
        let instances = spec.instances.max(1);
        let base_name = spec.name.clone().with_context(|| {
            format!(
                "app command '{}' is missing 'name'; {context} requires deterministic names",
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

            expanded.push(StartProcessSpec {
                command: spec.command.clone(),
                name: Some(name),
                pre_reload_cmd: spec.pre_reload_cmd.clone(),
                restart_policy: spec.restart_policy.clone(),
                max_restarts: spec.max_restarts,
                crash_restart_limit: spec.crash_restart_limit,
                cwd: spec.cwd.clone(),
                env,
                health_check: spec.health_check.clone(),
                stop_signal: spec.stop_signal.clone(),
                stop_timeout_secs: spec.stop_timeout_secs.max(1),
                restart_delay_secs: spec.restart_delay_secs,
                start_delay_secs: spec.start_delay_secs,
                watch: spec.watch,
                watch_paths: spec.watch_paths.clone(),
                ignore_watch: spec.ignore_watch.clone(),
                watch_delay_secs: spec.watch_delay_secs,
                cluster_mode: spec.cluster_mode,
                cluster_instances: spec.cluster_instances,
                namespace: spec.namespace.clone(),
                resource_limits: spec.resource_limits.clone(),
                git_repo: spec.git_repo.clone(),
                git_ref: spec.git_ref.clone(),
                pull_secret_hash: spec.pull_secret_hash.clone(),
                reuse_port: spec.reuse_port,
                wait_ready: spec.wait_ready,
                ready_timeout_secs: spec.ready_timeout_secs,
                log_date_format: spec.log_date_format.clone(),
                unified_logs: spec.unified_logs,
                cron_restart: spec.cron_restart.clone(),
            });
        }
    }

    Ok(expanded)
}

pub(crate) fn config_target_display(target: &str) -> String {
    Path::new(target).display().to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        expand_specs_with_deterministic_names, expect_ok, maybe_load_named_targets_from_config,
    };
    use crate::ecosystem::EcosystemProcessSpec;
    use crate::ipc::IpcResponse;
    use crate::process::RestartPolicy;

    #[test]
    fn expect_ok_returns_response_when_ok() {
        let response = IpcResponse::ok("all good");

        let result = expect_ok(response.clone()).expect("expected successful response");

        assert!(result.ok);
        assert_eq!(result.message, "all good");
    }

    #[test]
    fn expect_ok_returns_message_as_error_when_response_failed() {
        let err = expect_ok(IpcResponse::error("daemon unavailable"))
            .expect_err("expected failed response to become an error");

        assert_eq!(err.to_string(), "daemon unavailable");
    }

    #[test]
    fn expand_specs_with_deterministic_names_expands_instances() {
        let expanded = expand_specs_with_deterministic_names(
            vec![EcosystemProcessSpec {
                command: "sleep 1".to_string(),
                name: Some("api".to_string()),
                pre_reload_cmd: None,
                restart_policy: RestartPolicy::Never,
                max_restarts: 0,
                crash_restart_limit: 3,
                cwd: None,
                env: HashMap::new(),
                health_check: None,
                stop_signal: None,
                stop_timeout_secs: 1,
                restart_delay_secs: 0,
                start_delay_secs: 0,
                watch: false,
                watch_paths: Vec::new(),
                ignore_watch: Vec::new(),
                watch_delay_secs: 0,
                cluster_mode: false,
                cluster_instances: None,
                namespace: None,
                resource_limits: None,
                git_repo: None,
                git_ref: None,
                pull_secret_hash: None,
                reuse_port: false,
                start_order: 0,
                depends_on: Vec::new(),
                instances: 2,
                instance_var: None,
                wait_ready: false,
                ready_timeout_secs: 30,
                log_date_format: None,
                unified_logs: false,
                cron_restart: None,
            }],
            "tests",
        )
        .expect("expected expansion to succeed");

        let names: Vec<&str> = expanded
            .iter()
            .map(|spec| spec.name.as_deref().expect("name should be set"))
            .collect();
        assert_eq!(names, vec!["api-0", "api-1"]);
    }

    #[test]
    fn maybe_load_named_targets_from_config_reads_single_file() {
        let path = temp_file("lifecycle-config-target");
        fs::write(
            &path,
            r#"
version = 1

[[apps]]
name = "web"
command = "sleep 1"

[[apps]]
name = "worker"
command = "sleep 1"
instances = 2
"#,
        )
        .expect("failed to write config fixture");

        let targets = maybe_load_named_targets_from_config(&path.display().to_string())
            .expect("expected config target resolution to succeed")
            .expect("expected file path to be treated as config");

        assert_eq!(targets, vec!["web", "worker-0", "worker-1"]);

        let _ = fs::remove_file(path);
    }

    fn temp_file(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.toml"))
    }
}
