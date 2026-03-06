use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use serde_json::{Map, Value};

use crate::process::{HealthCheck, RestartPolicy};

use super::resources::{
    normalize_pull_secret_hash, parse_memory_limit_mb_value, set_cgroup_enforce,
    set_cpu_limit_percent, set_deny_gpu, set_memory_limit_mb,
};
use super::{
    is_cluster_exec_mode, millis_to_secs_ceil, watch_from, EcosystemWatch, ResolvedSettings,
};

pub(super) fn apply_profile_overrides(
    map: &Map<String, Value>,
    settings: &mut ResolvedSettings,
) -> Result<()> {
    if let Some(env_value) = map.get("env") {
        if let Some(env_obj) = env_value.as_object() {
            merge_env_object(env_obj, &mut settings.env);
        }
    }

    for (key, value) in map {
        match key.as_str() {
            "env" => {}
            "autorestart" => {
                if let Some(flag) = value.as_bool() {
                    settings.restart_policy = if flag {
                        RestartPolicy::OnFailure
                    } else {
                        RestartPolicy::Never
                    };
                }
            }
            "restart_policy" => {
                if let Some(policy) = parse_restart_policy_value(value)? {
                    settings.restart_policy = policy;
                }
            }
            "max_restarts" => {
                if let Some(parsed) = value.as_u64() {
                    settings.max_restarts = parsed as u32;
                }
            }
            "crash_restart_limit" => {
                if let Some(parsed) = value.as_u64() {
                    settings.crash_restart_limit = parsed as u32;
                }
            }
            "restart_delay" => {
                if let Some(parsed) = value.as_u64() {
                    settings.restart_delay_secs = parsed;
                }
            }
            "delay_start" | "start_delay" => {
                if let Some(parsed) = value.as_u64() {
                    settings.start_delay_secs = parsed;
                }
            }
            "watch" => {
                let (watch, watch_paths) = watch_from(parse_watch_value(value)?);
                settings.watch = watch;
                settings.watch_paths = watch_paths;
            }
            "ignore_watch" => {
                settings.ignore_watch = parse_string_list_value(value);
            }
            "watch_delay" => {
                if let Some(parsed) = value.as_u64() {
                    settings.watch_delay_secs = millis_to_secs_ceil(parsed);
                }
            }
            "priority" | "start_order" => {
                if let Some(parsed) = value.as_i64() {
                    settings.start_order = parsed as i32;
                }
            }
            "depends_on" => {
                if let Some(list) = value.as_array() {
                    settings.depends_on = list
                        .iter()
                        .filter_map(|item| item.as_str().map(|v| v.to_string()))
                        .collect();
                }
            }
            "namespace" => {
                if let Some(parsed) = value.as_str() {
                    settings.namespace = Some(parsed.to_string());
                }
            }
            "git_repo" => {
                if let Some(parsed) = value.as_str() {
                    settings.git_repo = Some(parsed.to_string());
                }
            }
            "git_ref" => {
                if let Some(parsed) = value.as_str() {
                    settings.git_ref = Some(parsed.to_string());
                }
            }
            "pull_secret" => {
                if let Some(parsed) = value.as_str() {
                    settings.pull_secret_hash =
                        normalize_pull_secret_hash(Some(parsed.to_string()))?;
                }
            }
            "exec_mode" => {
                if let Some(parsed) = value.as_str() {
                    settings.cluster_mode = is_cluster_exec_mode(parsed);
                    if settings.cluster_mode {
                        settings.instances = 1;
                    }
                }
            }
            "cluster_mode" => {
                let Some(parsed) = value.as_bool() else {
                    anyhow::bail!("cluster_mode override must be true/false");
                };
                settings.cluster_mode = parsed;
            }
            "cluster_instances" => {
                let Some(parsed) = value.as_u64() else {
                    anyhow::bail!("cluster_instances override must be a positive integer");
                };
                settings.cluster_instances = Some((parsed as u32).max(1));
            }
            "instances" => {
                if let Some(parsed) = value.as_u64() {
                    if settings.cluster_mode {
                        settings.cluster_instances = Some((parsed as u32).max(1));
                    } else {
                        settings.instances = (parsed as u32).max(1);
                    }
                }
            }
            "instance_var" => {
                if let Some(parsed) = value.as_str() {
                    settings.instance_var = Some(parsed.to_string());
                }
            }
            "kill_signal" | "pm2_kill_signal" => {
                if let Some(parsed) = value.as_str() {
                    settings.stop_signal = Some(parsed.to_string());
                }
            }
            "kill_timeout" | "stop_timeout" => {
                if let Some(parsed) = value.as_u64() {
                    settings.stop_timeout_secs = parsed.max(1);
                }
            }
            "cwd" => {
                if let Some(parsed) = value.as_str() {
                    settings.cwd = Some(PathBuf::from(parsed));
                }
            }
            "max_memory_restart" => {
                let parsed = parse_memory_limit_mb_value(value)?;
                set_memory_limit_mb(settings, parsed);
            }
            "max_memory_mb" => {
                let Some(parsed) = value.as_u64() else {
                    anyhow::bail!("max_memory_mb override must be a positive integer");
                };
                set_memory_limit_mb(settings, parsed);
            }
            "max_cpu_percent" => {
                let Some(parsed) = value.as_f64() else {
                    anyhow::bail!("max_cpu_percent override must be numeric");
                };
                set_cpu_limit_percent(settings, parsed as f32);
            }
            "cgroup_enforce" => {
                let Some(parsed) = value.as_bool() else {
                    anyhow::bail!("cgroup_enforce override must be true/false");
                };
                set_cgroup_enforce(settings, parsed);
            }
            "deny_gpu" => {
                let Some(parsed) = value.as_bool() else {
                    anyhow::bail!("deny_gpu override must be true/false");
                };
                set_deny_gpu(settings, parsed);
            }
            "health_cmd" => {
                if let Some(parsed) = value.as_str() {
                    let mut check = settings.health_check.clone().unwrap_or(HealthCheck {
                        command: parsed.to_string(),
                        interval_secs: 30,
                        timeout_secs: 5,
                        max_failures: 3,
                    });
                    check.command = parsed.to_string();
                    settings.health_check = Some(check);
                }
            }
            "health_interval" => {
                if let Some(parsed) = value.as_u64() {
                    let mut check = settings.health_check.clone().unwrap_or(HealthCheck {
                        command: "true".to_string(),
                        interval_secs: 30,
                        timeout_secs: 5,
                        max_failures: 3,
                    });
                    check.interval_secs = parsed.max(1);
                    settings.health_check = Some(check);
                }
            }
            "health_timeout" => {
                if let Some(parsed) = value.as_u64() {
                    let mut check = settings.health_check.clone().unwrap_or(HealthCheck {
                        command: "true".to_string(),
                        interval_secs: 30,
                        timeout_secs: 5,
                        max_failures: 3,
                    });
                    check.timeout_secs = parsed.max(1);
                    settings.health_check = Some(check);
                }
            }
            "health_max_failures" => {
                if let Some(parsed) = value.as_u64() {
                    let mut check = settings.health_check.clone().unwrap_or(HealthCheck {
                        command: "true".to_string(),
                        interval_secs: 30,
                        timeout_secs: 5,
                        max_failures: 3,
                    });
                    check.max_failures = (parsed as u32).max(1);
                    settings.health_check = Some(check);
                }
            }
            "wait_ready" => {
                let Some(parsed) = value.as_bool() else {
                    anyhow::bail!("wait_ready override must be true/false");
                };
                settings.wait_ready = parsed;
            }
            "listen_timeout" | "ready_timeout_secs" => {
                let Some(parsed) = value.as_u64() else {
                    anyhow::bail!("{key} override must be a positive integer");
                };
                settings.ready_timeout_secs = if key == "listen_timeout" {
                    millis_to_secs_ceil(parsed).max(1)
                } else {
                    parsed.max(1)
                };
            }
            _ => {
                if is_likely_env_key(key) {
                    if let Some(value) = value_to_string(value) {
                        settings.env.insert(key.clone(), value);
                    }
                }
            }
        }
    }

    Ok(())
}

fn merge_env_object(values: &Map<String, Value>, env: &mut HashMap<String, String>) {
    for (key, value) in values {
        if let Some(value) = value_to_string(value) {
            env.insert(key.clone(), value);
        }
    }
}

fn parse_watch_value(value: &Value) -> Result<Option<EcosystemWatch>> {
    match value {
        Value::Bool(enabled) => Ok(Some(EcosystemWatch::Bool(*enabled))),
        Value::String(path) => Ok(Some(EcosystemWatch::Single(path.clone()))),
        Value::Array(items) => {
            let mut paths = Vec::new();
            for item in items {
                let Some(path) = item.as_str() else {
                    anyhow::bail!("watch override list must contain only strings");
                };
                paths.push(path.to_string());
            }
            Ok(Some(EcosystemWatch::Many(paths)))
        }
        Value::Null => Ok(None),
        _ => anyhow::bail!("watch override must be true/false or a string/list of strings"),
    }
}

fn parse_string_list_value(value: &Value) -> Vec<String> {
    match value {
        Value::String(item) => {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                vec![trimmed.to_string()]
            }
        }
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .filter_map(|item| {
                let trimmed = item.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(v) => Some(v.clone()),
        Value::Number(v) => Some(v.to_string()),
        Value::Bool(v) => Some(v.to_string()),
        _ => None,
    }
}

fn is_likely_env_key(key: &str) -> bool {
    key.chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn parse_restart_policy_value(value: &Value) -> Result<Option<RestartPolicy>> {
    let Some(policy) = value.as_str() else {
        return Ok(None);
    };

    let normalized = policy.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "always" => Ok(Some(RestartPolicy::Always)),
        "on-failure" | "on_failure" => Ok(Some(RestartPolicy::OnFailure)),
        "never" | "no" | "false" => Ok(Some(RestartPolicy::Never)),
        _ => anyhow::bail!("unsupported restart_policy override: {policy}"),
    }
}
