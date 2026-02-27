use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::process::{HealthCheck, ResourceLimits, RestartPolicy};

#[derive(Debug, Clone)]
pub struct EcosystemProcessSpec {
    pub command: String,
    pub name: Option<String>,
    pub restart_policy: RestartPolicy,
    pub max_restarts: u32,
    pub crash_restart_limit: u32,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub health_check: Option<HealthCheck>,
    pub stop_signal: Option<String>,
    pub stop_timeout_secs: u64,
    pub restart_delay_secs: u64,
    pub start_delay_secs: u64,
    pub cluster_mode: bool,
    pub cluster_instances: Option<u32>,
    pub namespace: Option<String>,
    pub resource_limits: Option<ResourceLimits>,
    pub git_repo: Option<String>,
    pub git_ref: Option<String>,
    pub pull_secret_hash: Option<String>,
    pub start_order: i32,
    pub depends_on: Vec<String>,
    pub instances: u32,
    pub instance_var: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EcosystemFile {
    apps: Vec<EcosystemApp>,
}

#[derive(Debug, Deserialize)]
struct EcosystemApp {
    name: Option<String>,
    script: Option<String>,
    cmd: Option<String>,
    args: Option<EcosystemArgs>,
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    autorestart: Option<bool>,
    restart_policy: Option<RestartPolicy>,
    max_restarts: Option<u32>,
    crash_restart_limit: Option<u32>,
    restart_delay: Option<u64>,
    delay_start: Option<u64>,
    start_delay: Option<u64>,
    exec_mode: Option<String>,
    cluster_mode: Option<bool>,
    cluster_instances: Option<u32>,
    start_order: Option<i32>,
    priority: Option<i32>,
    depends_on: Option<Vec<String>>,
    namespace: Option<String>,
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret: Option<String>,
    instances: Option<u32>,
    instance_var: Option<String>,
    kill_signal: Option<String>,
    pm2_kill_signal: Option<String>,
    stop_timeout: Option<u64>,
    kill_timeout: Option<u64>,
    health_cmd: Option<String>,
    health_interval: Option<u64>,
    health_timeout: Option<u64>,
    health_max_failures: Option<u32>,
    health: Option<EcosystemHealth>,
    max_memory_restart: Option<Value>,
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
    cgroup_enforce: Option<bool>,
    deny_gpu: Option<bool>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EcosystemArgs {
    Single(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct EcosystemHealth {
    cmd: String,
    interval: Option<u64>,
    timeout: Option<u64>,
    max_failures: Option<u32>,
}

#[derive(Debug)]
struct ResolvedSettings {
    restart_policy: RestartPolicy,
    max_restarts: u32,
    crash_restart_limit: u32,
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
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret_hash: Option<String>,
    start_order: i32,
    depends_on: Vec<String>,
    instances: u32,
    instance_var: Option<String>,
}

pub fn load_with_profile(path: &Path, profile: Option<&str>) -> Result<Vec<EcosystemProcessSpec>> {
    let payload = fs::read_to_string(path)
        .with_context(|| format!("failed to read ecosystem file {}", path.display()))?;
    let file: EcosystemFile =
        serde_json::from_str(&payload).context("failed to parse ecosystem config JSON")?;

    let mut specs = Vec::with_capacity(file.apps.len());
    for (idx, app) in file.apps.into_iter().enumerate() {
        specs.push(app.into_spec(profile, idx as i32)?);
    }

    Ok(specs)
}

impl EcosystemApp {
    fn into_spec(self, profile: Option<&str>, default_order: i32) -> Result<EcosystemProcessSpec> {
        let command = self.resolve_command()?;
        let inferred_cluster_mode = self
            .exec_mode
            .as_deref()
            .map(is_cluster_exec_mode)
            .unwrap_or(false);
        let explicit_cluster_instances = normalize_cluster_instances(self.cluster_instances);
        let inferred_cluster_instances = if inferred_cluster_mode {
            normalize_cluster_instances(self.instances)
        } else {
            None
        };
        let cluster_mode = self.cluster_mode.unwrap_or(inferred_cluster_mode);
        let cluster_instances = explicit_cluster_instances.or(inferred_cluster_instances);
        let instances = if inferred_cluster_mode {
            1
        } else {
            self.instances.unwrap_or(1).max(1)
        };

        let mut settings = ResolvedSettings {
            restart_policy: restart_policy_from(self.restart_policy, self.autorestart),
            max_restarts: self.max_restarts.unwrap_or(10),
            crash_restart_limit: self.crash_restart_limit.unwrap_or(3),
            cwd: self.cwd,
            env: self.env.unwrap_or_default(),
            health_check: health_check_from(
                self.health,
                self.health_cmd,
                self.health_interval,
                self.health_timeout,
                self.health_max_failures,
            ),
            stop_signal: self.pm2_kill_signal.or(self.kill_signal),
            stop_timeout_secs: self.kill_timeout.or(self.stop_timeout).unwrap_or(5).max(1),
            restart_delay_secs: self.restart_delay.unwrap_or(0),
            start_delay_secs: self.start_delay.or(self.delay_start).unwrap_or(0),
            cluster_mode,
            cluster_instances,
            namespace: self.namespace,
            resource_limits: resource_limits_from(
                self.max_memory_restart,
                self.max_memory_mb,
                self.max_cpu_percent,
                self.cgroup_enforce,
                self.deny_gpu,
            )?,
            git_repo: self.git_repo,
            git_ref: self.git_ref,
            pull_secret_hash: normalize_pull_secret_hash(self.pull_secret)?,
            start_order: self.priority.or(self.start_order).unwrap_or(default_order),
            depends_on: self.depends_on.unwrap_or_default(),
            instances,
            instance_var: self.instance_var,
        };

        if let Some(profile_name) = profile {
            if let Some(value) = self.extra.get(&format!("env_{profile_name}")) {
                if let Some(map) = value.as_object() {
                    apply_profile_overrides(map, &mut settings)?;
                }
            }
        }

        Ok(EcosystemProcessSpec {
            command,
            name: self.name,
            restart_policy: settings.restart_policy,
            max_restarts: settings.max_restarts,
            crash_restart_limit: settings.crash_restart_limit,
            cwd: settings.cwd,
            env: settings.env,
            health_check: settings.health_check,
            stop_signal: settings.stop_signal,
            stop_timeout_secs: settings.stop_timeout_secs,
            restart_delay_secs: settings.restart_delay_secs,
            start_delay_secs: settings.start_delay_secs,
            cluster_mode: settings.cluster_mode,
            cluster_instances: settings.cluster_instances,
            namespace: settings.namespace,
            resource_limits: settings.resource_limits,
            git_repo: settings.git_repo,
            git_ref: settings.git_ref,
            pull_secret_hash: settings.pull_secret_hash,
            start_order: settings.start_order,
            depends_on: settings.depends_on,
            instances: settings.instances,
            instance_var: settings.instance_var,
        })
    }

    fn resolve_command(&self) -> Result<String> {
        if let Some(cmd) = &self.cmd {
            return Ok(cmd.clone());
        }

        let script = self
            .script
            .as_ref()
            .context("ecosystem app entry is missing both 'cmd' and 'script'")?;

        let mut parts = vec![shell_words::quote(script).to_string()];
        if let Some(args) = &self.args {
            match args {
                EcosystemArgs::Single(value) => parts.push(value.clone()),
                EcosystemArgs::Many(values) => {
                    for value in values {
                        parts.push(shell_words::quote(value).to_string());
                    }
                }
            }
        }

        Ok(parts.join(" "))
    }
}

fn normalize_cluster_instances(value: Option<u32>) -> Option<u32> {
    value.map(|instances| instances.max(1))
}

fn restart_policy_from(policy: Option<RestartPolicy>, autorestart: Option<bool>) -> RestartPolicy {
    if let Some(policy) = policy {
        policy
    } else if autorestart == Some(false) {
        RestartPolicy::Never
    } else {
        RestartPolicy::OnFailure
    }
}

fn is_cluster_exec_mode(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized == "cluster" || normalized == "cluster_mode"
}

fn health_check_from(
    health: Option<EcosystemHealth>,
    health_cmd: Option<String>,
    health_interval: Option<u64>,
    health_timeout: Option<u64>,
    health_max_failures: Option<u32>,
) -> Option<HealthCheck> {
    if let Some(health) = health {
        return Some(HealthCheck {
            command: health.cmd,
            interval_secs: health.interval.unwrap_or(30).max(1),
            timeout_secs: health.timeout.unwrap_or(5).max(1),
            max_failures: health.max_failures.unwrap_or(3).max(1),
        });
    }

    health_cmd.map(|command| HealthCheck {
        command,
        interval_secs: health_interval.unwrap_or(30).max(1),
        timeout_secs: health_timeout.unwrap_or(5).max(1),
        max_failures: health_max_failures.unwrap_or(3).max(1),
    })
}

fn apply_profile_overrides(
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

fn resource_limits_from(
    max_memory_restart: Option<Value>,
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
    cgroup_enforce: Option<bool>,
    deny_gpu: Option<bool>,
) -> Result<Option<ResourceLimits>> {
    let mut limits = ResourceLimits::default();

    if let Some(memory_mb) = max_memory_mb {
        if memory_mb > 0 {
            limits.max_memory_mb = Some(memory_mb);
        }
    }
    if let Some(cpu_percent) = max_cpu_percent {
        if cpu_percent > 0.0 {
            limits.max_cpu_percent = Some(cpu_percent);
        }
    }
    if let Some(memory_restart) = max_memory_restart {
        let parsed = parse_memory_limit_mb_value(&memory_restart)?;
        if parsed > 0 {
            limits.max_memory_mb = Some(parsed);
        }
    }
    limits.cgroup_enforce = cgroup_enforce.unwrap_or(false);
    limits.deny_gpu = deny_gpu.unwrap_or(false);

    Ok(normalize_resource_limits(limits))
}

fn parse_memory_limit_mb_value(value: &Value) -> Result<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .context("max_memory_restart numeric value must be a positive integer"),
        Value::String(text) => parse_memory_limit_mb_str(text),
        _ => anyhow::bail!(
            "max_memory_restart must be a string like '256M' or a numeric value in MB"
        ),
    }
}

fn parse_memory_limit_mb_str(input: &str) -> Result<u64> {
    let normalized = input.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        anyhow::bail!("max_memory_restart cannot be empty");
    }

    let split_idx = normalized
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(normalized.len());
    let (number_part, unit_part) = normalized.split_at(split_idx);
    if number_part.is_empty() {
        anyhow::bail!("max_memory_restart is missing numeric value");
    }

    let numeric_value: f64 = number_part
        .parse()
        .with_context(|| format!("invalid max_memory_restart numeric value: {input}"))?;
    if numeric_value <= 0.0 {
        anyhow::bail!("max_memory_restart must be greater than zero");
    }

    let multiplier = match unit_part.trim() {
        "" | "M" | "MB" => 1.0,
        "K" | "KB" => 1.0 / 1024.0,
        "G" | "GB" => 1024.0,
        "B" => 1.0 / (1024.0 * 1024.0),
        other => anyhow::bail!("unsupported max_memory_restart unit: {other}"),
    };

    let mb = (numeric_value * multiplier).ceil() as u64;
    Ok(mb.max(1))
}

fn set_memory_limit_mb(settings: &mut ResolvedSettings, value_mb: u64) {
    if value_mb == 0 {
        return;
    }
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.max_memory_mb = Some(value_mb);
    settings.resource_limits = normalize_resource_limits(limits);
}

fn set_cpu_limit_percent(settings: &mut ResolvedSettings, value_percent: f32) {
    if value_percent <= 0.0 {
        return;
    }
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.max_cpu_percent = Some(value_percent);
    settings.resource_limits = normalize_resource_limits(limits);
}

fn set_cgroup_enforce(settings: &mut ResolvedSettings, enabled: bool) {
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.cgroup_enforce = enabled;
    settings.resource_limits = normalize_resource_limits(limits);
}

fn set_deny_gpu(settings: &mut ResolvedSettings, deny: bool) {
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.deny_gpu = deny;
    settings.resource_limits = normalize_resource_limits(limits);
}

fn normalize_resource_limits(mut limits: ResourceLimits) -> Option<ResourceLimits> {
    if matches!(limits.max_memory_mb, Some(0)) {
        limits.max_memory_mb = None;
    }
    if matches!(limits.max_cpu_percent, Some(v) if v <= 0.0) {
        limits.max_cpu_percent = None;
    }
    if limits.max_memory_mb.is_none()
        && limits.max_cpu_percent.is_none()
        && !limits.cgroup_enforce
        && !limits.deny_gpu
    {
        None
    } else {
        Some(limits)
    }
}

fn normalize_pull_secret_hash(secret: Option<String>) -> Result<Option<String>> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        anyhow::bail!("pull_secret cannot be empty");
    }
    if trimmed.len() > 512 {
        anyhow::bail!("pull_secret exceeds maximum length 512");
    }

    let digest = Sha256::digest(trimmed.as_bytes());
    Ok(Some(format!("{:x}", digest)))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::load_with_profile;
    use crate::process::RestartPolicy;

    #[test]
    fn load_parses_cmd_and_health_fields() {
        let file_path = temp_file("ecosystem-cmd");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node server.js",
      "restart_policy": "always",
      "max_restarts": 8,
      "crash_restart_limit": 6,
      "health_cmd": "curl -fsS http://127.0.0.1:3000/health",
      "health_interval": 12,
      "health_timeout": 2,
      "health_max_failures": 4,
      "max_memory_restart": "256M",
      "max_cpu_percent": 70
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let specs = load_with_profile(&file_path, None).expect("failed to parse ecosystem config");
        assert_eq!(specs.len(), 1);

        let app = &specs[0];
        assert_eq!(app.name.as_deref(), Some("api"));
        assert_eq!(app.command, "node server.js");
        assert_eq!(app.restart_policy, RestartPolicy::Always);
        assert_eq!(app.max_restarts, 8);
        assert_eq!(app.crash_restart_limit, 6);

        let health = app.health_check.as_ref().expect("health check missing");
        assert_eq!(health.interval_secs, 12);
        assert_eq!(health.timeout_secs, 2);
        assert_eq!(health.max_failures, 4);
        let limits = app
            .resource_limits
            .as_ref()
            .expect("resource limits missing");
        assert_eq!(limits.max_memory_mb, Some(256));
        assert_eq!(limits.max_cpu_percent, Some(70.0));

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_parses_script_and_args_array() {
        let file_path = temp_file("ecosystem-script");
        let payload = r#"
{
  "apps": [
    {
      "name": "worker",
      "script": "python",
      "args": ["worker.py", "--threads", "4"],
      "autorestart": false
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let specs = load_with_profile(&file_path, None).expect("failed to parse ecosystem config");
        assert_eq!(specs.len(), 1);

        let app = &specs[0];
        assert_eq!(app.name.as_deref(), Some("worker"));
        assert_eq!(app.command, "python worker.py --threads 4");
        assert_eq!(app.restart_policy, RestartPolicy::Never);

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_maps_exec_mode_cluster_to_cluster_settings() {
        let file_path = temp_file("ecosystem-cluster");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node server.js",
      "exec_mode": "cluster",
      "instances": 3
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let specs = load_with_profile(&file_path, None).expect("failed to parse ecosystem config");
        assert_eq!(specs.len(), 1);
        let app = &specs[0];
        assert!(app.cluster_mode);
        assert_eq!(app.cluster_instances, Some(3));
        assert_eq!(app.instances, 1);

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_applies_env_profile_overrides_and_order() {
        let file_path = temp_file("ecosystem-env-profile");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node api.js",
      "env": {"BASE": "1"},
      "env_prod": {
        "NODE_ENV": "production",
        "instances": 2,
        "priority": 10,
        "crash_restart_limit": 4,
        "restart_delay": 7,
        "delay_start": 3,
        "pm2_kill_signal": "SIGINT",
        "kill_timeout": 9,
        "restart_policy": "always",
        "max_memory_restart": "512M",
        "max_cpu_percent": 80
      }
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let specs = load_with_profile(&file_path, Some("prod"))
            .expect("failed to parse ecosystem config with env profile");
        assert_eq!(specs.len(), 1);

        let app = &specs[0];
        assert_eq!(app.env.get("BASE").map(String::as_str), Some("1"));
        assert_eq!(
            app.env.get("NODE_ENV").map(String::as_str),
            Some("production")
        );
        assert_eq!(app.instances, 2);
        assert_eq!(app.start_order, 10);
        assert_eq!(app.crash_restart_limit, 4);
        assert_eq!(app.restart_delay_secs, 7);
        assert_eq!(app.start_delay_secs, 3);
        assert_eq!(app.stop_signal.as_deref(), Some("SIGINT"));
        assert_eq!(app.stop_timeout_secs, 9);
        assert_eq!(app.restart_policy, RestartPolicy::Always);
        let limits = app
            .resource_limits
            .as_ref()
            .expect("resource limits missing");
        assert_eq!(limits.max_memory_mb, Some(512));
        assert_eq!(limits.max_cpu_percent, Some(80.0));

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_defaults_crash_restart_limit_to_three() {
        let file_path = temp_file("ecosystem-default-crash-limit");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node server.js"
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let specs = load_with_profile(&file_path, None).expect("failed to parse ecosystem config");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].crash_restart_limit, 3);

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_parses_memory_units_for_resource_limits() {
        let file_path = temp_file("ecosystem-memory-units");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node api.js",
      "max_memory_restart": "1536K"
    },
    {
      "name": "worker",
      "cmd": "python worker.py",
      "max_memory_restart": "1G"
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let specs = load_with_profile(&file_path, None).expect("failed to parse ecosystem config");
        assert_eq!(specs.len(), 2);

        let first = &specs[0];
        assert_eq!(
            first.resource_limits.as_ref().and_then(|v| v.max_memory_mb),
            Some(2)
        );
        let second = &specs[1];
        assert_eq!(
            second
                .resource_limits
                .as_ref()
                .and_then(|v| v.max_memory_mb),
            Some(1024)
        );

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_rejects_unsupported_memory_unit() {
        let file_path = temp_file("ecosystem-memory-invalid");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node api.js",
      "max_memory_restart": "1T"
    }
  ]
}
"#;
        fs::write(&file_path, payload).expect("failed to write ecosystem fixture");

        let result = load_with_profile(&file_path, None);
        assert!(
            result.is_err(),
            "expected parser failure for unsupported unit"
        );

        let _ = fs::remove_file(file_path);
    }

    fn temp_file(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.json"))
    }
}
