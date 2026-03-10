//! Import support for PM2-compatible ecosystem config files.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::js_config::extract_js_object_literal;
use crate::process::{HealthCheck, ResourceLimits, RestartPolicy};

mod profile;
mod resources;

use self::profile::apply_profile_overrides;
use self::resources::{normalize_pull_secret_hash, resource_limits_from};

#[derive(Debug, Clone)]
/// Canonical process specification produced after importing external process
/// definitions such as PM2 ecosystem files or Oxfiles.
pub struct EcosystemProcessSpec {
    pub command: String,
    pub name: Option<String>,
    pub pre_reload_cmd: Option<String>,
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
    pub watch: bool,
    pub watch_paths: Vec<PathBuf>,
    pub ignore_watch: Vec<String>,
    pub watch_delay_secs: u64,
    pub cluster_mode: bool,
    pub cluster_instances: Option<u32>,
    pub namespace: Option<String>,
    pub resource_limits: Option<ResourceLimits>,
    pub git_repo: Option<String>,
    pub git_ref: Option<String>,
    pub pull_secret_hash: Option<String>,
    pub reuse_port: bool,
    pub start_order: i32,
    pub depends_on: Vec<String>,
    pub instances: u32,
    pub instance_var: Option<String>,
    pub wait_ready: bool,
    pub ready_timeout_secs: u64,
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
    pre_reload_cmd: Option<String>,
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    autorestart: Option<bool>,
    restart_policy: Option<RestartPolicy>,
    max_restarts: Option<u32>,
    crash_restart_limit: Option<u32>,
    restart_delay: Option<u64>,
    delay_start: Option<u64>,
    start_delay: Option<u64>,
    watch: Option<EcosystemWatch>,
    ignore_watch: Option<EcosystemStringList>,
    watch_delay: Option<u64>,
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
    reuse_port: Option<bool>,
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
    wait_ready: Option<bool>,
    listen_timeout: Option<u64>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EcosystemArgs {
    Single(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum EcosystemWatch {
    Bool(bool),
    Single(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum EcosystemStringList {
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
    pre_reload_cmd: Option<String>,
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    health_check: Option<HealthCheck>,
    stop_signal: Option<String>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    watch: bool,
    watch_paths: Vec<PathBuf>,
    ignore_watch: Vec<String>,
    watch_delay_secs: u64,
    cluster_mode: bool,
    cluster_instances: Option<u32>,
    namespace: Option<String>,
    resource_limits: Option<ResourceLimits>,
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret_hash: Option<String>,
    reuse_port: bool,
    start_order: i32,
    depends_on: Vec<String>,
    instances: u32,
    instance_var: Option<String>,
    wait_ready: bool,
    ready_timeout_secs: u64,
}

/// Loads a PM2-style ecosystem file and normalises it into Oxmgr process
/// specifications.
pub fn load_with_profile(path: &Path, profile: Option<&str>) -> Result<Vec<EcosystemProcessSpec>> {
    let payload = fs::read_to_string(path)
        .with_context(|| format!("failed to read ecosystem file {}", path.display()))?;
    let file = load_ecosystem_file(path, &payload)?;

    let mut specs = Vec::with_capacity(file.apps.len());
    for (idx, app) in file.apps.into_iter().enumerate() {
        specs.push(app.into_spec(profile, idx as i32)?);
    }

    Ok(specs)
}

fn load_ecosystem_file(path: &Path, payload: &str) -> Result<EcosystemFile> {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    match ext.as_deref() {
        Some("js") | Some("cjs") | Some("mjs") => {
            let object = extract_js_object_literal(payload, "ecosystem config")?;
            json5::from_str::<EcosystemFile>(&object)
                .with_context(|| format!("failed to parse JS ecosystem config {}", path.display()))
        }
        Some("json") | Some("json5") | None => json5::from_str::<EcosystemFile>(payload)
            .with_context(|| format!("failed to parse ecosystem config {}", path.display())),
        _ => json5::from_str::<EcosystemFile>(payload)
            .with_context(|| format!("failed to parse ecosystem config {}", path.display())),
    }
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
        let (watch, watch_paths) = watch_from(self.watch);

        let mut settings = ResolvedSettings {
            restart_policy: restart_policy_from(self.restart_policy, self.autorestart),
            max_restarts: self.max_restarts.unwrap_or(10),
            crash_restart_limit: self.crash_restart_limit.unwrap_or(3),
            pre_reload_cmd: self.pre_reload_cmd,
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
            watch,
            watch_paths,
            ignore_watch: string_list_from(self.ignore_watch),
            watch_delay_secs: millis_to_secs_ceil(self.watch_delay.unwrap_or(0)),
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
            reuse_port: self.reuse_port.unwrap_or(false),
            start_order: self.priority.or(self.start_order).unwrap_or(default_order),
            depends_on: self.depends_on.unwrap_or_default(),
            instances,
            instance_var: self.instance_var,
            wait_ready: self.wait_ready.unwrap_or(false),
            ready_timeout_secs: millis_to_secs_ceil(self.listen_timeout.unwrap_or(30_000)).max(1),
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
            pre_reload_cmd: settings.pre_reload_cmd,
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
            watch: settings.watch,
            watch_paths: settings.watch_paths,
            ignore_watch: settings.ignore_watch,
            watch_delay_secs: settings.watch_delay_secs,
            cluster_mode: settings.cluster_mode,
            cluster_instances: settings.cluster_instances,
            namespace: settings.namespace,
            resource_limits: settings.resource_limits,
            git_repo: settings.git_repo,
            git_ref: settings.git_ref,
            pull_secret_hash: settings.pull_secret_hash,
            reuse_port: settings.reuse_port,
            start_order: settings.start_order,
            depends_on: settings.depends_on,
            instances: settings.instances,
            instance_var: settings.instance_var,
            wait_ready: settings.wait_ready,
            ready_timeout_secs: settings.ready_timeout_secs,
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

fn watch_from(value: Option<EcosystemWatch>) -> (bool, Vec<PathBuf>) {
    match value {
        Some(EcosystemWatch::Bool(enabled)) => (enabled, Vec::new()),
        Some(EcosystemWatch::Single(path)) => {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                (false, Vec::new())
            } else {
                (true, vec![PathBuf::from(trimmed)])
            }
        }
        Some(EcosystemWatch::Many(paths)) => {
            let paths: Vec<PathBuf> = paths
                .into_iter()
                .filter_map(|path| {
                    let trimmed = path.trim();
                    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
                })
                .collect();
            (!paths.is_empty(), paths)
        }
        None => (false, Vec::new()),
    }
}

fn string_list_from(value: Option<EcosystemStringList>) -> Vec<String> {
    match value {
        Some(EcosystemStringList::Single(item)) => {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                vec![trimmed.to_string()]
            }
        }
        Some(EcosystemStringList::Many(items)) => items
            .into_iter()
            .filter_map(|item| {
                let trimmed = item.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            })
            .collect(),
        None => Vec::new(),
    }
}

fn millis_to_secs_ceil(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        value.saturating_add(999) / 1000
    }
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
    fn load_parses_js_ecosystem_with_watch_and_readiness_fields() {
        let file_path = temp_file_with_extension("ecosystem-js", "js");
        let payload = r#"
module.exports = {
  apps: [
    {
      name: "api",
      cmd: "node server.js",
      cwd: "/srv/api",
      watch: ["src", "config"],
      ignore_watch: ["node_modules", "\\.git"],
      watch_delay: 1500,
      health_cmd: "curl -fsS http://127.0.0.1:3000/health",
      wait_ready: true,
      listen_timeout: 9000
    }
  ]
};
"#;
        fs::write(&file_path, payload).expect("failed to write JS ecosystem fixture");

        let specs = load_with_profile(&file_path, None).expect("failed to parse JS ecosystem");
        let app = &specs[0];
        assert!(app.watch);
        assert_eq!(
            app.watch_paths,
            vec![PathBuf::from("src"), PathBuf::from("config")]
        );
        assert_eq!(app.ignore_watch, vec!["node_modules", "\\.git"]);
        assert_eq!(app.watch_delay_secs, 2);
        assert!(app.wait_ready);
        assert_eq!(app.ready_timeout_secs, 9);

        let _ = fs::remove_file(file_path);
    }

    #[test]
    fn load_applies_profile_watch_and_readiness_overrides() {
        let file_path = temp_file("ecosystem-watch-ready-profile");
        let payload = r#"
{
  "apps": [
    {
      "name": "api",
      "cmd": "node server.js",
      "cwd": "/srv/api",
      "watch": ["src"],
      "ignore_watch": ["node_modules"],
      "watch_delay": 500,
      "health_cmd": "curl -fsS http://127.0.0.1:3000/health",
      "wait_ready": false,
      "listen_timeout": 3000,
      "env_prod": {
        "watch": ["dist", "config"],
        "ignore_watch": ["\\.tmp$"],
        "watch_delay": 2100,
        "wait_ready": true,
        "listen_timeout": 8500
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
        assert!(app.watch);
        assert_eq!(
            app.watch_paths,
            vec![PathBuf::from("dist"), PathBuf::from("config")]
        );
        assert_eq!(app.ignore_watch, vec!["\\.tmp$"]);
        assert_eq!(app.watch_delay_secs, 3);
        assert!(app.wait_ready);
        assert_eq!(app.ready_timeout_secs, 9);

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

    fn temp_file_with_extension(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }
}
