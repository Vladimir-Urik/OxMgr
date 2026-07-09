//! Parsing and rendering of `oxfile.toml`, Oxmgr's native declarative process
//! configuration format.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ecosystem::EcosystemProcessSpec;
use crate::hash::sha256_hex;
use crate::process::{HealthCheck, ResourceLimits, RestartPolicy};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestartPolicyValue {
    Always,
    #[serde(alias = "on-failure")]
    OnFailure,
    Never,
}

impl From<RestartPolicyValue> for RestartPolicy {
    fn from(value: RestartPolicyValue) -> Self {
        match value {
            RestartPolicyValue::Always => RestartPolicy::Always,
            RestartPolicyValue::OnFailure => RestartPolicy::OnFailure,
            RestartPolicyValue::Never => RestartPolicy::Never,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum WatchValue {
    Bool(bool),
    Single(String),
    Many(Vec<String>),
}

impl WatchValue {
    fn resolve(&self) -> (bool, Vec<PathBuf>) {
        match self {
            Self::Bool(enabled) => (*enabled, Vec::new()),
            Self::Single(path) => {
                let trimmed = path.trim();
                if trimmed.is_empty() {
                    (false, Vec::new())
                } else {
                    (true, vec![PathBuf::from(trimmed)])
                }
            }
            Self::Many(paths) => {
                let paths: Vec<PathBuf> = paths
                    .iter()
                    .filter_map(|path| {
                        let trimmed = path.trim();
                        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
                    })
                    .collect();
                (!paths.is_empty(), paths)
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WatchValueOut {
    Bool(bool),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct OxLogs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stdout: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stderr: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    combined: Option<PathBuf>,
}

impl OxLogs {
    fn is_empty(&self) -> bool {
        self.stdout.is_none() && self.stderr.is_none() && self.combined.is_none()
    }
}

#[derive(Debug, Deserialize)]
struct Oxfile {
    version: Option<u32>,
    defaults: Option<OxDefaults>,
    apps: Vec<OxApp>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct OxDefaults {
    restart_policy: Option<RestartPolicyValue>,
    max_restarts: Option<u32>,
    crash_restart_limit: Option<u32>,
    pre_reload_cmd: Option<String>,
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    stop_signal: Option<String>,
    stop_timeout_secs: Option<u64>,
    restart_delay_secs: Option<u64>,
    start_delay_secs: Option<u64>,
    watch: Option<WatchValue>,
    ignore_watch: Option<Vec<String>>,
    watch_delay_secs: Option<u64>,
    cluster_mode: Option<bool>,
    cluster_instances: Option<u32>,
    namespace: Option<String>,
    start_order: Option<i32>,
    depends_on: Option<Vec<String>>,
    instances: Option<u32>,
    instance_var: Option<String>,
    health_cmd: Option<String>,
    health_interval_secs: Option<u64>,
    health_timeout_secs: Option<u64>,
    health_max_failures: Option<u32>,
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
    cgroup_enforce: Option<bool>,
    deny_gpu: Option<bool>,
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret: Option<String>,
    reuse_port: Option<bool>,
    wait_ready: Option<bool>,
    ready_timeout_secs: Option<u64>,
    log_date_format: Option<String>,
    unified_logs: Option<bool>,
    cron_restart: Option<String>,
    logs: Option<OxLogs>,
}

#[derive(Debug, Deserialize)]
struct OxApp {
    name: Option<String>,
    command: String,
    pre_reload_cmd: Option<String>,
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    restart_policy: Option<RestartPolicyValue>,
    max_restarts: Option<u32>,
    crash_restart_limit: Option<u32>,
    stop_signal: Option<String>,
    stop_timeout_secs: Option<u64>,
    restart_delay_secs: Option<u64>,
    start_delay_secs: Option<u64>,
    watch: Option<WatchValue>,
    ignore_watch: Option<Vec<String>>,
    watch_delay_secs: Option<u64>,
    cluster_mode: Option<bool>,
    cluster_instances: Option<u32>,
    namespace: Option<String>,
    start_order: Option<i32>,
    depends_on: Option<Vec<String>>,
    instances: Option<u32>,
    instance_var: Option<String>,
    health_cmd: Option<String>,
    health_interval_secs: Option<u64>,
    health_timeout_secs: Option<u64>,
    health_max_failures: Option<u32>,
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
    cgroup_enforce: Option<bool>,
    deny_gpu: Option<bool>,
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret: Option<String>,
    reuse_port: Option<bool>,
    wait_ready: Option<bool>,
    ready_timeout_secs: Option<u64>,
    log_date_format: Option<String>,
    unified_logs: Option<bool>,
    cron_restart: Option<String>,
    logs: Option<OxLogs>,
    profiles: Option<HashMap<String, OxProfile>>,
    disabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct OxProfile {
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    restart_policy: Option<RestartPolicyValue>,
    max_restarts: Option<u32>,
    crash_restart_limit: Option<u32>,
    pre_reload_cmd: Option<String>,
    stop_signal: Option<String>,
    stop_timeout_secs: Option<u64>,
    restart_delay_secs: Option<u64>,
    start_delay_secs: Option<u64>,
    watch: Option<WatchValue>,
    ignore_watch: Option<Vec<String>>,
    watch_delay_secs: Option<u64>,
    cluster_mode: Option<bool>,
    cluster_instances: Option<u32>,
    namespace: Option<String>,
    start_order: Option<i32>,
    depends_on: Option<Vec<String>>,
    instances: Option<u32>,
    instance_var: Option<String>,
    health_cmd: Option<String>,
    health_interval_secs: Option<u64>,
    health_timeout_secs: Option<u64>,
    health_max_failures: Option<u32>,
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
    cgroup_enforce: Option<bool>,
    deny_gpu: Option<bool>,
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret: Option<String>,
    reuse_port: Option<bool>,
    wait_ready: Option<bool>,
    ready_timeout_secs: Option<u64>,
    log_date_format: Option<String>,
    unified_logs: Option<bool>,
    cron_restart: Option<String>,
    logs: Option<OxLogs>,
    disabled: Option<bool>,
}

#[derive(Debug, Clone)]
struct Resolved {
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    restart_policy: RestartPolicy,
    max_restarts: u32,
    crash_restart_limit: u32,
    pre_reload_cmd: Option<String>,
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
    git_repo: Option<String>,
    git_ref: Option<String>,
    pull_secret_hash: Option<String>,
    reuse_port: bool,
    start_order: i32,
    depends_on: Vec<String>,
    instances: u32,
    instance_var: Option<String>,
    health_check: Option<HealthCheck>,
    resource_limits: Option<ResourceLimits>,
    wait_ready: bool,
    ready_timeout_secs: u64,
    log_date_format: Option<String>,
    unified_logs: bool,
    cron_restart: Option<String>,
    stdout_log_override: Option<PathBuf>,
    stderr_log_override: Option<PathBuf>,
    disabled: bool,
}

#[derive(Debug, Serialize)]
struct OxfileOut {
    version: u32,
    apps: Vec<OxAppOut>,
}

#[derive(Debug, Serialize)]
struct OxAppOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_reload_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<PathBuf>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    env: HashMap<String, String>,
    restart_policy: RestartPolicy,
    max_restarts: u32,
    crash_restart_limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_signal: Option<String>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    watch: Option<WatchValueOut>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    ignore_watch: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    watch_delay_secs: Option<u64>,
    #[serde(skip_serializing_if = "is_false", default)]
    cluster_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_instances: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_ref: Option<String>,
    start_order: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    depends_on: Vec<String>,
    instances: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_var: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_interval_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_max_failures: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_memory_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_cpu_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_enforce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_gpu: Option<bool>,
    #[serde(skip_serializing_if = "is_false", default)]
    reuse_port: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    wait_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ready_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_date_format: Option<String>,
    #[serde(skip_serializing_if = "is_false", default)]
    unified_logs: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cron_restart: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logs: Option<OxLogs>,
}

fn expand_env_values(env: &mut HashMap<String, String>) -> Result<()> {
    for (key, value) in env.iter_mut() {
        *value = crate::env_expand::expand(value)
            .with_context(|| format!("failed to expand env value for `{key}`"))?;
    }
    Ok(())
}

fn expand_path_value(path: &Path) -> Result<PathBuf> {
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("cwd path is not valid UTF-8: {}", path.display()))?;
    crate::env_expand::expand_path(raw).with_context(|| format!("failed to expand cwd `{raw}`"))
}

fn resolve_relative_to(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        base.join(value)
    }
}

fn merge_logs(defaults: Option<&OxLogs>, app: Option<&OxLogs>) -> OxLogs {
    let mut merged = defaults.cloned().unwrap_or_default();
    if let Some(app) = app {
        if app.stdout.is_some() {
            merged.stdout = app.stdout.clone();
        }
        if app.stderr.is_some() {
            merged.stderr = app.stderr.clone();
        }
        if app.combined.is_some() {
            merged.combined = app.combined.clone();
        }
    }
    merged
}

fn flatten_logs(logs: &OxLogs) -> (Option<PathBuf>, Option<PathBuf>) {
    let stdout = logs.stdout.clone().or_else(|| logs.combined.clone());
    let stderr = logs.stderr.clone().or_else(|| logs.combined.clone());
    (stdout, stderr)
}

fn expand_log_path(path: &Path) -> Result<PathBuf> {
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("log path is not valid UTF-8: {}", path.display()))?;
    crate::env_expand::expand_path(raw)
        .with_context(|| format!("failed to expand log path `{raw}`"))
}

/// Loads an `oxfile.toml`, applies defaults and optional profile overrides,
/// and converts the result into canonical process specifications.
pub fn load_with_profile(path: &Path, profile: Option<&str>) -> Result<Vec<EcosystemProcessSpec>> {
    let payload = fs::read_to_string(path)
        .with_context(|| format!("failed to read oxfile at {}", path.display()))?;
    let parsed: Oxfile = toml::from_str(&payload).context("failed to parse oxfile.toml")?;

    if let Some(version) = parsed.version {
        if version != 1 {
            anyhow::bail!("unsupported oxfile version: {}", version);
        }
    }

    let base_dir = path.parent().map(Path::to_path_buf);
    let defaults = parsed.defaults.unwrap_or_default();
    let mut result = Vec::with_capacity(parsed.apps.len());
    for (idx, app) in parsed.apps.into_iter().enumerate() {
        let mut resolved = resolve_app(&app, &defaults, profile, idx as i32)?;
        if resolved.disabled {
            continue;
        }
        expand_env_values(&mut resolved.env)?;
        if let Some(cwd) = resolved.cwd.as_ref() {
            resolved.cwd = Some(expand_path_value(cwd)?);
        }
        if let (Some(base), Some(cwd)) = (base_dir.as_deref(), resolved.cwd.as_ref()) {
            resolved.cwd = Some(resolve_relative_to(base, cwd));
        }

        if let Some(path) = resolved.stdout_log_override.as_ref() {
            let expanded = expand_log_path(path)?;
            resolved.stdout_log_override = Some(match base_dir.as_deref() {
                Some(base) => resolve_relative_to(base, &expanded),
                None => expanded,
            });
        }
        if let Some(path) = resolved.stderr_log_override.as_ref() {
            let expanded = expand_log_path(path)?;
            resolved.stderr_log_override = Some(match base_dir.as_deref() {
                Some(base) => resolve_relative_to(base, &expanded),
                None => expanded,
            });
        }

        result.push(EcosystemProcessSpec {
            command: app.command,
            name: app.name,
            pre_reload_cmd: resolved.pre_reload_cmd,
            restart_policy: resolved.restart_policy,
            max_restarts: resolved.max_restarts,
            crash_restart_limit: resolved.crash_restart_limit,
            cwd: resolved.cwd,
            env: resolved.env,
            health_check: resolved.health_check,
            stop_signal: resolved.stop_signal,
            stop_timeout_secs: resolved.stop_timeout_secs,
            restart_delay_secs: resolved.restart_delay_secs,
            start_delay_secs: resolved.start_delay_secs,
            watch: resolved.watch,
            watch_paths: resolved.watch_paths,
            ignore_watch: resolved.ignore_watch,
            watch_delay_secs: resolved.watch_delay_secs,
            cluster_mode: resolved.cluster_mode,
            cluster_instances: resolved.cluster_instances,
            namespace: resolved.namespace,
            resource_limits: resolved.resource_limits,
            git_repo: resolved.git_repo,
            git_ref: resolved.git_ref,
            pull_secret_hash: resolved.pull_secret_hash,
            reuse_port: resolved.reuse_port,
            start_order: resolved.start_order,
            depends_on: resolved.depends_on,
            instances: resolved.instances,
            instance_var: resolved.instance_var,
            wait_ready: resolved.wait_ready,
            ready_timeout_secs: resolved.ready_timeout_secs,
            log_date_format: resolved.log_date_format,
            unified_logs: resolved.unified_logs,
            cron_restart: resolved.cron_restart,
            stdout_log_override: resolved.stdout_log_override,
            stderr_log_override: resolved.stderr_log_override,
        });
    }

    Ok(result)
}

fn resolve_app(
    app: &OxApp,
    defaults: &OxDefaults,
    profile: Option<&str>,
    default_order: i32,
) -> Result<Resolved> {
    let default_watch = defaults.watch.as_ref().map(WatchValue::resolve);
    let app_watch = app.watch.as_ref().map(WatchValue::resolve);

    let mut resolved = Resolved {
        cwd: app.cwd.clone().or_else(|| defaults.cwd.clone()),
        env: defaults.env.clone().unwrap_or_default(),
        restart_policy: app
            .restart_policy
            .clone()
            .or_else(|| defaults.restart_policy.clone())
            .map(Into::into)
            .unwrap_or(RestartPolicy::OnFailure),
        max_restarts: app.max_restarts.or(defaults.max_restarts).unwrap_or(10),
        crash_restart_limit: app
            .crash_restart_limit
            .or(defaults.crash_restart_limit)
            .unwrap_or(3),
        pre_reload_cmd: app
            .pre_reload_cmd
            .clone()
            .or_else(|| defaults.pre_reload_cmd.clone()),
        stop_signal: app
            .stop_signal
            .clone()
            .or_else(|| defaults.stop_signal.clone()),
        stop_timeout_secs: app
            .stop_timeout_secs
            .or(defaults.stop_timeout_secs)
            .unwrap_or(5)
            .max(1),
        restart_delay_secs: app
            .restart_delay_secs
            .or(defaults.restart_delay_secs)
            .unwrap_or(0),
        start_delay_secs: app
            .start_delay_secs
            .or(defaults.start_delay_secs)
            .unwrap_or(0),
        watch: app_watch
            .as_ref()
            .map(|(enabled, _)| *enabled)
            .or_else(|| default_watch.as_ref().map(|(enabled, _)| *enabled))
            .unwrap_or(false),
        watch_paths: app_watch
            .as_ref()
            .map(|(_, paths)| paths.clone())
            .or_else(|| default_watch.as_ref().map(|(_, paths)| paths.clone()))
            .unwrap_or_default(),
        ignore_watch: app
            .ignore_watch
            .clone()
            .or_else(|| defaults.ignore_watch.clone())
            .unwrap_or_default(),
        watch_delay_secs: app
            .watch_delay_secs
            .or(defaults.watch_delay_secs)
            .unwrap_or(0),
        cluster_mode: app.cluster_mode.or(defaults.cluster_mode).unwrap_or(false),
        cluster_instances: normalize_cluster_instances(
            app.cluster_instances.or(defaults.cluster_instances),
        ),
        namespace: app.namespace.clone().or_else(|| defaults.namespace.clone()),
        git_repo: app.git_repo.clone().or_else(|| defaults.git_repo.clone()),
        git_ref: app.git_ref.clone().or_else(|| defaults.git_ref.clone()),
        pull_secret_hash: normalize_pull_secret_hash(
            app.pull_secret
                .clone()
                .or_else(|| defaults.pull_secret.clone()),
        )?,
        reuse_port: app.reuse_port.or(defaults.reuse_port).unwrap_or(false),
        start_order: app
            .start_order
            .or(defaults.start_order)
            .unwrap_or(default_order),
        depends_on: app
            .depends_on
            .clone()
            .or_else(|| defaults.depends_on.clone())
            .unwrap_or_default(),
        instances: app.instances.or(defaults.instances).unwrap_or(1).max(1),
        instance_var: app
            .instance_var
            .clone()
            .or_else(|| defaults.instance_var.clone()),
        health_check: health_from_parts(
            app.health_cmd
                .clone()
                .or_else(|| defaults.health_cmd.clone()),
            app.health_interval_secs.or(defaults.health_interval_secs),
            app.health_timeout_secs.or(defaults.health_timeout_secs),
            app.health_max_failures.or(defaults.health_max_failures),
        ),
        resource_limits: normalize_resource_limits(ResourceLimits {
            max_memory_mb: app.max_memory_mb.or(defaults.max_memory_mb),
            max_cpu_percent: app.max_cpu_percent.or(defaults.max_cpu_percent),
            cgroup_enforce: app
                .cgroup_enforce
                .or(defaults.cgroup_enforce)
                .unwrap_or(false),
            deny_gpu: app.deny_gpu.or(defaults.deny_gpu).unwrap_or(false),
        }),
        wait_ready: app.wait_ready.or(defaults.wait_ready).unwrap_or(false),
        ready_timeout_secs: app
            .ready_timeout_secs
            .or(defaults.ready_timeout_secs)
            .unwrap_or(30)
            .max(1),
        log_date_format: app
            .log_date_format
            .clone()
            .or_else(|| defaults.log_date_format.clone()),
        unified_logs: app.unified_logs.or(defaults.unified_logs).unwrap_or(false),
        cron_restart: app
            .cron_restart
            .clone()
            .or_else(|| defaults.cron_restart.clone()),
        stdout_log_override: None,
        stderr_log_override: None,
        disabled: app.disabled.unwrap_or(false),
    };

    let merged_logs = merge_logs(defaults.logs.as_ref(), app.logs.as_ref());
    let (stdout_override, stderr_override) = flatten_logs(&merged_logs);
    resolved.stdout_log_override = stdout_override;
    resolved.stderr_log_override = stderr_override;

    if let Some(env) = &app.env {
        for (key, value) in env {
            resolved.env.insert(key.clone(), value.clone());
        }
    }

    if let Some(profile_name) = profile {
        if let Some(profile_map) = &app.profiles {
            if let Some(profile_settings) = profile_map.get(profile_name) {
                apply_profile(profile_settings, &mut resolved)?;
            }
        }
    }

    if !resolved.cluster_mode {
        resolved.cluster_instances = None;
    }
    resolved.ignore_watch = normalize_string_list(resolved.ignore_watch);
    if !resolved.watch {
        resolved.watch_paths.clear();
        resolved.ignore_watch.clear();
        resolved.watch_delay_secs = 0;
    }

    Ok(resolved)
}

fn apply_profile(profile: &OxProfile, resolved: &mut Resolved) -> Result<()> {
    if let Some(disabled) = profile.disabled {
        resolved.disabled = disabled;
    }
    if let Some(cwd) = &profile.cwd {
        resolved.cwd = Some(cwd.clone());
    }
    if let Some(env) = &profile.env {
        for (key, value) in env {
            resolved.env.insert(key.clone(), value.clone());
        }
    }
    if let Some(policy) = &profile.restart_policy {
        resolved.restart_policy = policy.clone().into();
    }
    if let Some(max_restarts) = profile.max_restarts {
        resolved.max_restarts = max_restarts;
    }
    if let Some(crash_restart_limit) = profile.crash_restart_limit {
        resolved.crash_restart_limit = crash_restart_limit;
    }
    if let Some(pre_reload_cmd) = &profile.pre_reload_cmd {
        resolved.pre_reload_cmd = Some(pre_reload_cmd.clone());
    }
    if let Some(stop_signal) = &profile.stop_signal {
        resolved.stop_signal = Some(stop_signal.clone());
    }
    if let Some(stop_timeout_secs) = profile.stop_timeout_secs {
        resolved.stop_timeout_secs = stop_timeout_secs.max(1);
    }
    if let Some(restart_delay_secs) = profile.restart_delay_secs {
        resolved.restart_delay_secs = restart_delay_secs;
    }
    if let Some(start_delay_secs) = profile.start_delay_secs {
        resolved.start_delay_secs = start_delay_secs;
    }
    if let Some(watch) = &profile.watch {
        let (enabled, paths) = watch.resolve();
        resolved.watch = enabled;
        resolved.watch_paths = paths;
    }
    if let Some(ignore_watch) = &profile.ignore_watch {
        resolved.ignore_watch = ignore_watch.clone();
    }
    if let Some(watch_delay_secs) = profile.watch_delay_secs {
        resolved.watch_delay_secs = watch_delay_secs;
    }
    if let Some(cluster_mode) = profile.cluster_mode {
        resolved.cluster_mode = cluster_mode;
    }
    if profile.cluster_instances.is_some() {
        resolved.cluster_instances = normalize_cluster_instances(profile.cluster_instances);
    }
    if let Some(namespace) = &profile.namespace {
        resolved.namespace = Some(namespace.clone());
    }
    if let Some(git_repo) = &profile.git_repo {
        resolved.git_repo = Some(git_repo.clone());
    }
    if let Some(git_ref) = &profile.git_ref {
        resolved.git_ref = Some(git_ref.clone());
    }
    if let Some(pull_secret) = &profile.pull_secret {
        resolved.pull_secret_hash = normalize_pull_secret_hash(Some(pull_secret.clone()))?;
    }
    if let Some(reuse_port) = profile.reuse_port {
        resolved.reuse_port = reuse_port;
    }
    if let Some(start_order) = profile.start_order {
        resolved.start_order = start_order;
    }
    if let Some(depends_on) = &profile.depends_on {
        resolved.depends_on = depends_on.clone();
    }
    if let Some(instances) = profile.instances {
        resolved.instances = instances.max(1);
    }
    if let Some(instance_var) = &profile.instance_var {
        resolved.instance_var = Some(instance_var.clone());
    }

    let health_cmd = profile.health_cmd.clone().or_else(|| {
        resolved
            .health_check
            .as_ref()
            .map(|health| health.command.clone())
    });
    let health_interval_secs = profile.health_interval_secs.or_else(|| {
        resolved
            .health_check
            .as_ref()
            .map(|health| health.interval_secs)
    });
    let health_timeout_secs = profile.health_timeout_secs.or_else(|| {
        resolved
            .health_check
            .as_ref()
            .map(|health| health.timeout_secs)
    });
    let health_max_failures = profile.health_max_failures.or_else(|| {
        resolved
            .health_check
            .as_ref()
            .map(|health| health.max_failures)
    });

    resolved.health_check = health_from_parts(
        health_cmd,
        health_interval_secs,
        health_timeout_secs,
        health_max_failures,
    );

    if let Some(max_memory_mb) = profile.max_memory_mb {
        let mut limits = resolved.resource_limits.clone().unwrap_or_default();
        limits.max_memory_mb = Some(max_memory_mb);
        resolved.resource_limits = normalize_resource_limits(limits);
    }
    if let Some(max_cpu_percent) = profile.max_cpu_percent {
        let mut limits = resolved.resource_limits.clone().unwrap_or_default();
        limits.max_cpu_percent = Some(max_cpu_percent);
        resolved.resource_limits = normalize_resource_limits(limits);
    }
    if let Some(cgroup_enforce) = profile.cgroup_enforce {
        let mut limits = resolved.resource_limits.clone().unwrap_or_default();
        limits.cgroup_enforce = cgroup_enforce;
        resolved.resource_limits = normalize_resource_limits(limits);
    }
    if let Some(deny_gpu) = profile.deny_gpu {
        let mut limits = resolved.resource_limits.clone().unwrap_or_default();
        limits.deny_gpu = deny_gpu;
        resolved.resource_limits = normalize_resource_limits(limits);
    }
    if let Some(wait_ready) = profile.wait_ready {
        resolved.wait_ready = wait_ready;
    }
    if let Some(ready_timeout_secs) = profile.ready_timeout_secs {
        resolved.ready_timeout_secs = ready_timeout_secs.max(1);
    }
    if let Some(log_date_format) = &profile.log_date_format {
        resolved.log_date_format = Some(log_date_format.clone());
    }
    if let Some(unified_logs) = profile.unified_logs {
        resolved.unified_logs = unified_logs;
    }
    if let Some(cron_restart) = &profile.cron_restart {
        resolved.cron_restart = Some(cron_restart.clone());
    }
    if let Some(logs) = &profile.logs {
        if logs.stdout.is_some() {
            resolved.stdout_log_override = logs.stdout.clone();
        }
        if logs.stderr.is_some() {
            resolved.stderr_log_override = logs.stderr.clone();
        }
        if let Some(combined) = &logs.combined {
            if logs.stdout.is_none() {
                resolved.stdout_log_override = Some(combined.clone());
            }
            if logs.stderr.is_none() {
                resolved.stderr_log_override = Some(combined.clone());
            }
        }
    }
    Ok(())
}

fn health_from_parts(
    health_cmd: Option<String>,
    health_interval_secs: Option<u64>,
    health_timeout_secs: Option<u64>,
    health_max_failures: Option<u32>,
) -> Option<HealthCheck> {
    health_cmd.map(|command| HealthCheck {
        command,
        interval_secs: health_interval_secs.unwrap_or(30).max(1),
        timeout_secs: health_timeout_secs.unwrap_or(5).max(1),
        max_failures: health_max_failures.unwrap_or(3).max(1),
    })
}

fn normalize_cluster_instances(value: Option<u32>) -> Option<u32> {
    value.and_then(|instances| (instances > 0).then_some(instances))
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect()
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

    Ok(Some(sha256_hex(trimmed.as_bytes())))
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn logs_from_overrides(stdout: Option<&PathBuf>, stderr: Option<&PathBuf>) -> Option<OxLogs> {
    let logs = match (stdout, stderr) {
        (Some(s1), Some(s2)) if s1 == s2 => OxLogs {
            combined: Some(s1.clone()),
            ..Default::default()
        },
        _ => OxLogs {
            stdout: stdout.cloned(),
            stderr: stderr.cloned(),
            combined: None,
        },
    };
    if logs.is_empty() {
        None
    } else {
        Some(logs)
    }
}

fn render_watch_output(enabled: bool, paths: &[PathBuf]) -> Option<WatchValueOut> {
    if !enabled {
        return None;
    }
    if paths.is_empty() {
        Some(WatchValueOut::Bool(true))
    } else {
        Some(WatchValueOut::Many(
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        ))
    }
}

/// Writes canonical process specifications back into an `oxfile.toml`
/// representation understood by Oxmgr version 1.
pub fn write_from_specs(path: &Path, specs: &[EcosystemProcessSpec]) -> Result<()> {
    let mut apps = Vec::with_capacity(specs.len());
    for spec in specs {
        apps.push(OxAppOut {
            name: spec.name.clone(),
            command: spec.command.clone(),
            pre_reload_cmd: spec.pre_reload_cmd.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            restart_policy: spec.restart_policy.clone(),
            max_restarts: spec.max_restarts,
            crash_restart_limit: spec.crash_restart_limit,
            stop_signal: spec.stop_signal.clone(),
            stop_timeout_secs: spec.stop_timeout_secs,
            restart_delay_secs: spec.restart_delay_secs,
            start_delay_secs: spec.start_delay_secs,
            watch: render_watch_output(spec.watch, &spec.watch_paths),
            ignore_watch: spec.ignore_watch.clone(),
            watch_delay_secs: (spec.watch_delay_secs > 0).then_some(spec.watch_delay_secs),
            cluster_mode: spec.cluster_mode,
            cluster_instances: spec.cluster_instances,
            namespace: spec.namespace.clone(),
            git_repo: spec.git_repo.clone(),
            git_ref: spec.git_ref.clone(),
            start_order: spec.start_order,
            depends_on: spec.depends_on.clone(),
            instances: spec.instances,
            instance_var: spec.instance_var.clone(),
            health_cmd: spec
                .health_check
                .as_ref()
                .map(|health| health.command.clone()),
            health_interval_secs: spec
                .health_check
                .as_ref()
                .map(|health| health.interval_secs),
            health_timeout_secs: spec.health_check.as_ref().map(|health| health.timeout_secs),
            health_max_failures: spec.health_check.as_ref().map(|health| health.max_failures),
            max_memory_mb: spec
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.max_memory_mb),
            max_cpu_percent: spec
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.max_cpu_percent),
            cgroup_enforce: spec
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.cgroup_enforce.then_some(true)),
            deny_gpu: spec
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.deny_gpu.then_some(true)),
            reuse_port: spec.reuse_port,
            wait_ready: spec.wait_ready.then_some(true),
            ready_timeout_secs: spec.wait_ready.then_some(spec.ready_timeout_secs),
            log_date_format: spec.log_date_format.clone(),
            unified_logs: spec.unified_logs,
            cron_restart: spec.cron_restart.clone(),
            logs: logs_from_overrides(
                spec.stdout_log_override.as_ref(),
                spec.stderr_log_override.as_ref(),
            ),
        });
    }

    let output = OxfileOut { version: 1, apps };
    let rendered = toml::to_string_pretty(&output).context("failed to render oxfile.toml")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    fs::write(path, rendered)
        .with_context(|| format!("failed to write oxfile at {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{load_with_profile, write_from_specs};
    use crate::ecosystem::EcosystemProcessSpec;
    use crate::process::{HealthCheck, ResourceLimits, RestartPolicy};

    #[test]
    fn load_with_profile_applies_defaults_and_profile_overrides() {
        let path = temp_file("oxfile-profile");
        let payload = r#"
version = 1

[defaults]
restart_policy = "on-failure"
max_restarts = 5
crash_restart_limit = 4
start_order = 20
max_memory_mb = 256
cluster_mode = true
cluster_instances = 2

[[apps]]
name = "api"
command = "node server.js"
instances = 1
max_cpu_percent = 75

[apps.env]
BASE = "1"

[apps.profiles.prod]
instances = 3
start_order = 2
restart_policy = "always"
crash_restart_limit = 6
max_memory_mb = 512
max_cpu_percent = 80
cluster_instances = 4

[apps.profiles.prod.env]
NODE_ENV = "production"
"#;
        fs::write(&path, payload).expect("failed to write oxfile fixture");

        let specs = load_with_profile(&path, Some("prod")).expect("failed to parse oxfile");
        assert_eq!(specs.len(), 1);
        let app = &specs[0];
        assert_eq!(app.name.as_deref(), Some("api"));
        assert_eq!(app.instances, 3);
        assert_eq!(app.start_order, 2);
        assert_eq!(app.restart_policy, RestartPolicy::Always);
        assert_eq!(app.crash_restart_limit, 6);
        assert!(app.cluster_mode);
        assert_eq!(app.cluster_instances, Some(4));
        assert_eq!(
            app.env.get("NODE_ENV").map(String::as_str),
            Some("production")
        );
        let limits = app
            .resource_limits
            .as_ref()
            .expect("resource limits missing");
        assert_eq!(limits.max_memory_mb, Some(512));
        assert_eq!(limits.max_cpu_percent, Some(80.0));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_resolves_logs_section_relative_to_oxfile() {
        let path = temp_file("oxfile-logs");
        let payload = r#"
version = 1

[[apps]]
name = "worker"
command = "sleep 1"

[apps.logs]
stdout = "./logs/worker.out.log"
stderr = "./logs/worker.err.log"

[[apps]]
name = "api"
command = "sleep 1"

[apps.logs]
combined = "./logs/api.log"
"#;
        fs::write(&path, payload).expect("failed to write oxfile fixture");

        let specs = load_with_profile(&path, None).expect("failed to parse oxfile");
        let base = path.parent().expect("oxfile parent missing");
        assert_eq!(specs.len(), 2);

        let worker = &specs[0];
        assert_eq!(
            worker.stdout_log_override.as_ref(),
            Some(&base.join("./logs/worker.out.log"))
        );
        assert_eq!(
            worker.stderr_log_override.as_ref(),
            Some(&base.join("./logs/worker.err.log"))
        );

        let api = &specs[1];
        assert_eq!(
            api.stdout_log_override.as_ref(),
            Some(&base.join("./logs/api.log"))
        );
        assert_eq!(
            api.stderr_log_override.as_ref(),
            Some(&base.join("./logs/api.log"))
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_from_specs_renders_toml() {
        let path = temp_file("oxfile-write");
        let specs = vec![EcosystemProcessSpec {
            command: "sleep 1".to_string(),
            name: Some("worker".to_string()),
            pre_reload_cmd: Some("make build".to_string()),
            restart_policy: RestartPolicy::Never,
            max_restarts: 0,
            crash_restart_limit: 4,
            cwd: None,
            env: HashMap::new(),
            health_check: Some(HealthCheck {
                command: "true".to_string(),
                interval_secs: 10,
                timeout_secs: 3,
                max_failures: 2,
            }),
            resource_limits: Some(ResourceLimits {
                max_memory_mb: Some(256),
                max_cpu_percent: Some(60.0),
                cgroup_enforce: false,
                deny_gpu: false,
            }),
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 1,
            start_delay_secs: 2,
            watch: true,
            watch_paths: vec![PathBuf::from("src"), PathBuf::from("config")],
            ignore_watch: vec!["node_modules".to_string()],
            watch_delay_secs: 3,
            cluster_mode: true,
            cluster_instances: Some(2),
            namespace: Some("core".to_string()),
            git_repo: Some("git@github.com:org/worker.git".to_string()),
            git_ref: Some("main".to_string()),
            pull_secret_hash: None,
            reuse_port: true,
            start_order: 1,
            depends_on: vec!["db".to_string()],
            instances: 1,
            instance_var: Some("INSTANCE_ID".to_string()),
            wait_ready: true,
            ready_timeout_secs: 45,
            log_date_format: None,
            unified_logs: true,
            cron_restart: None,
            stdout_log_override: None,
            stderr_log_override: None,
        }];

        write_from_specs(&path, &specs).expect("failed to write oxfile");
        let rendered = fs::read_to_string(&path).expect("failed to read rendered oxfile");
        assert!(rendered.contains("version = 1"));
        assert!(rendered.contains("command = \"sleep 1\""));
        assert!(rendered.contains("depends_on = [\"db\"]"));
        assert!(rendered.contains("max_memory_mb = 256"));
        assert!(rendered.contains("max_cpu_percent = 60.0"));
        assert!(rendered.contains("cluster_mode = true"));
        assert!(rendered.contains("cluster_instances = 2"));
        assert!(rendered.contains("crash_restart_limit = 4"));
        assert!(rendered.contains("watch = ["));
        assert!(rendered.contains("\"src\""));
        assert!(rendered.contains("\"config\""));
        assert!(rendered.contains("ignore_watch = [\"node_modules\"]"));
        assert!(rendered.contains("wait_ready = true"));
        assert!(rendered.contains("unified_logs = true"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_with_profile_defaults_crash_restart_limit_to_three() {
        let path = temp_file("oxfile-default-crash-limit");
        let payload = r#"
version = 1

[[apps]]
name = "api"
command = "node server.js"
"#;
        fs::write(&path, payload).expect("failed to write oxfile fixture");

        let specs = load_with_profile(&path, None).expect("failed to parse oxfile");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].crash_restart_limit, 3);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn docs_examples_parse_successfully() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let examples = [
            root.join("docs/examples/oxfile.minimal.toml"),
            root.join("docs/examples/oxfile.web-stack.toml"),
            root.join("docs/examples/oxfile.profiles.toml"),
            root.join("docs/examples/oxfile.monorepo.toml"),
            root.join("docs/examples/oxfile.apply-idempotent.toml"),
        ];

        for path in examples {
            let specs = load_with_profile(&path, None)
                .unwrap_or_else(|err| panic!("failed to parse {}: {}", path.display(), err));
            assert!(
                !specs.is_empty(),
                "expected at least one app spec in {}",
                path.display()
            );
        }

        let prod_specs = load_with_profile(
            &root.join("docs/examples/oxfile.profiles.toml"),
            Some("prod"),
        )
        .expect("failed to parse profiles example with prod profile");
        assert!(!prod_specs.is_empty());
    }

    #[test]
    fn load_with_profile_expands_env_and_cwd_tilde_and_vars() {
        unsafe {
            std::env::set_var("HOME", "/home/tester");
            std::env::set_var("OXMGR_TEST_DATA", "shared");
        }
        let home = dirs::home_dir().expect("home directory");
        let dir = std::env::temp_dir().join(format!(
            "oxfile-expand-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock failure")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        let path = dir.join("oxfile.toml");
        let payload = r#"
version = 1

[[apps]]
name = "api"
command = "node server.js"
cwd = "~/projects/api"

[apps.env]
DATA_DIR = "$HOME/data/${OXMGR_TEST_DATA}"
LITERAL = "price=$$10"
"#;
        fs::write(&path, payload).expect("failed to write oxfile fixture");

        let specs = load_with_profile(&path, None).expect("failed to parse oxfile");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].cwd, Some(home.join("projects/api")));
        assert_eq!(
            specs[0].env.get("DATA_DIR").map(String::as_str),
            Some("/home/tester/data/shared")
        );
        assert_eq!(
            specs[0].env.get("LITERAL").map(String::as_str),
            Some("price=$10")
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_with_profile_errors_on_missing_env_variable() {
        unsafe {
            std::env::remove_var("OXMGR_TEST_MISSING_VAR");
        }
        let path = temp_file("oxfile-expand-missing");
        let payload = r#"
version = 1

[[apps]]
name = "api"
command = "node server.js"

[apps.env]
BAD = "$OXMGR_TEST_MISSING_VAR/x"
"#;
        fs::write(&path, payload).expect("failed to write oxfile fixture");
        let err = load_with_profile(&path, None).expect_err("expected error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("OXMGR_TEST_MISSING_VAR"),
            "error should mention the missing variable: {msg}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_with_profile_resolves_relative_cwd_against_oxfile_dir() {
        let dir = std::env::temp_dir().join(format!(
            "oxfile-cwd-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock failure")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        let path = dir.join("oxfile.toml");
        // An absolute cwd must be left untouched; "absolute" is platform-specific
        // (`/srv/abs` is not absolute on Windows), so pick a valid one per OS.
        // The value is written as a TOML literal string (single quotes) so the
        // Windows backslashes are not treated as escape sequences.
        let abs_cwd = if cfg!(windows) {
            r"C:\srv\abs"
        } else {
            "/srv/abs"
        };
        let payload = format!(
            "version = 1\n\n\
             [[apps]]\n\
             name = \"api\"\n\
             command = \"node server.js\"\n\
             cwd = \"./services/api\"\n\n\
             [[apps]]\n\
             name = \"abs\"\n\
             command = \"node abs.js\"\n\
             cwd = '{abs_cwd}'\n"
        );
        fs::write(&path, &payload).expect("failed to write oxfile fixture");

        let specs = load_with_profile(&path, None).expect("failed to parse oxfile");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].cwd, Some(dir.join("services/api")));
        assert_eq!(specs[1].cwd, Some(PathBuf::from(abs_cwd)));

        let _ = fs::remove_dir_all(dir);
    }

    fn temp_file(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.toml"))
    }
}
