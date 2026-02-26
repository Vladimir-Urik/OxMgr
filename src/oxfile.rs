use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ecosystem::EcosystemProcessSpec;
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
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    stop_signal: Option<String>,
    stop_timeout_secs: Option<u64>,
    restart_delay_secs: Option<u64>,
    start_delay_secs: Option<u64>,
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
}

#[derive(Debug, Deserialize)]
struct OxApp {
    name: Option<String>,
    command: String,
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    restart_policy: Option<RestartPolicyValue>,
    max_restarts: Option<u32>,
    stop_signal: Option<String>,
    stop_timeout_secs: Option<u64>,
    restart_delay_secs: Option<u64>,
    start_delay_secs: Option<u64>,
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
    profiles: Option<HashMap<String, OxProfile>>,
    disabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct OxProfile {
    cwd: Option<PathBuf>,
    env: Option<HashMap<String, String>>,
    restart_policy: Option<RestartPolicyValue>,
    max_restarts: Option<u32>,
    stop_signal: Option<String>,
    stop_timeout_secs: Option<u64>,
    restart_delay_secs: Option<u64>,
    start_delay_secs: Option<u64>,
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
    disabled: Option<bool>,
}

#[derive(Debug, Clone)]
struct Resolved {
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    restart_policy: RestartPolicy,
    max_restarts: u32,
    stop_signal: Option<String>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    namespace: Option<String>,
    start_order: i32,
    depends_on: Vec<String>,
    instances: u32,
    instance_var: Option<String>,
    health_check: Option<HealthCheck>,
    resource_limits: Option<ResourceLimits>,
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
    cwd: Option<PathBuf>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    env: HashMap<String, String>,
    restart_policy: RestartPolicy,
    max_restarts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_signal: Option<String>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
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
}

pub fn load_with_profile(path: &Path, profile: Option<&str>) -> Result<Vec<EcosystemProcessSpec>> {
    let payload = fs::read_to_string(path)
        .with_context(|| format!("failed to read oxfile at {}", path.display()))?;
    let parsed: Oxfile = toml::from_str(&payload).context("failed to parse oxfile.toml")?;

    if let Some(version) = parsed.version {
        if version != 1 {
            anyhow::bail!("unsupported oxfile version: {}", version);
        }
    }

    let defaults = parsed.defaults.unwrap_or_default();
    let mut result = Vec::with_capacity(parsed.apps.len());
    for (idx, app) in parsed.apps.into_iter().enumerate() {
        let resolved = resolve_app(&app, &defaults, profile, idx as i32);
        if resolved.disabled {
            continue;
        }

        result.push(EcosystemProcessSpec {
            command: app.command,
            name: app.name,
            restart_policy: resolved.restart_policy,
            max_restarts: resolved.max_restarts,
            cwd: resolved.cwd,
            env: resolved.env,
            health_check: resolved.health_check,
            stop_signal: resolved.stop_signal,
            stop_timeout_secs: resolved.stop_timeout_secs,
            restart_delay_secs: resolved.restart_delay_secs,
            start_delay_secs: resolved.start_delay_secs,
            namespace: resolved.namespace,
            resource_limits: resolved.resource_limits,
            start_order: resolved.start_order,
            depends_on: resolved.depends_on,
            instances: resolved.instances,
            instance_var: resolved.instance_var,
        });
    }

    Ok(result)
}

fn resolve_app(
    app: &OxApp,
    defaults: &OxDefaults,
    profile: Option<&str>,
    default_order: i32,
) -> Resolved {
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
        namespace: app.namespace.clone().or_else(|| defaults.namespace.clone()),
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
        disabled: app.disabled.unwrap_or(false),
    };

    if let Some(env) = &app.env {
        for (key, value) in env {
            resolved.env.insert(key.clone(), value.clone());
        }
    }

    if let Some(profile_name) = profile {
        if let Some(profile_map) = &app.profiles {
            if let Some(profile_settings) = profile_map.get(profile_name) {
                apply_profile(profile_settings, &mut resolved);
            }
        }
    }

    resolved
}

fn apply_profile(profile: &OxProfile, resolved: &mut Resolved) {
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
    if let Some(namespace) = &profile.namespace {
        resolved.namespace = Some(namespace.clone());
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

pub fn write_from_specs(path: &Path, specs: &[EcosystemProcessSpec]) -> Result<()> {
    let mut apps = Vec::with_capacity(specs.len());
    for spec in specs {
        apps.push(OxAppOut {
            name: spec.name.clone(),
            command: spec.command.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            restart_policy: spec.restart_policy.clone(),
            max_restarts: spec.max_restarts,
            stop_signal: spec.stop_signal.clone(),
            stop_timeout_secs: spec.stop_timeout_secs,
            restart_delay_secs: spec.restart_delay_secs,
            start_delay_secs: spec.start_delay_secs,
            namespace: spec.namespace.clone(),
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
start_order = 20
max_memory_mb = 256

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
max_memory_mb = 512
max_cpu_percent = 80

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
    fn write_from_specs_renders_toml() {
        let path = temp_file("oxfile-write");
        let specs = vec![EcosystemProcessSpec {
            command: "sleep 1".to_string(),
            name: Some("worker".to_string()),
            restart_policy: RestartPolicy::Never,
            max_restarts: 0,
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
            namespace: Some("core".to_string()),
            start_order: 1,
            depends_on: vec!["db".to_string()],
            instances: 1,
            instance_var: Some("INSTANCE_ID".to_string()),
        }];

        write_from_specs(&path, &specs).expect("failed to write oxfile");
        let rendered = fs::read_to_string(&path).expect("failed to read rendered oxfile");
        assert!(rendered.contains("version = 1"));
        assert!(rendered.contains("command = \"sleep 1\""));
        assert!(rendered.contains("depends_on = [\"db\"]"));
        assert!(rendered.contains("max_memory_mb = 256"));
        assert!(rendered.contains("max_cpu_percent = 60.0"));

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

    fn temp_file(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.toml"))
    }
}
