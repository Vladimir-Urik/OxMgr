use std::collections::HashMap;
use std::path::PathBuf;

use super::{HealthCheck, ManagedProcess, ResourceLimits, RestartPolicy, StartProcessSpec};
use crate::hash::sha256_hex;

impl ManagedProcess {
    /// Computes a stable fingerprint of the process configuration fields that
    /// affect runtime behaviour.
    pub fn config_fingerprint(&self) -> String {
        process_config_fingerprint(ProcessConfigRef {
            command: &self.command,
            args: &self.args,
            cwd: self.cwd.as_ref(),
            env: &self.env,
            pre_reload_cmd: self.pre_reload_cmd.as_deref(),
            restart_policy: &self.restart_policy,
            max_restarts: self.max_restarts,
            crash_restart_limit: self.crash_restart_limit,
            health_check: self.health_check.as_ref(),
            stop_signal: self.stop_signal.as_deref(),
            stop_timeout_secs: self.stop_timeout_secs,
            restart_delay_secs: self.restart_delay_secs,
            start_delay_secs: self.start_delay_secs,
            watch: self.watch,
            watch_paths: &self.watch_paths,
            ignore_watch: &self.ignore_watch,
            watch_delay_secs: self.watch_delay_secs,
            cluster_mode: self.cluster_mode,
            cluster_instances: self.cluster_instances,
            namespace: self.namespace.as_deref(),
            resource_limits: self.resource_limits.as_ref(),
            git_repo: self.git_repo.as_deref(),
            git_ref: self.git_ref.as_deref(),
            pull_secret_hash: self.pull_secret_hash.as_deref(),
            reuse_port: self.reuse_port,
            wait_ready: self.wait_ready,
            ready_timeout_secs: self.ready_timeout_secs,
            log_date_format: self.log_date_format.as_deref(),
            unified_logs: self.unified_logs,
            cron_restart: self.cron_restart.as_deref(),
        })
    }

    /// Recomputes and stores the current configuration fingerprint.
    pub fn refresh_config_fingerprint(&mut self) {
        self.config_fingerprint = self.config_fingerprint();
    }

    /// Returns a clone suitable for IPC transport, with sensitive values such
    /// as environment variables and webhook secrets removed.
    pub fn redacted_for_transport(&self) -> Self {
        let mut clone = self.clone();
        if clone.config_fingerprint.is_empty() {
            clone.config_fingerprint = self.config_fingerprint();
        }
        clone.env.clear();
        if clone.pull_secret_hash.is_some() {
            clone.pull_secret_hash = Some("<redacted>".to_string());
        }
        clone
    }
}

impl StartProcessSpec {
    /// Computes the same stable configuration fingerprint that the daemon stores
    /// on `ManagedProcess`.
    pub fn config_fingerprint(&self) -> String {
        let (command, args) = split_command_for_fingerprint(&self.command);
        process_config_fingerprint(ProcessConfigRef {
            command: &command,
            args: &args,
            cwd: self.cwd.as_ref(),
            env: &self.env,
            pre_reload_cmd: self.pre_reload_cmd.as_deref(),
            restart_policy: &self.restart_policy,
            max_restarts: self.max_restarts,
            crash_restart_limit: self.crash_restart_limit,
            health_check: self.health_check.as_ref(),
            stop_signal: self.stop_signal.as_deref(),
            stop_timeout_secs: self.stop_timeout_secs,
            restart_delay_secs: self.restart_delay_secs,
            start_delay_secs: self.start_delay_secs,
            watch: self.watch,
            watch_paths: &self.watch_paths,
            ignore_watch: &self.ignore_watch,
            watch_delay_secs: self.watch_delay_secs,
            cluster_mode: self.cluster_mode,
            cluster_instances: self.cluster_instances,
            namespace: self.namespace.as_deref(),
            resource_limits: self.resource_limits.as_ref(),
            git_repo: self.git_repo.as_deref(),
            git_ref: self.git_ref.as_deref(),
            pull_secret_hash: self.pull_secret_hash.as_deref(),
            reuse_port: self.reuse_port,
            wait_ready: self.wait_ready,
            ready_timeout_secs: self.ready_timeout_secs,
            log_date_format: self.log_date_format.as_deref(),
            unified_logs: self.unified_logs,
            cron_restart: self.cron_restart.as_deref(),
        })
    }
}

struct ProcessConfigRef<'a> {
    command: &'a str,
    args: &'a [String],
    cwd: Option<&'a PathBuf>,
    env: &'a HashMap<String, String>,
    pre_reload_cmd: Option<&'a str>,
    restart_policy: &'a RestartPolicy,
    max_restarts: u32,
    crash_restart_limit: u32,
    health_check: Option<&'a HealthCheck>,
    stop_signal: Option<&'a str>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    watch: bool,
    watch_paths: &'a [PathBuf],
    ignore_watch: &'a [String],
    watch_delay_secs: u64,
    cluster_mode: bool,
    cluster_instances: Option<u32>,
    namespace: Option<&'a str>,
    resource_limits: Option<&'a ResourceLimits>,
    git_repo: Option<&'a str>,
    git_ref: Option<&'a str>,
    pull_secret_hash: Option<&'a str>,
    reuse_port: bool,
    wait_ready: bool,
    ready_timeout_secs: u64,
    log_date_format: Option<&'a str>,
    unified_logs: bool,
    cron_restart: Option<&'a str>,
}

fn process_config_fingerprint(config: ProcessConfigRef<'_>) -> String {
    let mut payload = String::new();
    payload.push_str("command=");
    payload.push_str(config.command);
    payload.push('\n');
    payload.push_str("args=");
    for arg in config.args {
        payload.push_str(arg);
        payload.push('\u{1f}');
    }
    payload.push('\n');
    payload.push_str("cwd=");
    if let Some(cwd) = config.cwd {
        payload.push_str(&cwd.display().to_string());
    }
    payload.push('\n');
    payload.push_str("pre_reload_cmd=");
    if let Some(cmd) = config.pre_reload_cmd {
        payload.push_str(cmd);
    }
    payload.push('\n');
    payload.push_str("restart_policy=");
    payload.push_str(&config.restart_policy.to_string());
    payload.push('\n');
    payload.push_str(&format!(
        "max_restarts={}\ncrash_restart_limit={}\nstop_timeout_secs={}\nrestart_delay_secs={}\nstart_delay_secs={}\nwatch={}\nwatch_delay_secs={}\ncluster_mode={}\ncluster_instances={:?}\nnamespace={:?}\ngit_repo={:?}\ngit_ref={:?}\npull_secret_hash={:?}\nreuse_port={}\nwait_ready={}\nready_timeout_secs={}\n",
        config.max_restarts,
        config.crash_restart_limit,
        config.stop_timeout_secs,
        config.restart_delay_secs,
        config.start_delay_secs,
        config.watch,
        config.watch_delay_secs,
        config.cluster_mode,
        config.cluster_instances,
        config.namespace,
        config.git_repo,
        config.git_ref,
        config.pull_secret_hash,
        config.reuse_port,
        config.wait_ready,
        config.ready_timeout_secs
    ));
    payload.push_str("watch_paths=");
    let mut watch_paths: Vec<String> = config
        .watch_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    watch_paths.sort();
    for path in watch_paths {
        payload.push_str(&path);
        payload.push('\u{1d}');
    }
    payload.push('\n');
    payload.push_str("ignore_watch=");
    let mut ignore_watch = config.ignore_watch.to_vec();
    ignore_watch.sort();
    for pattern in ignore_watch {
        payload.push_str(&pattern);
        payload.push('\u{1d}');
    }
    payload.push('\n');
    payload.push_str("stop_signal=");
    if let Some(signal) = config.stop_signal {
        payload.push_str(signal);
    }
    payload.push('\n');
    payload.push_str("env=");
    let mut env_items: Vec<_> = config.env.iter().collect();
    env_items.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
    for (key, value) in env_items {
        payload.push_str(key);
        payload.push('=');
        payload.push_str(value);
        payload.push('\u{1e}');
    }
    payload.push('\n');
    payload.push_str("health_check=");
    if let Some(health) = config.health_check {
        payload.push_str(&format!(
            "{}|{}|{}|{}",
            health.command, health.interval_secs, health.timeout_secs, health.max_failures
        ));
    }
    payload.push('\n');
    payload.push_str("resource_limits=");
    if let Some(limits) = config.resource_limits {
        payload.push_str(&format!(
            "{:?}|{:?}|{}|{}",
            limits.max_memory_mb, limits.max_cpu_percent, limits.cgroup_enforce, limits.deny_gpu
        ));
    }
    payload.push('\n');
    payload.push_str("log_date_format=");
    if let Some(fmt) = config.log_date_format {
        payload.push_str(fmt);
    }
    payload.push('\n');
    payload.push_str("unified_logs=");
    payload.push_str(if config.unified_logs { "true" } else { "false" });
    payload.push('\n');
    payload.push_str("cron_restart=");
    if let Some(cron) = config.cron_restart {
        payload.push_str(cron);
    }

    sha256_hex(payload.as_bytes())
}

fn split_command_for_fingerprint(command_line: &str) -> (String, Vec<String>) {
    match shell_words::split(command_line) {
        Ok(tokens) if !tokens.is_empty() => (tokens[0].clone(), tokens[1..].to_vec()),
        _ => (command_line.to_string(), Vec::new()),
    }
}
