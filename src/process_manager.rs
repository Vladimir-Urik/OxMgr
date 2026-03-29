//! In-memory orchestration of managed processes, including persistence,
//! restarts, health checks, file watching, and metric collection.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{Context, Result};
use chrono::Local;
use cron::Schedule;
use std::str::FromStr;
use sysinfo::{Pid as SysPid, ProcessesToUpdate, System};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{sleep, Instant as TokioInstant};
use tracing::{error, info, warn};

use self::git::{
    constant_time_eq, ensure_origin_remote, ensure_repo_checkout, git_rev_parse_head, run_git,
    sha256_hex, short_commit, PullOutcome,
};
use self::health::execute_health_check;
#[cfg(test)]
use self::restart::CRASH_RESTART_WINDOW_SECS;
use self::restart::{
    compute_restart_delay_secs, crash_loop_limit_reached, maybe_reset_backoff_attempt,
    now_epoch_secs, record_auto_restart, reset_auto_restart_state,
};
#[cfg(all(test, unix))]
use self::runtime::graceful_wait_before_force_kill;
#[cfg(test)]
use self::runtime::{args_match_expected, program_matches_expected};
use self::runtime::{
    cleanup_process_cgroup, pid_matches_expected_process, process_exists, terminate_pid,
};
use self::spawn::{
    normalize_cluster_instances, parse_command_line, resolve_spawn_program, sanitize_name,
    validate_process_name,
};
use self::watch::watch_fingerprint_for_process;
#[cfg(test)]
use self::watch::{watch_fingerprint_for_dir, watch_fingerprint_for_roots};
use crate::cgroup;
use crate::config::AppConfig;
use crate::errors::OxmgrError;
use crate::logging::{open_log_writers, process_logs, ProcessLogs};
use crate::process::{
    DesiredState, HealthStatus, ManagedProcess, ProcessExitEvent, ProcessStatus, StartProcessSpec,
};
use crate::storage::{load_state, save_state, PersistedState};

mod git;
mod health;
mod restart;
mod runtime;
mod spawn;
mod watch;

/// Forwards stdout output from a process to a log file, prefixing each line with a formatted timestamp.
fn forward_logs_with_date_prefix_stdout(
    pipe: tokio::process::ChildStdout,
    log_path: std::path::PathBuf,
    date_format: String,
) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(pipe);
        let mut buffer = String::new();

        loop {
            buffer.clear();
            match reader.read_line(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    let now = Local::now();
                    let formatted_line = match now.format(&date_format).to_string() {
                        formatted => format!("{}: {}", formatted, buffer),
                    };

                    if let Ok(mut file) = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                        .await
                    {
                        let _ =
                            AsyncWriteExt::write_all(&mut file, formatted_line.as_bytes()).await;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

/// Forwards stderr output from a process to a log file, prefixing each line with a formatted timestamp.
fn forward_logs_with_date_prefix_stderr(
    pipe: tokio::process::ChildStderr,
    log_path: std::path::PathBuf,
    date_format: String,
) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(pipe);
        let mut buffer = String::new();

        loop {
            buffer.clear();
            match reader.read_line(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    let now = Local::now();
                    let formatted_line = match now.format(&date_format).to_string() {
                        formatted => format!("{}: {}", formatted, buffer),
                    };

                    if let Ok(mut file) = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)
                        .await
                    {
                        let _ =
                            AsyncWriteExt::write_all(&mut file, formatted_line.as_bytes()).await;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

/// Validates a cron expression string and returns the next execution time (epoch seconds).
/// Returns an error if the cron expression is invalid.
pub(crate) fn calculate_next_cron_restart(cron_expr: &str, from_time: Option<u64>) -> Result<u64> {
    let schedule = Schedule::from_str(cron_expr)
        .map_err(|e| anyhow::anyhow!("invalid cron expression '{}': {}", cron_expr, e))?;

    let now = if let Some(timestamp) = from_time {
        chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0)
            .ok_or_else(|| anyhow::anyhow!("invalid timestamp"))?
    } else {
        chrono::Utc::now()
    };

    schedule
        .after(&now)
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("no next execution time for cron expression '{}'", cron_expr)
        })
        .map(|dt| dt.timestamp() as u64)
}

/// Coordinates process lifecycle operations for one local Oxmgr daemon.
pub struct ProcessManager {
    config: AppConfig,
    processes: HashMap<String, ManagedProcess>,
    watch_fingerprints: HashMap<String, u64>,
    pending_watch_restarts: HashMap<String, PendingWatchRestart>,
    scheduled_restarts: HashMap<String, TokioInstant>,
    next_id: u64,
    exit_tx: UnboundedSender<ProcessExitEvent>,
    system: System,
}

#[derive(Debug, Clone, Copy)]
struct PendingWatchRestart {
    due_at: TokioInstant,
    fingerprint: u64,
}

impl ProcessManager {
    /// Rebuilds the manager from persisted state and prepares runtime-only
    /// bookkeeping such as health scheduling and system metrics.
    pub fn new(config: AppConfig, exit_tx: UnboundedSender<ProcessExitEvent>) -> Result<Self> {
        let state = load_state(&config.state_path)?;

        let mut processes = HashMap::new();
        let mut next_id = state.next_id.max(1);
        for mut process in state.processes {
            next_id = next_id.max(process.id + 1);
            if process.restart_backoff_cap_secs == 0 {
                process.restart_backoff_cap_secs = 300;
            }
            if process.restart_backoff_reset_secs == 0 {
                process.restart_backoff_reset_secs = 60;
            }
            if process.ready_timeout_secs == 0 {
                process.ready_timeout_secs = crate::process::default_ready_timeout_secs();
            }
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
            process.cpu_percent = 0.0;
            process.memory_bytes = 0;
            process.last_metrics_at = None;
            process.cgroup_path = None;
            process.refresh_config_fingerprint();
            processes.insert(process.name.clone(), process);
        }

        Ok(Self {
            config,
            processes,
            watch_fingerprints: HashMap::new(),
            pending_watch_restarts: HashMap::new(),
            scheduled_restarts: HashMap::new(),
            next_id,
            exit_tx,
            system: System::new_all(),
        })
    }

    /// Reconciles persisted process state with the live machine and respawns
    /// processes whose desired state is running.
    pub async fn recover_processes(&mut self) -> Result<()> {
        let stale: Vec<ManagedProcess> = self
            .processes
            .values()
            .filter(|process| process.pid.is_some())
            .cloned()
            .collect();

        for process in stale {
            let name = process.name.clone();
            let Some(pid) = process.pid else {
                continue;
            };
            if process_exists(pid) {
                if !self.pid_matches_managed_process(pid, &process) {
                    warn!(
                        "skipping stale pid cleanup for process {} because pid {} no longer matches expected command",
                        name, pid
                    );
                    continue;
                }
                warn!("cleaning stale pid {pid} for process {name}");
                let timeout = Duration::from_secs(process.stop_timeout_secs.max(1));
                let _ = terminate_pid(pid, process.stop_signal.as_deref(), timeout).await;
            }
        }

        let should_start: Vec<String> = self
            .processes
            .values()
            .filter(|process| process.desired_state == DesiredState::Running)
            .map(|process| process.name.clone())
            .collect();

        for process in self.processes.values_mut() {
            cleanup_process_cgroup(process);
            process.pid = None;
            process.status = ProcessStatus::Stopped;
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

            // Initialize next cron restart if configured
            if let Some(cron_expr) = &process.cron_restart {
                match calculate_next_cron_restart(cron_expr, Some(now_epoch_secs())) {
                    Ok(next_restart) => {
                        process.next_cron_restart = Some(next_restart);
                    }
                    Err(err) => {
                        warn!(
                            "failed to calculate next cron restart for process {}: {}",
                            process.name, err
                        );
                    }
                }
            }
        }
        self.watch_fingerprints.clear();
        self.pending_watch_restarts.clear();
        self.scheduled_restarts.clear();
        self.save()?;

        for name in should_start {
            if let Err(err) = self.spawn_existing(&name).await {
                error!("failed to recover process {name}: {err}");
                if let Some(process) = self.processes.get_mut(&name) {
                    process.status = ProcessStatus::Errored;
                }
            }
        }

        self.save()
    }

    /// Runs the daemon's periodic maintenance tasks.
    pub async fn run_periodic_tasks(&mut self) -> Result<()> {
        self.run_scheduled_restarts().await?;
        self.run_cron_restarts().await?;
        self.run_due_watch_restarts().await?;
        self.refresh_resource_metrics();
        self.run_resource_limit_checks().await?;
        self.run_watch_checks().await?;
        self.run_health_checks().await
    }

    /// Registers a new process, persists it, and starts it immediately.
    pub async fn start_process(&mut self, spec: StartProcessSpec) -> Result<ManagedProcess> {
        let StartProcessSpec {
            command: command_line,
            name,
            pre_reload_cmd,
            restart_policy,
            max_restarts,
            crash_restart_limit,
            cwd,
            env,
            health_check,
            stop_signal,
            stop_timeout_secs,
            restart_delay_secs,
            start_delay_secs,
            watch,
            watch_paths,
            ignore_watch,
            watch_delay_secs,
            cluster_mode,
            cluster_instances,
            namespace,
            resource_limits,
            git_repo,
            git_ref,
            pull_secret_hash,
            reuse_port,
            wait_ready,
            ready_timeout_secs,
            log_date_format,
            cron_restart,
        } = spec;

        let (command, args) = parse_command_line(&command_line)?;

        let resolved_name = match name {
            Some(given) => {
                validate_process_name(&given)?;
                if self.processes.contains_key(&given) {
                    return Err(OxmgrError::DuplicateProcessName(given).into());
                }
                given
            }
            None => self.generate_auto_name(&command),
        };

        let logs = process_logs(&self.config.log_dir, &resolved_name);
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let mut process = ManagedProcess {
            id,
            name: resolved_name.clone(),
            command,
            args,
            pre_reload_cmd,
            cwd,
            env,
            restart_policy,
            max_restarts,
            restart_count: 0,
            crash_restart_limit,
            auto_restart_history: Vec::new(),
            namespace,
            git_repo,
            git_ref,
            pull_secret_hash,
            reuse_port,
            stop_signal,
            stop_timeout_secs: stop_timeout_secs.max(1),
            restart_delay_secs,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs,
            watch,
            watch_paths,
            ignore_watch,
            watch_delay_secs,
            cluster_mode,
            cluster_instances: normalize_cluster_instances(cluster_instances),
            resource_limits,
            cgroup_path: None,
            pid: None,
            status: ProcessStatus::Stopped,
            desired_state: DesiredState::Running,
            last_exit_code: None,
            stdout_log: logs.stdout,
            stderr_log: logs.stderr,
            health_check,
            health_status: HealthStatus::Unknown,
            health_failures: 0,
            last_health_check: None,
            next_health_check: None,
            last_health_error: None,
            wait_ready,
            ready_timeout_secs: ready_timeout_secs.max(1),
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: Some(now_epoch_secs()),
            last_stopped_at: None,
            config_fingerprint: String::new(),
            log_date_format,
            cron_restart,
            next_cron_restart: None,
        };
        process.refresh_config_fingerprint();

        if process.start_delay_secs > 0 {
            sleep(Duration::from_secs(process.start_delay_secs)).await;
        }

        let pid = self.spawn_child_with_readiness(&mut process).await?;
        process.pid = Some(pid);
        process.status = ProcessStatus::Running;
        process.next_health_check = process
            .health_check
            .as_ref()
            .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

        // Initialize next cron restart time if configured
        if let Some(cron_expr) = &process.cron_restart {
            match calculate_next_cron_restart(cron_expr, Some(now_epoch_secs())) {
                Ok(next_restart) => {
                    process.next_cron_restart = Some(next_restart);
                }
                Err(err) => {
                    warn!(
                        "failed to calculate next cron restart for process {}: {}",
                        process.name, err
                    );
                }
            }
        }

        info!(
            "started process {} with pid {}",
            process.target_label(),
            pid
        );

        self.processes.insert(process.name.clone(), process.clone());
        self.update_watch_fingerprint(&process);
        self.save()?;
        Ok(process)
    }

    /// Stops a managed process and marks its desired state as stopped.
    pub async fn stop_process(&mut self, target: &str) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;
        let mut process = self
            .processes
            .get(&name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;

        process.desired_state = DesiredState::Stopped;
        if let Some(pid) = process.pid {
            let timeout = Duration::from_secs(process.stop_timeout_secs.max(1));
            terminate_pid(pid, process.stop_signal.as_deref(), timeout).await?;
        }

        process.pid = None;
        cleanup_process_cgroup(&mut process);
        process.status = ProcessStatus::Stopped;
        process.restart_backoff_attempt = 0;
        process.health_status = HealthStatus::Unknown;
        process.health_failures = 0;
        process.next_health_check = None;
        process.cpu_percent = 0.0;
        process.memory_bytes = 0;
        reset_auto_restart_state(&mut process);

        self.watch_fingerprints.remove(&name);
        self.pending_watch_restarts.remove(&name);
        self.scheduled_restarts.remove(&name);
        self.processes.insert(name, process.clone());
        self.save()?;
        Ok(process)
    }

    /// Restarts a managed process, resetting restart backoff state before the
    /// fresh spawn.
    pub async fn restart_process(&mut self, target: &str) -> Result<ManagedProcess> {
        self.restart_process_internal(target, true).await
    }

    async fn restart_process_internal(
        &mut self,
        target: &str,
        reset_restart_count: bool,
    ) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;

        let existing = self
            .processes
            .get(&name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;

        if let Some(pid) = existing.pid {
            let timeout = Duration::from_secs(existing.stop_timeout_secs.max(1));
            terminate_pid(pid, existing.stop_signal.as_deref(), timeout).await?;
        }

        {
            let process = self
                .processes
                .get_mut(&name)
                .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;
            if reset_restart_count {
                process.restart_count = 0;
                reset_auto_restart_state(process);
            }
            process.restart_backoff_attempt = 0;
            process.last_exit_code = None;
            process.desired_state = DesiredState::Running;
            process.status = ProcessStatus::Restarting;
            process.pid = None;
            self.watch_fingerprints.remove(&name);
            self.pending_watch_restarts.remove(&name);
            cleanup_process_cgroup(process);
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
        }

        self.scheduled_restarts.remove(&name);
        self.pending_watch_restarts.remove(&name);
        match self.spawn_existing(&name).await {
            Ok(process) => Ok(process),
            Err(err) => {
                if let Some(process) = self.processes.get_mut(&name) {
                    process.status = ProcessStatus::Errored;
                    process.desired_state = DesiredState::Stopped;
                    process.last_health_error = Some(format!("restart failed: {err}"));
                }
                self.save()?;
                Err(err)
            }
        }
    }

    /// Reloads a managed process, preferring replacement semantics over a full
    /// downtime window when the process is already running.
    pub async fn reload_process(&mut self, target: &str) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;

        let existing = self
            .processes
            .get(&name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;

        self.run_pre_reload_cmd(&existing).await?;

        if existing.pid.is_none() {
            return self.restart_process(target).await;
        }

        let old_pid = existing.pid.context("missing old pid for reload")?;
        let old_cgroup = existing.cgroup_path.clone();

        let mut replacement = existing.clone();
        let new_pid = self.spawn_child_with_readiness(&mut replacement).await?;
        replacement.pid = Some(new_pid);
        replacement.status = ProcessStatus::Running;
        replacement.desired_state = DesiredState::Running;
        replacement.last_exit_code = None;
        replacement.health_status = HealthStatus::Unknown;
        replacement.health_failures = 0;
        reset_auto_restart_state(&mut replacement);
        replacement.next_health_check = replacement
            .health_check
            .as_ref()
            .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

        self.scheduled_restarts.remove(&name);
        self.pending_watch_restarts.remove(&name);
        self.processes.insert(name.clone(), replacement.clone());
        self.update_watch_fingerprint(&replacement);
        self.save()?;

        let timeout = Duration::from_secs(existing.stop_timeout_secs.max(1));
        if let Err(err) = terminate_pid(old_pid, existing.stop_signal.as_deref(), timeout).await {
            warn!(
                "reload for process {} started new pid {} but failed to stop old pid {}: {}",
                name, new_pid, old_pid, err
            );
        }
        if let Some(path) = old_cgroup.as_deref() {
            if let Err(err) = cgroup::cleanup(path) {
                warn!("failed to cleanup cgroup for process {}: {}", name, err);
            }
        }

        Ok(replacement)
    }

    async fn run_pre_reload_cmd(&self, process: &ManagedProcess) -> Result<()> {
        let Some(command_line) = process.pre_reload_cmd.as_ref() else {
            return Ok(());
        };
        let trimmed = command_line.trim();
        if trimmed.is_empty() {
            anyhow::bail!(
                "pre_reload_cmd cannot be empty for process {}",
                process.name
            );
        }

        info!("running pre_reload_cmd for process {}", process.name);
        let mut command = if cfg!(windows) {
            let mut cmd = Command::new("cmd");
            cmd.arg("/C").arg(trimmed);
            cmd
        } else {
            let mut cmd = Command::new("sh");
            cmd.arg("-lc").arg(trimmed);
            cmd
        };

        if let Some(cwd) = &process.cwd {
            command.current_dir(cwd);
        }
        if !process.env.is_empty() {
            command.envs(&process.env);
        }
        command.env("OXMGR_PROCESS", &process.name);

        let output = command
            .output()
            .await
            .with_context(|| format!("pre_reload_cmd failed to start for {}", process.name))?;
        if output.status.success() {
            return Ok(());
        }

        let code = output
            .status
            .code()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "signal".to_string());
        let mut detail = String::new();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stdout.trim().is_empty() {
            detail.push_str("stdout: ");
            detail.push_str(stdout.trim());
        }
        if !stderr.trim().is_empty() {
            if !detail.is_empty() {
                detail.push_str(" | ");
            }
            detail.push_str("stderr: ");
            detail.push_str(stderr.trim());
        }
        if detail.len() > 2000 {
            detail.truncate(2000);
            detail.push_str("...");
        }

        if detail.is_empty() {
            anyhow::bail!(
                "pre_reload_cmd failed for {} (exit code {})",
                process.name,
                code
            );
        }
        anyhow::bail!(
            "pre_reload_cmd failed for {} (exit code {}): {}",
            process.name,
            code,
            detail
        );
    }

    /// Pulls Git updates for one or more managed processes and applies the
    /// corresponding reload or restart only when the checked-out revision changed.
    pub async fn pull_processes(&mut self, target: Option<&str>) -> Result<String> {
        let mut targets = if let Some(target) = target {
            vec![self.resolve_target(target)?]
        } else {
            let mut names: Vec<String> = self
                .processes
                .values()
                .filter(|process| process.git_repo.is_some())
                .map(|process| process.name.clone())
                .collect();
            names.sort();
            names
        };

        if targets.is_empty() {
            anyhow::bail!("no services configured with git_repo");
        }

        targets.sort();
        targets.dedup();

        let mut changed_count = 0_usize;
        let mut unchanged_count = 0_usize;
        let mut restarted_count = 0_usize;
        let mut failures = Vec::new();
        let mut details = Vec::new();

        for name in targets {
            match self.pull_single_process(&name).await {
                Ok(outcome) => {
                    if outcome.changed {
                        changed_count = changed_count.saturating_add(1);
                    } else {
                        unchanged_count = unchanged_count.saturating_add(1);
                    }
                    if outcome.restarted_or_reloaded {
                        restarted_count = restarted_count.saturating_add(1);
                    }
                    details.push(outcome.message);
                }
                Err(err) => {
                    failures.push(format!("{name}: {err}"));
                }
            }
        }

        if !failures.is_empty() {
            let mut lines = vec!["pull completed with failures:".to_string()];
            for failure in failures {
                lines.push(format!("- {failure}"));
            }
            anyhow::bail!(lines.join("\n"));
        }

        let mut summary = format!(
            "Pull complete: {} updated, {} unchanged, {} reloaded/restarted",
            changed_count, unchanged_count, restarted_count
        );
        if !details.is_empty() {
            summary.push('\n');
            summary.push_str(&details.join("\n"));
        }

        Ok(summary)
    }

    /// Verifies that a webhook secret matches the stored digest for the target
    /// process.
    pub fn verify_pull_webhook_secret(&self, target: &str, provided_secret: &str) -> Result<()> {
        let name = self.resolve_target(target)?;
        let process = self
            .processes
            .get(&name)
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;

        let expected_hash = process
            .pull_secret_hash
            .as_deref()
            .context("pull webhook secret is not configured for this service")?;
        let provided_hash = sha256_hex(provided_secret.trim());

        if !constant_time_eq(expected_hash.as_bytes(), provided_hash.as_bytes()) {
            anyhow::bail!("invalid pull webhook secret");
        }
        Ok(())
    }

    /// Deletes a managed process and removes its persisted metadata.
    pub async fn delete_process(&mut self, target: &str) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;

        if let Some(process) = self.processes.get(&name).cloned() {
            if let Some(pid) = process.pid {
                let timeout = Duration::from_secs(process.stop_timeout_secs.max(1));
                let _ = terminate_pid(pid, process.stop_signal.as_deref(), timeout).await;
            }
            if let Some(path) = process.cgroup_path.as_deref() {
                if let Err(err) = cgroup::cleanup(path) {
                    warn!("failed to cleanup cgroup for process {}: {}", name, err);
                }
            }
        }

        let removed = self
            .processes
            .remove(&name)
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;
        self.watch_fingerprints.remove(&name);
        self.pending_watch_restarts.remove(&name);
        self.scheduled_restarts.remove(&name);
        self.save()?;
        Ok(removed)
    }

    async fn pull_single_process(&mut self, name: &str) -> Result<PullOutcome> {
        let snapshot = self
            .processes
            .get(name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(name.to_string()))?;

        let repo = snapshot
            .git_repo
            .clone()
            .context("git_repo is not configured for this service")?;
        let cwd = snapshot
            .cwd
            .clone()
            .context("pull requires cwd to be set for the service")?;
        let git_ref = snapshot.git_ref.clone();

        ensure_repo_checkout(&cwd, &repo, git_ref.as_deref()).await?;
        ensure_origin_remote(&cwd, &repo).await?;

        let before = git_rev_parse_head(&cwd).await?;
        if let Some(git_ref) = git_ref.as_deref() {
            run_git(
                &cwd,
                &["pull", "--ff-only", "origin", git_ref],
                "pull repository from remote ref",
            )
            .await?;
        } else {
            run_git(&cwd, &["pull", "--ff-only"], "pull repository").await?;
        }
        let after = git_rev_parse_head(&cwd).await?;
        let changed = before != after;

        let mut action = "up-to-date".to_string();
        let mut restarted_or_reloaded = false;

        if changed {
            if snapshot.status == ProcessStatus::Running && snapshot.pid.is_some() {
                self.reload_process(name).await?;
                action = "reloaded".to_string();
                restarted_or_reloaded = true;
            } else if snapshot.desired_state == DesiredState::Running {
                self.restart_process(name).await?;
                action = "restarted".to_string();
                restarted_or_reloaded = true;
            } else {
                action = "updated (service stopped)".to_string();
            }
        }

        Ok(PullOutcome {
            changed,
            restarted_or_reloaded,
            message: format!(
                "{}: {} ({} -> {})",
                name,
                action,
                short_commit(&before),
                short_commit(&after)
            ),
        })
    }

    /// Returns an ordered snapshot of all managed processes.
    pub fn list_processes(&self) -> Vec<ManagedProcess> {
        let mut list: Vec<ManagedProcess> = self.processes.values().cloned().collect();
        list.sort_by_key(|process| process.id);
        list
    }

    /// Returns one managed process identified by name or numeric id.
    pub fn get_process(&self, target: &str) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;
        self.processes
            .get(&name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()).into())
    }

    /// Returns the stdout and stderr log paths for one managed process.
    pub fn logs_for(&self, target: &str) -> Result<ProcessLogs> {
        let process = self.get_process(target)?;
        Ok(ProcessLogs {
            stdout: process.stdout_log,
            stderr: process.stderr_log,
        })
    }

    /// Updates internal state after a child process exits and schedules an
    /// automatic restart when policy allows.
    pub async fn handle_exit_event(&mut self, event: ProcessExitEvent) -> Result<()> {
        let Some(mut process) = self.processes.get(&event.name).cloned() else {
            return Ok(());
        };

        if let Some(active_pid) = process.pid {
            if active_pid != event.pid {
                return Ok(());
            }
        } else if process.desired_state == DesiredState::Running {
            return Ok(());
        }

        process.pid = None;
        self.watch_fingerprints.remove(&process.name);
        self.pending_watch_restarts.remove(&process.name);
        self.scheduled_restarts.remove(&process.name);
        cleanup_process_cgroup(&mut process);
        process.cpu_percent = 0.0;
        process.memory_bytes = 0;
        process.last_exit_code = event.exit_code;
        let now = now_epoch_secs();
        process.last_stopped_at = Some(now);

        if process.desired_state == DesiredState::Stopped {
            process.status = ProcessStatus::Stopped;
            process.restart_backoff_attempt = 0;
            process.health_status = HealthStatus::Unknown;
            process.next_health_check = None;
            reset_auto_restart_state(&mut process);
            self.processes.insert(process.name.clone(), process);
            self.save()?;
            return Ok(());
        }

        let exited_successfully = event.success && !event.wait_error;
        let can_restart = !event.wait_error
            && process.restart_policy.should_restart(exited_successfully)
            && process.restart_count < process.max_restarts;

        if can_restart {
            if crash_loop_limit_reached(&mut process, now) {
                process.status = ProcessStatus::Errored;
                process.desired_state = DesiredState::Stopped;
                process.restart_backoff_attempt = 0;
                process.health_status = HealthStatus::Unknown;
                process.health_failures = 0;
                process.next_health_check = None;
                process.last_health_error = Some(format!(
                    "crash loop detected after {} auto restarts in 5 minutes; manual restart required",
                    process.crash_restart_limit
                ));
                self.processes.insert(process.name.clone(), process);
                self.save()?;
                return Ok(());
            }

            maybe_reset_backoff_attempt(&mut process);
            let restart_delay = compute_restart_delay_secs(&process);
            record_auto_restart(&mut process, now);
            process.status = ProcessStatus::Restarting;
            process.restart_count = process.restart_count.saturating_add(1);
            process.restart_backoff_attempt = process.restart_backoff_attempt.saturating_add(1);
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
            let process_name = process.name.clone();
            self.processes.insert(process_name.clone(), process.clone());

            if restart_delay == 0 {
                if let Err(err) = self.spawn_existing(&process_name).await {
                    error!(
                        "failed to restart process {} immediately after exit: {}",
                        process_name, err
                    );
                    if let Some(process) = self.processes.get_mut(&process_name) {
                        process.status = ProcessStatus::Errored;
                        process.desired_state = DesiredState::Stopped;
                        process.last_health_error = Some(format!("restart failed: {err}"));
                    }
                    self.save()?;
                }
                return Ok(());
            }

            self.scheduled_restarts.insert(
                process_name,
                TokioInstant::now() + Duration::from_secs(restart_delay),
            );
            self.save()?;
            return Ok(());
        }

        process.status = if event.wait_error {
            ProcessStatus::Errored
        } else if exited_successfully {
            ProcessStatus::Stopped
        } else {
            ProcessStatus::Crashed
        };
        process.restart_backoff_attempt = 0;
        process.health_status = HealthStatus::Unknown;
        process.next_health_check = None;
        if !matches!(process.status, ProcessStatus::Restarting) {
            reset_auto_restart_state(&mut process);
        }

        self.processes.insert(process.name.clone(), process);
        self.save()?;
        Ok(())
    }

    /// Stops every managed process as part of daemon shutdown.
    pub async fn shutdown_all(&mut self) -> Result<()> {
        let names: Vec<String> = self.processes.keys().cloned().collect();
        for name in names {
            if let Some(mut process) = self.processes.get(&name).cloned() {
                process.desired_state = DesiredState::Stopped;
                if let Some(pid) = process.pid {
                    let timeout = Duration::from_secs(process.stop_timeout_secs.max(1));
                    let _ = terminate_pid(pid, process.stop_signal.as_deref(), timeout).await;
                }
                process.pid = None;
                cleanup_process_cgroup(&mut process);
                process.status = ProcessStatus::Stopped;
                process.restart_backoff_attempt = 0;
                process.health_status = HealthStatus::Unknown;
                process.next_health_check = None;
                process.cpu_percent = 0.0;
                process.memory_bytes = 0;
                reset_auto_restart_state(&mut process);
                self.watch_fingerprints.remove(&name);
                self.pending_watch_restarts.remove(&name);
                self.scheduled_restarts.remove(&name);
                self.processes.insert(name, process);
            }
        }
        self.save()
    }

    async fn spawn_existing(&mut self, name: &str) -> Result<ManagedProcess> {
        let mut process = self
            .processes
            .get(name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(name.to_string()))?;

        let pid = self.spawn_child_with_readiness(&mut process).await?;
        process.pid = Some(pid);
        process.status = ProcessStatus::Running;
        process.desired_state = DesiredState::Running;
        process.last_started_at = Some(now_epoch_secs());
        process.next_health_check = process
            .health_check
            .as_ref()
            .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

        self.scheduled_restarts.remove(name);
        self.pending_watch_restarts.remove(name);
        self.processes.insert(name.to_string(), process.clone());
        self.update_watch_fingerprint(&process);
        self.save()?;
        Ok(process)
    }

    async fn spawn_child_with_readiness(&self, process: &mut ManagedProcess) -> Result<u32> {
        let pid = self.spawn_child(process).await?;
        if !process.wait_ready {
            return Ok(pid);
        }

        let Some(check) = process.health_check.clone() else {
            let timeout = Duration::from_secs(process.stop_timeout_secs.max(1));
            let _ = terminate_pid(pid, process.stop_signal.as_deref(), timeout).await;
            anyhow::bail!(
                "wait_ready requires a health check for process {}",
                process.name
            );
        };

        let mut snapshot = process.clone();
        snapshot.pid = Some(pid);
        let deadline = StdInstant::now() + Duration::from_secs(process.ready_timeout_secs.max(1));
        let detail = loop {
            if !process_exists(pid) {
                anyhow::bail!("process {} exited before becoming ready", process.name);
            }

            match execute_health_check(&snapshot, &check).await {
                Ok(()) => return Ok(pid),
                Err(err) => {
                    if StdInstant::now() >= deadline {
                        break err.to_string();
                    }
                }
            }

            sleep(Duration::from_millis(250)).await;
        };

        let timeout = Duration::from_secs(process.stop_timeout_secs.max(1));
        let _ = terminate_pid(pid, process.stop_signal.as_deref(), timeout).await;
        anyhow::bail!(
            "process {} did not become ready within {}s: {}",
            process.name,
            process.ready_timeout_secs.max(1),
            detail
        );
    }

    async fn spawn_child(&self, process: &mut ManagedProcess) -> Result<u32> {
        let logs = ProcessLogs {
            stdout: process.stdout_log.clone(),
            stderr: process.stderr_log.clone(),
        };
        let spawn = resolve_spawn_program(process, &self.config.base_dir)?;

        let mut command = Command::new(&spawn.program);
        #[cfg(unix)]
        {
            // Put managed children in their own process group so shutdown/restart can target the full tree.
            unsafe {
                command.pre_exec(|| {
                    if nix::libc::setpgid(0, 0) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        command.args(&spawn.args).stdin(Stdio::null());

        // Handle log formatting if date format is configured
        if process.log_date_format.is_some() {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            let (stdout, stderr) = open_log_writers(&logs, self.config.log_rotation)?;
            command
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
        }

        if let Some(cwd) = &process.cwd {
            command.current_dir(cwd);
        }
        if !process.env.is_empty() {
            command.envs(&process.env);
        }
        if !spawn.extra_env.is_empty() {
            command.envs(&spawn.extra_env);
        }
        if process.reuse_port {
            #[cfg(unix)]
            {
                command.env("OXMGR_REUSEPORT", "1");
                command.env("SO_REUSEPORT", "1");
            }
            #[cfg(windows)]
            {
                warn!(
                    "process {} requested reuse_port but SO_REUSEPORT is not supported on Windows",
                    process.name
                );
            }
        }
        if process
            .resource_limits
            .as_ref()
            .map(|limits| limits.deny_gpu)
            .unwrap_or(false)
        {
            command.env("CUDA_VISIBLE_DEVICES", "");
            command.env("NVIDIA_VISIBLE_DEVICES", "none");
            command.env("HIP_VISIBLE_DEVICES", "");
            command.env("ROCR_VISIBLE_DEVICES", "");
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn {}", process.command))?;
        let pid = child.id().context("spawned child has no pid")?;

        // Handle log forwarding with date formatting if configured
        if let Some(date_format) = &process.log_date_format {
            if let Some(stdout) = child.stdout.take() {
                let stdout_path = logs.stdout.clone();
                let date_fmt = date_format.clone();
                forward_logs_with_date_prefix_stdout(stdout, stdout_path, date_fmt);
            }
            if let Some(stderr) = child.stderr.take() {
                let stderr_path = logs.stderr.clone();
                let date_fmt = date_format.clone();
                forward_logs_with_date_prefix_stderr(stderr, stderr_path, date_fmt);
            }
        }
        process.cgroup_path = None;
        if let Some(limits) = process.resource_limits.as_ref() {
            match cgroup::apply_limits(&process.name, process.id, pid, limits) {
                Ok(path) => {
                    process.cgroup_path = path;
                }
                Err(err) => {
                    let _ = terminate_pid(
                        pid,
                        process.stop_signal.as_deref(),
                        Duration::from_secs(process.stop_timeout_secs.max(1)),
                    )
                    .await;
                    anyhow::bail!(
                        "failed to apply resource controls for process {}: {}",
                        process.name,
                        err
                    );
                }
            }
        }

        let tx = self.exit_tx.clone();
        let name = process.name.clone();
        tokio::spawn(async move {
            let event = match child.wait().await {
                Ok(status) => ProcessExitEvent {
                    name,
                    pid,
                    exit_code: status.code(),
                    success: status.success(),
                    wait_error: false,
                },
                Err(err) => {
                    error!("child wait failed: {err}");
                    ProcessExitEvent {
                        name,
                        pid,
                        exit_code: None,
                        success: false,
                        wait_error: true,
                    }
                }
            };

            let _ = tx.send(event);
        });

        Ok(pid)
    }

    fn update_watch_fingerprint(&mut self, process: &ManagedProcess) {
        if !process.watch || process.status != ProcessStatus::Running {
            self.watch_fingerprints.remove(&process.name);
            self.pending_watch_restarts.remove(&process.name);
            return;
        }

        match watch_fingerprint_for_process(process) {
            Ok(fingerprint) => {
                self.watch_fingerprints
                    .insert(process.name.clone(), fingerprint);
                self.pending_watch_restarts.remove(&process.name);
            }
            Err(err) => {
                warn!(
                    "failed to initialize watch fingerprint for process {}: {}",
                    process.name, err
                );
                self.watch_fingerprints.remove(&process.name);
                self.pending_watch_restarts.remove(&process.name);
            }
        }
    }

    /// Executes delayed restarts whose scheduled timestamp has already passed.
    pub async fn run_scheduled_restarts(&mut self) -> Result<()> {
        let now = TokioInstant::now();
        let mut due: Vec<(String, TokioInstant)> = self
            .scheduled_restarts
            .iter()
            .filter(|(_, due_at)| **due_at <= now)
            .map(|(name, due_at)| (name.clone(), *due_at))
            .collect();
        due.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));

        for (name, _) in due {
            self.scheduled_restarts.remove(&name);

            let Some(snapshot) = self.processes.get(&name).cloned() else {
                continue;
            };

            if snapshot.desired_state != DesiredState::Running
                || snapshot.status != ProcessStatus::Restarting
            {
                continue;
            }

            if let Err(err) = self.spawn_existing(&name).await {
                error!("failed to restart process {}: {err}", name);
                if let Some(process) = self.processes.get_mut(&name) {
                    process.status = ProcessStatus::Errored;
                    process.desired_state = DesiredState::Stopped;
                    process.last_health_error = Some(format!("restart failed: {err}"));
                }
                self.save()?;
            }
        }

        Ok(())
    }

    async fn run_cron_restarts(&mut self) -> Result<()> {
        let now_secs = now_epoch_secs();
        let mut due: Vec<String> = self
            .processes
            .iter()
            .filter(|(_, process)| {
                process.cron_restart.is_some()
                    && process.next_cron_restart.is_some()
                    && process.next_cron_restart.unwrap() <= now_secs
                    && process.status == ProcessStatus::Running
                    && process.desired_state == DesiredState::Running
            })
            .map(|(name, _)| name.clone())
            .collect();
        due.sort();

        for name in due {
            let Some(process) = self.processes.get(&name).cloned() else {
                continue;
            };

            info!("triggering cron-scheduled restart for process {}", name);

            match self.restart_process_internal(&name, false).await {
                Ok(_) => {
                    if let Some(p) = self.processes.get_mut(&name) {
                        p.restart_count = process.restart_count.saturating_add(1);
                        p.last_health_error = Some("cron-scheduled restart".to_string());

                        // Calculate next cron restart
                        if let Some(cron_expr) = &p.cron_restart.clone() {
                            match calculate_next_cron_restart(cron_expr, Some(now_secs)) {
                                Ok(next_restart) => {
                                    p.next_cron_restart = Some(next_restart);
                                }
                                Err(err) => {
                                    warn!(
                                        "failed to calculate next cron restart for {}: {}",
                                        name, err
                                    );
                                }
                            }
                        }
                    }
                    self.save()?;
                }
                Err(err) => {
                    error!("cron restart failed for process {}: {}", name, err);
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.status = ProcessStatus::Errored;
                        process.last_health_error = Some(format!("cron restart failed: {err}"));
                    }
                    self.save()?;
                }
            }
        }

        Ok(())
    }

    async fn run_due_watch_restarts(&mut self) -> Result<()> {
        let now = TokioInstant::now();
        let mut due: Vec<(String, PendingWatchRestart)> = self
            .pending_watch_restarts
            .iter()
            .filter(|(_, state)| state.due_at <= now)
            .map(|(name, state)| (name.clone(), *state))
            .collect();
        due.sort_by(|left, right| {
            left.1
                .due_at
                .cmp(&right.1.due_at)
                .then_with(|| left.0.cmp(&right.0))
        });

        for (name, pending) in due {
            self.pending_watch_restarts.remove(&name);

            let Some(snapshot) = self.processes.get(&name).cloned() else {
                continue;
            };
            if !snapshot.watch
                || snapshot.status != ProcessStatus::Running
                || snapshot.pid.is_none()
            {
                continue;
            }

            warn!(
                "watch delay elapsed for process {}; triggering restart",
                name
            );

            match self.restart_process_internal(&name, false).await {
                Ok(_) => {
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.restart_count = snapshot.restart_count.saturating_add(1);
                        process.last_health_error = Some("watch-triggered restart".to_string());
                    }
                    self.watch_fingerprints
                        .insert(name.clone(), pending.fingerprint);
                    self.save()?;
                }
                Err(err) => {
                    error!("watch restart failed for process {}: {}", name, err);
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.status = ProcessStatus::Errored;
                        process.last_health_error = Some(format!("watch restart failed: {err}"));
                    }
                    self.save()?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn next_scheduled_restart_at(&self) -> Option<TokioInstant> {
        let now_secs = now_epoch_secs();
        let cron_restarts = self
            .processes
            .values()
            .filter_map(|process| process.next_cron_restart)
            .filter(|&next_restart| next_restart >= now_secs)
            .map(|next_restart| {
                let secs_from_now = next_restart.saturating_sub(now_secs);
                TokioInstant::now() + Duration::from_secs(secs_from_now)
            });

        self.scheduled_restarts
            .values()
            .copied()
            .chain(
                self.pending_watch_restarts
                    .values()
                    .map(|state| state.due_at),
            )
            .chain(cron_restarts)
            .min()
    }

    fn save(&self) -> Result<()> {
        let mut values: Vec<ManagedProcess> = self.processes.values().cloned().collect();
        values.sort_by_key(|process| process.id);

        let state = PersistedState {
            next_id: self.next_id,
            processes: values,
        };

        save_state(&self.config.state_path, &state)
    }

    fn pid_matches_managed_process(&self, pid: u32, process: &ManagedProcess) -> bool {
        let spawn = match resolve_spawn_program(process, &self.config.base_dir) {
            Ok(spawn) => spawn,
            Err(err) => {
                warn!(
                    "failed to resolve expected spawn program for process {} while verifying stale pid {}: {}",
                    process.name, pid, err
                );
                return false;
            }
        };
        pid_matches_expected_process(pid, &spawn.program, &spawn.args, process.cwd.as_deref())
    }

    fn resolve_target(&self, target: &str) -> Result<String> {
        if self.processes.contains_key(target) {
            return Ok(target.to_string());
        }

        if let Ok(id) = target.parse::<u64>() {
            if let Some(name) = self
                .processes
                .values()
                .find(|process| process.id == id)
                .map(|process| process.name.clone())
            {
                return Ok(name);
            }
        }

        Err(OxmgrError::ProcessNotFound(target.to_string()).into())
    }

    fn generate_auto_name(&self, command: &str) -> String {
        let stem = Path::new(command)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("process");
        let base = sanitize_name(stem);

        if !self.processes.contains_key(&base) {
            return base;
        }

        let mut suffix = 1_u64;
        loop {
            let candidate = format!("{base}-{suffix}");
            if !self.processes.contains_key(&candidate) {
                return candidate;
            }
            suffix = suffix.saturating_add(1);
        }
    }

    fn refresh_resource_metrics(&mut self) {
        let now = now_epoch_secs();
        let tracked_pids: Vec<SysPid> = self
            .processes
            .values()
            .filter(|process| process.status == ProcessStatus::Running)
            .filter_map(|process| process.pid.map(SysPid::from_u32))
            .collect();

        if !tracked_pids.is_empty() {
            self.system
                .refresh_processes(ProcessesToUpdate::Some(&tracked_pids), true);
        }

        for process in self.processes.values_mut() {
            if process.status != ProcessStatus::Running {
                process.cpu_percent = 0.0;
                process.memory_bytes = 0;
                continue;
            }

            let Some(pid) = process.pid else {
                process.cpu_percent = 0.0;
                process.memory_bytes = 0;
                continue;
            };

            if let Some(proc_info) = self.system.process(SysPid::from_u32(pid)) {
                process.cpu_percent = proc_info.cpu_usage();
                process.memory_bytes = proc_info.memory();
                process.last_metrics_at = Some(now);
            } else {
                process.cpu_percent = 0.0;
                process.memory_bytes = 0;
                process.last_metrics_at = Some(now);
            }
        }
    }

    async fn run_resource_limit_checks(&mut self) -> Result<()> {
        let violating: Vec<(String, bool, bool)> = self
            .processes
            .values()
            .filter_map(|process| {
                if process.status != ProcessStatus::Running || process.pid.is_none() {
                    return None;
                }

                let limits = process.resource_limits.as_ref()?;

                let memory_exceeded = limits
                    .max_memory_mb
                    .map(|max_mb| process.memory_bytes > max_mb.saturating_mul(1024 * 1024))
                    .unwrap_or(false);
                let cpu_exceeded = limits
                    .max_cpu_percent
                    .map(|max_cpu| process.cpu_percent > max_cpu)
                    .unwrap_or(false);

                if memory_exceeded || cpu_exceeded {
                    Some((process.name.clone(), memory_exceeded, cpu_exceeded))
                } else {
                    None
                }
            })
            .collect();

        let mut should_save = false;

        for (name, memory_exceeded, cpu_exceeded) in violating {
            let Some(snapshot) = self.processes.get(&name).cloned() else {
                continue;
            };

            if snapshot.restart_count >= snapshot.max_restarts {
                warn!(
                    "resource limits exceeded for process {} and max_restarts reached; stopping process",
                    name
                );
                if let Some(pid) = snapshot.pid {
                    let timeout = Duration::from_secs(snapshot.stop_timeout_secs.max(1));
                    let _ = terminate_pid(pid, snapshot.stop_signal.as_deref(), timeout).await;
                }

                if let Some(process) = self.processes.get_mut(&name) {
                    process.pid = None;
                    cleanup_process_cgroup(process);
                    process.desired_state = DesiredState::Stopped;
                    process.status = ProcessStatus::Errored;
                    process.cpu_percent = 0.0;
                    process.memory_bytes = 0;
                    process.last_health_error =
                        Some("resource limit exceeded and max_restarts reached".to_string());
                }
                should_save = true;
                continue;
            }

            warn!(
                "resource limit exceeded for process {} (memory_exceeded={}, cpu_exceeded={}); restarting",
                name, memory_exceeded, cpu_exceeded
            );

            match self.restart_process_internal(&name, false).await {
                Ok(_) => {
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.restart_count = snapshot.restart_count.saturating_add(1);
                        process.last_health_error = Some(format!(
                            "resource limit restart (memory_exceeded={}, cpu_exceeded={})",
                            memory_exceeded, cpu_exceeded
                        ));
                    }
                    self.save()?;
                }
                Err(err) => {
                    error!(
                        "resource-limit restart failed for process {}: {}",
                        name, err
                    );
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.status = ProcessStatus::Errored;
                        process.last_health_error =
                            Some(format!("resource-limit restart failed: {err}"));
                    }
                    should_save = true;
                }
            }
        }

        if should_save {
            self.save()?;
        }

        Ok(())
    }

    async fn run_watch_checks(&mut self) -> Result<()> {
        let candidates: Vec<String> = self
            .processes
            .values()
            .filter(|process| {
                process.watch && process.status == ProcessStatus::Running && process.pid.is_some()
            })
            .map(|process| process.name.clone())
            .collect();

        for name in candidates {
            let Some(snapshot) = self.processes.get(&name).cloned() else {
                continue;
            };

            let current_fingerprint = match watch_fingerprint_for_process(&snapshot) {
                Ok(value) => value,
                Err(err) => {
                    warn!("watch scan failed for process {}: {}", name, err);
                    continue;
                }
            };

            let Some(previous_fingerprint) = self.watch_fingerprints.get(&name).copied() else {
                self.watch_fingerprints
                    .insert(name.clone(), current_fingerprint);
                continue;
            };

            if previous_fingerprint == current_fingerprint {
                self.pending_watch_restarts.remove(&name);
                continue;
            }

            if snapshot.watch_delay_secs > 0 {
                let due_at = TokioInstant::now() + Duration::from_secs(snapshot.watch_delay_secs);
                self.pending_watch_restarts.insert(
                    name.clone(),
                    PendingWatchRestart {
                        due_at,
                        fingerprint: current_fingerprint,
                    },
                );
                continue;
            }

            warn!(
                "filesystem change detected for process {}; triggering restart",
                name
            );

            match self.restart_process_internal(&name, false).await {
                Ok(_) => {
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.restart_count = snapshot.restart_count.saturating_add(1);
                        process.last_health_error = Some("watch-triggered restart".to_string());
                    }
                    self.watch_fingerprints
                        .insert(name.clone(), current_fingerprint);
                    self.pending_watch_restarts.remove(&name);
                    self.save()?;
                }
                Err(err) => {
                    error!("watch restart failed for process {}: {}", name, err);
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.status = ProcessStatus::Errored;
                        process.last_health_error = Some(format!("watch restart failed: {err}"));
                    }
                    self.pending_watch_restarts.remove(&name);
                    self.save()?;
                }
            }
        }

        Ok(())
    }

    async fn run_health_checks(&mut self) -> Result<()> {
        let now = now_epoch_secs();
        let due_names: Vec<String> = self
            .processes
            .values()
            .filter(|process| {
                process.status == ProcessStatus::Running
                    && process.pid.is_some()
                    && process.health_check.is_some()
                    && process
                        .next_health_check
                        .map(|next| next <= now)
                        .unwrap_or(true)
            })
            .map(|process| process.name.clone())
            .collect();

        let mut should_save = false;

        for name in due_names {
            let Some(snapshot) = self.processes.get(&name).cloned() else {
                continue;
            };

            let Some(check) = snapshot.health_check.clone() else {
                continue;
            };

            let outcome = execute_health_check(&snapshot, &check).await;
            let mut should_restart = false;

            {
                let Some(process) = self.processes.get_mut(&name) else {
                    continue;
                };

                if process.pid != snapshot.pid {
                    continue;
                }

                process.last_health_check = Some(now);
                process.next_health_check = Some(now.saturating_add(check.interval_secs.max(1)));

                match outcome {
                    Ok(()) => {
                        process.health_status = HealthStatus::Healthy;
                        process.health_failures = 0;
                        process.last_health_error = None;
                    }
                    Err(err) => {
                        process.health_status = HealthStatus::Unhealthy;
                        process.health_failures = process.health_failures.saturating_add(1);
                        process.last_health_error = Some(err.to_string());

                        if process.health_failures >= check.max_failures.max(1) {
                            should_restart = true;
                            process.health_failures = 0;
                        }
                    }
                }
                should_save = true;
            }

            if should_restart {
                if snapshot.restart_count >= snapshot.max_restarts {
                    warn!(
                        "health checks failed for process {} and max_restarts reached; stopping process",
                        name
                    );
                    if let Some(pid) = snapshot.pid {
                        let timeout = Duration::from_secs(snapshot.stop_timeout_secs.max(1));
                        let _ = terminate_pid(pid, snapshot.stop_signal.as_deref(), timeout).await;
                    }
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.pid = None;
                        cleanup_process_cgroup(process);
                        process.desired_state = DesiredState::Stopped;
                        process.status = ProcessStatus::Errored;
                        process.cpu_percent = 0.0;
                        process.memory_bytes = 0;
                        process.last_health_error =
                            Some("health checks failed and max_restarts reached".to_string());
                    }
                    should_save = true;
                    continue;
                }

                warn!(
                    "health checks failed for process {} repeatedly; restarting process",
                    name
                );
                if let Err(err) = self.restart_process_internal(&name, false).await {
                    error!("health-check restart failed for process {}: {}", name, err);
                    if let Some(process) = self.processes.get_mut(&name) {
                        process.status = ProcessStatus::Errored;
                        process.last_health_error =
                            Some(format!("health restart failed after max failures: {err}"));
                    }
                    should_save = true;
                } else if let Some(process) = self.processes.get_mut(&name) {
                    process.restart_count = snapshot.restart_count.saturating_add(1);
                }
            }
        }

        if should_save {
            self.save()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
