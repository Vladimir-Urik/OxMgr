use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sysinfo::{Pid as SysPid, ProcessesToUpdate, System};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;
#[cfg(windows)]
use tokio::time::timeout as tokio_timeout;
use tracing::{error, info, warn};

use crate::cgroup;
use crate::config::AppConfig;
use crate::errors::OxmgrError;
use crate::logging::{open_log_writers, process_logs, ProcessLogs};
use crate::process::{
    DesiredState, HealthCheck, HealthStatus, ManagedProcess, ProcessExitEvent, ProcessStatus,
    StartProcessSpec,
};
use crate::storage::{load_state, save_state, PersistedState};

pub struct ProcessManager {
    config: AppConfig,
    processes: HashMap<String, ManagedProcess>,
    watch_fingerprints: HashMap<String, u64>,
    scheduled_restarts: HashMap<String, u64>,
    next_id: u64,
    exit_tx: UnboundedSender<ProcessExitEvent>,
    system: System,
}

const CRASH_RESTART_WINDOW_SECS: u64 = 5 * 60;

impl ProcessManager {
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
            processes.insert(process.name.clone(), process);
        }

        Ok(Self {
            config,
            processes,
            watch_fingerprints: HashMap::new(),
            scheduled_restarts: HashMap::new(),
            next_id,
            exit_tx,
            system: System::new_all(),
        })
    }

    pub async fn recover_processes(&mut self) -> Result<()> {
        let stale: Vec<(String, u32, Option<String>, u64)> = self
            .processes
            .values()
            .filter_map(|process| {
                process.pid.map(|pid| {
                    (
                        process.name.clone(),
                        pid,
                        process.stop_signal.clone(),
                        process.stop_timeout_secs,
                    )
                })
            })
            .collect();

        for (name, pid, stop_signal, stop_timeout_secs) in stale {
            if process_exists(pid) {
                warn!("cleaning stale pid {pid} for process {name}");
                let timeout = Duration::from_secs(stop_timeout_secs.max(1));
                let _ = terminate_pid(pid, stop_signal.as_deref(), timeout).await;
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
        }
        self.watch_fingerprints.clear();
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

    pub async fn run_periodic_tasks(&mut self) -> Result<()> {
        self.run_scheduled_restarts().await?;
        self.refresh_resource_metrics();
        self.run_resource_limit_checks().await?;
        self.run_watch_checks().await?;
        self.run_health_checks().await
    }

    pub async fn start_process(&mut self, spec: StartProcessSpec) -> Result<ManagedProcess> {
        let StartProcessSpec {
            command: command_line,
            name,
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
            cluster_mode,
            cluster_instances,
            namespace,
            resource_limits,
            git_repo,
            git_ref,
            pull_secret_hash,
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
            stop_signal,
            stop_timeout_secs: stop_timeout_secs.max(1),
            restart_delay_secs,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs,
            watch,
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
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: Some(now_epoch_secs()),
            last_stopped_at: None,
        };

        if process.start_delay_secs > 0 {
            sleep(Duration::from_secs(process.start_delay_secs)).await;
        }

        let pid = self.spawn_child(&mut process).await?;
        process.pid = Some(pid);
        process.status = ProcessStatus::Running;
        process.next_health_check = process
            .health_check
            .as_ref()
            .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

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
        self.scheduled_restarts.remove(&name);
        self.processes.insert(name, process.clone());
        self.save()?;
        Ok(process)
    }

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
            cleanup_process_cgroup(process);
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
        }

        self.scheduled_restarts.remove(&name);
        self.spawn_existing(&name).await
    }

    pub async fn reload_process(&mut self, target: &str) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;

        let existing = self
            .processes
            .get(&name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()))?;

        if existing.pid.is_none() {
            return self.restart_process(target).await;
        }

        let old_pid = existing.pid.context("missing old pid for reload")?;
        let old_cgroup = existing.cgroup_path.clone();

        let mut replacement = existing.clone();
        let new_pid = self.spawn_child(&mut replacement).await?;
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

    pub fn list_processes(&self) -> Vec<ManagedProcess> {
        let mut list: Vec<ManagedProcess> = self.processes.values().cloned().collect();
        list.sort_by_key(|process| process.id);
        list
    }

    pub fn get_process(&self, target: &str) -> Result<ManagedProcess> {
        let name = self.resolve_target(target)?;
        self.processes
            .get(&name)
            .cloned()
            .ok_or_else(|| OxmgrError::ProcessNotFound(target.to_string()).into())
    }

    pub fn logs_for(&self, target: &str) -> Result<ProcessLogs> {
        let process = self.get_process(target)?;
        Ok(ProcessLogs {
            stdout: process.stdout_log,
            stderr: process.stderr_log,
        })
    }

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
            self.scheduled_restarts
                .insert(process.name.clone(), now.saturating_add(restart_delay));
            self.processes.insert(process.name.clone(), process.clone());
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

        let pid = self.spawn_child(&mut process).await?;
        process.pid = Some(pid);
        process.status = ProcessStatus::Running;
        process.desired_state = DesiredState::Running;
        process.last_started_at = Some(now_epoch_secs());
        process.next_health_check = process
            .health_check
            .as_ref()
            .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

        self.scheduled_restarts.remove(name);
        self.processes.insert(name.to_string(), process.clone());
        self.update_watch_fingerprint(&process);
        self.save()?;
        Ok(process)
    }

    async fn spawn_child(&self, process: &mut ManagedProcess) -> Result<u32> {
        let logs = ProcessLogs {
            stdout: process.stdout_log.clone(),
            stderr: process.stderr_log.clone(),
        };
        let (stdout, stderr) = open_log_writers(&logs, self.config.log_rotation)?;
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
        command
            .args(&spawn.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));

        if let Some(cwd) = &process.cwd {
            command.current_dir(cwd);
        }
        if !process.env.is_empty() {
            command.envs(&process.env);
        }
        if !spawn.extra_env.is_empty() {
            command.envs(&spawn.extra_env);
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
            return;
        }

        let Some(cwd) = process.cwd.as_ref() else {
            self.watch_fingerprints.remove(&process.name);
            return;
        };

        match watch_fingerprint_for_dir(cwd) {
            Ok(fingerprint) => {
                self.watch_fingerprints
                    .insert(process.name.clone(), fingerprint);
            }
            Err(err) => {
                warn!(
                    "failed to initialize watch fingerprint for process {} in {}: {}",
                    process.name,
                    cwd.display(),
                    err
                );
                self.watch_fingerprints.remove(&process.name);
            }
        }
    }

    pub async fn run_scheduled_restarts(&mut self) -> Result<()> {
        let now = now_epoch_secs();
        let mut due: Vec<(String, u64)> = self
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

    fn save(&self) -> Result<()> {
        let mut values: Vec<ManagedProcess> = self.processes.values().cloned().collect();
        values.sort_by_key(|process| process.id);

        let state = PersistedState {
            next_id: self.next_id,
            processes: values,
        };

        save_state(&self.config.state_path, &state)
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
                process.watch
                    && process.status == ProcessStatus::Running
                    && process.pid.is_some()
                    && process.cwd.is_some()
            })
            .map(|process| process.name.clone())
            .collect();

        for name in candidates {
            let Some(snapshot) = self.processes.get(&name).cloned() else {
                continue;
            };
            let Some(cwd) = snapshot.cwd.as_ref() else {
                continue;
            };

            let current_fingerprint = match watch_fingerprint_for_dir(cwd) {
                Ok(value) => value,
                Err(err) => {
                    warn!(
                        "watch scan failed for process {} in {}: {}",
                        name,
                        cwd.display(),
                        err
                    );
                    continue;
                }
            };

            let Some(previous_fingerprint) = self.watch_fingerprints.get(&name).copied() else {
                self.watch_fingerprints
                    .insert(name.clone(), current_fingerprint);
                continue;
            };

            if previous_fingerprint == current_fingerprint {
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

async fn execute_health_check(process: &ManagedProcess, check: &HealthCheck) -> Result<()> {
    let (command, args) = parse_command_line(&check.command)?;

    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(process.cwd.as_ref().unwrap_or(&std::env::current_dir()?))
        .envs(&process.env)
        .spawn()
        .context("failed to spawn health-check command")?;

    match tokio::time::timeout(Duration::from_secs(check.timeout_secs.max(1)), child.wait()).await {
        Ok(wait_result) => {
            let status = wait_result.context("health-check wait failed")?;
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!("health command exited with {:?}", status.code())
            }
        }
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("health command timed out after {}s", check.timeout_secs)
        }
    }
}

fn parse_command_line(command_line: &str) -> Result<(String, Vec<String>)> {
    let tokens = shell_words::split(command_line)
        .map_err(|err| OxmgrError::InvalidCommand(err.to_string()))?;

    if tokens.is_empty() {
        return Err(OxmgrError::InvalidCommand("command cannot be empty".to_string()).into());
    }

    let command = tokens[0].clone();
    let args = tokens[1..].to_vec();
    Ok((command, args))
}

#[derive(Debug, Clone)]
struct SpawnProgram {
    program: String,
    args: Vec<String>,
    extra_env: HashMap<String, String>,
}

fn resolve_spawn_program(process: &ManagedProcess, base_dir: &Path) -> Result<SpawnProgram> {
    if !process.cluster_mode {
        return Ok(SpawnProgram {
            program: process.command.clone(),
            args: process.args.clone(),
            extra_env: HashMap::new(),
        });
    }

    if !is_node_binary(&process.command) {
        anyhow::bail!("cluster mode requires a Node.js command (expected `node <script> ...`)");
    }
    let Some(script) = process.args.first() else {
        anyhow::bail!("cluster mode requires a script argument (expected `node <script> ...`)");
    };
    if script.starts_with('-') {
        anyhow::bail!(
            "cluster mode currently does not support Node runtime flags before script path"
        );
    }

    let bootstrap = ensure_node_cluster_bootstrap(base_dir)?;
    let mut args = Vec::with_capacity(process.args.len() + 2);
    args.push(bootstrap.display().to_string());
    args.push("--".to_string());
    args.extend(process.args.clone());

    let mut extra_env = HashMap::new();
    extra_env.insert(
        "OXMGR_CLUSTER_INSTANCES".to_string(),
        process
            .cluster_instances
            .map(|value| value.to_string())
            .unwrap_or_else(|| "auto".to_string()),
    );

    Ok(SpawnProgram {
        program: process.command.clone(),
        args,
        extra_env,
    })
}

fn ensure_node_cluster_bootstrap(base_dir: &Path) -> Result<PathBuf> {
    let runtime_dir = base_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "failed to create runtime directory {}",
            runtime_dir.display()
        )
    })?;

    let bootstrap_path = runtime_dir.join("node_cluster_bootstrap.cjs");
    fs::write(&bootstrap_path, NODE_CLUSTER_BOOTSTRAP).with_context(|| {
        format!(
            "failed to write node cluster bootstrap at {}",
            bootstrap_path.display()
        )
    })?;
    Ok(bootstrap_path)
}

fn normalize_cluster_instances(value: Option<u32>) -> Option<u32> {
    value.filter(|instances| *instances > 0)
}

fn is_node_binary(command: &str) -> bool {
    let executable = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    matches!(
        executable.as_str(),
        "node" | "node.exe" | "nodejs" | "nodejs.exe"
    )
}

fn validate_process_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(OxmgrError::InvalidProcessName("name cannot be empty".to_string()).into());
    }

    let valid = name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');

    if !valid {
        return Err(OxmgrError::InvalidProcessName(name.to_string()).into());
    }
    Ok(())
}

fn sanitize_name(input: &str) -> String {
    let value: String = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = value.trim_matches('-');
    if trimmed.is_empty() {
        "process".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn watch_fingerprint_for_dir(root: &Path) -> Result<u64> {
    if !root.exists() {
        anyhow::bail!("watch path does not exist: {}", root.display());
    }

    let mut hash = 1469598103934665603_u64;
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut children: Vec<PathBuf> = fs::read_dir(&dir)
            .with_context(|| format!("failed to read watch directory {}", dir.display()))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        children.sort();

        for child in children {
            let relative = child
                .strip_prefix(root)
                .unwrap_or(child.as_path())
                .to_string_lossy();
            hash_bytes(&mut hash, relative.as_bytes());

            let metadata = fs::symlink_metadata(&child)
                .with_context(|| format!("failed to read metadata for {}", child.display()))?;
            let file_type_tag = if metadata.file_type().is_dir() {
                1_u64
            } else if metadata.file_type().is_symlink() {
                2_u64
            } else {
                3_u64
            };
            hash_u64(&mut hash, file_type_tag);
            hash_u64(&mut hash, metadata.len());
            hash_u64(
                &mut hash,
                metadata
                    .modified()
                    .ok()
                    .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                    .map(|value| value.as_secs())
                    .unwrap_or(0),
            );
            hash_u64(
                &mut hash,
                metadata
                    .modified()
                    .ok()
                    .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                    .map(|value| value.subsec_nanos() as u64)
                    .unwrap_or(0),
            );

            if metadata.file_type().is_dir() {
                stack.push(child);
            }
        }
    }

    Ok(hash)
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= *byte as u64;
        *hash = hash.wrapping_mul(1099511628211);
    }
}

fn hash_u64(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_le_bytes());
}

const NODE_CLUSTER_BOOTSTRAP: &str = r#""use strict";
const cluster = require("node:cluster");
const os = require("node:os");
const path = require("node:path");
const process = require("node:process");

function parseDesiredInstances(raw) {
  if (!raw || raw === "auto") return 0;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return parsed;
}

function cpuCount() {
  if (typeof os.availableParallelism === "function") {
    const value = os.availableParallelism();
    if (Number.isFinite(value) && value > 0) return value;
  }
  const cpus = os.cpus();
  return Array.isArray(cpus) && cpus.length > 0 ? cpus.length : 1;
}

const argv = process.argv.slice(2);
if (argv[0] === "--") argv.shift();
const script = argv.shift();

if (!script) {
  console.error("[oxmgr] cluster mode needs a script argument (expected: node <script> ...)");
  process.exit(2);
}

const desired = parseDesiredInstances(process.env.OXMGR_CLUSTER_INSTANCES || "");
const workerCount = desired > 0 ? desired : cpuCount();

cluster.setupPrimary({
  exec: path.resolve(script),
  args: argv
});

let shuttingDown = false;
let nextInstance = 0;

function forkWorker() {
  const env = { NODE_APP_INSTANCE: String(nextInstance) };
  nextInstance += 1;
  return cluster.fork(env);
}

for (let idx = 0; idx < workerCount; idx += 1) {
  forkWorker();
}

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  const workers = Object.values(cluster.workers).filter(Boolean);
  for (const worker of workers) {
    worker.process.kill(signal);
  }
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

cluster.on("exit", (worker) => {
  if (shuttingDown) return;
  if (worker.exitedAfterDisconnect) return;
  forkWorker();
});
"#;

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn maybe_reset_backoff_attempt(process: &mut ManagedProcess) {
    let reset_after = process.restart_backoff_reset_secs;
    if reset_after == 0 {
        return;
    }

    let Some(started_at) = process.last_started_at else {
        return;
    };
    let now = now_epoch_secs();
    if now.saturating_sub(started_at) >= reset_after {
        process.restart_backoff_attempt = 0;
    }
}

fn compute_restart_delay_secs(process: &ManagedProcess) -> u64 {
    let base = process.restart_delay_secs.max(1);
    let exponent = process.restart_backoff_attempt.min(8);
    let exp_multiplier = 1_u64 << exponent;
    let cap = process.restart_backoff_cap_secs.max(base);

    let seed = hash_restart_seed(
        &process.name,
        process.restart_backoff_attempt,
        now_epoch_secs(),
    );
    let jitter = if base > 1 { seed % base } else { seed % 2 };

    base.saturating_mul(exp_multiplier)
        .saturating_add(jitter)
        .min(cap)
}

fn hash_restart_seed(name: &str, attempt: u32, now: u64) -> u64 {
    let mut hash = 1469598103934665603_u64;
    for byte in name.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash ^= attempt as u64;
    hash = hash.wrapping_mul(1099511628211);
    hash ^= now;
    hash
}

fn reset_auto_restart_state(process: &mut ManagedProcess) {
    process.auto_restart_history.clear();
}

fn prune_auto_restart_history(process: &mut ManagedProcess, now: u64) {
    process
        .auto_restart_history
        .retain(|timestamp| now.saturating_sub(*timestamp) < CRASH_RESTART_WINDOW_SECS);
}

fn crash_loop_limit_reached(process: &mut ManagedProcess, now: u64) -> bool {
    prune_auto_restart_history(process, now);
    process.crash_restart_limit > 0
        && process.auto_restart_history.len() >= process.crash_restart_limit as usize
}

fn record_auto_restart(process: &mut ManagedProcess, now: u64) {
    if process.crash_restart_limit == 0 {
        return;
    }
    prune_auto_restart_history(process, now);
    process.auto_restart_history.push(now);
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    match kill(Pid::from_raw(pid as i32), None::<Signal>) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn process_exists(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::Some(&[SysPid::from_u32(pid)]), true);
    system.process(SysPid::from_u32(pid)).is_some()
}

#[cfg(unix)]
async fn terminate_pid(pid: u32, signal_name: Option<&str>, timeout: Duration) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let os_pid = Pid::from_raw(pid as i32);
    let pgid = Pid::from_raw(-(pid as i32));
    let signal = unix_signal_from_name(signal_name).unwrap_or(Signal::SIGTERM);

    let mut delivered = false;
    match kill(pgid, signal) {
        Ok(()) => delivered = true,
        Err(Errno::ESRCH) => {}
        Err(err) => {
            warn!(
                "failed to send {:?} to process group {} for pid {}: {}",
                signal, pgid, pid, err
            );
        }
    }

    if !delivered {
        match kill(os_pid, signal) {
            Ok(()) => {}
            Err(Errno::ESRCH) => return Ok(()),
            Err(err) => {
                return Err(anyhow::anyhow!("failed to send {signal:?} to {pid}: {err}"));
            }
        }
    }

    let graceful_wait = graceful_wait_before_force_kill(signal, timeout);
    let start = Instant::now();
    while start.elapsed() < graceful_wait {
        if !process_exists(pid) {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }

    if process_exists(pid) {
        let _ = kill(pgid, Signal::SIGKILL);
        let _ = kill(os_pid, Signal::SIGKILL);
    }

    Ok(())
}

#[cfg(unix)]
fn graceful_wait_before_force_kill(
    signal: nix::sys::signal::Signal,
    timeout: Duration,
) -> Duration {
    if signal == nix::sys::signal::Signal::SIGTERM {
        timeout.min(Duration::from_secs(15))
    } else {
        timeout
    }
}

#[cfg(unix)]
fn unix_signal_from_name(value: Option<&str>) -> Option<nix::sys::signal::Signal> {
    use nix::sys::signal::Signal;

    let normalized = value?.trim().to_ascii_uppercase();
    let raw = normalized.strip_prefix("SIG").unwrap_or(&normalized);
    match raw {
        "TERM" => Some(Signal::SIGTERM),
        "INT" => Some(Signal::SIGINT),
        "QUIT" => Some(Signal::SIGQUIT),
        "HUP" => Some(Signal::SIGHUP),
        "KILL" => Some(Signal::SIGKILL),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        _ => None,
    }
}

#[cfg(windows)]
async fn terminate_pid(pid: u32, _signal_name: Option<&str>, timeout: Duration) -> Result<()> {
    if !process_exists(pid) {
        return Ok(());
    }

    let taskkill_timeout = timeout.max(Duration::from_secs(2));
    let pid_string = pid.to_string();
    let graceful_status = tokio_timeout(
        taskkill_timeout,
        Command::new("taskkill")
            .args(["/PID", &pid_string, "/T"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await
    .context("taskkill timed out during graceful stop")?
    .context("failed to run taskkill for graceful stop")?;

    if !graceful_status.success() && !process_exists(pid) {
        return Ok(());
    }

    let start = Instant::now();
    while start.elapsed() < timeout {
        if !process_exists(pid) {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }

    if process_exists(pid) {
        let force_status = tokio_timeout(
            taskkill_timeout,
            Command::new("taskkill")
                .args(["/PID", &pid_string, "/T", "/F"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await
        .context("taskkill timed out during forced stop")?
        .context("failed to run taskkill for forced stop")?;
        if !force_status.success() && process_exists(pid) {
            anyhow::bail!("failed to force-kill process {pid} with taskkill");
        }
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
async fn terminate_pid(_pid: u32, _signal_name: Option<&str>, _timeout: Duration) -> Result<()> {
    Ok(())
}

fn cleanup_process_cgroup(process: &mut ManagedProcess) {
    let Some(path) = process.cgroup_path.take() else {
        return;
    };
    if let Err(err) = cgroup::cleanup(&path) {
        warn!(
            "failed to cleanup cgroup for process {}: {}",
            process.name, err
        );
    }
}

#[derive(Debug)]
struct PullOutcome {
    changed: bool,
    restarted_or_reloaded: bool,
    message: String,
}

async fn ensure_repo_checkout(cwd: &Path, repo: &str, git_ref: Option<&str>) -> Result<()> {
    if !cwd.exists() {
        let parent = cwd.parent().context("cwd has no parent directory")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let cwd_text = cwd.to_string_lossy().to_string();
        if let Some(git_ref) = git_ref {
            run_git(
                parent,
                &["clone", "--branch", git_ref, repo, &cwd_text],
                "clone repository",
            )
            .await?;
        } else {
            run_git(parent, &["clone", repo, &cwd_text], "clone repository").await?;
        }
        return Ok(());
    }

    let dot_git = cwd.join(".git");
    if dot_git.exists() {
        return Ok(());
    }

    let mut entries =
        fs::read_dir(cwd).with_context(|| format!("failed to read directory {}", cwd.display()))?;
    if entries.next().is_some() {
        anyhow::bail!(
            "cwd {} exists but is not a git checkout and is not empty",
            cwd.display()
        );
    }

    if let Some(git_ref) = git_ref {
        run_git(
            cwd,
            &["clone", "--branch", git_ref, repo, "."],
            "clone repository into cwd",
        )
        .await
    } else {
        run_git(cwd, &["clone", repo, "."], "clone repository into cwd").await
    }?;
    Ok(())
}

async fn ensure_origin_remote(cwd: &Path, repo: &str) -> Result<()> {
    match run_git(cwd, &["remote", "get-url", "origin"], "read git origin").await {
        Ok(current) => {
            if current.trim() != repo {
                run_git(
                    cwd,
                    &["remote", "set-url", "origin", repo],
                    "set git origin",
                )
                .await?;
            }
        }
        Err(_) => {
            run_git(cwd, &["remote", "add", "origin", repo], "add git origin").await?;
        }
    }
    Ok(())
}

async fn git_rev_parse_head(cwd: &Path) -> Result<String> {
    run_git(cwd, &["rev-parse", "HEAD"], "read current commit")
        .await
        .map(|value| value.trim().to_string())
}

async fn run_git(cwd: &Path, args: &[&str], action: &str) -> Result<String> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .with_context(|| format!("timed out while attempting to {action}"))?
        .with_context(|| format!("failed to start git command to {action}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        anyhow::bail!(
            "git command failed while trying to {} in {}: {}",
            action,
            cwd.display(),
            details
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn short_commit(commit: &str) -> String {
    commit.chars().take(8).collect::<String>()
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{:x}", digest)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command as StdCommand;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::sync::mpsc::unbounded_channel;

    #[cfg(unix)]
    use super::graceful_wait_before_force_kill;
    use super::{
        compute_restart_delay_secs, constant_time_eq, maybe_reset_backoff_attempt, now_epoch_secs,
        resolve_spawn_program, sha256_hex, short_commit, watch_fingerprint_for_dir, ProcessManager,
    };
    use crate::config::AppConfig;
    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, ProcessExitEvent, ProcessStatus, RestartPolicy,
    };

    #[test]
    fn restart_backoff_increases_delay() {
        let mut process = fixture_process();
        process.restart_delay_secs = 2;
        process.restart_backoff_cap_secs = 120;
        process.restart_backoff_attempt = 0;
        let first = compute_restart_delay_secs(&process);

        process.restart_backoff_attempt = 1;
        let second = compute_restart_delay_secs(&process);

        assert!(second >= first);
    }

    #[test]
    fn restart_backoff_resets_after_cooldown() {
        let mut process = fixture_process();
        process.restart_backoff_attempt = 5;
        process.restart_backoff_reset_secs = 10;
        process.last_started_at = Some(now_epoch_secs().saturating_sub(30));

        maybe_reset_backoff_attempt(&mut process);
        assert_eq!(process.restart_backoff_attempt, 0);
    }

    #[test]
    fn restart_backoff_respects_cap() {
        let mut process = fixture_process();
        process.restart_delay_secs = 30;
        process.restart_backoff_cap_secs = 40;
        process.restart_backoff_attempt = 6;

        let delay = compute_restart_delay_secs(&process);
        assert!(delay <= 40, "delay should be capped, got {}", delay);
    }

    #[test]
    fn restart_backoff_does_not_reset_before_cooldown() {
        let mut process = fixture_process();
        process.restart_backoff_attempt = 5;
        process.restart_backoff_reset_secs = 60;
        process.last_started_at = Some(now_epoch_secs().saturating_sub(10));

        maybe_reset_backoff_attempt(&mut process);
        assert_eq!(process.restart_backoff_attempt, 5);
    }

    #[test]
    fn restart_backoff_has_minimum_delay_when_base_is_zero() {
        let mut process = fixture_process();
        process.restart_delay_secs = 0;
        process.restart_backoff_cap_secs = 5;
        process.restart_backoff_attempt = 0;

        let delay = compute_restart_delay_secs(&process);
        assert!(
            delay >= 1,
            "delay should be at least one second, got {}",
            delay
        );
        assert!(delay <= 5, "delay should stay under cap, got {}", delay);
    }

    #[test]
    fn crash_loop_window_drops_old_restart_attempts() {
        let now = now_epoch_secs();
        let mut process = fixture_process();
        process.crash_restart_limit = 3;
        process.auto_restart_history = vec![
            now.saturating_sub(super::CRASH_RESTART_WINDOW_SECS + 1),
            now.saturating_sub(super::CRASH_RESTART_WINDOW_SECS - 1),
        ];

        assert!(!super::crash_loop_limit_reached(&mut process, now));
        assert_eq!(process.auto_restart_history.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_escalates_after_fifteen_seconds_max() {
        let timeout = std::time::Duration::from_secs(30);
        let grace = graceful_wait_before_force_kill(nix::sys::signal::Signal::SIGTERM, timeout);
        assert_eq!(grace, std::time::Duration::from_secs(15));
    }

    #[cfg(unix)]
    #[test]
    fn non_sigterm_respects_full_timeout() {
        let timeout = std::time::Duration::from_secs(10);
        let grace = graceful_wait_before_force_kill(nix::sys::signal::Signal::SIGINT, timeout);
        assert_eq!(grace, timeout);
    }

    #[test]
    fn watch_fingerprint_changes_when_file_changes() {
        let dir = temp_watch_dir("watch-change");
        fs::create_dir_all(&dir).expect("failed to create watch directory");
        let file = dir.join("app.js");
        fs::write(&file, "console.log('a');").expect("failed writing seed file");

        let before = watch_fingerprint_for_dir(&dir).expect("failed to compute first fingerprint");
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(&file, "console.log('b');").expect("failed rewriting watched file");
        let after = watch_fingerprint_for_dir(&dir).expect("failed to compute second fingerprint");

        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn watch_fingerprint_changes_when_new_file_is_added() {
        let dir = temp_watch_dir("watch-add");
        fs::create_dir_all(dir.join("nested")).expect("failed to create nested watch directory");
        fs::write(dir.join("nested/one.txt"), "1").expect("failed writing initial file");

        let before = watch_fingerprint_for_dir(&dir).expect("failed to compute first fingerprint");
        fs::write(dir.join("nested/two.txt"), "2").expect("failed writing new watched file");
        let after = watch_fingerprint_for_dir(&dir).expect("failed to compute second fingerprint");

        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_spawn_program_passthrough_when_cluster_disabled() {
        let process = fixture_process();
        let tmp = std::env::temp_dir();
        let spawn =
            resolve_spawn_program(&process, &tmp).expect("expected passthrough spawn program");
        assert_eq!(spawn.program, "node");
        assert_eq!(spawn.args, vec!["server.js".to_string()]);
        assert!(spawn.extra_env.is_empty());
    }

    #[test]
    fn resolve_spawn_program_rejects_non_node_cluster_mode() {
        let mut process = fixture_process();
        process.command = "python".to_string();
        process.cluster_mode = true;
        process.cluster_instances = Some(4);

        let tmp = std::env::temp_dir();
        let err = resolve_spawn_program(&process, &tmp)
            .expect_err("expected non-node command to fail for cluster mode");
        assert!(
            err.to_string().contains("requires a Node.js command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_spawn_program_builds_bootstrap_for_cluster_mode() {
        let runtime = temp_watch_dir("cluster-runtime");
        let mut process = fixture_process();
        process.cluster_mode = true;
        process.cluster_instances = Some(3);

        let spawn = resolve_spawn_program(&process, &runtime)
            .expect("expected cluster spawn command to be generated");
        assert_eq!(spawn.program, "node");
        assert_eq!(spawn.args[1], "--");
        assert_eq!(spawn.args[2], "server.js");
        assert_eq!(
            spawn
                .extra_env
                .get("OXMGR_CLUSTER_INSTANCES")
                .map(String::as_str),
            Some("3")
        );
        assert!(
            Path::new(&spawn.args[0]).exists(),
            "expected bootstrap script to be written"
        );

        let _ = fs::remove_dir_all(&runtime);
    }

    #[test]
    fn short_commit_truncates_to_eight_chars() {
        assert_eq!(short_commit("0123456789abcdef"), "01234567");
        assert_eq!(short_commit("abcd"), "abcd");
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_eq_handles_equal_and_mismatched_values() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn verify_pull_webhook_secret_accepts_name_and_id_targets() {
        let mut manager = empty_manager("verify-secret-ok");
        let mut process = fixture_process();
        process.id = 42;
        process.name = "api".to_string();
        process.pull_secret_hash = Some(sha256_hex("super-secret-token"));
        manager.processes.insert(process.name.clone(), process);

        assert!(manager
            .verify_pull_webhook_secret("api", "super-secret-token")
            .is_ok());
        assert!(manager
            .verify_pull_webhook_secret("42", "super-secret-token")
            .is_ok());
        assert!(manager
            .verify_pull_webhook_secret("api", "wrong-secret")
            .is_err());
    }

    #[test]
    fn verify_pull_webhook_secret_requires_configured_hash() {
        let mut manager = empty_manager("verify-secret-missing");
        let mut process = fixture_process();
        process.name = "api".to_string();
        process.id = 1;
        process.pull_secret_hash = None;
        manager.processes.insert(process.name.clone(), process);

        let err = manager
            .verify_pull_webhook_secret("api", "anything")
            .expect_err("expected missing pull secret hash to fail");
        assert!(err.to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn pull_processes_errors_without_any_git_services() {
        let mut manager = empty_manager("pull-no-git");
        let err = manager
            .pull_processes(None)
            .await
            .expect_err("expected pull to fail without git-configured services");
        assert!(err
            .to_string()
            .contains("no services configured with git_repo"));
    }

    #[tokio::test]
    async fn pull_processes_reports_unchanged_checkout() {
        let git = setup_git_fixture("pull-unchanged");
        let mut manager = empty_manager("pull-unchanged-manager");
        let mut process = fixture_process();
        process.name = "api".to_string();
        process.id = 7;
        process.cwd = Some(git.clone_dir.clone());
        process.git_repo = Some(git.remote_dir.display().to_string());
        process.git_ref = Some("main".to_string());
        process.pid = None;
        process.status = ProcessStatus::Stopped;
        process.desired_state = DesiredState::Stopped;
        manager.processes.insert(process.name.clone(), process);

        let output = manager
            .pull_processes(Some("api"))
            .await
            .expect("expected pull to succeed");
        assert!(output.contains("0 updated, 1 unchanged"));
        assert!(output.contains("up-to-date"));

        cleanup_git_fixture(git);
    }

    #[tokio::test]
    async fn pull_processes_updates_checkout_when_remote_changes() {
        let git = setup_git_fixture("pull-changed");
        write_commit_and_push(&git.source_dir, "app.js", "console.log('v2');\n", "update");

        let mut manager = empty_manager("pull-changed-manager");
        let mut process = fixture_process();
        process.name = "api".to_string();
        process.id = 8;
        process.cwd = Some(git.clone_dir.clone());
        process.git_repo = Some(git.remote_dir.display().to_string());
        process.git_ref = Some("main".to_string());
        process.pid = None;
        process.status = ProcessStatus::Stopped;
        process.desired_state = DesiredState::Stopped;
        manager.processes.insert(process.name.clone(), process);

        let output = manager
            .pull_processes(Some("api"))
            .await
            .expect("expected pull to succeed");
        assert!(output.contains("1 updated, 0 unchanged"));
        assert!(output.contains("updated (service stopped)"));

        let source_head = git_head(&git.source_dir);
        let clone_head = git_head(&git.clone_dir);
        assert_eq!(source_head, clone_head, "clone should match source head");

        cleanup_git_fixture(git);
    }

    #[tokio::test]
    async fn handle_exit_event_schedules_restart_without_blocking() {
        let mut manager = empty_manager("scheduled-restart-fast");
        let mut process = fixture_process();
        process.pid = Some(7001);
        process.restart_delay_secs = 5;
        manager.processes.insert(process.name.clone(), process);

        let started = std::time::Instant::now();
        manager
            .handle_exit_event(ProcessExitEvent {
                name: "api".to_string(),
                pid: 7001,
                exit_code: Some(1),
                success: false,
                wait_error: false,
            })
            .await
            .expect("exit event should be handled");

        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "exit handling should not block on restart delay"
        );

        let process = manager
            .processes
            .get("api")
            .expect("process should still exist after exit");
        assert_eq!(process.status, ProcessStatus::Restarting);
        assert_eq!(process.restart_count, 1);
        assert!(manager.scheduled_restarts.contains_key("api"));
    }

    #[tokio::test]
    async fn scheduled_restart_spawns_due_process() {
        let mut manager = empty_manager("scheduled-restart-run");
        let mut process = spawnable_fixture_process();
        process.pid = None;
        process.status = ProcessStatus::Restarting;
        manager.processes.insert(process.name.clone(), process);
        manager
            .scheduled_restarts
            .insert("api".to_string(), now_epoch_secs().saturating_sub(1));

        manager
            .run_scheduled_restarts()
            .await
            .expect("due restart should be processed");

        let process = manager
            .processes
            .get("api")
            .expect("process should still exist after restart");
        assert_eq!(process.status, ProcessStatus::Running);
        assert!(
            process.pid.is_some(),
            "scheduled restart should spawn a child"
        );
        assert!(
            !manager.scheduled_restarts.contains_key("api"),
            "due restart should be cleared after spawn"
        );
    }

    #[tokio::test]
    async fn crash_loop_limit_stops_fourth_crash_after_three_auto_restarts() {
        let mut manager = empty_manager("crash-loop-limit");
        let mut process = fixture_process();
        process.restart_delay_secs = 0;
        process.crash_restart_limit = 3;
        process.pid = Some(8100);
        manager.processes.insert(process.name.clone(), process);

        let mut pid = 8100_u32;
        for expected_history_len in 1..=3 {
            manager
                .handle_exit_event(ProcessExitEvent {
                    name: "api".to_string(),
                    pid,
                    exit_code: Some(1),
                    success: false,
                    wait_error: false,
                })
                .await
                .expect("crash should schedule auto restart");

            let process = manager
                .processes
                .get("api")
                .expect("process should still exist after crash");
            assert_eq!(process.status, ProcessStatus::Restarting);
            assert_eq!(process.auto_restart_history.len(), expected_history_len);

            manager.scheduled_restarts.remove("api");
            pid = pid.saturating_add(1);
            if let Some(process) = manager.processes.get_mut("api") {
                process.pid = Some(pid);
                process.status = ProcessStatus::Running;
                process.desired_state = DesiredState::Running;
                process.last_started_at = Some(now_epoch_secs());
            }
        }

        manager
            .handle_exit_event(ProcessExitEvent {
                name: "api".to_string(),
                pid,
                exit_code: Some(1),
                success: false,
                wait_error: false,
            })
            .await
            .expect("fourth crash should be handled");

        let process = manager
            .processes
            .get("api")
            .expect("process should still exist after crash loop cutoff");
        assert_eq!(process.status, ProcessStatus::Errored);
        assert_eq!(process.desired_state, DesiredState::Stopped);
        assert!(
            process
                .last_health_error
                .as_deref()
                .unwrap_or_default()
                .contains("crash loop detected"),
            "expected crash loop message, got {:?}",
            process.last_health_error
        );
        assert!(
            !manager.scheduled_restarts.contains_key("api"),
            "crash loop cutoff should cancel pending restart"
        );
    }

    #[tokio::test]
    async fn manual_restart_clears_auto_restart_history() {
        let mut manager = empty_manager("manual-restart-clears-loop");
        let mut process = spawnable_fixture_process();
        process.pid = None;
        process.status = ProcessStatus::Stopped;
        process.desired_state = DesiredState::Stopped;
        process.auto_restart_history = vec![
            now_epoch_secs().saturating_sub(20),
            now_epoch_secs().saturating_sub(10),
        ];
        manager.processes.insert(process.name.clone(), process);

        let restarted = manager
            .restart_process("api")
            .await
            .expect("manual restart should succeed");

        assert_eq!(restarted.status, ProcessStatus::Running);
        let process = manager
            .processes
            .get("api")
            .expect("process should still exist after manual restart");
        assert!(
            process.auto_restart_history.is_empty(),
            "manual restart must clear crash-loop history"
        );
    }

    fn fixture_process() -> ManagedProcess {
        ManagedProcess {
            id: 1,
            name: "api".to_string(),
            command: "node".to_string(),
            args: vec!["server.js".to_string()],
            cwd: None,
            env: HashMap::new(),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            restart_count: 0,
            crash_restart_limit: 3,
            auto_restart_history: Vec::new(),
            namespace: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 1,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs: 0,
            watch: false,
            cluster_mode: false,
            cluster_instances: None,
            resource_limits: None,
            cgroup_path: None,
            pid: Some(1234),
            status: ProcessStatus::Running,
            desired_state: DesiredState::Running,
            last_exit_code: None,
            stdout_log: PathBuf::from("/tmp/out.log"),
            stderr_log: PathBuf::from("/tmp/err.log"),
            health_check: None,
            health_status: HealthStatus::Unknown,
            health_failures: 0,
            last_health_check: None,
            next_health_check: None,
            last_health_error: None,
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: Some(now_epoch_secs()),
            last_stopped_at: None,
        }
    }

    fn spawnable_fixture_process() -> ManagedProcess {
        let mut process = fixture_process();
        process.command = std::env::current_exe()
            .expect("failed to resolve current test executable")
            .display()
            .to_string();
        process.args = vec!["--help".to_string()];
        process
    }

    fn empty_manager(prefix: &str) -> ProcessManager {
        let config = test_config(prefix);
        let (exit_tx, _exit_rx) = unbounded_channel();
        ProcessManager::new(config, exit_tx).expect("failed to create test process manager")
    }

    fn test_config(prefix: &str) -> AppConfig {
        let base = temp_watch_dir(prefix);
        let log_dir = base.join("logs");
        fs::create_dir_all(&log_dir).expect("failed to create test log directory");
        AppConfig {
            base_dir: base.clone(),
            daemon_addr: "127.0.0.1:50100".to_string(),
            api_addr: "127.0.0.1:51100".to_string(),
            state_path: base.join("state.json"),
            log_dir,
            log_rotation: crate::logging::LogRotationPolicy {
                max_size_bytes: 1024 * 1024,
                max_files: 2,
                max_age_days: 1,
            },
        }
    }

    struct GitFixture {
        root: PathBuf,
        remote_dir: PathBuf,
        source_dir: PathBuf,
        clone_dir: PathBuf,
    }

    fn setup_git_fixture(prefix: &str) -> GitFixture {
        let root = temp_watch_dir(prefix);
        let remote_dir = root.join("remote.git");
        let source_dir = root.join("source");
        let clone_dir = root.join("clone");

        fs::create_dir_all(&root).expect("failed to create git fixture root");
        fs::create_dir_all(&source_dir).expect("failed to create git source dir");
        run_git_sync(
            &root,
            &["init", "--bare", remote_dir.to_str().unwrap_or_default()],
        );
        run_git_sync(&source_dir, &["init"]);
        run_git_sync(&source_dir, &["config", "user.email", "tests@oxmgr.local"]);
        run_git_sync(&source_dir, &["config", "user.name", "Oxmgr Tests"]);
        fs::write(source_dir.join("app.js"), "console.log('v1');\n")
            .expect("failed to write initial source file");
        run_git_sync(&source_dir, &["add", "."]);
        run_git_sync(&source_dir, &["commit", "-m", "initial"]);
        run_git_sync(&source_dir, &["branch", "-M", "main"]);
        run_git_sync(
            &source_dir,
            &[
                "remote",
                "add",
                "origin",
                remote_dir.to_str().unwrap_or_default(),
            ],
        );
        run_git_sync(&source_dir, &["push", "-u", "origin", "main"]);
        run_git_sync(
            &root,
            &[
                "clone",
                remote_dir.to_str().unwrap_or_default(),
                clone_dir.to_str().unwrap_or_default(),
            ],
        );
        run_git_sync(&clone_dir, &["checkout", "main"]);

        GitFixture {
            root,
            remote_dir,
            source_dir,
            clone_dir,
        }
    }

    fn write_commit_and_push(source_dir: &Path, file_name: &str, content: &str, message: &str) {
        fs::write(source_dir.join(file_name), content).expect("failed writing updated source file");
        run_git_sync(source_dir, &["add", "."]);
        run_git_sync(source_dir, &["commit", "-m", message]);
        run_git_sync(source_dir, &["push", "origin", "main"]);
    }

    fn git_head(repo_dir: &Path) -> String {
        let output = StdCommand::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .current_dir(repo_dir)
            .output()
            .expect("failed running git rev-parse");
        assert!(
            output.status.success(),
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn run_git_sync(cwd: &Path, args: &[&str]) {
        let output = StdCommand::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("failed to launch git in test");
        assert!(
            output.status.success(),
            "git {:?} failed in {}: {}",
            args,
            cwd.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn cleanup_git_fixture(fixture: GitFixture) {
        let _ = fs::remove_dir_all(fixture.root);
    }

    fn temp_watch_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("oxmgr-{prefix}-{nonce}"))
    }
}
