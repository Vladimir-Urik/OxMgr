use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
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
    next_id: u64,
    exit_tx: UnboundedSender<ProcessExitEvent>,
    system: System,
}

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
        self.refresh_resource_metrics();
        self.run_resource_limit_checks().await?;
        self.run_health_checks().await
    }

    pub async fn start_process(&mut self, spec: StartProcessSpec) -> Result<ManagedProcess> {
        let StartProcessSpec {
            command: command_line,
            name,
            restart_policy,
            max_restarts,
            cwd,
            env,
            health_check,
            stop_signal,
            stop_timeout_secs,
            restart_delay_secs,
            start_delay_secs,
            namespace,
            resource_limits,
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
            namespace,
            stop_signal,
            stop_timeout_secs: stop_timeout_secs.max(1),
            restart_delay_secs,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs,
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
            }
            process.restart_backoff_attempt = 0;
            process.last_exit_code = None;
            process.desired_state = DesiredState::Running;
            process.status = ProcessStatus::Restarting;
            process.pid = None;
            cleanup_process_cgroup(process);
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
        }

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
        replacement.next_health_check = replacement
            .health_check
            .as_ref()
            .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));

        self.processes.insert(name.clone(), replacement.clone());
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
        self.save()?;
        Ok(removed)
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
        cleanup_process_cgroup(&mut process);
        process.cpu_percent = 0.0;
        process.memory_bytes = 0;
        process.last_exit_code = event.exit_code;
        process.last_stopped_at = Some(now_epoch_secs());

        if process.desired_state == DesiredState::Stopped {
            process.status = ProcessStatus::Stopped;
            process.restart_backoff_attempt = 0;
            process.health_status = HealthStatus::Unknown;
            process.next_health_check = None;
            self.processes.insert(process.name.clone(), process);
            self.save()?;
            return Ok(());
        }

        let exited_successfully = event.success && !event.wait_error;
        let can_restart = !event.wait_error
            && process.restart_policy.should_restart(exited_successfully)
            && process.restart_count < process.max_restarts;

        if can_restart {
            maybe_reset_backoff_attempt(&mut process);
            let restart_delay = compute_restart_delay_secs(&process);
            process.status = ProcessStatus::Restarting;
            process.restart_count = process.restart_count.saturating_add(1);
            process.restart_backoff_attempt = process.restart_backoff_attempt.saturating_add(1);
            process.health_status = HealthStatus::Unknown;
            process.health_failures = 0;
            process.next_health_check = process
                .health_check
                .as_ref()
                .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
            self.processes.insert(process.name.clone(), process.clone());
            self.save()?;

            if restart_delay > 0 {
                sleep(Duration::from_secs(restart_delay)).await;
            }
            if let Err(err) = self.spawn_existing(&process.name).await {
                error!("failed to restart process {}: {err}", process.name);
                if let Some(p) = self.processes.get_mut(&process.name) {
                    p.status = ProcessStatus::Errored;
                }
                self.save()?;
            }
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

        self.processes.insert(name.to_string(), process.clone());
        self.save()?;
        Ok(process)
    }

    async fn spawn_child(&self, process: &mut ManagedProcess) -> Result<u32> {
        let logs = ProcessLogs {
            stdout: process.stdout_log.clone(),
            stderr: process.stderr_log.clone(),
        };
        let (stdout, stderr) = open_log_writers(&logs, self.config.log_rotation)?;

        let mut command = Command::new(&process.command);
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
            .args(&process.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));

        if let Some(cwd) = &process.cwd {
            command.current_dir(cwd);
        }
        if !process.env.is_empty() {
            command.envs(&process.env);
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

    let start = Instant::now();
    while start.elapsed() < timeout {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::{compute_restart_delay_secs, maybe_reset_backoff_attempt, now_epoch_secs};
    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy,
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
            namespace: None,
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 1,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs: 0,
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
}
