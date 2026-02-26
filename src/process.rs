use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            RestartPolicy::Always => "always",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::Never => "never",
        };
        write!(f, "{value}")
    }
}

impl RestartPolicy {
    pub fn should_restart(&self, exited_successfully: bool) -> bool {
        match self {
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => !exited_successfully,
            RestartPolicy::Never => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    Running,
    Stopped,
    Crashed,
    Restarting,
    Errored,
}

impl std::fmt::Display for ProcessStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            ProcessStatus::Running => "running",
            ProcessStatus::Stopped => "stopped",
            ProcessStatus::Crashed => "crashed",
            ProcessStatus::Restarting => "restarting",
            ProcessStatus::Errored => "errored",
        };
        write!(f, "{value}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HealthStatus {
    #[default]
    Unknown,
    Healthy,
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            HealthStatus::Unknown => "unknown",
            HealthStatus::Healthy => "healthy",
            HealthStatus::Unhealthy => "unhealthy",
        };
        write!(f, "{value}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthCheck {
    pub command: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub max_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ResourceLimits {
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    #[serde(default)]
    pub max_cpu_percent: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartProcessSpec {
    pub command: String,
    pub name: Option<String>,
    pub restart_policy: RestartPolicy,
    pub max_restarts: u32,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
    #[serde(default)]
    pub stop_signal: Option<String>,
    pub stop_timeout_secs: u64,
    pub restart_delay_secs: u64,
    pub start_delay_secs: u64,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub resource_limits: Option<ResourceLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedProcess {
    pub id: u64,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub restart_policy: RestartPolicy,
    pub max_restarts: u32,
    pub restart_count: u32,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub stop_signal: Option<String>,
    #[serde(default = "default_stop_timeout_secs")]
    pub stop_timeout_secs: u64,
    #[serde(default)]
    pub restart_delay_secs: u64,
    #[serde(default)]
    pub restart_backoff_cap_secs: u64,
    #[serde(default)]
    pub restart_backoff_reset_secs: u64,
    #[serde(default)]
    pub restart_backoff_attempt: u32,
    #[serde(default)]
    pub start_delay_secs: u64,
    #[serde(default)]
    pub resource_limits: Option<ResourceLimits>,
    pub pid: Option<u32>,
    pub status: ProcessStatus,
    pub desired_state: DesiredState,
    pub last_exit_code: Option<i32>,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
    #[serde(default)]
    pub health_status: HealthStatus,
    #[serde(default)]
    pub health_failures: u32,
    #[serde(default)]
    pub last_health_check: Option<u64>,
    #[serde(default)]
    pub next_health_check: Option<u64>,
    #[serde(default)]
    pub last_health_error: Option<String>,
    #[serde(default)]
    pub cpu_percent: f32,
    #[serde(default)]
    pub memory_bytes: u64,
    #[serde(default)]
    pub last_metrics_at: Option<u64>,
    #[serde(default)]
    pub last_started_at: Option<u64>,
    #[serde(default)]
    pub last_stopped_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExitEvent {
    pub name: String,
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub wait_error: bool,
}

impl ManagedProcess {
    pub fn target_label(&self) -> String {
        format!("{} ({})", self.name, self.id)
    }
}

fn default_stop_timeout_secs() -> u64 {
    5
}

#[cfg(test)]
mod tests {
    use super::RestartPolicy;

    #[test]
    fn restart_policy_always_restarts_on_success_and_failure() {
        assert!(RestartPolicy::Always.should_restart(true));
        assert!(RestartPolicy::Always.should_restart(false));
    }

    #[test]
    fn restart_policy_on_failure_only_restarts_failed_processes() {
        assert!(!RestartPolicy::OnFailure.should_restart(true));
        assert!(RestartPolicy::OnFailure.should_restart(false));
    }

    #[test]
    fn restart_policy_never_does_not_restart() {
        assert!(!RestartPolicy::Never.should_restart(true));
        assert!(!RestartPolicy::Never.should_restart(false));
    }
}
