use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use crate::process::{DesiredState, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy};

use super::{
    compute_table_view, delete_confirm_layout, esc_menu_layout, format_memory_cell,
    frame_content_line_left, frame_line_with_label, handle_delete_confirm_mouse, handle_menu_mouse,
    handle_table_mouse_selection, log_viewer_content_rows, process_sidebar_layout, progress_bar,
    table_inner_width, visible_len, visible_processes, CreateField, CreateProcessForm,
    DashboardState, DeleteConfirmChoice, DeleteConfirmLayout, EscMenuChoice, EscMenuLayout,
    FlashLevel, FlashMessage, LogSource, LogViewerState, ProcessFilter, ProcessSidebarLayout,
    ProcessSort, TableArea, TableView,
};

mod layout;
mod state;

fn sample_process() -> ManagedProcess {
    ManagedProcess {
        id: 7,
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
        stop_signal: None,
        stop_timeout_secs: 5,
        restart_delay_secs: 0,
        restart_backoff_cap_secs: 0,
        restart_backoff_reset_secs: 0,
        restart_backoff_attempt: 0,
        start_delay_secs: 0,
        watch: false,
        watch_paths: Vec::new(),
        ignore_watch: Vec::new(),
        watch_delay_secs: 0,
        cluster_mode: false,
        cluster_instances: None,
        resource_limits: None,
        cgroup_path: None,
        pid: Some(4242),
        status: ProcessStatus::Running,
        desired_state: DesiredState::Running,
        last_exit_code: None,
        stdout_log: PathBuf::from("stdout.log"),
        stderr_log: PathBuf::from("stderr.log"),
        health_check: None,
        health_status: HealthStatus::Unknown,
        health_failures: 0,
        last_health_check: None,
        next_health_check: None,
        last_health_error: None,
        wait_ready: false,
        ready_timeout_secs: crate::process::default_ready_timeout_secs(),
        cpu_percent: 0.0,
        memory_bytes: 0,
        last_metrics_at: None,
        last_started_at: None,
        last_stopped_at: None,
        config_fingerprint: String::new(),
    }
}
