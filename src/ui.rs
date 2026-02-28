//! Terminal styling helpers shared by list, status, and TUI rendering code.

use std::io::{self, IsTerminal};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::process::{HealthStatus, ProcessStatus};

fn colors_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }

        if std::env::var("TERM")
            .map(|term| term.eq_ignore_ascii_case("dumb"))
            .unwrap_or(false)
        {
            return false;
        }

        io::stdout().is_terminal()
    })
}

fn paint(value: &str, code: &str) -> String {
    if colors_enabled() {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

/// Styles a general UI label.
pub fn label(value: &str) -> String {
    paint(value, "1;36")
}

/// Styles a table header cell.
pub fn table_header(value: &str) -> String {
    paint(value, "1;36")
}

/// Styles a table border or separator fragment.
pub fn table_border(value: &str) -> String {
    paint(value, "2;34")
}

/// Renders a coloured process-status value for terminal output.
pub fn status_value(status: &ProcessStatus) -> String {
    let value = status.to_string();
    style_status_text(&value)
}

/// Renders a coloured health-status value for terminal output.
pub fn health_value(health: &HealthStatus) -> String {
    let value = health.to_string();
    style_health_text(&value)
}

/// Applies status-specific colouring to a pre-padded table cell.
pub fn style_status_cell(padded: &str, raw_status: &str) -> String {
    match raw_status {
        "running" => paint(padded, "1;32"),
        "restarting" => paint(padded, "1;33"),
        "stopped" => paint(padded, "2;37"),
        "crashed" | "errored" => paint(padded, "1;31"),
        _ => padded.to_string(),
    }
}

/// Applies health-specific colouring to a pre-padded table cell.
pub fn style_health_cell(padded: &str, raw_health: &str) -> String {
    match raw_health {
        "healthy" => paint(padded, "1;32"),
        "unknown" => paint(padded, "1;33"),
        "unhealthy" => paint(padded, "1;31"),
        _ => padded.to_string(),
    }
}

/// Formats the current uptime for a running process in a compact, human-readable
/// form.
pub fn format_process_uptime(status: &ProcessStatus, started_at: Option<u64>) -> String {
    if !matches!(status, ProcessStatus::Running | ProcessStatus::Restarting) {
        return "-".to_string();
    }

    let Some(started_at) = started_at else {
        return "-".to_string();
    };

    let now = now_epoch_secs();
    format_duration_compact(now.saturating_sub(started_at))
}

fn style_status_text(value: &str) -> String {
    match value {
        "running" => paint(value, "1;32"),
        "restarting" => paint(value, "1;33"),
        "stopped" => paint(value, "2;37"),
        "crashed" | "errored" => paint(value, "1;31"),
        _ => value.to_string(),
    }
}

fn style_health_text(value: &str) -> String {
    match value {
        "healthy" => paint(value, "1;32"),
        "unknown" => paint(value, "1;33"),
        "unhealthy" => paint(value, "1;31"),
        _ => value.to_string(),
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn format_duration_compact(total_secs: u64) -> String {
    let days = total_secs / 86_400;
    let hours = (total_secs % 86_400) / 3_600;
    let mins = (total_secs % 3_600) / 60;
    let secs = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::format_process_uptime;
    use crate::process::ProcessStatus;

    #[test]
    fn uptime_is_dash_for_non_running_process() {
        let uptime = format_process_uptime(&ProcessStatus::Stopped, Some(100));
        assert_eq!(uptime, "-");
    }

    #[test]
    fn uptime_formats_seconds_for_short_runtime() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock failure")
            .as_secs();
        let uptime = format_process_uptime(&ProcessStatus::Running, Some(now.saturating_sub(42)));
        assert!(uptime.ends_with('s'));
    }
}
