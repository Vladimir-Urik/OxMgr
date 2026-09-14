use std::time::{SystemTime, UNIX_EPOCH};

use crate::process::{DesiredState, HealthStatus, ManagedProcess, ProcessExitEvent, ProcessStatus};

pub(super) const CRASH_RESTART_WINDOW_SECS: u64 = 5 * 60;

/// Returns `true` when an exit event belongs to the pid currently tracked for
/// the process, filtering out stale notifications from earlier generations.
pub(super) fn exit_event_matches_process(
    process: &ManagedProcess,
    event: &ProcessExitEvent,
) -> bool {
    match process.pid {
        Some(active_pid) => active_pid == event.pid,
        // No tracked pid: only trust the event if the process is not expected
        // to be running, otherwise a newer spawn is already in flight.
        None => process.desired_state != DesiredState::Running,
    }
}

/// Returns `true` when restart policy and restart budget both allow another
/// automatic restart for this exit.
pub(super) fn can_auto_restart(
    process: &ManagedProcess,
    event: &ProcessExitEvent,
    exited_successfully: bool,
) -> bool {
    !event.wait_error
        && process.restart_policy.should_restart(exited_successfully)
        && process.restart_count < process.max_restarts
}

/// Clears health tracking so a stopped or exited process reports no stale
/// health verdict.
pub(super) fn clear_health_state(process: &mut ManagedProcess) {
    process.health_status = HealthStatus::Unknown;
    process.health_failures = 0;
    process.next_health_check = None;
}

/// Moves a process into the restarting state and reschedules its health check.
pub(super) fn mark_restarting(process: &mut ManagedProcess) {
    process.status = ProcessStatus::Restarting;
    process.restart_count = process.restart_count.saturating_add(1);
    process.restart_backoff_attempt = process.restart_backoff_attempt.saturating_add(1);
    process.health_status = HealthStatus::Unknown;
    process.health_failures = 0;
    process.next_health_check = process
        .health_check
        .as_ref()
        .map(|check| now_epoch_secs().saturating_add(check.interval_secs.max(1)));
}

/// Maps an exit event to the terminal status of a process that will not be
/// restarted.
pub(super) fn terminal_exit_status(
    event: &ProcessExitEvent,
    exited_successfully: bool,
) -> ProcessStatus {
    if event.wait_error {
        ProcessStatus::Errored
    } else if exited_successfully {
        ProcessStatus::Stopped
    } else {
        ProcessStatus::Crashed
    }
}

pub(super) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(super) fn maybe_reset_backoff_attempt(process: &mut ManagedProcess) {
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

pub(super) fn compute_restart_delay_secs(process: &ManagedProcess) -> u64 {
    let base = process.restart_delay_secs;
    if base == 0 {
        return 0;
    }
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

pub(super) fn reset_auto_restart_state(process: &mut ManagedProcess) {
    process.auto_restart_history.clear();
}

fn prune_auto_restart_history(process: &mut ManagedProcess, now: u64) {
    process
        .auto_restart_history
        .retain(|timestamp| now.saturating_sub(*timestamp) < CRASH_RESTART_WINDOW_SECS);
}

pub(super) fn crash_loop_limit_reached(process: &mut ManagedProcess, now: u64) -> bool {
    prune_auto_restart_history(process, now);
    process.crash_restart_limit > 0
        && process.auto_restart_history.len() >= process.crash_restart_limit as usize
}

pub(super) fn record_auto_restart(process: &mut ManagedProcess, now: u64) {
    if process.crash_restart_limit == 0 {
        return;
    }
    prune_auto_restart_history(process, now);
    process.auto_restart_history.push(now);
}
