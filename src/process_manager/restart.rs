use std::time::{SystemTime, UNIX_EPOCH};

use crate::process::ManagedProcess;

pub(super) const CRASH_RESTART_WINDOW_SECS: u64 = 5 * 60;

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
