use super::*;

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
fn zero_restart_delay_disables_hidden_backoff() {
    let mut process = fixture_process();
    process.restart_delay_secs = 0;
    process.restart_backoff_cap_secs = 300;
    process.restart_backoff_attempt = 6;

    let delay = compute_restart_delay_secs(&process);
    assert_eq!(delay, 0, "zero restart delay should restart immediately");
}

#[test]
fn crash_loop_window_drops_old_restart_attempts() {
    let now = now_epoch_secs();
    let mut process = fixture_process();
    process.crash_restart_limit = 3;
    process.auto_restart_history = vec![
        now.saturating_sub(CRASH_RESTART_WINDOW_SECS + 1),
        now.saturating_sub(CRASH_RESTART_WINDOW_SECS - 1),
    ];

    assert!(!crash_loop_limit_reached(&mut process, now));
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
