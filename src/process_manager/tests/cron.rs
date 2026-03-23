use super::*;

#[test]
fn cron_next_restart_daily_at_2am() {
    // Test cron expression with seconds "0 0 2 * * *" (2 AM every day)
    let cron_expr = "0 0 2 * * *";

    // Use a recent timestamp
    let base_time = crate::process_manager::now_epoch_secs();

    let result = crate::process_manager::calculate_next_cron_restart(cron_expr, Some(base_time));
    assert!(result.is_ok(), "cron expression should be valid: {:?}", result);

    let next_restart = result.unwrap();
    // Next restart should be in the future
    assert!(
        next_restart > base_time,
        "next restart should be in the future (next_restart={}, now={})",
        next_restart,
        base_time
    );
}

#[test]
fn cron_next_restart_every_6_hours() {
    // Test cron expression with seconds "0 0 */6 * * *" (every 6 hours: 00:00, 06:00, 12:00, 18:00)
    let cron_expr = "0 0 */6 * * *";
    let base_time = crate::process_manager::now_epoch_secs();

    let result = crate::process_manager::calculate_next_cron_restart(cron_expr, Some(base_time));
    assert!(result.is_ok(), "cron expression should be valid: {:?}", result);

    let next_restart = result.unwrap();
    // Next restart should be in the future
    assert!(
        next_restart > base_time,
        "next restart should be in the future"
    );
}

#[test]
fn cron_invalid_expression_fails() {
    let invalid_cron = "this is not valid at all";
    let result = crate::process_manager::calculate_next_cron_restart(invalid_cron, None);

    assert!(result.is_err(), "invalid cron should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid cron expression"),
        "error should mention invalid cron, got: {err_msg}"
    );
}

#[test]
fn cron_expression_hourly() {
    // Test cron expression with seconds "0 * * * * *" (every hour on the hour)
    let cron_expr = "0 * * * * *";
    let base_time = crate::process_manager::now_epoch_secs();

    let result = crate::process_manager::calculate_next_cron_restart(cron_expr, Some(base_time));
    assert!(result.is_ok(), "cron expression should be valid: {:?}", result);

    let next_restart = result.unwrap();
    // Next restart should be in the future
    assert!(
        next_restart > base_time,
        "next restart should be in the future"
    );
    // Should be within 1 hour (3600 seconds)
    assert!(
        next_restart <= base_time + 3600,
        "next restart should be within 1 hour"
    );
}

#[test]
fn cron_process_initialization_with_valid_schedule() {
    let mut process = fixture_process();
    process.cron_restart = Some("0 0 */6 * * *".to_string());

    // When a process is created with cron_restart, next_cron_restart should be calculated
    if let Some(cron_expr) = &process.cron_restart {
        let result = crate::process_manager::calculate_next_cron_restart(
            cron_expr,
            Some(crate::process_manager::now_epoch_secs()),
        );
        assert!(result.is_ok(), "should calculate next restart time");
        process.next_cron_restart = result.ok();
    }

    assert!(
        process.next_cron_restart.is_some(),
        "next_cron_restart should be initialized"
    );
}

#[test]
fn cron_process_without_schedule() {
    let process = fixture_process();
    assert!(
        process.cron_restart.is_none(),
        "fixture process should not have cron_restart"
    );
    assert!(
        process.next_cron_restart.is_none(),
        "fixture process should not have next_cron_restart"
    );
}
