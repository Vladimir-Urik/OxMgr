use super::*;

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
        .insert("api".to_string(), TokioInstant::now());

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
async fn handle_exit_event_with_zero_delay_restarts_immediately() {
    let mut manager = empty_manager("immediate-crash-restart");
    let mut process = long_running_fixture_process();
    process.pid = Some(9100);
    process.restart_delay_secs = 0;
    manager.processes.insert(process.name.clone(), process);

    manager
        .handle_exit_event(ProcessExitEvent {
            name: "api".to_string(),
            pid: 9100,
            exit_code: Some(1),
            success: false,
            wait_error: false,
        })
        .await
        .expect("zero-delay crash should restart immediately");

    let process = manager
        .processes
        .get("api")
        .expect("process should exist after immediate restart");
    assert_eq!(process.status, ProcessStatus::Running);
    assert_eq!(process.desired_state, DesiredState::Running);
    assert!(
        process.pid.is_some(),
        "expected replacement pid to be recorded"
    );
    assert_ne!(process.pid, Some(9100), "replacement pid should differ");
    assert!(
        !manager.scheduled_restarts.contains_key("api"),
        "zero-delay restart should not queue scheduled restart"
    );

    manager
        .shutdown_all()
        .await
        .expect("shutdown should cleanup immediate restart fixture");
}

#[test]
fn next_scheduled_restart_at_returns_earliest_deadline() {
    let mut manager = empty_manager("next-scheduled-restart");
    manager.scheduled_restarts.insert(
        "later".to_string(),
        TokioInstant::now() + Duration::from_secs(10),
    );
    let earlier = TokioInstant::now() + Duration::from_secs(3);
    manager
        .scheduled_restarts
        .insert("earlier".to_string(), earlier);

    let next = manager
        .next_scheduled_restart_at()
        .expect("expected earliest scheduled restart");
    assert_eq!(next, earlier);
}

#[tokio::test]
async fn crash_loop_limit_stops_fourth_crash_after_three_auto_restarts() {
    let mut manager = empty_manager("crash-loop-limit");
    let mut process = fixture_process();
    process.restart_delay_secs = 1;
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

#[tokio::test]
async fn reload_process_keeps_existing_pid_when_replacement_fails_readiness() {
    let mut manager = empty_manager("reload-ready-fail");
    let fixture = long_running_fixture_process();
    let started = manager
        .start_process(StartProcessSpec {
            command: command_line(&fixture.command, &fixture.args),
            name: Some("api".to_string()),
            pre_reload_cmd: None,
            restart_policy: RestartPolicy::Never,
            max_restarts: 1,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: None,
            stop_signal: fixture.stop_signal.clone(),
            stop_timeout_secs: fixture.stop_timeout_secs,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            watch_paths: Vec::new(),
            ignore_watch: Vec::new(),
            watch_delay_secs: 0,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            reuse_port: false,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
            log_date_format: None,
            cron_restart: None,
        })
        .await
        .expect("initial process should start");

    let old_pid = started.pid.expect("started process should have pid");
    let process = manager
        .processes
        .get_mut("api")
        .expect("process should be stored");
    process.wait_ready = true;
    process.ready_timeout_secs = 1;
    process.health_check = Some(HealthCheck {
        command: failing_readiness_check_command(),
        interval_secs: 1,
        timeout_secs: 1,
        max_failures: 1,
    });
    process.refresh_config_fingerprint();

    let err = manager
        .reload_process("api")
        .await
        .expect_err("reload should fail when replacement never becomes ready");
    assert!(
        err.to_string().contains("did not become ready within"),
        "unexpected reload error: {err}"
    );

    let current = manager
        .processes
        .get("api")
        .expect("old process should remain registered");
    assert_eq!(current.pid, Some(old_pid));
    assert!(process_exists(old_pid), "old pid should still be alive");

    manager
        .shutdown_all()
        .await
        .expect("shutdown should cleanup reload fixture");
}

#[tokio::test]
async fn reload_process_replaces_pid_when_replacement_becomes_ready() {
    let mut manager = empty_manager("reload-ready-ok");
    let fixture = long_running_fixture_process();
    let started = manager
        .start_process(StartProcessSpec {
            command: command_line(&fixture.command, &fixture.args),
            name: Some("api".to_string()),
            pre_reload_cmd: None,
            restart_policy: RestartPolicy::Never,
            max_restarts: 1,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: Some(HealthCheck {
                command: successful_readiness_check_command(),
                interval_secs: 1,
                timeout_secs: 1,
                max_failures: 1,
            }),
            stop_signal: fixture.stop_signal.clone(),
            stop_timeout_secs: 1,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            watch_paths: Vec::new(),
            ignore_watch: Vec::new(),
            watch_delay_secs: 0,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            reuse_port: false,
            wait_ready: true,
            ready_timeout_secs: 2,
            log_date_format: None,
            cron_restart: None,
        })
        .await
        .expect("initial process should start");

    let old_pid = started.pid.expect("started process should have pid");
    let reloaded = manager
        .reload_process("api")
        .await
        .expect("reload should succeed when replacement becomes ready");
    let new_pid = reloaded.pid.expect("reloaded process should have pid");
    assert_ne!(new_pid, old_pid, "reload should swap to a new pid");
    assert!(process_exists(new_pid), "new pid should be alive");
    assert!(
        wait_for_process_exit(old_pid, Duration::from_secs(2)),
        "old pid should terminate after successful reload"
    );

    manager
        .shutdown_all()
        .await
        .expect("shutdown should cleanup reload fixture");
}
