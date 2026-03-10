use super::*;

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
fn watch_fingerprint_ignores_matching_paths() {
    let dir = temp_watch_dir("watch-ignore");
    fs::create_dir_all(dir.join("src")).expect("failed to create src dir");
    fs::create_dir_all(dir.join("node_modules")).expect("failed to create node_modules dir");
    fs::write(dir.join("src/app.js"), "console.log('a');").expect("failed writing watched file");
    fs::write(dir.join("node_modules/lib.js"), "console.log('ignored-a');")
        .expect("failed writing ignored file");

    let before = watch_fingerprint_for_roots(
        std::slice::from_ref(&dir),
        &dir,
        &["node_modules".to_string()],
    )
    .expect("failed to compute fingerprint");

    std::thread::sleep(std::time::Duration::from_millis(5));
    fs::write(dir.join("node_modules/lib.js"), "console.log('ignored-b');")
        .expect("failed rewriting ignored file");
    let after_ignored = watch_fingerprint_for_roots(
        std::slice::from_ref(&dir),
        &dir,
        &["node_modules".to_string()],
    )
    .expect("failed to compute fingerprint after ignored change");
    assert_eq!(before, after_ignored);

    std::thread::sleep(std::time::Duration::from_millis(5));
    fs::write(dir.join("src/app.js"), "console.log('b');").expect("failed rewriting watched file");
    let after_watched = watch_fingerprint_for_roots(
        std::slice::from_ref(&dir),
        &dir,
        &["node_modules".to_string()],
    )
    .expect("failed to compute fingerprint after watched change");
    assert_ne!(before, after_watched);

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn watch_delay_schedules_restart_until_due() {
    let mut manager = empty_manager("watch-delay");
    let watch_root = temp_watch_dir("watch-delay-root");
    let src_dir = watch_root.join("src");
    fs::create_dir_all(&src_dir).expect("failed to create watch source dir");
    let watched_file = src_dir.join("app.js");
    fs::write(&watched_file, "console.log('a');").expect("failed to write watched file");

    let fixture = long_running_fixture_process();
    let started = manager
        .start_process(StartProcessSpec {
            command: command_line(&fixture.command, &fixture.args),
            name: Some("api".to_string()),
            pre_reload_cmd: None,
            restart_policy: RestartPolicy::Never,
            max_restarts: 1,
            crash_restart_limit: 3,
            cwd: Some(watch_root.clone()),
            env: HashMap::new(),
            health_check: None,
            stop_signal: fixture.stop_signal.clone(),
            stop_timeout_secs: 1,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: true,
            watch_paths: vec![PathBuf::from("src")],
            ignore_watch: Vec::new(),
            watch_delay_secs: 1,
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
        })
        .await
        .expect("initial process should start");

    let old_pid = started.pid.expect("started process should have pid");
    std::thread::sleep(Duration::from_millis(5));
    fs::write(&watched_file, "console.log('b');").expect("failed to rewrite watched file");

    manager
        .run_watch_checks()
        .await
        .expect("watch check should schedule delayed restart");
    assert!(
        manager.pending_watch_restarts.contains_key("api"),
        "watch change should schedule delayed restart"
    );
    assert_eq!(
        manager.processes.get("api").and_then(|process| process.pid),
        Some(old_pid),
        "process should keep old pid until delay elapses"
    );

    if let Some(pending) = manager.pending_watch_restarts.get_mut("api") {
        pending.due_at = TokioInstant::now();
    } else {
        panic!("pending watch restart missing");
    }

    manager
        .run_due_watch_restarts()
        .await
        .expect("due watch restart should be processed");

    let current = manager
        .processes
        .get("api")
        .expect("process should still exist after watch restart");
    let new_pid = current
        .pid
        .expect("watch restart should spawn replacement pid");
    assert_ne!(new_pid, old_pid, "watch restart should replace the pid");
    assert_eq!(current.restart_count, 1);
    assert_eq!(
        current.last_health_error.as_deref(),
        Some("watch-triggered restart")
    );
    assert!(
        !manager.pending_watch_restarts.contains_key("api"),
        "pending watch restart should be cleared once processed"
    );

    manager
        .shutdown_all()
        .await
        .expect("shutdown should cleanup watch-delay fixture");
    let _ = fs::remove_dir_all(&watch_root);
}
