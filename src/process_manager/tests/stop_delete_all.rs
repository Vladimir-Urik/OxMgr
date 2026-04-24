use super::*;

#[tokio::test]
async fn stop_all_stops_every_process() {
    let mut manager = empty_manager("stop-all-basic");
    let mut p1 = fixture_process();
    p1.name = "web".to_string();
    p1.pid = None;
    p1.status = ProcessStatus::Running;
    p1.desired_state = DesiredState::Running;

    let mut p2 = fixture_process();
    p2.name = "worker".to_string();
    p2.pid = None;
    p2.status = ProcessStatus::Running;
    p2.desired_state = DesiredState::Running;

    manager.processes.insert(p1.name.clone(), p1);
    manager.processes.insert(p2.name.clone(), p2);

    let stopped = manager
        .stop_all_processes()
        .await
        .expect("stop_all should succeed");

    assert_eq!(stopped.len(), 2, "both processes should be returned");

    for name in &["web", "worker"] {
        let process = manager
            .processes
            .get(*name)
            .expect("process should still exist after stop_all");
        assert_eq!(process.status, ProcessStatus::Stopped);
        assert_eq!(process.desired_state, DesiredState::Stopped);
        assert!(
            process.pid.is_none(),
            "pid should be cleared after stop_all"
        );
    }
}

#[tokio::test]
async fn stop_all_on_empty_manager_returns_empty_list() {
    let mut manager = empty_manager("stop-all-empty");

    let stopped = manager
        .stop_all_processes()
        .await
        .expect("stop_all on empty manager should succeed");

    assert!(stopped.is_empty(), "no processes to stop");
}

#[tokio::test]
async fn stop_all_clears_scheduled_restarts() {
    let mut manager = empty_manager("stop-all-clears-state");
    let mut p = fixture_process();
    p.name = "api".to_string();
    p.pid = None;
    p.status = ProcessStatus::Running;
    p.desired_state = DesiredState::Running;
    manager.processes.insert(p.name.clone(), p);
    manager
        .scheduled_restarts
        .insert("api".to_string(), tokio::time::Instant::now());

    manager
        .stop_all_processes()
        .await
        .expect("stop_all should succeed");

    assert!(
        !manager.scheduled_restarts.contains_key("api"),
        "stop_all should clear scheduled restarts"
    );
}

#[tokio::test]
async fn restart_all_restarts_every_process() {
    let mut manager = empty_manager("restart-all-basic");
    let mut p1 = spawnable_fixture_process();
    p1.name = "web".to_string();
    p1.pid = None;

    let mut p2 = spawnable_fixture_process();
    p2.name = "worker".to_string();
    p2.pid = None;

    manager.processes.insert(p1.name.clone(), p1);
    manager.processes.insert(p2.name.clone(), p2);

    let restarted = manager
        .restart_all_processes()
        .await
        .expect("restart_all should succeed");

    assert_eq!(restarted.len(), 2, "both processes should be returned");

    for name in &["web", "worker"] {
        let process = manager
            .processes
            .get(*name)
            .expect("process should still exist after restart_all");
        assert_eq!(process.status, ProcessStatus::Running);
        assert_eq!(process.desired_state, DesiredState::Running);
        assert!(process.pid.is_some(), "pid should be set after restart_all");
    }
}

#[tokio::test]
async fn restart_all_on_empty_manager_returns_empty_list() {
    let mut manager = empty_manager("restart-all-empty");

    let restarted = manager
        .restart_all_processes()
        .await
        .expect("restart_all on empty manager should succeed");

    assert!(restarted.is_empty(), "no processes to restart");
}

#[tokio::test]
async fn delete_all_removes_every_process() {
    let mut manager = empty_manager("delete-all-basic");
    let mut p1 = fixture_process();
    p1.name = "web".to_string();
    p1.pid = None;

    let mut p2 = fixture_process();
    p2.name = "worker".to_string();
    p2.pid = None;

    manager.processes.insert(p1.name.clone(), p1);
    manager.processes.insert(p2.name.clone(), p2);

    let deleted = manager
        .delete_all_processes()
        .await
        .expect("delete_all should succeed");

    assert_eq!(deleted.len(), 2, "both processes should be returned");
    assert!(
        manager.processes.is_empty(),
        "all processes should be removed from the manager"
    );
}

#[tokio::test]
async fn delete_all_on_empty_manager_returns_empty_list() {
    let mut manager = empty_manager("delete-all-empty");

    let deleted = manager
        .delete_all_processes()
        .await
        .expect("delete_all on empty manager should succeed");

    assert!(deleted.is_empty(), "no processes to delete");
}

#[tokio::test]
async fn delete_all_clears_scheduled_restarts() {
    let mut manager = empty_manager("delete-all-clears-state");
    let mut p = fixture_process();
    p.name = "api".to_string();
    p.pid = None;
    manager.processes.insert(p.name.clone(), p);
    manager
        .scheduled_restarts
        .insert("api".to_string(), tokio::time::Instant::now());

    manager
        .delete_all_processes()
        .await
        .expect("delete_all should succeed");

    assert!(
        !manager.scheduled_restarts.contains_key("api"),
        "delete_all should clear scheduled restarts"
    );
    assert!(
        manager.processes.is_empty(),
        "processes map should be empty after delete_all"
    );
}
