use super::*;

#[test]
fn short_commit_truncates_to_eight_chars() {
    assert_eq!(short_commit("0123456789abcdef"), "01234567");
    assert_eq!(short_commit("abcd"), "abcd");
}

#[test]
fn sha256_hex_matches_known_vector() {
    assert_eq!(
        sha256_hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn constant_time_eq_handles_equal_and_mismatched_values() {
    assert!(constant_time_eq(b"abcdef", b"abcdef"));
    assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
}

#[test]
fn verify_pull_webhook_secret_accepts_name_and_id_targets() {
    let mut manager = empty_manager("verify-secret-ok");
    let mut process = fixture_process();
    process.id = 42;
    process.name = "api".to_string();
    process.pull_secret_hash = Some(sha256_hex("super-secret-token"));
    manager.processes.insert(process.name.clone(), process);

    assert!(manager
        .verify_pull_webhook_secret("api", "super-secret-token")
        .is_ok());
    assert!(manager
        .verify_pull_webhook_secret("42", "super-secret-token")
        .is_ok());
    assert!(manager
        .verify_pull_webhook_secret("api", "wrong-secret")
        .is_err());
}

#[test]
fn verify_pull_webhook_secret_requires_configured_hash() {
    let mut manager = empty_manager("verify-secret-missing");
    let mut process = fixture_process();
    process.name = "api".to_string();
    process.id = 1;
    process.pull_secret_hash = None;
    manager.processes.insert(process.name.clone(), process);

    let err = manager
        .verify_pull_webhook_secret("api", "anything")
        .expect_err("expected missing pull secret hash to fail");
    assert!(err.to_string().contains("not configured"));
}

#[tokio::test]
async fn pull_processes_errors_without_any_git_services() {
    let mut manager = empty_manager("pull-no-git");
    let err = manager
        .pull_processes(None)
        .await
        .expect_err("expected pull to fail without git-configured services");
    assert!(err
        .to_string()
        .contains("no services configured with git_repo"));
}

#[tokio::test]
async fn pull_processes_reports_unchanged_checkout() {
    let git = setup_git_fixture("pull-unchanged");
    let mut manager = empty_manager("pull-unchanged-manager");
    let mut process = fixture_process();
    process.name = "api".to_string();
    process.id = 7;
    process.cwd = Some(git.clone_dir.clone());
    process.git_repo = Some(git.remote_dir.display().to_string());
    process.git_ref = Some("main".to_string());
    process.pid = None;
    process.status = ProcessStatus::Stopped;
    process.desired_state = DesiredState::Stopped;
    manager.processes.insert(process.name.clone(), process);

    let output = manager
        .pull_processes(Some("api"))
        .await
        .expect("expected pull to succeed");
    assert!(output.contains("0 updated, 1 unchanged"));
    assert!(output.contains("up-to-date"));

    cleanup_git_fixture(git);
}

#[tokio::test]
async fn pull_processes_updates_checkout_when_remote_changes() {
    let git = setup_git_fixture("pull-changed");
    write_commit_and_push(&git.source_dir, "app.js", "console.log('v2');\n", "update");

    let mut manager = empty_manager("pull-changed-manager");
    let mut process = fixture_process();
    process.name = "api".to_string();
    process.id = 8;
    process.cwd = Some(git.clone_dir.clone());
    process.git_repo = Some(git.remote_dir.display().to_string());
    process.git_ref = Some("main".to_string());
    process.pid = None;
    process.status = ProcessStatus::Stopped;
    process.desired_state = DesiredState::Stopped;
    manager.processes.insert(process.name.clone(), process);

    let output = manager
        .pull_processes(Some("api"))
        .await
        .expect("expected pull to succeed");
    assert!(output.contains("1 updated, 0 unchanged"));
    assert!(output.contains("updated (service stopped)"));

    let source_head = git_head(&git.source_dir);
    let clone_head = git_head(&git.clone_dir);
    assert_eq!(source_head, clone_head, "clone should match source head");

    cleanup_git_fixture(git);
}
