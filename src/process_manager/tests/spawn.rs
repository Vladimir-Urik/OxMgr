use super::*;

#[test]
fn resolve_spawn_program_passthrough_when_cluster_disabled() {
    let process = fixture_process();
    let tmp = std::env::temp_dir();
    let spawn = resolve_spawn_program(&process, &tmp).expect("expected passthrough spawn program");
    assert_eq!(spawn.program, "node");
    assert_eq!(spawn.args, vec!["server.js".to_string()]);
    assert!(spawn.extra_env.is_empty());
}

#[test]
fn resolve_spawn_program_rejects_non_node_cluster_mode() {
    let mut process = fixture_process();
    process.command = "python".to_string();
    process.cluster_mode = true;
    process.cluster_instances = Some(4);

    let tmp = std::env::temp_dir();
    let err = resolve_spawn_program(&process, &tmp)
        .expect_err("expected non-node command to fail for cluster mode");
    assert!(
        err.to_string().contains("requires a Node.js command"),
        "unexpected error: {err}"
    );
}

#[test]
fn resolve_spawn_program_builds_bootstrap_for_cluster_mode() {
    let runtime = temp_watch_dir("cluster-runtime");
    let mut process = fixture_process();
    process.cluster_mode = true;
    process.cluster_instances = Some(3);

    let spawn = resolve_spawn_program(&process, &runtime)
        .expect("expected cluster spawn command to be generated");
    assert_eq!(spawn.program, "node");
    assert_eq!(spawn.args[1], "--");
    assert_eq!(spawn.args[2], "server.js");
    assert_eq!(
        spawn
            .extra_env
            .get("OXMGR_CLUSTER_INSTANCES")
            .map(String::as_str),
        Some("3")
    );
    assert!(
        Path::new(&spawn.args[0]).exists(),
        "expected bootstrap script to be written"
    );

    let _ = fs::remove_dir_all(&runtime);
}

#[test]
fn program_matches_expected_checks_absolute_and_basename_forms() {
    let exe = std::env::current_exe().expect("failed to resolve current exe");
    assert!(program_matches_expected(
        Some(&exe),
        &exe.display().to_string()
    ));

    let basename = exe
        .file_name()
        .and_then(|value| value.to_str())
        .expect("missing exe basename");
    assert!(program_matches_expected(Some(&exe), basename));
    assert!(!program_matches_expected(
        Some(&exe),
        "definitely-not-this-binary"
    ));
}

#[test]
fn args_match_expected_requires_exact_argument_match() {
    let actual = vec![OsString::from("--help"), OsString::from("api")];
    let expected = vec!["--help".to_string(), "api".to_string()];
    let different = vec!["--help".to_string(), "worker".to_string()];

    assert!(args_match_expected(&actual, "oxmgr", &expected));
    assert!(!args_match_expected(&actual, "oxmgr", &different));
}

#[test]
fn args_match_expected_accepts_leading_executable_in_process_snapshot() {
    let actual = vec![
        OsString::from("/usr/local/bin/oxmgr"),
        OsString::from("--help"),
    ];
    let expected = vec!["--help".to_string()];

    assert!(args_match_expected(&actual, "oxmgr", &expected));
}
