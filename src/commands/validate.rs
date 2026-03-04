use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use regex::RegexSet;

use crate::ecosystem::EcosystemProcessSpec;

use super::import::load_import_specs;

#[derive(Debug, Clone)]
struct OxfileValidationReport {
    app_count: usize,
    expanded_process_count: usize,
    unnamed_count: usize,
}

pub(crate) fn run(path: &Path, env: Option<&str>, only: &[String]) -> Result<()> {
    validate_oxfile_command(path, env, only)
}

fn validate_oxfile_command(path: &Path, env: Option<&str>, only: &[String]) -> Result<()> {
    let mut specs = load_import_specs(path, env)?;
    if !only.is_empty() {
        specs.retain(|spec| {
            spec.name
                .as_ref()
                .map(|name| only.iter().any(|selected| selected == name))
                .unwrap_or(false)
        });
    }

    if specs.is_empty() {
        if only.is_empty() {
            anyhow::bail!("no apps resolved from {}", path.display());
        } else {
            anyhow::bail!(
                "no apps matched --only filter ({}) in {}",
                only.join(","),
                path.display()
            );
        }
    }

    let report = validate_resolved_specs(&specs)?;

    println!("Config validation: OK");
    println!("Path: {}", path.display());
    println!("Format: {}", config_format_label(path));
    println!("Profile: {}", env.unwrap_or("default"));
    println!("Apps: {}", report.app_count);
    println!("Expanded Processes: {}", report.expanded_process_count);
    if report.unnamed_count > 0 {
        println!(
            "Warning: {} app(s) have no name. Add `name` for deterministic `oxmgr apply`.",
            report.unnamed_count
        );
    }

    Ok(())
}

fn validate_resolved_specs(specs: &[EcosystemProcessSpec]) -> Result<OxfileValidationReport> {
    if specs.is_empty() {
        anyhow::bail!("empty app list");
    }

    let mut named_apps = HashSet::new();
    let mut unnamed_count = 0_usize;
    for spec in specs {
        let tokens = shell_words::split(&spec.command)
            .with_context(|| format!("invalid command syntax: {}", spec.command))?;
        if tokens.is_empty() {
            anyhow::bail!("app command cannot be empty");
        }
        validate_cluster_settings(spec, &tokens)?;
        validate_watch_settings(spec)?;
        validate_readiness_settings(spec)?;

        if let Some(check) = &spec.health_check {
            let health_tokens = shell_words::split(&check.command)
                .with_context(|| format!("invalid health command syntax: {}", check.command))?;
            if health_tokens.is_empty() {
                anyhow::bail!("health command cannot be empty for app {:?}", spec.name);
            }
        }

        if let Some(name) = &spec.name {
            if !named_apps.insert(name.clone()) {
                anyhow::bail!("duplicate app name in oxfile: {}", name);
            }
        } else {
            unnamed_count = unnamed_count.saturating_add(1);
        }
    }

    for spec in specs {
        for dependency in &spec.depends_on {
            if !named_apps.contains(dependency) {
                anyhow::bail!(
                    "app {:?} depends_on unknown app '{}'",
                    spec.name,
                    dependency
                );
            }
        }
    }

    let mut expanded_names = HashSet::new();
    let mut expanded_process_count = 0_usize;
    for spec in specs {
        let instances = spec.instances.max(1) as usize;
        expanded_process_count = expanded_process_count.saturating_add(instances);

        let Some(base_name) = &spec.name else {
            continue;
        };

        if instances == 1 {
            if !expanded_names.insert(base_name.clone()) {
                anyhow::bail!("duplicate expanded process name: {}", base_name);
            }
            continue;
        }

        for idx in 0..instances {
            let expanded = format!("{base_name}-{idx}");
            if !expanded_names.insert(expanded.clone()) {
                anyhow::bail!("duplicate expanded process name: {}", expanded);
            }
        }
    }

    Ok(OxfileValidationReport {
        app_count: specs.len(),
        expanded_process_count,
        unnamed_count,
    })
}

fn validate_watch_settings(spec: &EcosystemProcessSpec) -> Result<()> {
    if !spec.watch {
        if !spec.watch_paths.is_empty()
            || !spec.ignore_watch.is_empty()
            || spec.watch_delay_secs > 0
        {
            anyhow::bail!(
                "app {:?} configures watch paths/ignore/delay but watch is disabled",
                spec.name
            );
        }
        return Ok(());
    }

    if spec.watch_paths.is_empty() && spec.cwd.is_none() {
        anyhow::bail!(
            "app {:?} enables watch but does not set cwd or explicit watch paths",
            spec.name
        );
    }

    if spec.cwd.is_none() && spec.watch_paths.iter().any(|path| !path.is_absolute()) {
        anyhow::bail!(
            "app {:?} uses relative watch paths but does not set cwd",
            spec.name
        );
    }

    if !spec.ignore_watch.is_empty() {
        RegexSet::new(&spec.ignore_watch)
            .with_context(|| format!("invalid ignore_watch regex for app {:?}", spec.name))?;
    }

    Ok(())
}

fn validate_readiness_settings(spec: &EcosystemProcessSpec) -> Result<()> {
    if spec.wait_ready && spec.health_check.is_none() {
        anyhow::bail!(
            "app {:?} enables wait_ready but does not define a health check",
            spec.name
        );
    }
    if spec.ready_timeout_secs == 0 {
        anyhow::bail!("app {:?} has ready_timeout_secs = 0", spec.name);
    }
    Ok(())
}

fn validate_cluster_settings(spec: &EcosystemProcessSpec, command_tokens: &[String]) -> Result<()> {
    if !spec.cluster_mode {
        if spec.cluster_instances.is_some() {
            anyhow::bail!(
                "app {:?} sets cluster_instances but cluster_mode is disabled",
                spec.name
            );
        }
        return Ok(());
    }

    if !is_node_command_token(&command_tokens[0]) {
        anyhow::bail!(
            "app {:?} enables cluster_mode but command is not Node.js: {}",
            spec.name,
            command_tokens[0]
        );
    }
    if command_tokens.len() < 2 {
        anyhow::bail!(
            "app {:?} enables cluster_mode but command has no script argument",
            spec.name
        );
    }
    if command_tokens[1].starts_with('-') {
        anyhow::bail!(
            "app {:?} enables cluster_mode with unsupported Node flags before script path",
            spec.name
        );
    }

    Ok(())
}

fn is_node_command_token(token: &str) -> bool {
    let executable = std::path::Path::new(token)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(token)
        .to_ascii_lowercase();
    matches!(
        executable.as_str(),
        "node" | "node.exe" | "nodejs" | "nodejs.exe"
    )
}

fn config_format_label(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("toml") => "oxfile.toml",
        Some("js") | Some("cjs") | Some("mjs") | Some("json") | Some("json5") => "ecosystem config",
        _ => "config",
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_oxfile_command, validate_resolved_specs};
    use crate::ecosystem::EcosystemProcessSpec;
    use crate::process::{HealthCheck, RestartPolicy};
    use std::collections::HashMap;
    #[test]
    fn validate_resolved_specs_accepts_valid_definitions() {
        let specs = vec![
            fixture_spec("db", "docker compose up db", vec![], 1),
            fixture_spec("api", "node server.js", vec!["db".to_string()], 2),
        ];

        let report = validate_resolved_specs(&specs).expect("validation should pass");
        assert_eq!(report.app_count, 2);
        assert_eq!(report.expanded_process_count, 3);
        assert_eq!(report.unnamed_count, 0);
    }

    #[test]
    fn validate_resolved_specs_rejects_unknown_dependency() {
        let specs = vec![fixture_spec(
            "api",
            "node server.js",
            vec!["missing-db".to_string()],
            1,
        )];

        let error = validate_resolved_specs(&specs).expect_err("validation should fail");
        assert!(
            error.to_string().contains("depends_on unknown app"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_duplicate_names() {
        let specs = vec![
            fixture_spec("api", "node server.js", vec![], 1),
            fixture_spec("api", "node worker.js", vec![], 1),
        ];

        let error = validate_resolved_specs(&specs).expect_err("validation should fail");
        assert!(
            error.to_string().contains("duplicate app name"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_invalid_command_syntax() {
        let specs = vec![fixture_spec("api", "node \"unterminated", vec![], 1)];

        let error = validate_resolved_specs(&specs).expect_err("validation should fail");
        assert!(
            error.to_string().contains("invalid command syntax"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_empty_app_list() {
        let error = validate_resolved_specs(&[]).expect_err("validation should fail");
        assert_eq!(error.to_string(), "empty app list");
    }

    #[test]
    fn validate_resolved_specs_rejects_invalid_health_command_syntax() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.health_check = Some(HealthCheck {
            command: "curl \"unterminated".to_string(),
            interval_secs: 30,
            timeout_secs: 5,
            max_failures: 3,
        });

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error.to_string().contains("invalid health command syntax"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_wait_ready_without_health_check() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.health_check = None;
        spec.wait_ready = true;

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error.to_string().contains("wait_ready"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_watch_without_cwd_or_paths() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.watch = true;
        spec.watch_paths.clear();
        spec.cwd = None;

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("does not set cwd or explicit watch paths"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_relative_watch_paths_without_cwd() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.watch = true;
        spec.cwd = None;
        spec.watch_paths = vec![std::path::PathBuf::from("src")];

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("uses relative watch paths but does not set cwd"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_watch_tuning_when_watch_disabled() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.watch = false;
        spec.ignore_watch = vec!["node_modules".to_string()];

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("configures watch paths/ignore/delay but watch is disabled"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_invalid_ignore_watch_regex() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.watch = true;
        spec.cwd = Some(std::env::temp_dir());
        spec.ignore_watch = vec!["(".to_string()];

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error.to_string().contains("invalid ignore_watch regex"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_zero_ready_timeout() {
        let mut spec = fixture_spec("api", "node server.js", vec![], 1);
        spec.ready_timeout_secs = 0;

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error.to_string().contains("ready_timeout_secs = 0"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_cluster_mode_for_non_node_command() {
        let mut spec = fixture_spec("api", "python app.py", vec![], 1);
        spec.cluster_mode = true;

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("cluster_mode but command is not Node.js"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_cluster_mode_without_script_argument() {
        let mut spec = fixture_spec("api", "node", vec![], 1);
        spec.cluster_mode = true;

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("cluster_mode but command has no script argument"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_cluster_mode_with_node_flags_before_script() {
        let mut spec = fixture_spec(
            "api",
            "node --require ts-node/register server.js",
            vec![],
            1,
        );
        spec.cluster_mode = true;

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("unsupported Node flags before script path"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_rejects_cluster_instances_without_cluster_mode() {
        let mut spec = fixture_spec("api", "node app.js", vec![], 1);
        spec.cluster_instances = Some(2);

        let error = validate_resolved_specs(&[spec]).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("cluster_instances but cluster_mode is disabled"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_accepts_absolute_node_binary_in_cluster_mode() {
        let mut spec = fixture_spec("api", "/usr/local/bin/node server.js", vec![], 1);
        spec.cluster_mode = true;
        spec.cluster_instances = Some(2);

        let report = validate_resolved_specs(&[spec]).expect("validation should pass");
        assert_eq!(report.app_count, 1);
        assert_eq!(report.expanded_process_count, 1);
    }

    #[test]
    fn validate_resolved_specs_rejects_duplicate_expanded_names() {
        let specs = vec![
            fixture_spec("api", "node server.js", vec![], 2),
            fixture_spec("api-0", "node sidecar.js", vec![], 1),
        ];

        let error = validate_resolved_specs(&specs).expect_err("validation should fail");
        assert!(
            error
                .to_string()
                .contains("duplicate expanded process name"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn validate_resolved_specs_counts_unnamed_apps() {
        let unnamed = EcosystemProcessSpec {
            command: "echo unnamed".to_string(),
            name: None,
            restart_policy: RestartPolicy::Never,
            max_restarts: 0,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: None,
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
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
            start_order: 0,
            depends_on: Vec::new(),
            instances: 1,
            instance_var: None,
            wait_ready: false,
            ready_timeout_secs: 30,
        };
        let named = fixture_spec("api", "node server.js", vec![], 1);

        let report = validate_resolved_specs(&[unnamed, named]).expect("validation should succeed");
        assert_eq!(report.app_count, 2);
        assert_eq!(report.expanded_process_count, 2);
        assert_eq!(report.unnamed_count, 1);
    }

    #[test]
    fn validate_command_accepts_ecosystem_json_path() {
        let path = temp_file("validate-ecosystem", "json");
        std::fs::write(
            &path,
            r#"{
  "apps": [
    { "name": "api", "script": "server.js" }
  ]
}"#,
        )
        .expect("failed to write ecosystem fixture");

        validate_oxfile_command(&path, None, &[]).expect("validate should accept ecosystem json");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn validate_command_accepts_ecosystem_js_path() {
        let path = temp_file("validate-ecosystem-js", "js");
        std::fs::write(
            &path,
            r#"
module.exports = {
  apps: [
    {
      name: "api",
      cmd: "node server.js",
      cwd: "/srv/api",
      watch: ["src"],
      ignore_watch: ["node_modules"],
      watch_delay: 1000,
      health_cmd: "curl -fsS http://127.0.0.1:3000/health",
      wait_ready: true,
      listen_timeout: 5000
    }
  ]
};
"#,
        )
        .expect("failed to write ecosystem fixture");

        validate_oxfile_command(&path, None, &[]).expect("validate should accept ecosystem js");

        let _ = std::fs::remove_file(path);
    }

    fn fixture_spec(
        name: &str,
        command: &str,
        depends_on: Vec<String>,
        instances: u32,
    ) -> EcosystemProcessSpec {
        EcosystemProcessSpec {
            command: command.to_string(),
            name: Some(name.to_string()),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: Some(HealthCheck {
                command: "echo ok".to_string(),
                interval_secs: 30,
                timeout_secs: 5,
                max_failures: 3,
            }),
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
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
            start_order: 0,
            depends_on,
            instances,
            instance_var: Some("INSTANCE_ID".to_string()),
            wait_ready: false,
            ready_timeout_secs: 30,
        }
    }

    fn temp_file(prefix: &str, extension: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }
}
