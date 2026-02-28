use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::ecosystem::EcosystemProcessSpec;
use crate::oxfile;

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
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    if extension.as_deref() != Some("toml") {
        anyhow::bail!(
            "validate expects oxfile.toml input (got: {})",
            path.display()
        );
    }

    let mut specs = oxfile::load_with_profile(path, env)?;
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

    println!("Oxfile validation: OK");
    println!("Path: {}", path.display());
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

#[cfg(test)]
mod tests {
    use super::{validate_oxfile_command, validate_resolved_specs};
    use crate::ecosystem::EcosystemProcessSpec;
    use crate::process::{HealthCheck, RestartPolicy};
    use std::collections::HashMap;
    use std::path::Path;

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
        let mut spec = fixture_spec("api", "node --require ts-node/register server.js", vec![], 1);
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
        };
        let named = fixture_spec("api", "node server.js", vec![], 1);

        let report = validate_resolved_specs(&[unnamed, named]).expect("validation should succeed");
        assert_eq!(report.app_count, 2);
        assert_eq!(report.expanded_process_count, 2);
        assert_eq!(report.unnamed_count, 1);
    }

    #[test]
    fn validate_command_rejects_non_toml_path() {
        let error = validate_oxfile_command(Path::new("ecosystem.config.json"), None, &[])
            .expect_err("validate should reject non-toml path");
        assert!(
            error
                .to_string()
                .contains("validate expects oxfile.toml input"),
            "unexpected error: {}",
            error
        );
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
        }
    }
}
