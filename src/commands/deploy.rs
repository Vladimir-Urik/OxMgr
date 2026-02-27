use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
enum DeployAction {
    Setup,
    Update {
        ref_override: Option<String>,
        force: bool,
    },
    Revert {
        steps: u32,
    },
    Current,
    Previous,
    List,
    Exec {
        command: String,
    },
}

#[derive(Debug, Clone)]
struct DeployInvocation {
    config_path: PathBuf,
    environment: String,
    action: DeployAction,
}

#[derive(Debug, Clone)]
struct DeployTarget {
    environment: String,
    user: String,
    hosts: Vec<String>,
    port: Option<u16>,
    key: Option<PathBuf>,
    repo: Option<String>,
    path: String,
    deploy_ref: Option<String>,
    pre_setup: Option<String>,
    post_setup: Option<String>,
    pre_deploy: Option<String>,
    post_deploy: Option<String>,
    pre_deploy_local: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DeployFile {
    #[serde(default)]
    deploy: HashMap<String, DeployTargetRaw>,
}

#[derive(Debug, Clone, Deserialize)]
struct DeployTargetRaw {
    user: String,
    host: HostField,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    key: Option<PathBuf>,
    #[serde(default)]
    repo: Option<String>,
    path: String,
    #[serde(rename = "ref", default)]
    deploy_ref: Option<String>,
    #[serde(rename = "pre-setup", alias = "pre_setup", default)]
    pre_setup: Option<String>,
    #[serde(rename = "post-setup", alias = "post_setup", default)]
    post_setup: Option<String>,
    #[serde(rename = "pre-deploy", alias = "pre_deploy", default)]
    pre_deploy: Option<String>,
    #[serde(rename = "post-deploy", alias = "post_deploy", default)]
    post_deploy: Option<String>,
    #[serde(rename = "pre-deploy-local", alias = "pre_deploy_local", default)]
    pre_deploy_local: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum HostField {
    Single(String),
    Many(Vec<String>),
}

impl HostField {
    fn into_vec(self) -> Vec<String> {
        match self {
            HostField::Single(value) => vec![value],
            HostField::Many(values) => values,
        }
    }
}

pub(crate) async fn run(config: Option<PathBuf>, force: bool, args: Vec<String>) -> Result<()> {
    let invocation = parse_invocation(config, force, args)?;
    let target = load_target_from_file(&invocation.config_path, &invocation.environment)?;

    println!("--> Deploying to {} environment", target.environment);
    match invocation.action {
        DeployAction::Setup => {
            let script = build_setup_script(&target)?;
            run_remote_on_all_hosts(&target, &script).await?;
        }
        DeployAction::Update {
            ref_override,
            force,
        } => {
            if let Some(local) = target.pre_deploy_local.as_deref() {
                println!("--> hook pre-deploy-local");
                run_local_shell(local)?;
            }
            let script = build_update_script(&target, ref_override.as_deref(), force)?;
            run_remote_on_all_hosts(&target, &script).await?;
        }
        DeployAction::Revert { steps } => {
            let script = build_revert_script(&target, steps)?;
            let outputs = run_remote_on_all_hosts(&target, &script).await?;
            for (host, output) in outputs {
                if !output.is_empty() {
                    println!("--> host {host} reverted to commit {output}");
                }
            }
        }
        DeployAction::Current => {
            let script = build_current_script(&target);
            let outputs = run_remote_on_all_hosts(&target, &script).await?;
            for (host, output) in outputs {
                println!("{host}: {}", output.if_empty("-"));
            }
        }
        DeployAction::Previous => {
            let script = build_previous_script(&target);
            let outputs = run_remote_on_all_hosts(&target, &script).await?;
            for (host, output) in outputs {
                println!("{host}: {}", output.if_empty("-"));
            }
        }
        DeployAction::List => {
            let script = build_list_script(&target);
            let outputs = run_remote_on_all_hosts(&target, &script).await?;
            for (host, output) in outputs {
                println!("== {host} ==");
                if output.is_empty() {
                    println!("-");
                } else {
                    println!("{output}");
                }
            }
        }
        DeployAction::Exec { command } => {
            let script = build_exec_script(&target, &command);
            run_remote_on_all_hosts(&target, &script).await?;
        }
    }

    Ok(())
}

fn parse_invocation(
    config: Option<PathBuf>,
    force: bool,
    args: Vec<String>,
) -> Result<DeployInvocation> {
    if args.is_empty() {
        anyhow::bail!(
            "deploy requires at least <environment>. Example: oxmgr deploy production setup"
        );
    }

    let (resolved_config, environment, command_tokens) = if let Some(path) = config {
        let environment = args[0].clone();
        let command_tokens = args[1..].to_vec();
        (path, environment, command_tokens)
    } else if args.len() >= 2 && looks_like_config_argument(&args[0]) {
        (PathBuf::from(&args[0]), args[1].clone(), args[2..].to_vec())
    } else {
        (
            discover_default_deploy_config()?,
            args[0].clone(),
            args[1..].to_vec(),
        )
    };

    let action = parse_action(command_tokens, force)?;
    Ok(DeployInvocation {
        config_path: resolved_config,
        environment,
        action,
    })
}

fn parse_action(tokens: Vec<String>, force: bool) -> Result<DeployAction> {
    if tokens.is_empty() {
        return Ok(DeployAction::Update {
            ref_override: None,
            force,
        });
    }

    let first_token = tokens[0].clone();
    let command = first_token.to_ascii_lowercase();
    match command.as_str() {
        "setup" => {
            ensure_exact_args("setup", &tokens, 1)?;
            Ok(DeployAction::Setup)
        }
        "update" => {
            if tokens.len() > 2 {
                anyhow::bail!("update expects at most one optional ref argument");
            }
            Ok(DeployAction::Update {
                ref_override: tokens.get(1).cloned(),
                force,
            })
        }
        "revert" => {
            if tokens.len() > 2 {
                anyhow::bail!("revert expects optional numeric argument");
            }
            let steps = tokens
                .get(1)
                .map(|value| {
                    value
                        .parse::<u32>()
                        .with_context(|| format!("invalid revert step count: {value}"))
                })
                .transpose()?
                .unwrap_or(1)
                .max(1);
            Ok(DeployAction::Revert { steps })
        }
        "curr" | "current" => {
            ensure_exact_args("current", &tokens, 1)?;
            Ok(DeployAction::Current)
        }
        "prev" | "previous" => {
            ensure_exact_args("previous", &tokens, 1)?;
            Ok(DeployAction::Previous)
        }
        "list" => {
            ensure_exact_args("list", &tokens, 1)?;
            Ok(DeployAction::List)
        }
        "exec" | "run" => {
            if tokens.len() < 2 {
                anyhow::bail!("exec requires a command string");
            }
            Ok(DeployAction::Exec {
                command: tokens[1..].join(" "),
            })
        }
        _ => {
            if tokens.len() > 1 {
                anyhow::bail!(
                    "unrecognized deploy command '{}'. Use setup|update|revert|current|previous|list|exec or provide a single ref",
                    first_token
                );
            }
            Ok(DeployAction::Update {
                ref_override: Some(first_token),
                force,
            })
        }
    }
}

fn ensure_exact_args(name: &str, tokens: &[String], expected: usize) -> Result<()> {
    if tokens.len() != expected {
        anyhow::bail!("{name} does not accept extra arguments");
    }
    Ok(())
}

fn looks_like_config_argument(value: &str) -> bool {
    if value.contains(std::path::MAIN_SEPARATOR) {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".cjs")
        || lower.ends_with(".mjs")
        || lower.ends_with(".json")
        || lower.ends_with(".toml")
        || lower == "ecosystem.config.js"
        || lower == "pm2.config.js"
}

fn discover_default_deploy_config() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to resolve current directory")?;
    let candidates = [
        "ecosystem.config.js",
        "ecosystem.config.cjs",
        "ecosystem.config.json",
        "pm2.config.js",
        "pm2.config.cjs",
        "pm2.config.json",
        "oxfile.toml",
    ];

    for candidate in candidates {
        let path = cwd.join(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    anyhow::bail!(
        "no deploy config found in current directory. Use --config <path> or create ecosystem.config.js / pm2.config.js / ecosystem.config.json / oxfile.toml"
    );
}

fn load_target_from_file(path: &Path, environment: &str) -> Result<DeployTarget> {
    let raw = load_deploy_file(path)?;
    let env_raw = raw.deploy.get(environment).cloned().with_context(|| {
        let mut names: Vec<String> = raw.deploy.keys().cloned().collect();
        names.sort();
        format!(
            "environment '{}' not found in deploy config {} (available: {})",
            environment,
            path.display(),
            if names.is_empty() {
                "-".to_string()
            } else {
                names.join(", ")
            }
        )
    })?;

    let hosts: Vec<String> = env_raw
        .host
        .into_vec()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if hosts.is_empty() {
        anyhow::bail!("deploy.{} host list is empty", environment);
    }

    let key = env_raw.key.map(|key| {
        if key.is_absolute() {
            key
        } else {
            path.parent().unwrap_or_else(|| Path::new(".")).join(key)
        }
    });

    Ok(DeployTarget {
        environment: environment.to_string(),
        user: env_raw.user,
        hosts,
        port: env_raw.port,
        key,
        repo: env_raw.repo,
        path: env_raw.path,
        deploy_ref: env_raw.deploy_ref,
        pre_setup: env_raw.pre_setup,
        post_setup: env_raw.post_setup,
        pre_deploy: env_raw.pre_deploy,
        post_deploy: env_raw.post_deploy,
        pre_deploy_local: env_raw.pre_deploy_local,
    })
}

fn load_deploy_file(path: &Path) -> Result<DeployFile> {
    let payload = fs::read_to_string(path)
        .with_context(|| format!("failed to read deploy config {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    match ext.as_deref() {
        Some("toml") => toml::from_str::<DeployFile>(&payload)
            .with_context(|| format!("failed to parse TOML deploy config {}", path.display())),
        Some("json") => json5::from_str::<DeployFile>(&payload)
            .with_context(|| format!("failed to parse JSON deploy config {}", path.display())),
        Some("js") | Some("cjs") | Some("mjs") => {
            let object = extract_js_object_literal(&payload)?;
            json5::from_str::<DeployFile>(&object)
                .with_context(|| format!("failed to parse JS deploy config {}", path.display()))
        }
        _ => {
            if let Ok(parsed) = toml::from_str::<DeployFile>(&payload) {
                return Ok(parsed);
            }
            if let Ok(parsed) = json5::from_str::<DeployFile>(&payload) {
                return Ok(parsed);
            }
            anyhow::bail!(
                "unsupported deploy config format for {} (expected .toml/.json/.js/.cjs/.mjs)",
                path.display()
            )
        }
    }
}

fn extract_js_object_literal(payload: &str) -> Result<String> {
    let trimmed = payload.trim();
    if trimmed.starts_with('{') {
        return Ok(trimmed.to_string());
    }

    let Some(start) = trimmed.find('{') else {
        anyhow::bail!("failed to locate JS object in deploy config");
    };
    let Some(end) = trimmed.rfind('}') else {
        anyhow::bail!("failed to locate JS object end in deploy config");
    };
    if end < start {
        anyhow::bail!("invalid JS object boundaries in deploy config");
    }

    Ok(trimmed[start..=end].to_string())
}

fn build_setup_script(target: &DeployTarget) -> Result<String> {
    let repo = target
        .repo
        .as_deref()
        .context("deploy setup requires `repo` in deploy config")?;
    let source = source_path(&target.path);
    let source_git = format!("{source}/.git");
    let history = history_path(&target.path);

    let mut lines = vec!["set -e".to_string()];
    if let Some(hook) = target.pre_setup.as_deref() {
        lines.push(hook.to_string());
    }
    lines.push(format!("mkdir -p {}", sh_quote(&target.path)));
    lines.push(format!(
        "if [ ! -d {} ]; then git clone {} {}; fi",
        sh_quote(&source_git),
        sh_quote(repo),
        sh_quote(&source)
    ));
    lines.push(format!("cd {}", sh_quote(&source)));
    lines.push("git fetch --all --tags".to_string());
    lines.push("commit=$(git rev-parse HEAD)".to_string());
    lines.push("ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)".to_string());
    lines.push(format!(
        "printf \"%s\\t%s\\t%s\\n\" \"$ts\" \"$commit\" \"setup\" >> {}",
        sh_quote(&history)
    ));
    if let Some(hook) = target.post_setup.as_deref() {
        lines.push(hook.to_string());
    }
    Ok(lines.join("\n"))
}

fn build_update_script(
    target: &DeployTarget,
    ref_override: Option<&str>,
    force: bool,
) -> Result<String> {
    let repo = target
        .repo
        .as_deref()
        .context("deploy update requires `repo` in deploy config")?;
    let source = source_path(&target.path);
    let source_git = format!("{source}/.git");
    let history = history_path(&target.path);
    let requested_ref = ref_override.or(target.deploy_ref.as_deref());

    let mut lines = vec!["set -e".to_string()];
    lines.push(format!("mkdir -p {}", sh_quote(&target.path)));
    lines.push(format!(
        "if [ ! -d {} ]; then git clone {} {}; fi",
        sh_quote(&source_git),
        sh_quote(repo),
        sh_quote(&source)
    ));
    lines.push(format!("cd {}", sh_quote(&source)));
    if let Some(hook) = target.pre_deploy.as_deref() {
        lines.push(hook.to_string());
    }
    lines.push("git fetch --all --tags".to_string());
    if force {
        lines.push("git reset --hard".to_string());
        lines.push("git clean -fd".to_string());
    }
    if let Some(reference) = requested_ref {
        lines.push(format!("target_ref={}", sh_quote(reference)));
    } else {
        lines.push("target_ref=$(git describe --tags --abbrev=0 2>/dev/null || true)".to_string());
        lines.push(
            "if [ -z \"$target_ref\" ]; then target_ref=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true); fi".to_string(),
        );
        lines.push("if [ -z \"$target_ref\" ]; then target_ref=\"origin/master\"; fi".to_string());
    }
    lines.push("git checkout -f \"$target_ref\"".to_string());
    lines.push("git reset --hard \"$target_ref\"".to_string());
    lines.push("commit=$(git rev-parse HEAD)".to_string());
    lines.push("ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)".to_string());
    lines.push(format!(
        "printf \"%s\\t%s\\t%s\\n\" \"$ts\" \"$commit\" \"$target_ref\" >> {}",
        sh_quote(&history)
    ));
    if let Some(hook) = target.post_deploy.as_deref() {
        lines.push(hook.to_string());
    }
    Ok(lines.join("\n"))
}

fn build_revert_script(target: &DeployTarget, steps: u32) -> Result<String> {
    let source = source_path(&target.path);
    let source_git = format!("{source}/.git");
    let history = history_path(&target.path);
    let tail_count = steps.saturating_add(1);

    let mut lines = vec!["set -e".to_string()];
    lines.push(format!(
        "if [ ! -d {} ]; then echo \"missing source checkout\"; exit 1; fi",
        sh_quote(&source_git)
    ));
    lines.push(format!(
        "if [ ! -f {} ]; then echo \"missing deploy history\"; exit 1; fi",
        sh_quote(&history)
    ));
    lines.push(format!(
        "target_commit=$(awk '{{print $2}}' {} | tail -n {} | head -n 1)",
        sh_quote(&history),
        tail_count
    ));
    lines.push("if [ -z \"$target_commit\" ]; then echo \"not enough deploy history to revert\"; exit 1; fi".to_string());
    lines.push(format!("cd {}", sh_quote(&source)));
    lines.push("git fetch --all --tags || true".to_string());
    lines.push("git checkout -f \"$target_commit\"".to_string());
    lines.push("git reset --hard \"$target_commit\"".to_string());
    lines.push("ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)".to_string());
    lines.push(format!(
        "printf \"%s\\t%s\\t%s\\n\" \"$ts\" \"$target_commit\" \"revert-{}\" >> {}",
        steps,
        sh_quote(&history)
    ));
    if let Some(hook) = target.post_deploy.as_deref() {
        lines.push(hook.to_string());
    }
    lines.push("printf \"%s\" \"$target_commit\"".to_string());
    Ok(lines.join("\n"))
}

fn build_current_script(target: &DeployTarget) -> String {
    let source = source_path(&target.path);
    let source_git = format!("{source}/.git");
    let history = history_path(&target.path);
    vec![
        "set -e".to_string(),
        format!(
            "if [ -f {} ]; then tail -n 1 {} | awk '{{print $2}}'; elif [ -d {} ]; then cd {} && git rev-parse HEAD; fi",
            sh_quote(&history),
            sh_quote(&history),
            sh_quote(&source_git),
            sh_quote(&source)
        ),
    ]
    .join("\n")
}

fn build_previous_script(target: &DeployTarget) -> String {
    let history = history_path(&target.path);
    vec![
        "set -e".to_string(),
        format!(
            "if [ -f {} ]; then tail -n 2 {} | head -n 1 | awk '{{print $2}}'; fi",
            sh_quote(&history),
            sh_quote(&history)
        ),
    ]
    .join("\n")
}

fn build_list_script(target: &DeployTarget) -> String {
    let history = history_path(&target.path);
    vec![
        "set -e".to_string(),
        format!(
            "if [ -f {} ]; then cat {}; fi",
            sh_quote(&history),
            sh_quote(&history)
        ),
    ]
    .join("\n")
}

fn build_exec_script(target: &DeployTarget, command: &str) -> String {
    let source = source_path(&target.path);
    vec![
        "set -e".to_string(),
        format!("cd {}", sh_quote(&source)),
        command.to_string(),
    ]
    .join("\n")
}

async fn run_remote_on_all_hosts(
    target: &DeployTarget,
    script: &str,
) -> Result<Vec<(String, String)>> {
    let mut tasks = Vec::with_capacity(target.hosts.len());
    for host in &target.hosts {
        println!("--> on host {host}");
        let host_owned = host.clone();
        let script_owned = script.to_string();
        let target_owned = target.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            let result = run_remote_shell(&target_owned, &host_owned, &script_owned);
            (host_owned, result)
        }));
    }

    let mut outputs = Vec::with_capacity(tasks.len());
    let mut failures = Vec::new();
    for task in tasks {
        let (host, result) = task.await.context("failed joining deploy host task")?;
        match result {
            Ok(output) => {
                if !output.is_empty() {
                    println!("== {host} ==\n{output}");
                }
                outputs.push((host, output));
            }
            Err(err) => failures.push(format!("{host}: {err}")),
        }
    }

    if !failures.is_empty() {
        anyhow::bail!(
            "deploy failed on {} host(s): {}",
            failures.len(),
            failures.join(" | ")
        );
    }

    Ok(outputs)
}

fn run_remote_shell(target: &DeployTarget, host: &str, script: &str) -> Result<String> {
    let mut command = Command::new("ssh");
    command.arg("-o").arg("BatchMode=yes");
    if let Some(port) = target.port {
        command.arg("-p").arg(port.to_string());
    }
    if let Some(key) = target.key.as_ref() {
        command.arg("-i").arg(key);
    }
    command
        .arg(format!("{}@{}", target.user, host))
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .stdin(Stdio::null());

    let output = command
        .output()
        .with_context(|| format!("failed to run ssh command on host {host}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        anyhow::bail!(
            "deploy command failed on host {} with exit code {:?}: {}",
            host,
            output.status.code(),
            if stderr.is_empty() {
                "no stderr".to_string()
            } else {
                stderr
            }
        );
    }

    if !stderr.is_empty() {
        println!("{stderr}");
    }
    Ok(stdout)
}

fn run_local_shell(command_line: &str) -> Result<()> {
    let mut command = if cfg!(windows) {
        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg(command_line);
        cmd
    } else {
        let mut cmd = Command::new("sh");
        cmd.arg("-lc").arg(command_line);
        cmd
    };

    let status = command
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("failed running local deploy hook: {command_line}"))?;
    if !status.success() {
        anyhow::bail!(
            "local deploy hook failed with exit code {:?}: {}",
            status.code(),
            command_line
        );
    }
    Ok(())
}

fn source_path(base: &str) -> String {
    format!("{}/source", base.trim_end_matches('/'))
}

fn history_path(base: &str) -> String {
    format!("{}/.oxmgr-deploy-history", base.trim_end_matches('/'))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

trait EmptyFallback {
    fn if_empty(self, fallback: &str) -> String;
}

impl EmptyFallback for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        extract_js_object_literal, load_target_from_file, parse_action, parse_invocation,
        DeployAction,
    };

    #[test]
    fn parse_action_defaults_to_update() {
        let action = parse_action(vec![], false).expect("expected default update action");
        match action {
            DeployAction::Update {
                ref_override,
                force,
            } => {
                assert!(ref_override.is_none());
                assert!(!force);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn parse_action_maps_exec_command() {
        let action = parse_action(
            vec!["exec".to_string(), "echo".to_string(), "ok".to_string()],
            false,
        )
        .expect("expected exec action parse");
        match action {
            DeployAction::Exec { command } => assert_eq!(command, "echo ok"),
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn parse_invocation_accepts_positional_config() {
        let invocation = parse_invocation(
            None,
            false,
            vec![
                "ecosystem.config.js".to_string(),
                "production".to_string(),
                "setup".to_string(),
            ],
        )
        .expect("expected invocation parse");
        assert_eq!(invocation.environment, "production");
        assert_eq!(invocation.config_path, PathBuf::from("ecosystem.config.js"));
    }

    #[test]
    fn extract_js_object_literal_handles_module_exports_wrapping() {
        let source = r#"
module.exports = {
  deploy: {
    production: {
      user: "ubuntu"
    }
  }
};
"#;
        let object = extract_js_object_literal(source).expect("expected object extraction");
        assert!(object.contains("deploy"));
        assert!(object.starts_with('{'));
        assert!(object.ends_with('}'));
    }

    #[test]
    fn load_target_reads_json_deploy_environment() {
        let path = temp_file("deploy-json", "json");
        let payload = r#"
{
  "deploy": {
    "production": {
      "user": "ubuntu",
      "host": ["1.2.3.4", "1.2.3.5"],
      "repo": "git@github.com:example/repo.git",
      "ref": "origin/main",
      "path": "/var/www/my-app",
      "post-deploy": "npm ci && oxmgr apply ./oxfile.toml --env production"
    }
  }
}
"#;
        fs::write(&path, payload).expect("failed writing deploy fixture");

        let target = load_target_from_file(&path, "production").expect("failed loading target");
        assert_eq!(target.user, "ubuntu");
        assert_eq!(target.hosts.len(), 2);
        assert_eq!(target.deploy_ref.as_deref(), Some("origin/main"));
        assert_eq!(target.path, "/var/www/my-app");

        let _ = fs::remove_file(path);
    }

    fn temp_file(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }
}
