use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::errors::OxmgrError;
use crate::process::ManagedProcess;

#[derive(Debug, Clone)]
pub(super) struct SpawnProgram {
    pub(super) program: String,
    pub(super) args: Vec<String>,
    pub(super) extra_env: HashMap<String, String>,
}

pub(super) fn parse_command_line(command_line: &str) -> Result<(String, Vec<String>)> {
    let tokens = shell_words::split(command_line)
        .map_err(|err| OxmgrError::InvalidCommand(err.to_string()))?;

    if tokens.is_empty() {
        return Err(OxmgrError::InvalidCommand("command cannot be empty".to_string()).into());
    }

    let command = tokens[0].clone();
    let args = tokens[1..].to_vec();
    Ok((command, args))
}

pub(super) fn resolve_spawn_program(
    process: &ManagedProcess,
    base_dir: &Path,
) -> Result<SpawnProgram> {
    if !process.cluster_mode {
        return Ok(SpawnProgram {
            program: process.command.clone(),
            args: process.args.clone(),
            extra_env: HashMap::new(),
        });
    }

    if !is_node_binary(&process.command) {
        anyhow::bail!("cluster mode requires a Node.js command (expected `node <script> ...`)");
    }
    let Some(script) = process.args.first() else {
        anyhow::bail!("cluster mode requires a script argument (expected `node <script> ...`)");
    };
    if script.starts_with('-') {
        anyhow::bail!(
            "cluster mode currently does not support Node runtime flags before script path"
        );
    }

    let bootstrap = ensure_node_cluster_bootstrap(base_dir)?;
    let mut args = Vec::with_capacity(process.args.len() + 2);
    args.push(bootstrap.display().to_string());
    args.push("--".to_string());
    args.extend(process.args.clone());

    let mut extra_env = HashMap::new();
    extra_env.insert(
        "OXMGR_CLUSTER_INSTANCES".to_string(),
        process
            .cluster_instances
            .map(|value| value.to_string())
            .unwrap_or_else(|| "auto".to_string()),
    );

    Ok(SpawnProgram {
        program: process.command.clone(),
        args,
        extra_env,
    })
}

fn ensure_node_cluster_bootstrap(base_dir: &Path) -> Result<PathBuf> {
    let runtime_dir = base_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "failed to create runtime directory {}",
            runtime_dir.display()
        )
    })?;

    let bootstrap_path = runtime_dir.join("node_cluster_bootstrap.cjs");
    fs::write(&bootstrap_path, NODE_CLUSTER_BOOTSTRAP).with_context(|| {
        format!(
            "failed to write node cluster bootstrap at {}",
            bootstrap_path.display()
        )
    })?;
    Ok(bootstrap_path)
}

pub(super) fn normalize_cluster_instances(value: Option<u32>) -> Option<u32> {
    value.filter(|instances| *instances > 0)
}

fn is_node_binary(command: &str) -> bool {
    let executable = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    matches!(
        executable.as_str(),
        "node" | "node.exe" | "nodejs" | "nodejs.exe"
    )
}

pub(super) fn validate_process_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(OxmgrError::InvalidProcessName("name cannot be empty".to_string()).into());
    }

    if name == "all" {
        return Err(OxmgrError::InvalidProcessName("'all' is a reserved name".to_string()).into());
    }

    let valid = name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');

    if !valid {
        return Err(OxmgrError::InvalidProcessName(name.to_string()).into());
    }
    Ok(())
}

pub(super) fn sanitize_name(input: &str) -> String {
    let value: String = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = value.trim_matches('-');
    if trimmed.is_empty() {
        "process".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

const NODE_CLUSTER_BOOTSTRAP: &str = r#""use strict";
const cluster = require("node:cluster");
const os = require("node:os");
const path = require("node:path");
const process = require("node:process");

function parseDesiredInstances(raw) {
  if (!raw || raw === "auto") return 0;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return parsed;
}

function cpuCount() {
  if (typeof os.availableParallelism === "function") {
    const value = os.availableParallelism();
    if (Number.isFinite(value) && value > 0) return value;
  }
  const cpus = os.cpus();
  return Array.isArray(cpus) && cpus.length > 0 ? cpus.length : 1;
}

const argv = process.argv.slice(2);
if (argv[0] === "--") argv.shift();
const script = argv.shift();

if (!script) {
  console.error("[oxmgr] cluster mode needs a script argument (expected: node <script> ...)");
  process.exit(2);
}

const desired = parseDesiredInstances(process.env.OXMGR_CLUSTER_INSTANCES || "");
const workerCount = desired > 0 ? desired : cpuCount();

cluster.setupPrimary({
  exec: path.resolve(script),
  args: argv
});

let shuttingDown = false;
let nextInstance = 0;

function forkWorker() {
  const env = { NODE_APP_INSTANCE: String(nextInstance) };
  nextInstance += 1;
  return cluster.fork(env);
}

for (let idx = 0; idx < workerCount; idx += 1) {
  forkWorker();
}

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  const workers = Object.values(cluster.workers).filter(Boolean);
  for (const worker of workers) {
    worker.process.kill(signal);
  }
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

cluster.on("exit", (worker) => {
  if (shuttingDown) return;
  if (worker.exitedAfterDisconnect) return;
  forkWorker();
});
"#;
