use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::AppConfig;
use crate::ecosystem::EcosystemProcessSpec;
use crate::ipc::{send_request, IpcRequest};
use crate::oxfile;
use crate::process::StartProcessSpec;

pub(crate) async fn run(
    config: &AppConfig,
    path: PathBuf,
    env: Option<String>,
    only: Vec<String>,
) -> Result<()> {
    let mut specs = load_import_specs(&path, env.as_deref())?;
    if !only.is_empty() {
        specs.retain(|spec| {
            spec.name
                .as_ref()
                .map(|name| only.iter().any(|selected| selected == name))
                .unwrap_or(false)
        });
    }
    specs = order_specs_for_start(specs);

    if specs.is_empty() {
        println!("No apps found in {}", path.display());
        return Ok(());
    }

    let mut success = 0_usize;
    let mut failed = Vec::new();

    for spec in specs {
        let instances = spec.instances.max(1);
        for idx in 0..instances {
            let mut env_vars = spec.env.clone();
            if instances > 1 {
                let key = spec
                    .instance_var
                    .clone()
                    .unwrap_or_else(|| "NODE_APP_INSTANCE".to_string());
                env_vars.insert(key, idx.to_string());
            }

            let name = match (&spec.name, instances) {
                (Some(base), count) if count > 1 => Some(format!("{base}-{idx}")),
                (Some(base), _) => Some(base.clone()),
                (None, _) => None,
            };

            let response = send_request(
                &config.daemon_addr,
                &IpcRequest::Start {
                    spec: Box::new(StartProcessSpec {
                        command: spec.command.clone(),
                        name,
                        restart_policy: spec.restart_policy.clone(),
                        max_restarts: spec.max_restarts,
                        cwd: spec.cwd.clone(),
                        env: env_vars,
                        health_check: spec.health_check.clone(),
                        stop_signal: spec.stop_signal.clone(),
                        stop_timeout_secs: spec.stop_timeout_secs.max(1),
                        restart_delay_secs: spec.restart_delay_secs,
                        start_delay_secs: spec.start_delay_secs,
                        namespace: spec.namespace.clone(),
                        resource_limits: spec.resource_limits.clone(),
                    }),
                },
            )
            .await?;

            if response.ok {
                success += 1;
                println!("{}", response.message);
            } else {
                failed.push(response.message);
            }
        }
    }

    println!("Imported: {} started, {} failed", success, failed.len());
    if !failed.is_empty() {
        for message in failed {
            eprintln!("- {}", message);
        }
        anyhow::bail!("ecosystem import finished with failures");
    }

    Ok(())
}

pub(crate) fn load_import_specs(
    path: &Path,
    env: Option<&str>,
) -> Result<Vec<EcosystemProcessSpec>> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    match extension.as_deref() {
        Some("toml") => oxfile::load_with_profile(path, env),
        _ => crate::ecosystem::load_with_profile(path, env),
    }
}

pub(crate) fn order_specs_for_start(specs: Vec<EcosystemProcessSpec>) -> Vec<EcosystemProcessSpec> {
    let mut by_name = HashMap::new();
    for (idx, spec) in specs.iter().enumerate() {
        if let Some(name) = &spec.name {
            by_name.insert(name.clone(), idx);
        }
    }

    let mut indegree = vec![0_usize; specs.len()];
    let mut edges = vec![Vec::<usize>::new(); specs.len()];

    for (idx, spec) in specs.iter().enumerate() {
        for dependency in &spec.depends_on {
            if let Some(dep_idx) = by_name.get(dependency) {
                edges[*dep_idx].push(idx);
                indegree[idx] = indegree[idx].saturating_add(1);
            }
        }
    }

    let mut remaining: HashSet<usize> = (0..specs.len()).collect();
    let mut ordered_indices = Vec::with_capacity(specs.len());

    while !remaining.is_empty() {
        let mut ready: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|idx| indegree[*idx] == 0)
            .collect();

        if ready.is_empty() {
            let mut leftovers: Vec<usize> = remaining.iter().copied().collect();
            leftovers.sort_by(|left, right| {
                let left_spec = &specs[*left];
                let right_spec = &specs[*right];

                left_spec
                    .start_order
                    .cmp(&right_spec.start_order)
                    .then_with(|| left_spec.name.cmp(&right_spec.name))
                    .then_with(|| left.cmp(right))
            });
            ordered_indices.extend(leftovers);
            break;
        }

        ready.sort_by(|left, right| {
            let left_spec = &specs[*left];
            let right_spec = &specs[*right];

            left_spec
                .start_order
                .cmp(&right_spec.start_order)
                .then_with(|| left_spec.name.cmp(&right_spec.name))
                .then_with(|| left.cmp(right))
        });

        let current = ready[0];
        remaining.remove(&current);
        ordered_indices.push(current);
        for next in &edges[current] {
            indegree[*next] = indegree[*next].saturating_sub(1);
        }
    }

    let mut slots: Vec<Option<EcosystemProcessSpec>> = specs.into_iter().map(Some).collect();
    let mut ordered = Vec::with_capacity(slots.len());
    for idx in ordered_indices {
        if let Some(spec) = slots[idx].take() {
            ordered.push(spec);
        }
    }

    ordered
}
