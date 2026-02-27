use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use url::Url;

use crate::bundle::{decode_bundle, looks_like_bundle, max_bundle_bytes};
use crate::config::AppConfig;
use crate::ecosystem::EcosystemProcessSpec;
use crate::ipc::{send_request, IpcRequest};
use crate::oxfile;
use crate::process::StartProcessSpec;

pub(crate) async fn run(
    config: &AppConfig,
    source: String,
    env: Option<String>,
    only: Vec<String>,
    sha256: Option<String>,
) -> Result<()> {
    let mut start_specs = if is_remote_source(&source) {
        if sha256.is_none() {
            eprintln!(
                "warning: importing remote bundle without --sha256 pin; integrity pinning is recommended"
            );
        }
        load_remote_bundle_specs(&source, sha256.as_deref()).await?
    } else {
        load_local_specs(&source, env.as_deref())?
    };

    if !only.is_empty() {
        start_specs.retain(|spec| {
            spec.name
                .as_ref()
                .map(|name| only.iter().any(|selected| selected == name))
                .unwrap_or(false)
        });
    }

    if start_specs.is_empty() {
        println!("No apps found in {source}");
        return Ok(());
    }

    let mut success = 0_usize;
    let mut failed = Vec::new();

    for spec in start_specs {
        let response = send_request(
            &config.daemon_addr,
            &IpcRequest::Start {
                spec: Box::new(spec),
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

    println!("Imported: {} started, {} failed", success, failed.len());
    if !failed.is_empty() {
        for message in failed {
            eprintln!("- {}", message);
        }
        anyhow::bail!("import finished with failures");
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

fn load_local_specs(source: &str, env: Option<&str>) -> Result<Vec<StartProcessSpec>> {
    let path = PathBuf::from(source);
    if !path.exists() {
        anyhow::bail!("import source not found: {}", path.display());
    }
    if !path.is_file() {
        anyhow::bail!("import source is not a file: {}", path.display());
    }

    let metadata = fs::metadata(&path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let has_bundle_extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("oxpkg"))
        .unwrap_or(false);

    if has_bundle_extension && metadata.len() as usize > max_bundle_bytes() + 128 {
        anyhow::bail!(
            "bundle file {} is too large ({} bytes > {} bytes)",
            path.display(),
            metadata.len(),
            max_bundle_bytes() + 128
        );
    }

    if metadata.len() as usize <= max_bundle_bytes() + 128 {
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read import source {}", path.display()))?;
        if looks_like_bundle(&bytes) {
            return decode_bundle(&bytes).with_context(|| {
                format!(
                    "failed to decode exported service bundle {}",
                    path.display()
                )
            });
        }
        if has_bundle_extension {
            anyhow::bail!(
                "file {} has .oxpkg extension but does not contain a valid oxmgr bundle",
                path.display()
            );
        }
    }

    let specs = load_import_specs(&path, env)?;
    let ordered = order_specs_for_start(specs);
    Ok(expand_ecosystem_specs(ordered))
}

async fn load_remote_bundle_specs(
    source: &str,
    sha256: Option<&str>,
) -> Result<Vec<StartProcessSpec>> {
    let url = parse_secure_remote_url(source)?;
    let bytes = download_remote_bundle(&url).await?;

    if bytes.is_empty() {
        anyhow::bail!("remote import payload is empty");
    }

    if let Some(pin) = sha256 {
        verify_sha256(&bytes, pin)?;
    }

    if !looks_like_bundle(&bytes) {
        anyhow::bail!("remote imports only support oxmgr exported bundle files");
    }

    decode_bundle(&bytes).with_context(|| format!("failed to decode remote bundle from {url}"))
}

async fn download_remote_bundle(url: &Url) -> Result<Vec<u8>> {
    let mut command = Command::new("curl");
    command
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("--location")
        .arg("--max-redirs")
        .arg("5")
        .arg("--proto")
        .arg("=https")
        .arg("--proto-redir")
        .arg("=https")
        .arg("--max-time")
        .arg("30")
        .arg("--connect-timeout")
        .arg("10")
        .arg(url.as_str());

    let output = match command.output().await {
        Ok(output) => output,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            anyhow::bail!(
                "curl is required for remote imports but is not available in PATH on this machine"
            );
        }
        Err(err) => {
            return Err(err).with_context(|| format!("failed to start curl for {url}"));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to download {url} via curl: {}", stderr.trim());
    }

    if output.stdout.len() > max_bundle_bytes() {
        anyhow::bail!(
            "remote import exceeds max allowed size of {} bytes",
            max_bundle_bytes()
        );
    }

    Ok(output.stdout)
}

fn parse_secure_remote_url(source: &str) -> Result<Url> {
    let url = Url::parse(source).context("invalid remote import URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("remote imports require https:// URLs");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("remote import URL must not include credentials");
    }
    if url.host().is_none() {
        anyhow::bail!("remote import URL is missing host");
    }
    if url.fragment().is_some() {
        anyhow::bail!("remote import URL must not include a fragment");
    }
    Ok(url)
}

fn verify_sha256(payload: &[u8], expected_hex: &str) -> Result<()> {
    let normalized = expected_hex.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("--sha256 must be a 64-character hexadecimal SHA-256 digest");
    }

    let digest = Sha256::digest(payload);
    let actual = format!("{:x}", digest);
    if actual != normalized {
        anyhow::bail!("remote import checksum mismatch for --sha256 pin");
    }
    Ok(())
}

fn is_remote_source(source: &str) -> bool {
    source.starts_with("https://") || source.starts_with("http://")
}

fn expand_ecosystem_specs(specs: Vec<EcosystemProcessSpec>) -> Vec<StartProcessSpec> {
    let mut result = Vec::new();

    for spec in specs {
        let instances = spec.instances.max(1);
        for idx in 0..instances {
            let mut env = spec.env.clone();
            if instances > 1 {
                let key = spec
                    .instance_var
                    .clone()
                    .unwrap_or_else(|| "NODE_APP_INSTANCE".to_string());
                env.insert(key, idx.to_string());
            }

            let name = match (&spec.name, instances) {
                (Some(base), count) if count > 1 => Some(format!("{base}-{idx}")),
                (Some(base), _) => Some(base.clone()),
                (None, _) => None,
            };

            result.push(StartProcessSpec {
                command: spec.command.clone(),
                name,
                restart_policy: spec.restart_policy.clone(),
                max_restarts: spec.max_restarts,
                cwd: spec.cwd.clone(),
                env,
                health_check: spec.health_check.clone(),
                stop_signal: spec.stop_signal.clone(),
                stop_timeout_secs: spec.stop_timeout_secs.max(1),
                restart_delay_secs: spec.restart_delay_secs,
                start_delay_secs: spec.start_delay_secs,
                watch: false,
                cluster_mode: spec.cluster_mode,
                cluster_instances: spec.cluster_instances,
                namespace: spec.namespace.clone(),
                resource_limits: spec.resource_limits.clone(),
            });
        }
    }

    result
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

#[cfg(test)]
mod tests {
    use super::{is_remote_source, parse_secure_remote_url, verify_sha256};

    #[test]
    fn parse_secure_remote_url_accepts_https_without_credentials() {
        let parsed = parse_secure_remote_url("https://example.com/path/file.oxpkg")
            .expect("expected secure URL to parse");
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("example.com"));
    }

    #[test]
    fn parse_secure_remote_url_rejects_http_and_credentials() {
        let insecure = parse_secure_remote_url("http://example.com/file.oxpkg")
            .expect_err("expected non-https URL rejection");
        assert!(insecure.to_string().contains("https://"));

        let with_credentials = parse_secure_remote_url("https://user:pass@example.com/file.oxpkg")
            .expect_err("expected URL credential rejection");
        assert!(with_credentials.to_string().contains("credentials"));
    }

    #[test]
    fn verify_sha256_validates_expected_digest() {
        verify_sha256(
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .expect("expected checksum verification to pass");

        let err = verify_sha256(
            b"abc",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect_err("expected checksum mismatch");
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn is_remote_source_only_matches_http_schemes() {
        assert!(is_remote_source("https://example.com/a.oxpkg"));
        assert!(is_remote_source("http://example.com/a.oxpkg"));
        assert!(!is_remote_source("./a.oxpkg"));
    }
}
