use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::process::{
    HealthCheck, ManagedProcess, ResourceLimits, RestartPolicy, StartProcessSpec,
};

const MAGIC: &[u8; 8] = b"OXBUNDLE";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 4 + 4 + 32;
const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_SERVICE_COUNT: usize = 512;
const MAX_ENV_VARS: usize = 256;
const MAX_NAME_LEN: usize = 128;
const MAX_PROGRAM_LEN: usize = 2048;
const MAX_ARG_LEN: usize = 4096;
const MAX_COMMAND_PARTS: usize = 256;
const MAX_ENV_KEY_LEN: usize = 128;
const MAX_ENV_VALUE_LEN: usize = 4096;
const MAX_STOP_TIMEOUT_SECS: u64 = 24 * 60 * 60;
const MAX_DELAY_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Serialize, Deserialize)]
struct BundlePayload {
    kind: String,
    version: u8,
    created_at: u64,
    services: Vec<BundleService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleService {
    name: String,
    program: String,
    #[serde(default)]
    args: Vec<String>,
    restart_policy: RestartPolicy,
    max_restarts: u32,
    crash_restart_limit: u32,
    #[serde(default)]
    cwd: Option<PathBuf>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    health_check: Option<HealthCheck>,
    #[serde(default)]
    stop_signal: Option<String>,
    stop_timeout_secs: u64,
    restart_delay_secs: u64,
    start_delay_secs: u64,
    #[serde(default)]
    watch: bool,
    #[serde(default)]
    cluster_mode: bool,
    #[serde(default)]
    cluster_instances: Option<u32>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    resource_limits: Option<ResourceLimits>,
    #[serde(default)]
    git_repo: Option<String>,
    #[serde(default)]
    git_ref: Option<String>,
    #[serde(default)]
    pull_secret_hash: Option<String>,
}

pub fn default_bundle_file_name(process_name: &str) -> String {
    let mut clean: String = process_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if clean.trim_matches('_').is_empty() {
        clean = "service".to_string();
    }
    format!("{clean}.oxpkg")
}

pub fn looks_like_bundle(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

pub fn max_bundle_bytes() -> usize {
    MAX_BUNDLE_BYTES
}

pub fn encode_bundle(processes: &[ManagedProcess]) -> Result<Vec<u8>> {
    if processes.is_empty() {
        anyhow::bail!("cannot export an empty process selection");
    }
    if processes.len() > MAX_SERVICE_COUNT {
        anyhow::bail!("cannot export more than {MAX_SERVICE_COUNT} processes in a single bundle");
    }

    let mut services = Vec::with_capacity(processes.len());
    for process in processes {
        let service = BundleService::from_managed(process);
        validate_service(&service)?;
        services.push(service);
    }

    let payload = BundlePayload {
        kind: "oxmgr_bundle".to_string(),
        version: FORMAT_VERSION,
        created_at: now_epoch_secs(),
        services,
    };
    let json = serde_json::to_vec(&payload).context("failed to serialize export bundle")?;
    if json.len() > MAX_JSON_BYTES {
        anyhow::bail!(
            "bundle is too large after serialization ({} bytes > {} bytes)",
            json.len(),
            MAX_JSON_BYTES
        );
    }

    let uncompressed_len = json.len();
    let hash = Sha256::digest(&json);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&json)
        .context("failed to compress export bundle")?;
    let compressed = encoder
        .finish()
        .context("failed to finalize compressed export bundle")?;

    if compressed.len() > MAX_BUNDLE_BYTES {
        anyhow::bail!(
            "compressed bundle is too large ({} bytes > {} bytes)",
            compressed.len(),
            MAX_BUNDLE_BYTES
        );
    }

    let payload_len = u32::try_from(compressed.len()).context("bundle payload too large")?;
    let uncompressed_len =
        u32::try_from(uncompressed_len).context("bundle uncompressed payload too large")?;

    let mut out = Vec::with_capacity(HEADER_LEN + compressed.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&uncompressed_len.to_le_bytes());
    out.extend_from_slice(hash.as_slice());
    out.extend_from_slice(&compressed);
    Ok(out)
}

pub fn decode_bundle(bytes: &[u8]) -> Result<Vec<StartProcessSpec>> {
    if bytes.len() < HEADER_LEN {
        anyhow::bail!("invalid bundle: payload too small");
    }
    if bytes.len() > HEADER_LEN + MAX_BUNDLE_BYTES {
        anyhow::bail!("invalid bundle: payload exceeds maximum allowed size");
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        anyhow::bail!("invalid bundle: magic header mismatch");
    }

    let version = bytes[MAGIC.len()];
    if version != FORMAT_VERSION {
        anyhow::bail!("unsupported bundle version {version}");
    }

    let payload_len = u32::from_le_bytes(
        bytes[9..13]
            .try_into()
            .context("invalid bundle: malformed payload length")?,
    ) as usize;
    let expected_json_len = u32::from_le_bytes(
        bytes[13..17]
            .try_into()
            .context("invalid bundle: malformed uncompressed length")?,
    ) as usize;

    if payload_len > MAX_BUNDLE_BYTES {
        anyhow::bail!("invalid bundle: compressed payload exceeds allowed limit");
    }
    if expected_json_len > MAX_JSON_BYTES {
        anyhow::bail!("invalid bundle: decompressed payload exceeds allowed limit");
    }

    let expected_len = HEADER_LEN + payload_len;
    if bytes.len() != expected_len {
        anyhow::bail!(
            "invalid bundle: expected {} bytes, got {} bytes",
            expected_len,
            bytes.len()
        );
    }

    let expected_hash = &bytes[17..49];
    let compressed = &bytes[49..];
    let decoded = decompress_payload(compressed)?;

    if decoded.len() != expected_json_len {
        anyhow::bail!(
            "invalid bundle: decompressed length mismatch (expected {}, got {})",
            expected_json_len,
            decoded.len()
        );
    }

    let actual_hash = Sha256::digest(&decoded);
    if actual_hash.as_slice() != expected_hash {
        anyhow::bail!("invalid bundle: checksum mismatch");
    }

    let parsed: BundlePayload =
        serde_json::from_slice(&decoded).context("failed to decode bundle metadata")?;
    if parsed.kind != "oxmgr_bundle" {
        anyhow::bail!("invalid bundle kind: {}", parsed.kind);
    }
    if parsed.version != FORMAT_VERSION {
        anyhow::bail!("unsupported bundle payload version {}", parsed.version);
    }
    if parsed.services.is_empty() {
        anyhow::bail!("bundle does not include any services");
    }
    if parsed.services.len() > MAX_SERVICE_COUNT {
        anyhow::bail!(
            "bundle includes too many services ({} > {})",
            parsed.services.len(),
            MAX_SERVICE_COUNT
        );
    }

    let mut seen_names = HashSet::new();
    let mut result = Vec::with_capacity(parsed.services.len());
    for service in parsed.services {
        validate_service(&service)?;
        if !seen_names.insert(service.name.clone()) {
            anyhow::bail!("bundle contains duplicate service name '{}'", service.name);
        }
        result.push(service.into_start_spec());
    }

    Ok(result)
}

pub fn command_line_from_parts(program: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_words::quote(program).to_string());
    for arg in args {
        parts.push(shell_words::quote(arg).to_string());
    }
    parts.join(" ")
}

impl BundleService {
    fn from_managed(process: &ManagedProcess) -> Self {
        Self {
            name: process.name.clone(),
            program: process.command.clone(),
            args: process.args.clone(),
            restart_policy: process.restart_policy.clone(),
            max_restarts: process.max_restarts,
            crash_restart_limit: process.crash_restart_limit,
            cwd: process.cwd.clone(),
            env: process.env.clone(),
            health_check: process.health_check.clone(),
            stop_signal: process.stop_signal.clone(),
            stop_timeout_secs: process.stop_timeout_secs.max(1),
            restart_delay_secs: process.restart_delay_secs,
            start_delay_secs: process.start_delay_secs,
            watch: process.watch,
            cluster_mode: process.cluster_mode,
            cluster_instances: process.cluster_instances.map(|value| value.max(1)),
            namespace: process.namespace.clone(),
            resource_limits: process.resource_limits.clone(),
            git_repo: process.git_repo.clone(),
            git_ref: process.git_ref.clone(),
            pull_secret_hash: process.pull_secret_hash.clone(),
        }
    }

    fn into_start_spec(self) -> StartProcessSpec {
        StartProcessSpec {
            command: command_line_from_parts(&self.program, &self.args),
            name: Some(self.name),
            restart_policy: self.restart_policy,
            max_restarts: self.max_restarts,
            crash_restart_limit: self.crash_restart_limit,
            cwd: self.cwd,
            env: self.env,
            health_check: self.health_check,
            stop_signal: self.stop_signal,
            stop_timeout_secs: self.stop_timeout_secs.max(1),
            restart_delay_secs: self.restart_delay_secs,
            start_delay_secs: self.start_delay_secs,
            watch: self.watch,
            cluster_mode: self.cluster_mode,
            cluster_instances: if self.cluster_mode {
                self.cluster_instances.map(|value| value.max(1))
            } else {
                None
            },
            namespace: self.namespace,
            resource_limits: self.resource_limits,
            git_repo: self.git_repo,
            git_ref: self.git_ref,
            pull_secret_hash: self.pull_secret_hash,
        }
    }
}

fn decompress_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(payload);
    let mut result = Vec::new();
    let mut chunk = [0_u8; 8192];

    loop {
        let read = decoder
            .read(&mut chunk)
            .context("failed to decompress bundle payload")?;
        if read == 0 {
            break;
        }
        if result.len() + read > MAX_JSON_BYTES {
            anyhow::bail!("invalid bundle: decompressed payload exceeds allowed limit");
        }
        result.extend_from_slice(&chunk[..read]);
    }

    Ok(result)
}

fn validate_service(service: &BundleService) -> Result<()> {
    if service.name.trim().is_empty() {
        anyhow::bail!("service name cannot be empty");
    }
    if service.name.len() > MAX_NAME_LEN {
        anyhow::bail!(
            "service name '{}' exceeds maximum length {}",
            service.name,
            MAX_NAME_LEN
        );
    }
    if service.program.trim().is_empty() {
        anyhow::bail!("service '{}' has an empty program", service.name);
    }
    if service.program.len() > MAX_PROGRAM_LEN {
        anyhow::bail!(
            "service '{}' program exceeds maximum length {}",
            service.name,
            MAX_PROGRAM_LEN
        );
    }
    if service.args.len() > MAX_COMMAND_PARTS {
        anyhow::bail!(
            "service '{}' exceeds max arg count {}",
            service.name,
            MAX_COMMAND_PARTS
        );
    }
    if service.args.iter().any(|arg| arg.len() > MAX_ARG_LEN) {
        anyhow::bail!(
            "service '{}' includes an argument that exceeds {} characters",
            service.name,
            MAX_ARG_LEN
        );
    }
    if service.stop_timeout_secs == 0 || service.stop_timeout_secs > MAX_STOP_TIMEOUT_SECS {
        anyhow::bail!(
            "service '{}' has invalid stop_timeout_secs {}",
            service.name,
            service.stop_timeout_secs
        );
    }
    if service.restart_delay_secs > MAX_DELAY_SECS {
        anyhow::bail!(
            "service '{}' restart_delay_secs exceeds {}",
            service.name,
            MAX_DELAY_SECS
        );
    }
    if service.start_delay_secs > MAX_DELAY_SECS {
        anyhow::bail!(
            "service '{}' start_delay_secs exceeds {}",
            service.name,
            MAX_DELAY_SECS
        );
    }
    if service.env.len() > MAX_ENV_VARS {
        anyhow::bail!(
            "service '{}' exceeds max env var count {}",
            service.name,
            MAX_ENV_VARS
        );
    }

    for (key, value) in &service.env {
        if key.is_empty() || key.len() > MAX_ENV_KEY_LEN || !is_safe_env_key(key) {
            anyhow::bail!("service '{}' has invalid env key '{}'", service.name, key);
        }
        if value.len() > MAX_ENV_VALUE_LEN {
            anyhow::bail!(
                "service '{}' has env value for '{}' exceeding {} characters",
                service.name,
                key,
                MAX_ENV_VALUE_LEN
            );
        }
    }

    if let Some(health) = service.health_check.as_ref() {
        if health.command.trim().is_empty() || health.command.len() > MAX_PROGRAM_LEN {
            anyhow::bail!("service '{}' has invalid health command", service.name);
        }
        if health.interval_secs == 0 || health.timeout_secs == 0 || health.max_failures == 0 {
            anyhow::bail!("service '{}' has invalid health thresholds", service.name);
        }
    }

    if !service.cluster_mode && service.cluster_instances.is_some() {
        anyhow::bail!(
            "service '{}' sets cluster_instances without cluster_mode",
            service.name
        );
    }
    if let Some(instances) = service.cluster_instances {
        if instances == 0 {
            anyhow::bail!("service '{}' has invalid cluster_instances 0", service.name);
        }
    }
    if let Some(secret_hash) = service.pull_secret_hash.as_deref() {
        if secret_hash.len() != 64 || !secret_hash.bytes().all(|ch| ch.is_ascii_hexdigit()) {
            anyhow::bail!("service '{}' has invalid pull_secret_hash", service.name);
        }
    }

    Ok(())
}

fn is_safe_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::{decode_bundle, encode_bundle, looks_like_bundle, BundleService};
    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy,
    };

    #[test]
    fn encode_decode_roundtrip_preserves_start_spec() {
        let process = fixture_process();
        let encoded = encode_bundle(&[process]).expect("bundle encoding failed");
        assert!(looks_like_bundle(&encoded));

        let decoded = decode_bundle(&encoded).expect("bundle decoding failed");
        assert_eq!(decoded.len(), 1);
        let spec = &decoded[0];
        assert_eq!(spec.name.as_deref(), Some("api"));
        assert_eq!(spec.command, "node server.js --port 3000");
        assert_eq!(spec.stop_timeout_secs, 15);
        assert_eq!(spec.max_restarts, 10);
        assert_eq!(spec.crash_restart_limit, 3);
        assert!(spec.watch);
        assert_eq!(spec.git_repo.as_deref(), Some("git@github.com:org/api.git"));
        assert_eq!(spec.git_ref.as_deref(), Some("main"));
        assert_eq!(
            spec.pull_secret_hash.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn decode_bundle_rejects_tampered_payload() {
        let process = fixture_process();
        let mut encoded = encode_bundle(&[process]).expect("bundle encoding failed");
        let index = encoded.len() - 1;
        encoded[index] ^= 0xFF;

        let err = decode_bundle(&encoded).expect_err("expected corruption error");
        assert!(
            err.to_string().contains("checksum mismatch")
                || err.to_string().contains("decompress bundle payload"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decode_bundle_rejects_invalid_env_key() {
        let payload = BundleService {
            name: "api".to_string(),
            program: "node".to_string(),
            args: vec!["server.js".to_string()],
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::from([("BAD-KEY".to_string(), "1".to_string())]),
            health_check: None,
            stop_signal: None,
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
        };

        let err = super::validate_service(&payload).expect_err("expected validation error");
        assert!(
            err.to_string().contains("invalid env key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_service_rejects_invalid_pull_secret_hash_length() {
        let payload = BundleService {
            name: "api".to_string(),
            program: "node".to_string(),
            args: vec!["server.js".to_string()],
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: None,
            stop_signal: None,
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: Some("abc123".to_string()),
        };

        let err = super::validate_service(&payload).expect_err("expected hash validation error");
        assert!(err.to_string().contains("invalid pull_secret_hash"));
    }

    fn fixture_process() -> ManagedProcess {
        ManagedProcess {
            id: 7,
            name: "api".to_string(),
            command: "node".to_string(),
            args: vec![
                "server.js".to_string(),
                "--port".to_string(),
                "3000".to_string(),
            ],
            cwd: Some(PathBuf::from("/srv/api")),
            env: HashMap::from([("NODE_ENV".to_string(), "production".to_string())]),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            restart_count: 0,
            crash_restart_limit: 3,
            auto_restart_history: Vec::new(),
            namespace: Some("backend".to_string()),
            git_repo: Some("git@github.com:org/api.git".to_string()),
            git_ref: Some("main".to_string()),
            pull_secret_hash: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 15,
            restart_delay_secs: 1,
            restart_backoff_cap_secs: 300,
            restart_backoff_reset_secs: 60,
            restart_backoff_attempt: 0,
            start_delay_secs: 0,
            watch: true,
            cluster_mode: false,
            cluster_instances: None,
            resource_limits: None,
            cgroup_path: None,
            pid: Some(12345),
            status: ProcessStatus::Running,
            desired_state: DesiredState::Running,
            last_exit_code: None,
            stdout_log: PathBuf::from("/tmp/api.out.log"),
            stderr_log: PathBuf::from("/tmp/api.err.log"),
            health_check: None,
            health_status: HealthStatus::Unknown,
            health_failures: 0,
            last_health_check: None,
            next_health_check: None,
            last_health_error: None,
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: None,
            last_stopped_at: None,
        }
    }
}
