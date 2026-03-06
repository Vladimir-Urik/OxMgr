use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::process::ResourceLimits;

use super::ResolvedSettings;

pub(super) fn resource_limits_from(
    max_memory_restart: Option<Value>,
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
    cgroup_enforce: Option<bool>,
    deny_gpu: Option<bool>,
) -> Result<Option<ResourceLimits>> {
    let mut limits = ResourceLimits::default();

    if let Some(memory_mb) = max_memory_mb {
        if memory_mb > 0 {
            limits.max_memory_mb = Some(memory_mb);
        }
    }
    if let Some(cpu_percent) = max_cpu_percent {
        if cpu_percent > 0.0 {
            limits.max_cpu_percent = Some(cpu_percent);
        }
    }
    if let Some(memory_restart) = max_memory_restart {
        let parsed = parse_memory_limit_mb_value(&memory_restart)?;
        if parsed > 0 {
            limits.max_memory_mb = Some(parsed);
        }
    }
    limits.cgroup_enforce = cgroup_enforce.unwrap_or(false);
    limits.deny_gpu = deny_gpu.unwrap_or(false);

    Ok(normalize_resource_limits(limits))
}

pub(super) fn parse_memory_limit_mb_value(value: &Value) -> Result<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .context("max_memory_restart numeric value must be a positive integer"),
        Value::String(text) => parse_memory_limit_mb_str(text),
        _ => anyhow::bail!(
            "max_memory_restart must be a string like '256M' or a numeric value in MB"
        ),
    }
}

pub(super) fn set_memory_limit_mb(settings: &mut ResolvedSettings, value_mb: u64) {
    if value_mb == 0 {
        return;
    }
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.max_memory_mb = Some(value_mb);
    settings.resource_limits = normalize_resource_limits(limits);
}

pub(super) fn set_cpu_limit_percent(settings: &mut ResolvedSettings, value_percent: f32) {
    if value_percent <= 0.0 {
        return;
    }
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.max_cpu_percent = Some(value_percent);
    settings.resource_limits = normalize_resource_limits(limits);
}

pub(super) fn set_cgroup_enforce(settings: &mut ResolvedSettings, enabled: bool) {
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.cgroup_enforce = enabled;
    settings.resource_limits = normalize_resource_limits(limits);
}

pub(super) fn set_deny_gpu(settings: &mut ResolvedSettings, deny: bool) {
    let mut limits = settings.resource_limits.clone().unwrap_or_default();
    limits.deny_gpu = deny;
    settings.resource_limits = normalize_resource_limits(limits);
}

pub(super) fn normalize_pull_secret_hash(secret: Option<String>) -> Result<Option<String>> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        anyhow::bail!("pull_secret cannot be empty");
    }
    if trimmed.len() > 512 {
        anyhow::bail!("pull_secret exceeds maximum length 512");
    }

    let digest = Sha256::digest(trimmed.as_bytes());
    Ok(Some(format!("{:x}", digest)))
}

fn parse_memory_limit_mb_str(input: &str) -> Result<u64> {
    let normalized = input.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        anyhow::bail!("max_memory_restart cannot be empty");
    }

    let split_idx = normalized
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(normalized.len());
    let (number_part, unit_part) = normalized.split_at(split_idx);
    if number_part.is_empty() {
        anyhow::bail!("max_memory_restart is missing numeric value");
    }

    let numeric_value: f64 = number_part
        .parse()
        .with_context(|| format!("invalid max_memory_restart numeric value: {input}"))?;
    if numeric_value <= 0.0 {
        anyhow::bail!("max_memory_restart must be greater than zero");
    }

    let multiplier = match unit_part.trim() {
        "" | "M" | "MB" => 1.0,
        "K" | "KB" => 1.0 / 1024.0,
        "G" | "GB" => 1024.0,
        "B" => 1.0 / (1024.0 * 1024.0),
        other => anyhow::bail!("unsupported max_memory_restart unit: {other}"),
    };

    let mb = (numeric_value * multiplier).ceil() as u64;
    Ok(mb.max(1))
}

fn normalize_resource_limits(mut limits: ResourceLimits) -> Option<ResourceLimits> {
    if matches!(limits.max_memory_mb, Some(0)) {
        limits.max_memory_mb = None;
    }
    if matches!(limits.max_cpu_percent, Some(v) if v <= 0.0) {
        limits.max_cpu_percent = None;
    }
    if limits.max_memory_mb.is_none()
        && limits.max_cpu_percent.is_none()
        && !limits.cgroup_enforce
        && !limits.deny_gpu
    {
        None
    } else {
        Some(limits)
    }
}
