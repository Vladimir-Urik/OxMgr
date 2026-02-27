use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::bundle::{default_bundle_file_name, encode_bundle};
use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig, target: String, out: Option<PathBuf>) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::Status { target }).await?;
    let response = expect_ok(response)?;
    let process = response
        .process
        .context("daemon returned no process for export command")?;

    let output_path = resolve_output_path(&process.name, out)?;
    let bundle = encode_bundle(&[process])?;
    write_bundle_file(&output_path, &bundle)?;

    println!(
        "Exported service bundle: {} ({} bytes)",
        output_path.display(),
        bundle.len()
    );
    Ok(())
}

fn resolve_output_path(process_name: &str, out: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = out {
        return Ok(path);
    }
    Ok(std::env::current_dir()
        .context("failed to resolve current working directory")?
        .join(default_bundle_file_name(process_name)))
}

fn write_bundle_file(path: &PathBuf, payload: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create bundle file {}", path.display()))?;
    file.write_all(payload)
        .with_context(|| format!("failed to write bundle file {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush bundle file {}", path.display()))?;
    Ok(())
}
