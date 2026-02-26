use anyhow::Result;

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig, target: String) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::Restart { target }).await?;
    let response = expect_ok(response)?;
    println!("{}", response.message);

    Ok(())
}
