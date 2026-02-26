use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::logging::ProcessLogs;
use crate::process::{ManagedProcess, StartProcessSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    Shutdown,
    Start { spec: Box<StartProcessSpec> },
    Stop { target: String },
    Restart { target: String },
    Reload { target: String },
    Delete { target: String },
    List,
    Status { target: String },
    Logs { target: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub process: Option<ManagedProcess>,
    #[serde(default)]
    pub processes: Vec<ManagedProcess>,
    #[serde(default)]
    pub logs: Option<ProcessLogs>,
}

impl IpcResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            process: None,
            processes: Vec::new(),
            logs: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            process: None,
            processes: Vec::new(),
            logs: None,
        }
    }
}

pub async fn send_request(daemon_addr: &str, request: &IpcRequest) -> Result<IpcResponse> {
    let mut stream = TcpStream::connect(daemon_addr)
        .await
        .with_context(|| format!("failed to connect to daemon at {daemon_addr}"))?;
    write_json_line(&mut stream, request).await?;
    read_json_line(&mut stream).await
}

pub async fn read_json_line<T, S>(stream: &mut S) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    S: AsyncRead + Unpin,
{
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let bytes = reader
        .read_line(&mut line)
        .await
        .context("failed to read from IPC stream")?;

    if bytes == 0 {
        anyhow::bail!("daemon closed IPC connection unexpectedly");
    }

    serde_json::from_str::<T>(line.trim_end())
        .context("failed to decode daemon response/request payload")
}

pub async fn write_json_line<T, S>(stream: &mut S, value: &T) -> Result<()>
where
    T: Serialize,
    S: AsyncWrite + Unpin,
{
    let mut payload = serde_json::to_vec(value)?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .await
        .context("failed to write IPC payload")?;
    stream
        .flush()
        .await
        .context("failed to flush IPC payload")?;
    Ok(())
}
