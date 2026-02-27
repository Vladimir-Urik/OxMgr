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
    Pull { target: Option<String> },
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

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{read_json_line, send_request, write_json_line, IpcRequest, IpcResponse};

    #[test]
    fn ipc_response_constructors_set_expected_fields() {
        let ok = IpcResponse::ok("ready");
        assert!(ok.ok);
        assert_eq!(ok.message, "ready");
        assert!(ok.process.is_none());
        assert!(ok.processes.is_empty());
        assert!(ok.logs.is_none());

        let err = IpcResponse::error("boom");
        assert!(!err.ok);
        assert_eq!(err.message, "boom");
        assert!(err.process.is_none());
        assert!(err.processes.is_empty());
        assert!(err.logs.is_none());
    }

    #[tokio::test]
    async fn read_and_write_json_line_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        let request = IpcRequest::Status {
            target: "api".to_string(),
        };

        write_json_line(&mut writer, &request)
            .await
            .expect("failed writing request payload");
        let decoded: IpcRequest = read_json_line(&mut reader)
            .await
            .expect("failed reading request payload");

        match decoded {
            IpcRequest::Status { target } => assert_eq!(target, "api"),
            other => panic!("unexpected request variant decoded: {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_json_line_fails_when_stream_is_closed() {
        let (writer, mut reader) = duplex(64);
        drop(writer);

        let err = read_json_line::<IpcResponse, _>(&mut reader)
            .await
            .expect_err("expected EOF to be treated as an error");
        assert!(
            err.to_string()
                .contains("daemon closed IPC connection unexpectedly"),
            "unexpected read error: {err}"
        );
    }

    #[tokio::test]
    async fn read_json_line_fails_on_invalid_payload() {
        let (mut writer, mut reader) = duplex(64);
        writer
            .write_all(b"this is not json\n")
            .await
            .expect("failed writing invalid payload");
        writer
            .flush()
            .await
            .expect("failed flushing invalid payload");

        let err = read_json_line::<IpcResponse, _>(&mut reader)
            .await
            .expect_err("expected decode failure");
        assert!(
            err.to_string()
                .contains("failed to decode daemon response/request payload"),
            "unexpected read error: {err}"
        );
    }

    #[tokio::test]
    async fn send_request_roundtrip_with_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind local listener");
        let addr = listener
            .local_addr()
            .expect("failed to resolve listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept failed");
            let request: IpcRequest = read_json_line(&mut stream).await.expect("read failed");
            assert!(matches!(request, IpcRequest::Ping));
            write_json_line(&mut stream, &IpcResponse::ok("pong"))
                .await
                .expect("write failed");
        });

        let response = send_request(&addr.to_string(), &IpcRequest::Ping)
            .await
            .expect("send_request failed");
        assert!(response.ok);
        assert_eq!(response.message, "pong");

        server.await.expect("server task failed");
    }
}
