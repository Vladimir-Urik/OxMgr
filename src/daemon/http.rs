use std::fmt::Write as _;
use std::str;

use anyhow::{Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::process::{ManagedProcess, ProcessStatus};
use crate::process_manager::ProcessManager;

use super::{DaemonSnapshot, ManagerCommand, JSON_CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE};

pub(super) async fn handle_api_client(
    mut stream: TcpStream,
    snapshot: DaemonSnapshot,
    command_tx: mpsc::UnboundedSender<ManagerCommand>,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;
    let response = if let Some(response) = execute_snapshot_api_request(&request, &snapshot).await {
        response
    } else {
        super::send_api_command(&command_tx, request).await?
    };
    write_http_response(&mut stream, &response).await
}

pub(super) async fn execute_snapshot_api_request(
    request: &HttpRequest,
    snapshot: &DaemonSnapshot,
) -> Option<HttpResponse> {
    if request.method == "GET" && request.path == "/metrics" {
        let processes = snapshot.list_processes().await;
        return Some(HttpResponse::text(
            200,
            PROMETHEUS_CONTENT_TYPE,
            render_prometheus_metrics(&processes),
        ));
    }

    None
}

pub(super) async fn execute_api_request(
    request: HttpRequest,
    manager: &mut ProcessManager,
) -> HttpResponse {
    if request.method != "POST" {
        return HttpResponse::error(405, "method not allowed");
    }

    let Some(target) = request.path.strip_prefix("/pull/") else {
        return HttpResponse::error(404, "not found");
    };
    if target.is_empty() {
        return HttpResponse::error(404, "not found");
    }

    if manager.get_process(target).is_err() {
        return HttpResponse::error(404, "service not found");
    }

    let Some(secret) = extract_api_secret(&request) else {
        return HttpResponse::error(401, "missing webhook secret");
    };

    if manager.verify_pull_webhook_secret(target, &secret).is_err() {
        return HttpResponse::error(401, "invalid webhook secret");
    }

    match manager.pull_processes(Some(target)).await {
        Ok(message) => HttpResponse::ok(message),
        Err(err) => HttpResponse::error(500, err.to_string()),
    }
}

pub(super) fn extract_api_secret(request: &HttpRequest) -> Option<String> {
    if let Some(value) = request.headers.get("x-oxmgr-secret") {
        return Some(value.trim().to_string());
    }
    request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
}

pub(super) fn render_prometheus_metrics(processes: &[ManagedProcess]) -> String {
    let mut body = String::new();

    body.push_str(
        "# HELP oxmgr_managed_processes Total number of processes currently managed by oxmgr.\n",
    );
    body.push_str("# TYPE oxmgr_managed_processes gauge\n");
    let _ = writeln!(body, "oxmgr_managed_processes {}", processes.len());
    body.push('\n');

    body.push_str("# HELP oxmgr_process_info Static metadata about each managed process.\n");
    body.push_str("# TYPE oxmgr_process_info gauge\n");
    for process in processes {
        let labels = process_metric_labels(
            process,
            &[
                ("desired_state", desired_state_label(process)),
                ("restart_policy", process.restart_policy.to_string()),
                ("status", process.status.to_string()),
            ],
        );
        let _ = writeln!(body, "oxmgr_process_info{labels} 1");
    }
    body.push('\n');

    body.push_str("# HELP oxmgr_process_up Whether the managed process is currently running.\n");
    body.push_str("# TYPE oxmgr_process_up gauge\n");
    for process in processes {
        let value =
            u8::from(matches!(process.status, ProcessStatus::Running) && process.pid.is_some());
        let _ = writeln!(
            body,
            "oxmgr_process_up{} {}",
            process_metric_labels(process, &[]),
            value
        );
    }
    body.push('\n');

    body.push_str(
        "# HELP oxmgr_process_restart_count Number of restarts recorded for the managed process.\n",
    );
    body.push_str("# TYPE oxmgr_process_restart_count counter\n");
    for process in processes {
        let _ = writeln!(
            body,
            "oxmgr_process_restart_count{} {}",
            process_metric_labels(process, &[]),
            process.restart_count
        );
    }
    body.push('\n');

    body.push_str(
        "# HELP oxmgr_process_cpu_percent Latest CPU usage percentage reported by oxmgr.\n",
    );
    body.push_str("# TYPE oxmgr_process_cpu_percent gauge\n");
    for process in processes {
        let _ = writeln!(
            body,
            "oxmgr_process_cpu_percent{} {}",
            process_metric_labels(process, &[]),
            sanitize_prometheus_f32(process.cpu_percent)
        );
    }
    body.push('\n');

    body.push_str(
        "# HELP oxmgr_process_memory_bytes Latest memory usage in bytes reported by oxmgr.\n",
    );
    body.push_str("# TYPE oxmgr_process_memory_bytes gauge\n");
    for process in processes {
        let _ = writeln!(
            body,
            "oxmgr_process_memory_bytes{} {}",
            process_metric_labels(process, &[]),
            process.memory_bytes
        );
    }
    body.push('\n');

    body.push_str("# HELP oxmgr_process_pid Current operating-system PID for the process, or 0 when unavailable.\n");
    body.push_str("# TYPE oxmgr_process_pid gauge\n");
    for process in processes {
        let _ = writeln!(
            body,
            "oxmgr_process_pid{} {}",
            process_metric_labels(process, &[]),
            process.pid.unwrap_or_default()
        );
    }
    body.push('\n');

    body.push_str("# HELP oxmgr_process_status Current lifecycle status of the managed process.\n");
    body.push_str("# TYPE oxmgr_process_status gauge\n");
    for process in processes {
        let labels = process_metric_labels(process, &[("status", process.status.to_string())]);
        let _ = writeln!(body, "oxmgr_process_status{labels} 1");
    }
    body.push('\n');

    body.push_str(
        "# HELP oxmgr_process_health_status Current health-check status of the managed process.\n",
    );
    body.push_str("# TYPE oxmgr_process_health_status gauge\n");
    for process in processes {
        let labels = process_metric_labels(
            process,
            &[("health_status", process.health_status.to_string())],
        );
        let _ = writeln!(body, "oxmgr_process_health_status{labels} 1");
    }
    body.push('\n');

    body.push_str("# HELP oxmgr_process_last_started_at_seconds Unix timestamp of the last successful start, or 0 when unknown.\n");
    body.push_str("# TYPE oxmgr_process_last_started_at_seconds gauge\n");
    for process in processes {
        let _ = writeln!(
            body,
            "oxmgr_process_last_started_at_seconds{} {}",
            process_metric_labels(process, &[]),
            process.last_started_at.unwrap_or_default()
        );
    }
    body.push('\n');

    body.push_str("# HELP oxmgr_process_last_metrics_at_seconds Unix timestamp of the last resource metrics refresh, or 0 when unknown.\n");
    body.push_str("# TYPE oxmgr_process_last_metrics_at_seconds gauge\n");
    for process in processes {
        let _ = writeln!(
            body,
            "oxmgr_process_last_metrics_at_seconds{} {}",
            process_metric_labels(process, &[]),
            process.last_metrics_at.unwrap_or_default()
        );
    }

    body
}

pub(super) fn escape_prometheus_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(super) struct HttpRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) headers: std::collections::HashMap<String, String>,
}

pub(super) struct HttpResponse {
    pub(super) status_code: u16,
    pub(super) content_type: &'static str,
    pub(super) body: HttpBody,
}

pub(super) enum HttpBody {
    Json(serde_json::Value),
    Text(String),
}

impl HttpResponse {
    fn ok(message: impl Into<String>) -> Self {
        Self::json(
            200,
            json!({
                "ok": true,
                "message": message.into()
            }),
        )
    }

    fn error(status_code: u16, message: impl Into<String>) -> Self {
        Self::json(
            status_code,
            json!({
                "ok": false,
                "message": message.into()
            }),
        )
    }

    fn json(status_code: u16, body: serde_json::Value) -> Self {
        Self {
            status_code,
            content_type: JSON_CONTENT_TYPE,
            body: HttpBody::Json(body),
        }
    }

    fn text(status_code: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status_code,
            content_type,
            body: HttpBody::Text(body.into()),
        }
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];

    loop {
        let read = timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .context("timed out while reading webhook request")?
            .context("failed to read webhook request")?;

        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);

        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            anyhow::bail!("webhook request headers exceed maximum size");
        }
    }

    let raw = str::from_utf8(&buffer).context("webhook request is not valid UTF-8")?;
    let header_end = raw
        .find("\r\n\r\n")
        .context("malformed webhook request headers")?;
    let head = &raw[..header_end];

    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .context("missing webhook request line")?
        .trim()
        .to_string();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .context("missing webhook request method")?
        .to_string();
    let path = request_parts
        .next()
        .context("missing webhook request path")?
        .to_string();

    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
    })
}

async fn write_http_response(stream: &mut TcpStream, response: &HttpResponse) -> Result<()> {
    let reason = http_reason_phrase(response.status_code);
    let body_text = match &response.body {
        HttpBody::Json(body) => {
            serde_json::to_string(body).context("failed to encode webhook response")?
        }
        HttpBody::Text(body) => body.clone(),
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status_code,
        reason,
        response.content_type,
        body_text.len(),
        body_text
    );

    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write webhook response")?;
    stream
        .flush()
        .await
        .context("failed to flush webhook response")?;
    let _ = stream.shutdown().await;
    Ok(())
}

fn http_reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn process_metric_labels(process: &ManagedProcess, extra: &[(&str, String)]) -> String {
    let mut labels = vec![
        ("id", process.id.to_string()),
        ("name", process.name.clone()),
        ("namespace", process.namespace.clone().unwrap_or_default()),
    ];
    labels.extend(extra.iter().map(|(key, value)| (*key, value.clone())));

    let mut rendered = String::from("{");
    for (index, (key, value)) in labels.iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }
        rendered.push_str(key);
        rendered.push_str("=\"");
        rendered.push_str(&escape_prometheus_label_value(value));
        rendered.push('"');
    }
    rendered.push('}');
    rendered
}

fn desired_state_label(process: &ManagedProcess) -> String {
    match process.desired_state {
        crate::process::DesiredState::Running => "running".to_string(),
        crate::process::DesiredState::Stopped => "stopped".to_string(),
    }
}

fn sanitize_prometheus_f32(value: f32) -> f32 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}
