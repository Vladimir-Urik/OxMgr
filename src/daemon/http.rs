use std::collections::HashMap;
use std::fmt::Write as _;
use std::str;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::process::{ManagedProcess, ProcessStatus};
use crate::process_manager::ProcessManager;

use super::{DaemonSnapshot, ManagerCommand, JSON_CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE};

/// Embedded single-page web dashboard served at `GET /`.
///
/// HTML, CSS, and JS live as separate files under `web/` for maintainability
/// and are embedded into the binary at compile time. The CSS and JS are
/// injected into the HTML shell when the root route is served.
const DASHBOARD_HTML: &str = include_str!("../../web/dashboard.html");
const DASHBOARD_CSS: &str = include_str!("../../web/dashboard.css");
const DASHBOARD_JS: &str = include_str!("../../web/dashboard.js");
const FAVICON_SVG: &str = include_str!("../../web/favicon.svg");
const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const TEXT_PLAIN_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const SVG_CONTENT_TYPE: &str = "image/svg+xml; charset=utf-8";
/// Build version injected at compile time by `build.rs` (mirrors the CLI).
const BUILD_VERSION: &str = env!("OXMGR_BUILD_VERSION");

/// Env vars that configure dashboard Basic Auth (see `dashboard_auth`).
const ENV_DASHBOARD_USER: &str = "OXMGR_DASHBOARD_USER";
const ENV_DASHBOARD_PASS: &str = "OXMGR_DASHBOARD_PASS";

/// Renders the dashboard HTML shell with the embedded CSS and JS injected.
fn render_dashboard_html() -> String {
    DASHBOARD_HTML
        .replace(
            "</head>",
            &format!(
                "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap\">\n<style>\n{DASHBOARD_CSS}\n</style>\n</head>"
            ),
        )
        .replace("</body>", &format!("<script>\n{DASHBOARD_JS}\n</script>\n</body>"))
        .replace(
            "Ox<span>Mgr</span> Dashboard",
            &format!("Ox<span>Mgr</span> Dashboard <span class=\"version\">v{BUILD_VERSION}</span>"),
        )
}

/// Dashboard credentials from the environment. Auth is enabled only when the
/// user provides both a username and a password, e.g.:
///   OXMGR_DASHBOARD_USER=admin OXMGR_DASHBOARD_PASS=s3cret
fn dashboard_auth() -> Option<(String, String)> {
    let user = std::env::var(ENV_DASHBOARD_USER).ok()?;
    let pass = std::env::var(ENV_DASHBOARD_PASS).ok()?;
    if user.trim().is_empty() || pass.is_empty() {
        return None;
    }
    Some((user, pass))
}

/// Verifies the `Authorization: Basic <base64(user:pass)>` header. Returns
/// `true` when auth is disabled, or when the provided credentials match.
fn auth_ok(headers: &std::collections::HashMap<String, String>) -> bool {
    let Some((expected_user, expected_pass)) = dashboard_auth() else {
        return true;
    };
    let Some(auth) = headers.get("authorization") else {
        return false;
    };
    let Some(encoded) = auth
        .strip_prefix("Basic ")
        .or_else(|| auth.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    if let Some((user, pass)) = decoded.split_once(':') {
        user == expected_user && pass == expected_pass
    } else {
        false
    }
}

/// A `401 Unauthorized` response with a `WWW-Authenticate` challenge, used to
/// protect the dashboard and REST API when credentials are configured.
fn unauthorized_response() -> HttpResponse {
    let mut response = HttpResponse::error(401, "authentication required");
    response.content_type = TEXT_PLAIN_CONTENT_TYPE;
    response.body = HttpBody::Text("authentication required".to_string());
    response.headers.insert(
        "WWW-Authenticate".to_string(),
        "Basic realm=\"oxmgr dashboard\"".to_string(),
    );
    response
}

/// Routes an incoming webhook/API client to the appropriate handler after
/// applying request middleware.
///
/// Middleware chain:
///   - Basic Auth: protects the dashboard page and all `/api/*` routes when
///     `OXMGR_DASHBOARD_USER` / `OXMGR_DASHBOARD_PASS` are configured.
///   - Non-protected routes (`/metrics`, `/pull/*`) pass through unchanged;
///     `/pull/*` enforces its own webhook-secret check later.
pub(super) async fn handle_api_client(
    mut stream: TcpStream,
    snapshot: DaemonSnapshot,
    command_tx: mpsc::UnboundedSender<ManagerCommand>,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;

    if let Some(resp) = authorize_request(&request) {
        return write_http_response(&mut stream, &resp).await;
    }

    let (base, _query) = split_path_and_query(&request.path);
    if base == "/api/processes/stream" {
        return handle_processes_stream(&mut stream, &snapshot).await;
    }
    if base.ends_with("/logs/stream") {
        return handle_log_stream(&mut stream, &request, &snapshot).await;
    }

    let response = if let Some(response) = execute_snapshot_api_request(&request, &snapshot).await {
        response
    } else {
        super::send_api_command(&command_tx, request).await?
    };
    write_http_response(&mut stream, &response).await
}

/// Streams the full (redacted) process list over Server-Sent Events. Pushes a
/// snapshot every few seconds so the dashboard updates live over one connection.
async fn handle_processes_stream(stream: &mut TcpStream, snapshot: &DaemonSnapshot) -> Result<()> {
    let sse_head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(sse_head.as_bytes()).await?;
    stream.flush().await?;

    loop {
        let processes = snapshot.list_processes().await;
        let redacted: Vec<ManagedProcess> = processes
            .into_iter()
            .map(|process| process.redacted_for_transport())
            .collect();
        let payload = serde_json::to_string(&redacted).unwrap_or_else(|_| "[]".to_string());
        let frame = format!("data: {payload}\n\n");

        if stream.write_all(frame.as_bytes()).await.is_err() {
            break; // client disconnected
        }
        stream.flush().await?;

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}

async fn handle_log_stream(
    stream: &mut TcpStream,
    request: &HttpRequest,
    snapshot: &DaemonSnapshot,
) -> Result<()> {
    let (base, query) = split_path_and_query(&request.path);
    let Some(rest) = base.strip_prefix("/api/processes/") else {
        return write_http_response(stream, &HttpResponse::error(404, "not found")).await;
    };
    let name = decode_segment(rest.trim_end_matches("/logs/stream"));

    let Some(process) = snapshot.get_process(&name).await else {
        return write_http_response(stream, &HttpResponse::error(404, "service not found")).await;
    };

    let stream_type = query.get("stream").map_or("stdout", String::as_str);
    let log_path = match stream_type {
        "stderr" | "error" => process.stderr_log,
        _ => process.stdout_log,
    };

    // SSE headers
    let sse_head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(sse_head.as_bytes()).await?;
    stream.flush().await?;

    // Send initial snapshot
    let lines = crate::logging::read_last_lines(&log_path, 200).unwrap_or_default();
    for line in lines {
        write_sse_line(stream, &line).await?;
    }
    stream.flush().await?;

    // Follow log (rotations and truncations reopen the file).
    let mut file = tokio::fs::File::open(&log_path).await?;
    file.seek(std::io::SeekFrom::End(0)).await?;

    let mut buffer = Vec::default();
    loop {
        buffer.clear();
        let bytes_read = file.read_to_end(&mut buffer).await?;
        if bytes_read > 0 {
            let text = String::from_utf8_lossy(&buffer);
            for raw in text.split('\n') {
                let line = raw.trim_end_matches('\r');
                if !line.is_empty() {
                    write_sse_line(stream, line).await?;
                }
            }
            stream.flush().await?;
        } else {
            let current_pos = file.stream_position().await?;
            if let Ok(meta) = tokio::fs::metadata(&log_path).await {
                if meta.len() < current_pos {
                    file = tokio::fs::File::open(&log_path).await?;
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

/// Writes one line as a Server-Sent Events `data:` payload, splitting embedded
/// newlines into separate `data:` fields as required by the SSE spec.
async fn write_sse_line(stream: &mut TcpStream, line: &str) -> Result<()> {
    for part in line.split('\n') {
        stream
            .write_all(format!("data: {part}\n\n").as_bytes())
            .await?;
    }
    Ok(())
}

/// Applies Basic Auth middleware. Returns `Some(HttpResponse)` if authorization
/// is required and fails, otherwise `None`.
pub(super) fn authorize_request(request: &HttpRequest) -> Option<HttpResponse> {
    if needs_basic_auth(&request.path) && !auth_ok(&request.headers) {
        return Some(unauthorized_response());
    }
    None
}

/// Whether a request path is protected by Basic Auth. The Prometheus metrics
/// endpoint and git webhook are excluded (metrics is intentionally public and
/// `/pull/*` uses its own secret mechanism).
fn needs_basic_auth(path: &str) -> bool {
    path == "/" || path.starts_with("/api/")
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

    if request.method == "GET" && request.path == "/" {
        return Some(HttpResponse::text(
            200,
            HTML_CONTENT_TYPE,
            render_dashboard_html(),
        ));
    }

    if request.method == "GET" && request.path == "/favicon.svg" {
        return Some(HttpResponse::text(200, SVG_CONTENT_TYPE, FAVICON_SVG));
    }

    // Browsers request /favicon.ico by default; there is none, answer 204
    // (No Content) so clients do not retry and the request is not misrouted
    // to the POST-only API handler.
    if request.path == "/favicon.ico" {
        return Some(HttpResponse::empty(204));
    }

    if request.method == "GET" && request.path.starts_with("/api/") {
        return Some(execute_api_snapshot_get(request, snapshot).await);
    }

    None
}

/// Serves read-only dashboard API endpoints from the daemon snapshot without
/// acquiring the manager lock: process listing, single-process detail, and log
/// tails for stdout/stderr/error streams.
async fn execute_api_snapshot_get(
    request: &HttpRequest,
    snapshot: &DaemonSnapshot,
) -> HttpResponse {
    let (base, query) = split_path_and_query(&request.path);

    if base == "/api/processes" {
        let processes = snapshot.list_processes().await;
        let redacted: Vec<ManagedProcess> = processes
            .into_iter()
            .map(|process| process.redacted_for_transport())
            .collect();
        return HttpResponse::json(
            200,
            serde_json::to_value(redacted).unwrap_or_else(|_| serde_json::Value::Array(Vec::default())),
        );
    }

    let Some(rest) = base.strip_prefix("/api/processes/") else {
        return HttpResponse::error(404, "not found");
    };
    let (name, sub) = match rest.split_once('/') {
        Some((name, sub)) => (name, Some(sub)),
        None => (rest, None),
    };
    let name = decode_segment(name);

    match sub {
        None => match snapshot.get_process(&name).await {
            Some(process) => HttpResponse::json(
                200,
                serde_json::to_value(process.redacted_for_transport())
                    .unwrap_or(serde_json::Value::Null),
            ),
            None => HttpResponse::error(404, "service not found"),
        },
        Some("logs") => {
            let Some(process) = snapshot.get_process(&name).await else {
                return HttpResponse::error(404, "service not found");
            };
            let stream = query.get("stream").map_or("stdout", String::as_str);
            let lines = query
                .get("lines")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(200)
                .min(5000);
            let log_path = match stream {
                "stderr" | "error" => process.stderr_log,
                _ => process.stdout_log,
            };
            let content = crate::logging::read_last_lines(&log_path, lines).unwrap_or_default();
            HttpResponse::json(
                200,
                json!({
                    "path": log_path.display().to_string(),
                    "stream": stream,
                    "lines": content,
                }),
            )
        }
        _ => HttpResponse::error(404, "not found"),
    }
}

pub(super) async fn execute_api_request(
    request: HttpRequest,
    manager: &mut ProcessManager,
) -> HttpResponse {
    if request.method != "POST" {
        return HttpResponse::error(405, "method not allowed");
    }

    if let Some(rest) = request.path.strip_prefix("/api/processes/") {
        let (target, action) = match rest.split_once('/') {
            Some((target, action)) => (target, action.split('?').next().unwrap_or(action)),
            None => return HttpResponse::error(404, "not found"),
        };
        let target = decode_segment(target);
        if target.is_empty() || action.is_empty() {
            return HttpResponse::error(404, "not found");
        }
        return execute_process_action(&target, action, manager).await;
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

/// Executes a process mutation (`stop`, `restart`, `reload`) against the
/// manager. A target of `"all"` applies to every managed process where the
/// manager exposes a batch operation.
async fn execute_process_action(
    target: &str,
    action: &str,
    manager: &mut ProcessManager,
) -> HttpResponse {
    let result = match action {
        "stop" => {
            if target == "all" {
                manager.stop_all_processes().await.map(|ps| ps.len())
            } else {
                manager.stop_process(target).await.map(|_| 1)
            }
        }
        "restart" => {
            if target == "all" {
                manager.restart_all_processes().await.map(|ps| ps.len())
            } else {
                manager.restart_process(target).await.map(|_| 1)
            }
        }
        "reload" => {
            if target == "all" {
                return HttpResponse::error(400, "reload all is not supported");
            }
            manager.reload_process(target).await.map(|_| 1)
        }
        _ => return HttpResponse::error(404, "unknown action"),
    };

    match result {
        Ok(count) => HttpResponse::ok(format!("{action} {count} process(es)")),
        Err(err) => HttpResponse::error(error_status(&err), err.to_string()),
    }
}

/// Splits an HTTP request path into its base path and decoded query parameters.
fn split_path_and_query(path: &str) -> (&str, std::collections::HashMap<String, String>) {
    match path.split_once('?') {
        Some((base, query)) => (
            base,
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect(),
        ),
        None => (path, HashMap::default()),
    }
}

/// Percent-decodes a URL path segment (e.g. a process name). Process names are
/// restricted to `[a-zA-Z0-9_-]`, so the decoder only needs to handle the
/// common `%XX` byte escapes emitted by URL-aware clients.
fn decode_segment(segment: &str) -> String {
    if !segment.contains('%') {
        return segment.to_string();
    }
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[index + 1]), hex_val(bytes[index + 2])) {
                out.push((hi << 4) | lo);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Maps a domain error to an HTTP status code: process-not-found style errors
/// become 404, everything else 500.
fn error_status(err: &anyhow::Error) -> u16 {
    if err.downcast_ref::<crate::errors::OxmgrError>().is_some() {
        404
    } else {
        500
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
    pub(super) headers: std::collections::HashMap<String, String>,
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
            headers: HashMap::default(),
        }
    }

    fn text(status_code: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status_code,
            content_type,
            body: HttpBody::Text(body.into()),
            headers: HashMap::default(),
        }
    }

    /// A response with an empty body (e.g. 204 No Content).
    fn empty(status_code: u16) -> Self {
        Self {
            status_code,
            content_type: TEXT_PLAIN_CONTENT_TYPE,
            body: HttpBody::Text(String::default()),
            headers: HashMap::default(),
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

    let mut lines = head.lines();
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

        let mut headers = HashMap::default();
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
    let mut response_head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status_code,
        reason,
        response.content_type,
        body_text.len(),
    );
    for (name, value) in &response.headers {
        response_head.push_str(name);
        response_head.push_str(": ");
        response_head.push_str(value);
        response_head.push_str("\r\n");
    }
    response_head.push_str("\r\n");
    response_head.push_str(&body_text);

    stream
        .write_all(response_head.as_bytes())
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
        204 => "No Content",
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
