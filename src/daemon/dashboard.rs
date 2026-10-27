//! Web dashboard served on the daemon's HTTP API address: the embedded single
//! page app, sign-in sessions, request authorization and the authenticated
//! WebSocket that streams live updates.
//!
//! The dashboard is off unless `OXMGR_DASHBOARD` enables it. Without
//! `OXMGR_DASHBOARD_USER` / `OXMGR_DASHBOARD_PASS` it is only served on a
//! loopback listener; with them, the app signs in through `POST /api/login`,
//! which sets an `HttpOnly`, `SameSite=Strict` session cookie. Scripts may send
//! Basic Auth instead.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Instant;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::warn;

use crate::events::BusEvent;
use crate::process::ManagedProcess;

use super::http::{split_path_and_query, HttpRequest, HttpResponse};
use super::DaemonSnapshot;

// Built by `npm run build` in `web/` (see web/README.md) and committed, so a
// plain `cargo build` needs no Node.js toolchain.
const INDEX_HTML: &str = include_str!("../../web/dist/index.html");
const APP_JS: &str = include_str!("../../web/dist/assets/app.js");
const APP_CSS: &str = include_str!("../../web/dist/assets/app.css");
const FAVICON_SVG: &str = include_str!("../../web/dist/favicon.svg");
const BUILD_VERSION: &str = env!("OXMGR_BUILD_VERSION");

pub(super) const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const JS_CONTENT_TYPE: &str = "text/javascript; charset=utf-8";
const CSS_CONTENT_TYPE: &str = "text/css; charset=utf-8";
const SVG_CONTENT_TYPE: &str = "image/svg+xml; charset=utf-8";

const ENV_DASHBOARD: &str = "OXMGR_DASHBOARD";
const ENV_DASHBOARD_USER: &str = "OXMGR_DASHBOARD_USER";
const ENV_DASHBOARD_PASS: &str = "OXMGR_DASHBOARD_PASS";
const ENV_DASHBOARD_INTERVAL_MS: &str = "OXMGR_DASHBOARD_INTERVAL_MS";
const ENV_DASHBOARD_LABEL: &str = "OXMGR_DASHBOARD_LABEL";
const ENV_DASHBOARD_LABEL_COLOR: &str = "OXMGR_DASHBOARD_LABEL_COLOR";

pub(super) const WS_PATH: &str = "/api/ws";
const SESSION_COOKIE: &str = "oxmgr_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_SESSIONS: usize = 256;

/// Five failed sign-ins within a minute lock the login for 30 seconds.
const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_FAILURES: usize = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(30);

/// Upper bound on concurrently open WebSocket connections, so abandoned
/// browser tabs cannot pile up tasks in the daemon.
const MAX_SOCKETS: usize = 32;
const WS_PING_EVERY: Duration = Duration::from_secs(20);
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const WS_MAX_MESSAGE_BYTES: usize = 64 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Settings and credentials
// ─────────────────────────────────────────────────────────────────────────────

/// Dashboard credentials. Sign-in is required only when both a username and a
/// password are configured.
#[derive(Debug, Clone)]
pub(super) struct DashboardAuth {
    user: String,
    pass: String,
}

impl DashboardAuth {
    pub(super) fn new(user: impl Into<String>, pass: impl Into<String>) -> Option<Self> {
        let user = user.into();
        let pass = pass.into();
        if user.trim().is_empty() || pass.is_empty() {
            return None;
        }
        Some(Self { user, pass })
    }

    fn from_env() -> Option<Self> {
        let auth = Self::new(
            std::env::var(ENV_DASHBOARD_USER).ok()?,
            std::env::var(ENV_DASHBOARD_PASS).ok()?,
        )?;
        if auth.pass.starts_with("{SHA256}") || auth.pass.starts_with("{SHA512}") {
            warn!(
                "{ENV_DASHBOARD_PASS} looks like a {{SHA256}}/{{SHA512}} hash; hashed passwords are \
                 not supported, so the value is used as the literal password"
            );
        }
        Some(auth)
    }

    /// Both halves are always compared, each in constant time, so a mismatch
    /// leaks neither which half failed nor how much of it matched.
    fn verify(&self, user: &str, pass: &str) -> bool {
        let user_ok = constant_time_eq(user.as_bytes(), self.user.as_bytes());
        let pass_ok = constant_time_eq(pass.as_bytes(), self.pass.as_bytes());
        user_ok & pass_ok
    }
}

/// Dashboard settings, read once: the daemon environment does not change while it runs.
#[derive(Debug, Clone, Default)]
pub(super) struct DashboardSettings {
    /// The dashboard and its `/api/*` routes are off unless `OXMGR_DASHBOARD` is truthy.
    pub(super) enabled: bool,
    pub(super) auth: Option<DashboardAuth>,
    pub(super) interval_ms: u64,
    pub(super) label: Option<String>,
    pub(super) label_color: Option<String>,
}

impl DashboardSettings {
    fn from_env() -> Self {
        let enabled = std::env::var(ENV_DASHBOARD).is_ok_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
        let non_empty = |key: &str| {
            std::env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        Self {
            enabled,
            auth: DashboardAuth::from_env(),
            interval_ms: non_empty(ENV_DASHBOARD_INTERVAL_MS)
                .and_then(|value| value.parse().ok())
                .unwrap_or(2000),
            label: non_empty(ENV_DASHBOARD_LABEL),
            label_color: non_empty(ENV_DASHBOARD_LABEL_COLOR),
        }
    }

    fn refresh_interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.clamp(200, 10_000))
    }
}

pub(super) fn settings() -> &'static DashboardSettings {
    static SETTINGS: OnceLock<DashboardSettings> = OnceLock::new();
    SETTINGS.get_or_init(DashboardSettings::from_env)
}

/// Compares `input` with the configured `expected` secret. The loop always
/// walks the whole of `expected`, so the time taken depends on the configured
/// value only, not on how much of the input matches or how long it is.
fn constant_time_eq(input: &[u8], expected: &[u8]) -> bool {
    let mut diff = u8::from(input.len() != expected.len());
    for (index, byte) in expected.iter().enumerate() {
        diff |= byte ^ input.get(index).copied().unwrap_or(0);
    }
    diff == 0
}

/// Verifies an `Authorization: Basic <base64(user:pass)>` header (scripts, curl).
/// Guesses count against the same per-peer throttle as the sign-in form.
fn basic_auth_ok(request: &HttpRequest, auth: &DashboardAuth) -> bool {
    let Some(credentials) = request.headers.get("authorization").and_then(|value| {
        let (scheme, encoded) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("basic").then_some(encoded)
    }) else {
        return false;
    };
    let decoded = STANDARD
        .decode(credentials.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default();
    let (user, pass) = decoded.split_once(':').unwrap_or((decoded.as_str(), ""));
    matches!(
        check_credentials(auth, request.peer, user, pass),
        Credentials::Valid
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Sessions and login throttling
// ─────────────────────────────────────────────────────────────────────────────

/// A panic while holding one of these locks leaves plain data behind, so a
/// poisoned lock is still safe to use.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Session tokens are kept only as SHA-256 digests, mapped to their expiry.
fn sessions() -> &'static Mutex<HashMap<String, Instant>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn token_digest(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn create_session() -> Result<String> {
    let mut raw = [0_u8; 32];
    getrandom::fill(&mut raw)
        .map_err(|err| anyhow::anyhow!("failed to generate session token: {err}"))?;
    let token = hex(&raw);

    let now = Instant::now();
    let mut store = lock(sessions());
    store.retain(|_, expires| *expires > now);
    if store.len() >= MAX_SESSIONS {
        if let Some(oldest) = store
            .iter()
            .min_by_key(|(_, expires)| **expires)
            .map(|(key, _)| key.clone())
        {
            store.remove(&oldest);
        }
    }
    store.insert(token_digest(&token), now + SESSION_TTL);
    Ok(token)
}

fn session_valid(token: &str) -> bool {
    let store = lock(sessions());
    store
        .get(&token_digest(token))
        .is_some_and(|expires| *expires > Instant::now())
}

fn revoke_session(token: &str) {
    lock(sessions()).remove(&token_digest(token));
}

fn session_token(headers: &HashMap<String, String>) -> Option<&str> {
    headers.get("cookie")?.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == SESSION_COOKIE && !value.is_empty()).then_some(value)
    })
}

fn has_valid_session(headers: &HashMap<String, String>) -> bool {
    session_token(headers).is_some_and(session_valid)
}

/// Failed credential checks per client address (`None` when the peer address
/// is unknown). Behind a reverse proxy every client shares the proxy's entry.
type FailureLog = HashMap<Option<IpAddr>, Vec<Instant>>;

fn login_failures() -> &'static Mutex<FailureLog> {
    static FAILURES: OnceLock<Mutex<FailureLog>> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Upper bound on tracked client addresses, so spraying from many addresses
/// cannot grow the log without limit.
const MAX_TRACKED_PEERS: usize = 4096;

/// Reserves one credential check for `peer`. While the peer is locked out it
/// returns the remaining lockout; otherwise it records a provisional failure
/// under the same lock, so concurrent guesses cannot all slip past the limit.
/// [`forgive_attempt`] withdraws it when the credentials turn out valid.
fn begin_attempt(peer: Option<IpAddr>, now: Instant) -> Result<(), Duration> {
    let mut log = lock(login_failures());
    log.retain(|_, failures| {
        failures.retain(|at| now.duration_since(*at) < LOGIN_FAILURE_WINDOW);
        !failures.is_empty()
    });
    if log.len() >= MAX_TRACKED_PEERS && !log.contains_key(&peer) {
        log.clear();
    }
    let failures = log.entry(peer).or_default();
    if failures.len() >= LOGIN_MAX_FAILURES {
        if let Some(last) = failures.last() {
            let until = *last + LOGIN_LOCKOUT;
            if until > now {
                return Err(until - now);
            }
        }
    }
    failures.push(now);
    Ok(())
}

fn forgive_attempt(peer: Option<IpAddr>, at: Instant) {
    let mut log = lock(login_failures());
    if let Some(failures) = log.get_mut(&peer) {
        if let Some(index) = failures.iter().rposition(|recorded| *recorded == at) {
            failures.remove(index);
        }
    }
}

enum Credentials {
    Valid,
    Invalid,
    LockedOut(Duration),
}

/// Checks a username and password under the per-peer throttle: five failures
/// within a minute lock that peer out for 30 seconds.
fn check_credentials(
    auth: &DashboardAuth,
    peer: Option<IpAddr>,
    user: &str,
    pass: &str,
) -> Credentials {
    let now = Instant::now();
    if let Err(remaining) = begin_attempt(peer, now) {
        return Credentials::LockedOut(remaining);
    }
    if auth.verify(user, pass) {
        forgive_attempt(peer, now);
        Credentials::Valid
    } else {
        Credentials::Invalid
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Authorization middleware
// ─────────────────────────────────────────────────────────────────────────────

/// Decides whether a request may reach a dashboard route. Returns the
/// rejection to send, or `None` when the request may proceed (also for routes
/// that are not part of the dashboard).
///
/// - The dashboard is off unless `OXMGR_DASHBOARD` enables it (`404`).
/// - Without credentials it is only served on a loopback listener, and only to
///   requests whose `Host` names the loopback interface; anything else could
///   be a DNS-rebinding page reaching the daemon through the browser.
/// - With credentials, everything except the app shell, the sign-in endpoints
///   and the session probe needs a session cookie or Basic Auth (`401`).
/// - State-changing requests need the `X-Oxmgr-Request` header, which a
///   cross-origin page cannot send without a CORS preflight, and a matching
///   `Origin` when the browser sends one. The WebSocket upgrade always needs a
///   same-origin `Origin` (cross-site WebSocket hijacking).
///
/// `/metrics` and `/pull/*` are not dashboard routes and pass through;
/// `/pull/*` enforces its own webhook secret later.
pub(super) fn authorize_request(
    request: &HttpRequest,
    settings: &DashboardSettings,
    local_is_loopback: bool,
) -> Option<HttpResponse> {
    let (base, _) = split_path_and_query(&request.path);
    if !is_dashboard_route(base) {
        return None;
    }
    if !settings.enabled {
        return Some(HttpResponse::error(
            404,
            "the web dashboard is disabled (set OXMGR_DASHBOARD=1 to enable it)",
        ));
    }

    match settings.auth.as_ref() {
        None if !local_is_loopback => {
            return Some(HttpResponse::error(
                403,
                "the dashboard requires OXMGR_DASHBOARD_USER and OXMGR_DASHBOARD_PASS \
                 when OXMGR_API_ADDR is not a loopback address",
            ));
        }
        None => {
            if !request
                .headers
                .get("host")
                .is_some_and(|host| is_loopback_host(host))
            {
                return Some(HttpResponse::error(403, "unexpected Host header"));
            }
        }
        Some(auth) => {
            // Public routes skip the check so they never count as a failed guess.
            let signed_in = || has_valid_session(&request.headers) || basic_auth_ok(request, auth);
            if !is_public_route(&request.method, base) && !signed_in() {
                return Some(HttpResponse::error(401, "sign-in required"));
            }
        }
    }

    if base == WS_PATH {
        if !origin_matches_host(request) {
            return Some(HttpResponse::error(403, "cross-origin WebSocket rejected"));
        }
    } else if request.method != "GET" && !same_origin_write(request) {
        return Some(HttpResponse::error(403, "cross-origin request rejected"));
    }
    None
}

/// Only the sign-in form needs a request body; every other route ignores it.
pub(super) fn reads_body(method: &str, path: &str) -> bool {
    method == "POST" && split_path_and_query(path).0 == "/api/login"
}

fn is_dashboard_route(base: &str) -> bool {
    matches!(base, "/" | "/index.html" | "/favicon.svg" | "/favicon.ico")
        || base.starts_with("/assets/")
        || base.starts_with("/api/")
}

/// Routes reachable before signing in: the app shell (it renders the sign-in
/// screen), the session probe and the sign-in endpoints themselves.
fn is_public_route(method: &str, base: &str) -> bool {
    match method {
        "GET" => {
            matches!(
                base,
                "/" | "/index.html" | "/favicon.svg" | "/favicon.ico" | "/api/session"
            ) || base.starts_with("/assets/")
        }
        "POST" => matches!(base, "/api/login" | "/api/logout"),
        _ => false,
    }
}

/// Accepts `localhost`, `127.0.0.1`, `[::1]` and their `:port` forms.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(inner, _)| inner)
    } else {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn origin_matches_host(request: &HttpRequest) -> bool {
    let (Some(origin), Some(host)) = (request.headers.get("origin"), request.headers.get("host"))
    else {
        return false;
    };
    let origin_host = origin
        .split_once("://")
        .map_or(origin.as_str(), |(_, rest)| rest)
        .trim_end_matches('/');
    host.trim().eq_ignore_ascii_case(origin_host)
}

fn same_origin_write(request: &HttpRequest) -> bool {
    if !request.headers.contains_key("x-oxmgr-request") {
        return false;
    }
    // Non-browser clients (curl, scripts) do not send Origin.
    !request.headers.contains_key("origin") || origin_matches_host(request)
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP routes
// ─────────────────────────────────────────────────────────────────────────────

/// Serves the dashboard's own routes that need no process manager: the app
/// shell and assets, the session probe, sign-in and sign-out. Called only after
/// [`authorize_request`] admitted the request.
pub(super) fn handle_request(
    request: &HttpRequest,
    settings: &DashboardSettings,
) -> Option<HttpResponse> {
    let (base, _) = split_path_and_query(&request.path);
    match (request.method.as_str(), base) {
        ("GET", "/" | "/index.html") => {
            let mut response = HttpResponse::text(200, HTML_CONTENT_TYPE, INDEX_HTML);
            response
                .headers
                .insert("Cache-Control".to_string(), "no-cache".to_string());
            Some(response)
        }
        ("GET", "/assets/app.js") => Some(asset(JS_CONTENT_TYPE, APP_JS)),
        ("GET", "/assets/app.css") => Some(asset(CSS_CONTENT_TYPE, APP_CSS)),
        ("GET", "/favicon.svg" | "/favicon.ico") => Some(asset(SVG_CONTENT_TYPE, FAVICON_SVG)),
        ("GET", "/api/session") => Some(session_info(request, settings)),
        ("POST", "/api/login") => Some(login(request, settings)),
        ("POST", "/api/logout") => Some(logout(request)),
        _ => None,
    }
}

fn asset(content_type: &'static str, body: &'static str) -> HttpResponse {
    let mut response = HttpResponse::text(200, content_type, body);
    // Asset names are fixed, so caching must not outlive the daemon build.
    response
        .headers
        .insert("Cache-Control".to_string(), "no-cache".to_string());
    response
}

fn session_info(request: &HttpRequest, settings: &DashboardSettings) -> HttpResponse {
    let authenticated = match settings.auth.as_ref() {
        None => true,
        Some(auth) => has_valid_session(&request.headers) || basic_auth_ok(request, auth),
    };
    let status = if authenticated { 200 } else { 401 };
    HttpResponse::json(
        status,
        json!({
            "authenticated": authenticated,
            "auth_required": settings.auth.is_some(),
            "version": BUILD_VERSION,
            "label": settings.label,
            "label_color": settings.label_color,
            "interval_ms": settings.refresh_interval().as_millis() as u64,
        }),
    )
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    #[serde(default = "default_remember")]
    remember: bool,
}

fn default_remember() -> bool {
    true
}

fn login(request: &HttpRequest, settings: &DashboardSettings) -> HttpResponse {
    let Some(auth) = settings.auth.as_ref() else {
        return HttpResponse::error(400, "sign-in is not required on this daemon");
    };
    let Ok(body) = serde_json::from_str::<LoginRequest>(&request.body) else {
        return HttpResponse::error(400, "expected a JSON body with username and password");
    };
    match check_credentials(auth, request.peer, &body.username, &body.password) {
        Credentials::Valid => {}
        Credentials::Invalid => return HttpResponse::error(401, "Wrong username or password."),
        Credentials::LockedOut(remaining) => {
            let seconds = remaining.as_secs().max(1);
            let mut response = HttpResponse::json(
                429,
                json!({
                    "ok": false,
                    "message": format!("Too many failed attempts. Try again in {seconds} seconds."),
                    "retry_after": seconds,
                }),
            );
            response
                .headers
                .insert("Retry-After".to_string(), seconds.to_string());
            return response;
        }
    }

    let token = match create_session() {
        Ok(token) => token,
        Err(err) => return HttpResponse::error(500, err.to_string()),
    };
    let max_age = if body.remember {
        format!("; Max-Age={}", SESSION_TTL.as_secs())
    } else {
        String::new()
    };
    let mut response = HttpResponse::ok("signed in");
    response.headers.insert(
        "Set-Cookie".to_string(),
        format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict{max_age}{}",
            secure_attribute(request)
        ),
    );
    response
}

/// Marks the cookie `Secure` when a TLS reverse proxy forwarded the request;
/// the daemon itself only speaks plain HTTP, where a `Secure` cookie would be dropped.
fn secure_attribute(request: &HttpRequest) -> &'static str {
    let forwarded_https = request
        .headers
        .get("x-forwarded-proto")
        .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"));
    if forwarded_https {
        "; Secure"
    } else {
        ""
    }
}

fn logout(request: &HttpRequest) -> HttpResponse {
    if let Some(token) = session_token(&request.headers) {
        revoke_session(token);
    }
    let mut response = HttpResponse::ok("signed out");
    response.headers.insert(
        "Set-Cookie".to_string(),
        format!(
            "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            secure_attribute(request)
        ),
    );
    response
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket
// ─────────────────────────────────────────────────────────────────────────────

static OPEN_SOCKETS: AtomicUsize = AtomicUsize::new(0);

/// Holds one of the [`MAX_SOCKETS`] slots for the lifetime of a connection.
struct SocketSlot;

impl SocketSlot {
    fn acquire() -> Option<Self> {
        // A plain compare-exchange loop: `fetch_update` is deprecated on newer
        // toolchains and its replacement does not exist on older ones.
        let mut open = OPEN_SOCKETS.load(Ordering::Acquire);
        loop {
            if open >= MAX_SOCKETS {
                return None;
            }
            match OPEN_SOCKETS.compare_exchange_weak(
                open,
                open + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(SocketSlot),
                Err(current) => open = current,
            }
        }
    }
}

impl Drop for SocketSlot {
    fn drop(&mut self) {
        OPEN_SOCKETS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Messages the browser may send.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Stream log lines of one process (replaces any previous subscription).
    SubscribeLogs {
        process: String,
    },
    UnsubscribeLogs,
}

/// Upgrades an authorized `GET /api/ws` request and streams live updates:
///
/// - `{"type":"hello",...}` once, with the daemon version and dashboard settings;
/// - `{"type":"processes","data":[...]}` every refresh interval (it also
///   feeds the dashboard's CPU and memory history);
/// - `{"type":"event","data":<bus event>}` for lifecycle and health events;
/// - `{"type":"log","process","stream","at","line"}` for the subscribed process.
///
/// The connection closes when its session is revoked or expires.
pub(super) async fn serve_websocket(
    mut stream: TcpStream,
    request: &HttpRequest,
    snapshot: DaemonSnapshot,
    settings: &DashboardSettings,
) -> Result<()> {
    let header_is = |name: &str, expected: &str| {
        request.headers.get(name).is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(expected))
        })
    };
    let key = request.headers.get("sec-websocket-key");
    if request.method != "GET"
        || !header_is("upgrade", "websocket")
        || !header_is("connection", "upgrade")
        || !header_is("sec-websocket-version", "13")
        || key.is_none()
    {
        return super::http::write_http_response(
            &mut stream,
            &HttpResponse::error(400, "expected a WebSocket upgrade"),
        )
        .await;
    }
    let Some(_slot) = SocketSlot::acquire() else {
        return super::http::write_http_response(
            &mut stream,
            &HttpResponse::error(503, "too many open dashboard connections"),
        )
        .await;
    };
    let session = settings
        .auth
        .as_ref()
        .and_then(|_| session_token(&request.headers))
        .map(str::to_string);

    let accept = derive_accept_key(key.map(String::as_bytes).unwrap_or_default());
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .await
        .context("failed to complete WebSocket handshake")?;

    let config = WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_MESSAGE_BYTES))
        .max_frame_size(Some(WS_MAX_MESSAGE_BYTES));
    let socket = WebSocketStream::from_raw_socket(stream, Role::Server, Some(config)).await;
    stream_updates(socket, snapshot, settings, session).await
}

type SocketSink = SplitSink<WebSocketStream<TcpStream>, Message>;

/// A client that stops reading (suspended laptop, frozen tab) must not pin a
/// connection slot until the kernel gives up on the TCP connection.
async fn send(sink: &mut SocketSink, message: Message) -> Result<()> {
    timeout(WS_SEND_TIMEOUT, sink.send(message))
        .await
        .context("dashboard client stopped reading")?
        .context("failed to send WebSocket message")
}

async fn stream_updates(
    socket: WebSocketStream<TcpStream>,
    snapshot: DaemonSnapshot,
    settings: &DashboardSettings,
    session: Option<String>,
) -> Result<()> {
    let (mut sink, mut source) = socket.split();
    let mut bus = snapshot.event_tx.subscribe();
    let mut refresh = interval(settings.refresh_interval());
    refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_ping = Instant::now();
    // Browsers answer pings with pongs, so a silent client is a dead one.
    let mut last_heard = Instant::now();
    let mut log_target: Option<String> = None;

    let hello = json!({
        "type": "hello",
        "version": BUILD_VERSION,
        "label": settings.label,
        "label_color": settings.label_color,
        "interval_ms": settings.refresh_interval().as_millis() as u64,
    });
    send(&mut sink, Message::text(hello.to_string())).await?;

    loop {
        tokio::select! {
            _ = refresh.tick() => {
                // A signed-out or expired session ends the live feed too.
                if session.as_deref().is_some_and(|token| !session_valid(token)) {
                    let _ = send(&mut sink, Message::Close(None)).await;
                    break;
                }
                if last_heard.elapsed() > WS_PING_EVERY * 2 {
                    break;
                }
                let payload = processes_message(&snapshot.list_processes().await);
                send(&mut sink, Message::text(payload)).await?;
                if last_ping.elapsed() >= WS_PING_EVERY {
                    send(&mut sink, Message::Ping(Default::default())).await?;
                    last_ping = Instant::now();
                }
            }
            event = bus.recv() => match event {
                Ok(event) => {
                    if let Some(message) = event_message(&event, log_target.as_deref()) {
                        send(&mut sink, Message::text(message.to_string())).await?;
                    }
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            },
            incoming = source.next() => {
                last_heard = Instant::now();
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMessage>(text.as_str()) {
                            Ok(ClientMessage::SubscribeLogs { process }) => log_target = Some(process),
                            Ok(ClientMessage::UnsubscribeLogs) => log_target = None,
                            Err(_) => {}
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }
    Ok(())
}

fn processes_message(processes: &[ManagedProcess]) -> String {
    let redacted: Vec<ManagedProcess> = processes
        .iter()
        .map(ManagedProcess::redacted_for_transport)
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    // `now` lets the browser compute uptimes against the daemon's clock.
    json!({ "type": "processes", "now": now, "data": redacted }).to_string()
}

/// Maps a bus event to a WebSocket message. Log lines are forwarded only for
/// the subscribed process; everything else goes to every client.
pub(super) fn event_message(
    event: &BusEvent,
    log_target: Option<&str>,
) -> Option<serde_json::Value> {
    let (at, process, data, stream) = match event {
        BusEvent::LogOut { at, process, data } => (at, process, data, "stdout"),
        BusEvent::LogErr { at, process, data } => (at, process, data, "stderr"),
        other => return Some(json!({ "type": "event", "data": other })),
    };
    (log_target == Some(process.name.as_str())).then(|| {
        json!({
            "type": "log",
            "process": process.name,
            "stream": stream,
            "at": at,
            "line": data.line,
        })
    })
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serial_test::serial;

    use super::{
        authorize_request, begin_attempt, create_session, event_message, handle_request, lock,
        login_failures, revoke_session, session_valid, DashboardAuth, DashboardSettings,
        INDEX_HTML, SESSION_COOKIE, WS_PATH,
    };
    use crate::daemon::http::HttpRequest;
    use crate::events::{BusEvent, EventProcessInfo};

    fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: String::new(),
            peer: None,
        }
    }

    fn enabled(auth: Option<(&str, &str)>) -> DashboardSettings {
        DashboardSettings {
            enabled: true,
            auth: auth.and_then(|(user, pass)| DashboardAuth::new(user, pass)),
            ..DashboardSettings::default()
        }
    }

    fn status(response: Option<super::HttpResponse>) -> Option<u16> {
        response.map(|r| r.status_code)
    }

    const HOST: (&str, &str) = ("Host", "127.0.0.1:46001");

    #[test]
    fn dashboard_is_disabled_by_default() {
        let settings = DashboardSettings::default();
        for path in [
            "/",
            "/assets/app.js",
            "/api/processes",
            "/api/session",
            WS_PATH,
        ] {
            let denied = authorize_request(&request("GET", path, &[HOST]), &settings, true);
            assert_eq!(status(denied), Some(404), "{path}");
        }
        // The pre-existing endpoints are unaffected.
        assert!(authorize_request(&request("GET", "/metrics", &[]), &settings, true).is_none());
        assert!(authorize_request(&request("POST", "/pull/api", &[]), &settings, true).is_none());
    }

    #[test]
    #[serial]
    fn credentials_gate_api_but_not_app_shell_or_sign_in() {
        let settings = enabled(Some(("admin", "s3cret")));
        for (method, path) in [
            ("GET", "/"),
            ("GET", "/assets/app.js"),
            ("GET", "/api/session"),
        ] {
            assert!(
                authorize_request(&request(method, path, &[HOST]), &settings, false).is_none(),
                "{path} must be reachable before sign-in"
            );
        }
        let login = request("POST", "/api/login", &[HOST, ("X-Oxmgr-Request", "1")]);
        assert!(authorize_request(&login, &settings, false).is_none());

        for path in ["/api/processes", "/api/processes/web/logs"] {
            let denied = authorize_request(&request("GET", path, &[HOST]), &settings, false);
            assert_eq!(status(denied), Some(401), "{path}");
        }
    }

    #[test]
    #[serial]
    fn basic_auth_still_works_for_scripts() {
        lock(login_failures()).clear();
        let settings = enabled(Some(("admin", "s3cret")));
        let header = format!("Basic {}", STANDARD.encode("admin:s3cret"));
        let ok = request("GET", "/api/processes", &[HOST, ("Authorization", &header)]);
        assert!(authorize_request(&ok, &settings, false).is_none());

        for wrong in ["admin:wrong", "root:s3cret", "admin:s3cret2", "admin"] {
            let header = format!("Basic {}", STANDARD.encode(wrong));
            let denied = request("GET", "/api/processes", &[HOST, ("Authorization", &header)]);
            assert_eq!(
                status(authorize_request(&denied, &settings, false)),
                Some(401),
                "{wrong}"
            );
        }
    }

    #[test]
    fn passwords_compare_exactly() {
        let auth = DashboardAuth::new("admin", "s3cret").expect("valid auth");
        assert!(auth.verify("admin", "s3cret"));
        for (user, pass) in [
            ("admin", "s3cre"),
            ("admin", "s3cret "),
            ("admin", "S3cret"),
            ("admin", ""),
            ("admi", "s3cret"),
            ("", ""),
        ] {
            assert!(!auth.verify(user, pass), "{user:?}/{pass:?}");
        }
        // Hash-looking values are literal passwords, not supervisord hashes.
        let literal = DashboardAuth::new("admin", "{SHA256}abc").expect("valid auth");
        assert!(literal.verify("admin", "{SHA256}abc"));
        assert!(!literal.verify("admin", "abc"));
    }

    #[test]
    fn session_cookie_authorizes_until_revoked() {
        let settings = enabled(Some(("admin", "s3cret")));
        let token = create_session().expect("session");
        let cookie = format!("theme=dark; {SESSION_COOKIE}={token}");
        let with_cookie = request("GET", "/api/processes", &[HOST, ("Cookie", &cookie)]);
        assert!(authorize_request(&with_cookie, &settings, false).is_none());
        assert!(session_valid(&token));

        revoke_session(&token);
        assert!(!session_valid(&token));
        assert_eq!(
            status(authorize_request(&with_cookie, &settings, false)),
            Some(401)
        );

        let forged = request(
            "GET",
            "/api/processes",
            &[HOST, ("Cookie", &format!("{SESSION_COOKIE}=deadbeef"))],
        );
        assert_eq!(
            status(authorize_request(&forged, &settings, false)),
            Some(401)
        );
    }

    #[test]
    fn no_credentials_means_loopback_only_with_loopback_host() {
        let settings = enabled(None);
        let denied = authorize_request(&request("GET", "/", &[HOST]), &settings, false);
        assert_eq!(
            status(denied),
            Some(403),
            "non-loopback listener without credentials"
        );

        for host in ["evil.example", "evil.example:46001", "127.0.0.1.nip.io"] {
            let denied =
                authorize_request(&request("GET", "/", &[("Host", host)]), &settings, true);
            assert_eq!(status(denied), Some(403), "{host}");
        }
        for host in ["localhost:46001", "127.0.0.1", "[::1]:46001", "LOCALHOST"] {
            let ok = authorize_request(&request("GET", "/", &[("Host", host)]), &settings, true);
            assert!(ok.is_none(), "{host}");
        }
    }

    #[test]
    fn writes_need_csrf_marker_and_same_origin() {
        let settings = enabled(None);
        let path = "/api/processes/web/restart";
        let bare = request("POST", path, &[HOST]);
        assert_eq!(status(authorize_request(&bare, &settings, true)), Some(403));

        let cross = request(
            "POST",
            path,
            &[
                HOST,
                ("X-Oxmgr-Request", "1"),
                ("Origin", "http://evil.example"),
            ],
        );
        assert_eq!(
            status(authorize_request(&cross, &settings, true)),
            Some(403)
        );

        let same = request(
            "POST",
            path,
            &[
                HOST,
                ("X-Oxmgr-Request", "1"),
                ("Origin", "http://127.0.0.1:46001"),
            ],
        );
        assert!(authorize_request(&same, &settings, true).is_none());

        let script = request("POST", path, &[HOST, ("X-Oxmgr-Request", "1")]);
        assert!(authorize_request(&script, &settings, true).is_none());
    }

    #[test]
    #[serial]
    fn websocket_requires_same_origin() {
        let settings = enabled(None);
        let missing = request("GET", WS_PATH, &[HOST]);
        assert_eq!(
            status(authorize_request(&missing, &settings, true)),
            Some(403)
        );
        let cross = request("GET", WS_PATH, &[HOST, ("Origin", "http://evil.example")]);
        assert_eq!(
            status(authorize_request(&cross, &settings, true)),
            Some(403)
        );
        let same = request(
            "GET",
            WS_PATH,
            &[HOST, ("Origin", "http://127.0.0.1:46001")],
        );
        assert!(authorize_request(&same, &settings, true).is_none());

        let signed_out = enabled(Some(("admin", "s3cret")));
        assert_eq!(
            status(authorize_request(&same, &signed_out, true)),
            Some(401)
        );
    }

    #[test]
    #[serial]
    fn login_sets_http_only_cookie_and_rejects_wrong_password() {
        lock(login_failures()).clear();
        let settings = enabled(Some(("admin", "s3cret")));
        let mut ok = request("POST", "/api/login", &[HOST, ("X-Oxmgr-Request", "1")]);
        ok.body = r#"{"username":"admin","password":"s3cret","remember":true}"#.to_string();
        let response = handle_request(&ok, &settings).expect("login route");
        assert_eq!(response.status_code, 200);
        let cookie = response.headers.get("Set-Cookie").expect("cookie");
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=")));
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Strict")
                && cookie.contains("Max-Age=")
        );

        let mut wrong = request("POST", "/api/login", &[HOST, ("X-Oxmgr-Request", "1")]);
        wrong.body = r#"{"username":"admin","password":"nope"}"#.to_string();
        assert_eq!(handle_request(&wrong, &settings).unwrap().status_code, 401);
        lock(login_failures()).clear();
    }

    #[test]
    #[serial]
    fn repeated_failures_lock_out_only_that_peer() {
        lock(login_failures()).clear();
        let attacker: Option<std::net::IpAddr> = Some([10, 0, 0, 66].into());
        let neighbour: Option<std::net::IpAddr> = Some([10, 0, 0, 7].into());
        let now = Instant::now();
        for _ in 0..5 {
            assert!(begin_attempt(attacker, now).is_ok());
        }
        assert!(
            begin_attempt(attacker, now).is_err(),
            "sixth guess is locked out"
        );
        assert!(
            begin_attempt(neighbour, now).is_ok(),
            "other clients keep working"
        );

        let settings = enabled(Some(("admin", "s3cret")));
        let mut correct = request("POST", "/api/login", &[HOST, ("X-Oxmgr-Request", "1")]);
        correct.body = r#"{"username":"admin","password":"s3cret"}"#.to_string();
        correct.peer = attacker;
        let locked = handle_request(&correct, &settings).unwrap();
        assert_eq!(
            locked.status_code, 429,
            "even the right password waits out the lockout"
        );
        assert!(locked.headers.contains_key("Retry-After"));

        // Basic Auth shares the throttle, so it is no way around the lockout.
        let header = format!("Basic {}", STANDARD.encode("admin:s3cret"));
        let mut basic = request("GET", "/api/processes", &[HOST, ("Authorization", &header)]);
        basic.peer = attacker;
        assert_eq!(
            status(authorize_request(&basic, &settings, false)),
            Some(401)
        );
        lock(login_failures()).clear();
    }

    #[test]
    #[serial]
    fn basic_auth_guesses_count_and_successes_are_forgiven() {
        lock(login_failures()).clear();
        let settings = enabled(Some(("admin", "s3cret")));
        let peer: Option<std::net::IpAddr> = Some([10, 0, 0, 9].into());
        let good = format!("Basic {}", STANDARD.encode("admin:s3cret"));
        for _ in 0..10 {
            let mut ok = request("GET", "/api/processes", &[HOST, ("Authorization", &good)]);
            ok.peer = peer;
            assert!(
                authorize_request(&ok, &settings, false).is_none(),
                "valid checks never lock"
            );
        }
        let bad = format!("Basic {}", STANDARD.encode("admin:guess"));
        for _ in 0..5 {
            let mut guess = request("GET", "/api/processes", &[HOST, ("Authorization", &bad)]);
            guess.peer = peer;
            assert_eq!(
                status(authorize_request(&guess, &settings, false)),
                Some(401)
            );
        }
        assert!(
            begin_attempt(peer, Instant::now()).is_err(),
            "five Basic guesses lock the peer"
        );
        lock(login_failures()).clear();
    }

    #[test]
    fn app_shell_references_the_embedded_bundle() {
        assert!(
            INDEX_HTML.contains("/assets/app.js"),
            "rebuild web/ with npm run build"
        );
        assert!(
            INDEX_HTML.contains("/assets/app.css"),
            "rebuild web/ with npm run build"
        );
        let settings = enabled(None);
        for path in ["/assets/app.js", "/assets/app.css", "/favicon.svg"] {
            let response = handle_request(&request("GET", path, &[HOST]), &settings).expect(path);
            assert_eq!(response.status_code, 200, "{path}");
        }
    }

    #[test]
    fn logs_reach_only_the_subscribed_process() {
        let info = |name: &str| EventProcessInfo {
            id: 1,
            name: name.to_string(),
            namespace: None,
            pid: Some(42),
            command: String::new(),
            cwd: None,
        };
        let line = BusEvent::log_out(info("api"), "GET /health 200".to_string());
        assert!(event_message(&line, None).is_none());
        assert!(event_message(&line, Some("worker")).is_none());
        let message = event_message(&line, Some("api")).expect("subscribed");
        assert_eq!(message["type"], "log");
        assert_eq!(message["stream"], "stdout");
        assert_eq!(message["line"], "GET /health 200");

        let shutdown = BusEvent::daemon_shutdown();
        assert_eq!(event_message(&shutdown, None).unwrap()["type"], "event");
    }
}
