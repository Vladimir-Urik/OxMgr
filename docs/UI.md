# UI Guide

Oxmgr provides two interactive dashboards:
- **Terminal UI** (`oxmgr ui` or `oxmgr ui tui`): Full-featured TUI for terminal environments
- **Web Dashboard** (`oxmgr ui web`): Browser-based dashboard with real-time SSE streaming

---

# Terminal UI

`oxmgr ui` is the interactive terminal dashboard for fleet monitoring and quick actions.

## Start

```bash
oxmgr ui
oxmgr ui --interval-ms 500
```

Refresh interval is clamped to `200..5000 ms`.

## Key Controls

- `j` / `k` or `↑` / `↓`: move selection
- `/`: open search input for live filtering by name / namespace / command
- `f`: cycle process filter (`all` -> `running` -> `stopped` -> `unhealthy`)
- `o`: cycle sort (`id` -> `name` -> `cpu` -> `ram` -> `restarts`)
- `n`: open create-process modal
- `s`: stop selected service
- `d`: open delete confirmation for selected service
- `r`: reload selected service (best-effort no-downtime)
- `Shift+R`: restart selected service
- `l`: open fullscreen log viewer for selected service
- `p`: pull selected service from git and auto reload/restart on commit change
- `t`: show latest log line snapshot
- `g` or `Space`: refresh immediately
- `?`: open/close help overlay
- `Esc`: open quick menu
- `q`: quit

Delete confirmation uses `Enter` or `y` to confirm, and `Esc` or `n` to cancel.

Search input uses:

- type to filter immediately
- `Backspace`: delete one character
- `Delete` or `Ctrl+U`: clear query
- `Enter` or `Esc`: close the input while keeping the current filter text

## Log Viewer

Press `l` on a selected service to open the fullscreen log viewer.

- `j` / `k` or `↑` / `↓`: scroll
- `PageUp` / `PageDown`: fast scroll
- `Home` / `End`: jump to top/bottom
- `Tab`: switch between `stderr` and `stdout`
- `g` or `Space`: reload log files from disk
- `l` or `Esc`: close the viewer

## Mouse Controls

- Left click on a row: select service
- Mouse wheel: move selection
- Esc menu buttons are clickable (`Resume`, `Quit`)

## Panels

- Header: timestamp, refresh cadence, selected-service summary
- Fleet summary: visible/total plus running/restarting/stopped/unhealthy counters
- Left services pane: ID, name, status, PID, uptime, CPU, RAM, health
- Right sidebar (on selected process): full-height runtime/process/git details and compact bars
- Create modal: in-UI process creation flow
- Fullscreen log viewer: scrollable per-service stdout/stderr view

## Notes

- UI uses ANSI + UTF line drawing and progress bars.
- Rendering avoids last-column overflow artifacts by reserving one column.
- Dashboard redraw is event-driven to reduce unnecessary flicker.

---

# Web Dashboard

`oxmgr ui web` opens a browser-based dashboard with real-time updates via Server-Sent Events (SSE).

## Start

```bash
oxmgr ui web
oxmgr ui web --port 8080
oxmgr ui web --bind 0.0.0.0 --no-open
```

Or navigate directly to `http://127.0.0.1:46001` while the daemon is running.

## Features

- Real-time process list with status, CPU, RAM, uptime, and health
- Live log streaming (stdout/stderr/error) via SSE
- Process control: stop, restart, reload from the browser
- Prometheus metrics at `/metrics`
- Responsive design for desktop and mobile

## Authentication

Configure Basic Auth via `[http_server]` in `oxfile.toml`:

```toml
[http_server]
port = "0.0.0.0:46001"
username = "admin"
password = "changeme"
interval_ms = 1000  # refresh interval in ms (200-10000)
label = "PRODUCTION"  # environment label in header
label_color = "#ef4444"  # label color (CSS value)
```

Or via environment variables (take precedence over oxfile):

```bash
export OXMGR_DASHBOARD_USER="admin"
export OXMGR_DASHBOARD_PASS="s3cret"
export OXMGR_DASHBOARD_LABEL="PRODUCTION"
export OXMGR_DASHBOARD_LABEL_COLOR="#ef4444"
```

Common label colors:
- Production: `#ef4444` (red)
- Staging: `#f97316` (orange)
- Development: `#eab308` (yellow)
- Local: `#22c55e` (green)

Password formats:
- Plain text: `s3cret`
- SHA256 (supervisord-compatible): `{SHA256}<base64-hash>`
- SHA512: `{SHA512}<base64-hash>`

Generate a SHA256 hash:

```bash
echo -n 'yourpassword' | openssl dgst -sha256 -binary | base64
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard HTML |
| `/api/processes` | GET | JSON list of all processes |
| `/api/processes/:name` | GET | Single process details |
| `/api/processes/:name/logs` | GET | Log tail (`?stream=stdout\|stderr\|error`) |
| `/api/processes/:name/stop` | POST | Stop a process |
| `/api/processes/:name/restart` | POST | Restart a process |
| `/api/processes/:name/reload` | POST | Reload a process |
| `/api/stop-all` | POST | Stop all processes |
| `/api/events` | GET | SSE stream of real-time updates |
| `/metrics` | GET | Prometheus metrics |
| `/health` | GET | Health check endpoint |

## Docker

The Docker image exposes the web dashboard on port 46001:

```bash
docker compose up --build
# open http://localhost:46001
# credentials: admin / oxmgr-demo
```

See [docker-compose.yaml](../docker-compose.yaml) for configuration options.
