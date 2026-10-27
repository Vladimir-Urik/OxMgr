# UI Guide

Oxmgr provides two interactive dashboards:
- **Terminal UI** (`oxmgr ui` or `oxmgr ui tui`): Full-featured TUI for terminal environments
- **Web Dashboard** (`oxmgr ui web`): browser dashboard with live updates over WebSocket (off by default)

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

The daemon serves a browser dashboard on its HTTP API address (`OXMGR_API_ADDR`,
loopback by default) with live updates over Server-Sent Events.

## Enable

The dashboard and its `/api/*` routes are **off by default**. Start the daemon with:

```bash
OXMGR_DASHBOARD=1 oxmgr daemon run
```

then open it:

```bash
oxmgr ui web            # checks the daemon and opens the browser
oxmgr ui web --no-open  # only print the URL
```

`/metrics` and `/pull/*` are not affected by this switch.

## Features

- Overview with running / issue counts and live CPU and memory sparklines
- Process table grouped by namespace, with status filters and search (`/`)
- Last error (stderr tail) of crashed processes inline
- Process drawer with live logs (stdout / stderr, filter, follow) and details
- Stop, restart, reload and restart-all, with confirmation
- Live updates over an authenticated WebSocket
- English UI in the oxmgr design language; works at phone width

## Sign-in and security

- Without credentials the dashboard only answers on a loopback listener, and
  only to requests whose `Host` is `localhost`, `127.0.0.1` or `[::1]`
  (protection against DNS rebinding).
- When `OXMGR_API_ADDR` is not a loopback address, `OXMGR_DASHBOARD_USER` and
  `OXMGR_DASHBOARD_PASS` are required; otherwise the dashboard answers `403`.
- With credentials the dashboard shows its own sign-in screen. A successful
  `POST /api/login` sets an `HttpOnly`, `SameSite=Strict` session cookie valid
  for 12 hours; `POST /api/logout` revokes it and closes its live connection.
  Five failed sign-ins within a minute lock the login for 30 seconds.
- Scripts can skip the cookie and send Basic Auth instead.
- Credentials are checked in constant time. The daemon speaks plain HTTP, so
  put a TLS reverse proxy in front of the dashboard when exposing it. The proxy
  must pass the original `Host` header and WebSocket upgrades through, and set
  `X-Forwarded-Proto: https` so the session cookie is marked `Secure`.
- `POST` requests require the `X-Oxmgr-Request` header and, when the browser
  sends an `Origin`, a same-origin request (CSRF protection). The WebSocket
  upgrade requires a same-origin `Origin` (cross-site WebSocket hijacking).
- Pages are served with `X-Frame-Options: DENY` and a Content-Security-Policy
  without inline scripts; the dashboard loads nothing from other hosts.
- At most 32 live connections are served at once.

```bash
export OXMGR_DASHBOARD=1
export OXMGR_DASHBOARD_USER="admin"
export OXMGR_DASHBOARD_PASS="use-a-long-random-password"
```

The password is compared as plain text (in constant time). Keep it out of
shell history and world-readable files, for example by setting it in the
service manager's environment file with restricted permissions.

Optional appearance settings:

- `OXMGR_DASHBOARD_INTERVAL_MS`: how often the process list is pushed over the WebSocket (default 2000, clamped to 200..10000)
- `OXMGR_DASHBOARD_LABEL`, `OXMGR_DASHBOARD_LABEL_COLOR`: environment label in the header, e.g. `PRODUCTION` / `#ef4444`

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard app (public; renders the sign-in screen) |
| `/api/session` | GET | Session state and dashboard settings (`401` when signed out) |
| `/api/login` | POST | `{"username","password","remember"}`, sets the session cookie |
| `/api/logout` | POST | Revokes the session |
| `/api/processes` | GET | JSON list of processes (secrets redacted) |
| `/api/processes/:name` | GET | Single process |
| `/api/processes/:name/logs` | GET | Log tail (`?stream=stdout\|stderr&lines=200`) |
| `/api/processes/:name/stop` | POST | Stop (`all` stops every process) |
| `/api/processes/:name/restart` | POST | Restart (`all` restarts every process) |
| `/api/processes/:name/reload` | POST | Reload one process |
| `/api/ws` | GET | WebSocket with live updates |

The WebSocket sends JSON messages: `hello` (version and settings), `processes`
(the full list every refresh interval), `event` (lifecycle and health events from
the event bus) and `log` (lines of the process the client subscribed to with
`{"type":"subscribe_logs","process":"<name>"}`; `{"type":"unsubscribe_logs"}`
stops them).

From scripts, send the CSRF header with actions:

```bash
curl -u admin:secret -H 'X-Oxmgr-Request: 1' -X POST http://127.0.0.1:<port>/api/processes/web/restart
```

## Developing the frontend

The dashboard is a React + TypeScript app in [`web/`](../web). The daemon embeds
the built files from `web/dist/`, which are committed so `cargo build` needs no
Node.js. After changing the frontend:

```bash
cd web
npm ci
npm run build   # type-checks and writes web/dist/
```

`npm run dev` serves the app with hot reload and proxies `/api` (including the
WebSocket) to a daemon at `OXMGR_API_URL` (default `http://127.0.0.1:47812`).
