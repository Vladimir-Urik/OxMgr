# Terminal UI Guide

`oxmgr ui` is the interactive dashboard for fleet monitoring and quick actions.

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
