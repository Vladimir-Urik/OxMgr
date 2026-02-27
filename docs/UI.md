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
- `s`: stop selected service
- `r`: restart selected service
- `l`: reload selected service (best-effort no-downtime)
- `p`: pull selected service from git and auto reload/restart on commit change
- `t`: show latest log line snapshot
- `g` or `Space`: refresh immediately
- `?`: open/close help overlay
- `Esc`: open quick menu
- `q`: quit

## Mouse Controls

- Left click on a row: select service
- Mouse wheel: move selection
- Esc menu buttons are clickable (`Resume`, `Quit`)

## Panels

- Header: timestamp, refresh cadence, selected-service summary
- Fleet summary: total/running/restarting/stopped/unhealthy counters
- Table: ID, name, status, PID, uptime, CPU, RAM, health
- Detail panel: mode, restarts, watch, namespace, pull-hook state, git source, command, cwd

## Notes

- UI uses ANSI + UTF line drawing and progress bars.
- Rendering avoids last-column overflow artifacts by reserving one column.
- Dashboard redraw is event/heartbeat driven to reduce unnecessary flicker.
