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
- `n`: open create-process modal
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
- Full-width table: ID, name, status, PID, uptime, CPU, RAM, health
- Right sidebar (on selected process): runtime/process/git details and compact bars
- Create modal: in-UI process creation flow

## Notes

- UI uses ANSI + UTF line drawing and progress bars.
- Rendering avoids last-column overflow artifacts by reserving one column.
- Dashboard redraw is event-driven to reduce unnecessary flicker.
