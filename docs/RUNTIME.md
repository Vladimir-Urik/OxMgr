# Runtime Mode (`oxmgr runtime`)

`oxmgr runtime` is Oxmgr's foreground mode for containers and PID 1 environments (similar to `pm2-runtime`).

## What It Does

- Runs in foreground (no daemonization).
- Starts configured apps as child processes.
- Forwards child logs to parent stdout/stderr (works with `docker logs` and Kubernetes log collection).
- Handles `SIGTERM` / `SIGINT` and gracefully stops children.
- Applies restart policy in foreground mode (`restart_policy`, `max_restarts`, `crash_restart_limit`, `restart_delay_secs`).

## What It Does Not Do

- No background daemon.
- No persisted daemon state.
- No IPC/UI management loop (`oxmgr ui`, `oxmgr list`, etc. are daemon mode features).

## Supported Config Files

`oxmgr runtime` accepts the same local config formats as `import` / `apply`:

- Oxmgr native: `oxfile.toml`
- PM2 ecosystem files:
  - `ecosystem.config.js`
  - `ecosystem.config.cjs`
  - `ecosystem.config.mjs`
  - `ecosystem.config.json`

## Usage

```bash
oxmgr runtime ./oxfile.toml
oxmgr runtime ./oxfile.toml --env production
oxmgr runtime ./oxfile.toml --only api,worker
```

PM2 ecosystem example:

```bash
oxmgr runtime ./ecosystem.config.js
oxmgr runtime ./ecosystem.config.json --only api
```

## Docker Example (Oxfile)

```dockerfile
FROM node:20-alpine

WORKDIR /app
COPY . .
RUN npm ci --omit=dev

RUN npm install -g oxmgr

CMD ["oxmgr", "runtime", "./oxfile.toml"]
```

## Docker Example (PM2 Ecosystem File)

```dockerfile
FROM node:20-alpine

WORKDIR /app
COPY . .
RUN npm ci --omit=dev

RUN npm install -g oxmgr

CMD ["oxmgr", "runtime", "./ecosystem.config.js"]
```

## Operational Notes

- Container shutdown: `docker stop` sends `SIGTERM`; runtime mode propagates stop to child processes and exits.
- Multi-instance entries from config (`instances`) are expanded into deterministic child names.
- PM2 field `merge_logs` is supported during ecosystem import mapping.
