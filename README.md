# Oxmgr

**Oxmgr** is a lightweight, language-agnostic process manager written in Rust.

It is a modern, production-minded alternative to PM2 for any executable (Node.js, Python, Go, Rust, shell commands, and more).

It can be used as a drop-in replacement for many PM2 setups because Oxmgr supports PM2 ecosystem config format (`ecosystem.config.json`).

Supported platforms: **Linux, macOS, Windows**.

## Documentation

- [Docs Index](./docs/README.md)
- [Installation Guide](./docs/install.md)
- [Oxfile Specification](./docs/OXFILE.md)
- [Oxfile Examples](./docs/examples)

## Why Oxmgr Instead Of PM2?

- Language-agnostic by design
- Rust performance and low overhead
- Durable daemon model with persistent state
- Explicit restart policies + health checks
- Idempotent config apply (`oxmgr apply`)
- Built-in per-process logs and runtime metrics
- Drop-in migration path via PM2 ecosystem config compatibility

## Features

- Start/stop/restart/reload/delete managed processes
- Named processes (`--name`) with safe auto-generated names
- Restart policies: `always`, `on-failure`, `never`
- Configurable max restart count (`--max-restarts`)
- Background daemon with local IPC over localhost TCP
- CLI auto-starts daemon when needed
- Persistent state in JSON (`state.json`)
- Per-process stdout/stderr logs + tail mode
- Automatic log rotation and retention policy
- Process statuses: `running`, `stopped`, `crashed`, `restarting`, `errored`
- Graceful shutdown (SIGTERM, then SIGKILL on timeout)
- Process-tree aware shutdown (Unix process groups / Windows taskkill tree)
- Health checks with automatic restart on repeated failures
- CPU/RAM monitoring in `list` and `status`
- Resource limits (`max_memory_mb`, `max_cpu_percent`) with auto-restart
- Exponential restart backoff with jitter and cooldown reset
- Ecosystem config import (`ecosystem.config.json` style) for PM2 drop-in compatibility
- Idempotent config reconcile via `oxmgr apply`
- Reload without downtime (best-effort hot replacement)

## Installation

### npm / yarn

```bash
npm install -g oxmgr
# or
yarn global add oxmgr
```

### Homebrew

```bash
brew tap Vladimir-Urik/OxMgr
brew install oxmgr
```

### Chocolatey

```powershell
choco install oxmgr -y
```

### APT (Debian/Ubuntu)

```bash
echo "deb [trusted=yes] https://vladimir-urik.github.io/OxMgr/apt stable main" | sudo tee /etc/apt/sources.list.d/oxmgr.list
sudo apt update
sudo apt install oxmgr
```

### Build from source

```bash
git clone https://github.com/Vladimir-Urik/OxMgr.git
cd OxMgr
cargo build --release
```

Binary:

```bash
./target/release/oxmgr
```

### Install locally

```bash
cargo install --path .
```

## Quick Start

```bash
# Start process with restart policy
oxmgr start "node server.js" --name api --restart always --max-restarts 20

# Check fleet
oxmgr list

# Reconcile config idempotently (only changed apps restart)
oxmgr apply ./oxfile.toml --env prod

# Validate oxfile syntax + dependencies + expanded names
oxmgr validate ./oxfile.toml --env prod

# Install daemon service on current platform
oxmgr service install --system auto

# Detailed status (includes CPU/RAM + health)
oxmgr status api

# Reload with minimal disruption (best effort)
oxmgr reload api

# Logs
oxmgr logs api
oxmgr logs api -f
```

## CLI Reference

### `oxmgr start <command>`

Start and register a process.

Options:

- `--name <name>`
- `--restart <always|on-failure|never>` (default: `on-failure`)
- `--max-restarts <n>` (default: `10`)
- `--cwd <path>`
- `--env KEY=VALUE` (repeatable)
- `--health-cmd <command>`
- `--health-interval <seconds>` (default: `30`)
- `--health-timeout <seconds>` (default: `5`)
- `--health-max-failures <n>` (default: `3`)
- `--kill-signal <signal>` (for graceful stop, e.g. `SIGINT`)
- `--stop-timeout <seconds>` (default: `5`)
- `--restart-delay <seconds>` (default: `0`)
- `--start-delay <seconds>` (default: `0`)
- `--namespace <name>`
- `--max-memory-mb <n>`
- `--max-cpu-percent <n>`

Example:

```bash
oxmgr start "python app.py" \
  --name worker \
  --restart on-failure \
  --max-restarts 5 \
  --health-cmd "curl -fsS http://127.0.0.1:8080/health" \
  --health-interval 15 \
  --health-timeout 3 \
  --health-max-failures 3 \
  --max-memory-mb 512 \
  --max-cpu-percent 80
```

### `oxmgr stop <name|id>`

Gracefully stop process.

### `oxmgr restart <name|id>`

Stop and start process using stored definition.

### `oxmgr reload <name|id>`

Start a replacement instance, then terminate the old one (best effort no-downtime reload).

### `oxmgr delete <name|id>`

Remove process definition (stops it first if running).

### `oxmgr list`

Show all managed processes with runtime metrics.

Columns include: `ID NAME STATUS PID RESTARTS CPU% RAM(MB) HEALTH`.

### `oxmgr status <name|id>`

Show detailed process metadata, logs, health state, CPU, and RAM.

### `oxmgr logs <name|id>`

Show process logs.

Options:

- `-f, --follow` stream continuously
- `--lines <n>` number of lines from each log file (default `100`)

### `oxmgr import <path>`

Import process definitions from `ecosystem.config.json` or `oxfile.toml`.

Example:

```bash
oxmgr import ./ecosystem.config.json
oxmgr import ./ecosystem.config.json --env prod --only api,worker
```

Options:

- `--env <name>`: applies profile overrides (`env_<name>` for ecosystem, `[apps.profiles.<name>]` for oxfile)
- `--only <names>`: comma-separated app names filter

### `oxmgr apply <path>`

Idempotently reconcile desired config with daemon state.

- unchanged and already running apps are not touched
- changed apps are recreated
- matching but stopped/crashed apps are restarted
- optional `--prune` removes managed apps missing from config

Example:

```bash
oxmgr apply ./oxfile.toml --env prod --only api,worker
oxmgr apply ./ecosystem.config.json --prune
```

Options:

- `--env <name>`: profile selector (`env_<name>` or `[apps.profiles.<name>]`)
- `--only <names>`: comma-separated app filter
- `--prune`: delete apps not present in desired config

### `oxmgr convert <ecosystem.json> --out oxfile.toml`

Convert ecosystem config into Oxmgr-native TOML format.

Example:

```bash
oxmgr convert ecosystem.config.json --out oxfile.toml --env prod
```

### `oxmgr validate <oxfile.toml>`

Validate native oxfile config without talking to daemon.

Checks include:

- TOML parse + profile resolution
- command syntax sanity
- duplicate app names
- `depends_on` references
- duplicate expanded names (`instances` expansion)

Example:

```bash
oxmgr validate ./oxfile.toml
oxmgr validate ./oxfile.toml --env prod --only api,worker
```

Options:

- `--env <name>` profile selector
- `--only <names>` comma-separated app filter

### `oxmgr startup [--system <auto|systemd|launchd|task-scheduler>]`

Print boot autostart setup instructions for daemon.

### `oxmgr daemon run`

Run daemon in foreground mode. Normally unnecessary; CLI auto-start handles it.

### `oxmgr daemon stop`

Request graceful daemon shutdown.

### `oxmgr service <install|uninstall|status> [--system <auto|systemd|launchd|task-scheduler>]`

Manage Oxmgr as an OS service directly.

```bash
oxmgr service install --system auto
oxmgr service status --system auto
oxmgr service uninstall --system auto
```

## Runtime Environment Variables

- `OXMGR_HOME`: override Oxmgr data directory (state/logs)
- `OXMGR_DAEMON_ADDR`: override daemon bind/connect address (default `127.0.0.1:<derived-port>`)
- `OXMGR_LOG_MAX_SIZE_MB`: log rotation size threshold in MB (default `20`)
- `OXMGR_LOG_MAX_FILES`: number of rotated files kept per log (default `5`)
- `OXMGR_LOG_MAX_DAYS`: maximum rotated log age in days (default `14`)

## Ecosystem Config (`ecosystem.config.json`)

Oxmgr supports PM2-like config files with an `apps` array.

Supported fields per app:

- `name`
- `cmd` (full command line) OR `script` + `args`
- `cwd`
- `env`
- `autorestart`
- `restart_policy`
- `max_restarts`
- `health_cmd`, `health_interval`, `health_timeout`, `health_max_failures`
- or nested `health: { cmd, interval, timeout, max_failures }`
- `restart_delay`
- `delay_start` / `start_delay`
- `start_order` / `priority`
- `kill_signal` / `pm2_kill_signal`
- `stop_timeout` / `kill_timeout`
- `max_memory_restart` (e.g. `"256M"`), `max_memory_mb`, `max_cpu_percent`
- `namespace`
- `instances`, `instance_var`
- `env_<profile>` object overrides (used via `oxmgr import --env <profile>`)

Example:

```json
{
  "apps": [
    {
      "name": "api",
      "cmd": "node server.js",
      "cwd": "/srv/api",
      "env": { "NODE_ENV": "production" },
      "restart_policy": "always",
      "max_restarts": 20,
      "health_cmd": "curl -fsS http://127.0.0.1:3000/health",
      "health_interval": 15,
      "health_timeout": 3,
      "health_max_failures": 3,
      "max_memory_restart": "512M",
      "max_cpu_percent": 80
    },
    {
      "name": "worker",
      "script": "python",
      "args": ["worker.py"],
      "autorestart": true,
      "max_restarts": 10
    },
    {
      "name": "api",
      "cmd": "node api.js",
      "instances": 2,
      "instance_var": "INSTANCE_ID",
      "priority": 10,
      "restart_delay": 5,
      "delay_start": 3,
      "pm2_kill_signal": "SIGINT",
      "kill_timeout": 8,
      "max_memory_restart": "256M",
      "env_prod": {
        "NODE_ENV": "production",
        "instances": 4,
        "priority": 1,
        "max_memory_restart": "1024M"
      }
    }
  ]
}
```

## Oxfile Format (`oxfile.toml`)

`oxfile.toml` is Oxmgr-native config with extra features (profiles and dependency ordering).

Example:

```toml
version = 1

[defaults]
restart_policy = "on_failure"
max_restarts = 10
stop_timeout_secs = 5
max_memory_mb = 256

[[apps]]
name = "db"
command = "docker compose up db"
start_order = 0

[[apps]]
name = "api"
command = "node server.js"
depends_on = ["db"]
instances = 2
instance_var = "INSTANCE_ID"
restart_delay_secs = 2
start_delay_secs = 1
stop_signal = "SIGINT"
stop_timeout_secs = 8
namespace = "backend"
max_cpu_percent = 80

[apps.env]
BASE = "1"

[apps.profiles.prod]
instances = 4
start_order = 1
max_memory_mb = 768

[apps.profiles.prod.env]
NODE_ENV = "production"
```

Supported oxfile features include:

- global `[defaults]`
- per-app `depends_on` (startup ordering)
- per-profile overrides in `[apps.profiles.<name>]`
- `instances` and `instance_var`
- restart/stop delay and signal settings
- namespace and health checks
- resource limits (`max_memory_mb`, `max_cpu_percent`)

## How Daemon Works

- Single-user localhost endpoint: `127.0.0.1:<derived-port>`
- CLI sends JSON IPC requests
- Daemon owns lifecycle, restart logic, health checks, and metrics refresh
- Child exits are handled asynchronously
- State is persisted after lifecycle changes
- On daemon restart, desired-running processes are restored

## Logging

Per process logs:

- `~/.local/share/oxmgr/logs/<name>.out.log`
- `~/.local/share/oxmgr/logs/<name>.err.log`

Use `oxmgr logs <name>` or `oxmgr logs <name> -f`.

## Auto-Start On Boot

Use:

```bash
oxmgr startup --system systemd
# or
oxmgr startup --system launchd
# or
oxmgr startup --system task-scheduler
```

This prints ready-to-use service definitions and activation commands.

## Release Automation

Tagging `vX.Y.Z` triggers automated release pipeline in [`.github/workflows/release.yml`](./.github/workflows/release.yml):

- builds binaries for Linux/macOS/Windows
- creates `.deb` package
- publishes GitHub release assets + checksums
- publishes npm package (when `NPM_TOKEN` exists)
- updates Homebrew tap formula (when Homebrew secrets exist)
- publishes Chocolatey package (when `CHOCO_API_KEY` exists)
- publishes APT repository content to `gh-pages/apt`

Required release secrets are documented in [`docs/RELEASE.md`](./docs/RELEASE.md).

## Automated Tests

Current automated tests cover:

- restart policy behavior (`always`, `on-failure`, `never`)
- `ecosystem.config.json` parsing (`cmd`, `script+args`, health config)
- ecosystem/oxfile resource limit parsing and serialization
- idempotent `apply` planning behavior (noop/recreate/restart/prune)
- storage roundtrip and corrupted state recovery

Run:

```bash
cargo test
```

CI runs the same checks on Linux/macOS/Windows via `.github/workflows/ci.yml`.

## Architecture

```text
src/
  main.rs            CLI entrypoint + command dispatch
  cli.rs             clap command model
  daemon.rs          daemon loop, IPC listener, auto-start helper
  oxfile.rs          oxfile.toml parser + converter writer
  process_manager.rs lifecycle + restart/reload + health + metrics
  process.rs         domain models/status/restart/health enums
  ipc.rs             request/response protocol
  ecosystem.rs       ecosystem.config.json import parser
  storage.rs         durable state load/save
  logging.rs         log handling and tail helpers
  config.rs          paths and filesystem layout
  errors.rs          domain errors
```

## Contributing

1. Fork and create branch (`codex/<feature-name>`)
2. Add/update tests for behavior changes
3. Run:

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

4. Open PR with:
- problem statement
- design summary
- migration/backward compatibility notes

## License

Suggested license: **MIT**.

## Author

Author and lead developer: **Vladimír Urík**

This project is created under the open-source patronage of [Empellio.com](https://empellio.com).
