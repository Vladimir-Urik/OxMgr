# Oxmgr — AI Skill Reference

Drop this file into your project (e.g. reference it from `CLAUDE.md`, `.cursor/rules`, or paste it into your AI context) so your AI assistant knows how to help you use Oxmgr.

---

## What Oxmgr Does

Oxmgr is a lightweight process manager (PM2 alternative) for running and supervising long-running services. It works with any language — Node.js, Python, Go, Rust, shell scripts, anything you can run from a terminal.

You use it to:
- Start services and keep them running with auto-restart
- Manage multiple services with a single config file (`oxfile.toml`)
- Apply config idempotently in CI/CD: `oxmgr apply ./oxfile.toml`
- Tail logs, check status, monitor CPU/RAM
- Watch files and restart on changes (dev workflow)
- Do zero-downtime reloads with health checks
- Auto-update services via git pull or webhook

Install: `npm install -g oxmgr` or see [oxmgr releases](https://github.com/Vladimir-Urik/OxMgr/releases).

---

## Everyday Commands

```bash
# Start a service
oxmgr start "node server.js" --name api --restart always

# List all services
oxmgr list          # aliases: ls, ps

# Check one service
oxmgr status api

# Tail logs
oxmgr logs api -f

# Stop / restart / reload
oxmgr stop api
oxmgr restart api   # alias: rs
oxmgr reload api    # zero-downtime if health check configured

# Delete
oxmgr delete api    # alias: rm

# Interactive TUI
oxmgr ui

# Config workflow
oxmgr validate ./oxfile.toml
oxmgr apply ./oxfile.toml
oxmgr apply ./oxfile.toml --env prod
```

---

## Config File: `oxfile.toml`

The recommended way to manage services. One file, multiple services, repeatable deploys.

### Minimal config

```toml
version = 1

[[apps]]
name = "api"
command = "node server.js"
restart_policy = "on_failure"
max_restarts = 10
stop_timeout_secs = 5
```

```bash
oxmgr apply ./oxfile.toml
```

### Common fields

```toml
version = 1

[[apps]]
name = "api"
command = "node server.js"
cwd = "./services/api"               # working directory
restart_policy = "on_failure"        # always | on_failure | never
max_restarts = 10
crash_restart_limit = 3              # max auto-restarts in 5min window; 0 = disable
stop_signal = "SIGTERM"
stop_timeout_secs = 5
restart_delay_secs = 2
start_delay_secs = 0
namespace = "backend"                # logical group label

[apps.env]
NODE_ENV = "production"
PORT = "3000"
```

### Health checks

```toml
[[apps]]
name = "api"
command = "node server.js"
health_cmd = "curl -fsS http://127.0.0.1:3000/health"
health_interval_secs = 15
health_timeout_secs = 3
health_max_failures = 3
```

Health check runs periodically. After `health_max_failures` consecutive failures the process is restarted.

### Zero-downtime reload

```toml
health_cmd = "curl -fsS http://127.0.0.1:3000/health"
wait_ready = true
ready_timeout_secs = 30
pre_reload_cmd = "npm run build"     # optional: run before reload; failure aborts reload
```

`oxmgr reload api` starts the new process, waits until health check passes, then cuts over. If readiness times out, the old process keeps running.

### File watch (dev)

```toml
watch = ["src", "package.json"]
ignore_watch = ["node_modules/", "\\.log$"]
watch_delay_secs = 1
```

`watch = true` watches `cwd`. `watch = "path"` or `watch = ["a", "b"]` watches explicit paths.

### Multiple instances

```toml
instances = 4
instance_var = "INSTANCE_ID"         # env var set to 0/1/2/3 per instance
```

Oxmgr spawns `api-0`, `api-1`, `api-2`, `api-3` as separate managed processes.

### Node.js cluster mode

```toml
command = "node server.js"
cluster_mode = true
cluster_instances = 4               # omit to use all CPUs
```

Single managed process entry, Node.js handles worker fan-out internally. Command must be `node <script>`.

### Resource limits

```toml
max_memory_mb = 512
max_cpu_percent = 80.0
cgroup_enforce = true               # Linux only: hard cgroup v2 limits at spawn
```

Soft limits are checked periodically; when exceeded the process is restarted. `cgroup_enforce` applies hard OS-level limits.

### Service dependencies

```toml
[[apps]]
name = "db"
command = "docker compose up db"
start_order = 0
health_cmd = "pg_isready -h 127.0.0.1"

[[apps]]
name = "api"
command = "node server.js"
depends_on = ["db"]                 # waits for db to be up
start_order = 10
```

`depends_on` enforces start direction. `start_order` is a tie-break among apps ready to start at the same time.

### Profiles (dev / staging / prod)

```toml
[[apps]]
name = "api"
command = "node server.js"
instances = 1

[apps.env]
NODE_ENV = "development"
PORT = "3000"

[apps.profiles.prod]
instances = 4
restart_policy = "always"
max_memory_mb = 768

[apps.profiles.prod.env]
NODE_ENV = "production"
PORT = "8080"
```

```bash
oxmgr apply ./oxfile.toml --env prod
```

Config resolution order: `[defaults]` → `[[apps]]` → `[apps.profiles.<name>]`. Scalars override; `env` maps merge.

### Shared defaults

```toml
[defaults]
restart_policy = "on_failure"
max_restarts = 10
stop_timeout_secs = 5
health_interval_secs = 20
health_timeout_secs = 4
health_max_failures = 3
max_memory_mb = 512
env = { TZ = "UTC" }

[[apps]]
name = "api"
command = "node server.js"
# inherits all defaults above

[[apps]]
name = "worker"
command = "python worker.py"
max_memory_mb = 256                 # overrides default
```

### Skip an app

```toml
[[apps]]
name = "worker"
command = "python worker.py"
disabled = true                     # skipped by apply
```

### Git pull + webhook auto-update

```toml
[[apps]]
name = "api"
command = "node server.js"
git_repo = "git@github.com:org/repo.git"
git_ref = "main"
pull_secret = "your-long-random-secret"
```

```bash
oxmgr pull api
# or via HTTP webhook:
curl -X POST http://localhost:<port>/pull/api \
  -H "X-Oxmgr-Secret: your-long-random-secret"
```

Only reloads/restarts if the commit changed.

---

## Full Field Reference

### `[[apps]]` / `[defaults]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | Recommended for `apply` |
| `command` | string | required | Command to run |
| `cwd` | string | — | Working directory |
| `restart_policy` | `always\|on_failure\|never` | `on_failure` | |
| `max_restarts` | int | `10` | Total restart budget |
| `crash_restart_limit` | int | `3` | Auto-restarts in 5-min window; `0` disables |
| `stop_signal` | string | `SIGTERM` | e.g. `SIGINT`, `SIGTERM` |
| `stop_timeout_secs` | int | `5` | Grace period before force-kill |
| `restart_delay_secs` | int | `0` | Delay before auto-restart |
| `start_delay_secs` | int | `0` | Delay before initial start |
| `start_order` | int | — | Tie-break among concurrent starts |
| `depends_on` | `[string]` | — | Names of apps that must start first |
| `namespace` | string | — | Logical group label |
| `disabled` | bool | `false` | Skip in `apply` |
| `env` | table | — | Env vars; merged across layers |
| `instances` | int | — | Spawn N identical processes |
| `instance_var` | string | — | Env var set to instance index |
| `cluster_mode` | bool | `false` | Node.js cluster fan-out |
| `cluster_instances` | int | all CPUs | Worker count for cluster mode |
| `health_cmd` | string | — | Health check command |
| `health_interval_secs` | int | `30` | Seconds between checks |
| `health_timeout_secs` | int | `5` | Timeout per check |
| `health_max_failures` | int | `3` | Failures before restart |
| `wait_ready` | bool | `false` | Block reload until health passes |
| `ready_timeout_secs` | int | `30` | Readiness timeout (requires `wait_ready`) |
| `pre_reload_cmd` | string | — | Run before reload; failure aborts |
| `watch` | bool / string / `[string]` | — | Watch paths for file changes |
| `ignore_watch` | `[string]` | — | Regex patterns to ignore |
| `watch_delay_secs` | int | — | Debounce after file change |
| `max_memory_mb` | int | — | Soft memory limit |
| `max_cpu_percent` | float | — | Soft CPU limit |
| `cgroup_enforce` | bool | `false` | Hard cgroup v2 limits (Linux) |
| `deny_gpu` | bool | `false` | Disable GPU visibility via env |
| `reuse_port` | bool | `false` | SO_REUSEPORT hint (macOS/Linux) |
| `git_repo` | string | — | Git remote for `oxmgr pull` |
| `git_ref` | string | — | Branch/tag/ref to pull |
| `pull_secret` | string | — | Webhook auth secret |

---

## Gotchas

- `restart_policy` uses underscores in `oxfile.toml` (`on_failure`) but hyphens in CLI flags (`--restart on-failure`).
- `instances` (Oxmgr multi-process) and `cluster_mode` (Node.js internal clustering) are separate features — don't combine them.
- `crash_restart_limit = 0` disables the 5-minute crash-loop cutoff only, not the total `max_restarts` budget.
- `wait_ready` requires `health_cmd` to be set.
- `cluster_mode` requires the command to be `node <script>` — no runtime flags before the script.
- `env` tables are always merged (not replaced) across the `defaults` → `app` → `profile` layers.
- `--prune` flag on `apply` removes processes from the daemon that are no longer in the config.
- `apply` is idempotent — safe to run in CI/CD on every deploy. Unchanged apps are left untouched.
