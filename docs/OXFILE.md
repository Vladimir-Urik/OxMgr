# Oxfile (`oxfile.toml`) Documentation

`oxfile.toml` is the native Oxmgr configuration format.

It is designed for deterministic, idempotent process management via `oxmgr apply`.

## Why Oxfile Is Better Than Ecosystem JSON

Compared to `ecosystem.config.json` style files, `oxfile.toml` gives Oxmgr-specific advantages:

1. Deterministic, idempotent workflows
- Built for `oxmgr apply`, where unchanged apps are left untouched.
- Safer for CI/CD because repeated apply operations converge to the same state.

2. Stronger native feature model
- First-class support for health checks, resource limits, startup dependencies, namespaces, cluster mode, and profile overlays.
- No PM2 compatibility compromises needed for core fields.

3. Cleaner profile layering
- Explicit `[defaults]`, per-app fields, and `[apps.profiles.<name>]` overrides.
- Easy to reason about what changes between `dev`, `staging`, and `prod`.

4. Better readability for larger fleets
- TOML structure is concise for nested config and environment maps.
- Less noisy than large JSON files for multi-service repos.

5. Safe by default
- Declarative config only; no dynamic JavaScript execution.
- More predictable behavior for automation and review.

## Quick Start

```bash
# Validate oxfile before deploy/apply
oxmgr validate ./oxfile.toml --env prod

# Apply desired state from oxfile
oxmgr apply ./oxfile.toml

# Apply production profile
oxmgr apply ./oxfile.toml --env prod

# Reconcile only selected apps
oxmgr apply ./oxfile.toml --only api,worker

# Remove unmanaged processes from daemon state
oxmgr apply ./oxfile.toml --prune
```

## Validation Command

Use `validate` to test oxfile config in CI or pre-deploy scripts:

```bash
oxmgr validate ./oxfile.toml
oxmgr validate ./oxfile.toml --env prod --only api,worker
```

Validation checks:

- TOML parse and version support
- profile override resolution
- command/health command syntax sanity
- cluster-mode command validity (`node <script> ...` when enabled)
- duplicate app names
- unknown `depends_on` references
- duplicate expanded names from `instances`

## File Structure

```toml
version = 1

[defaults]
# optional default values for all apps

[[apps]]
# repeated app entries
```

## Merge and Override Rules

Oxmgr resolves config in this order:

1. Global defaults (`[defaults]`)
2. App entry (`[[apps]]`)
3. Profile override (`[apps.profiles.<name>]`, when `--env <name>` is used)

Details:

- Scalar fields: later layer overrides earlier layer.
- `env` map: merged by key (`defaults.env` -> `apps.env` -> `profiles.<name>.env`).
- `depends_on`: replaced when profile specifies it.
- Health check exists only when a command is defined (`health_cmd`).
- Resource limits exist only when at least one non-zero limit is set (or when `cgroup_enforce` / `deny_gpu` is enabled).

## Supported Fields

### Top-level

- `version` (required recommended): currently `1`
- `defaults` (optional)
- `apps` (required, array of app entries)
- `deploy` (optional, map of deploy environments)

### `[defaults]` fields

- `restart_policy`: `always | on_failure | never`
- `max_restarts`: integer
- `cwd`: string path
- `env`: key/value table
- `stop_signal`: string (for example `SIGTERM`, `SIGINT`)
- `stop_timeout_secs`: integer
- `restart_delay_secs`: integer
- `start_delay_secs`: integer
- `cluster_mode`: bool
- `cluster_instances`: integer (`>=1`)
- `namespace`: string
- `start_order`: integer
- `depends_on`: array of app names
- `instances`: integer (`>=1`)
- `instance_var`: string
- `health_cmd`: command string
- `health_interval_secs`: integer
- `health_timeout_secs`: integer
- `health_max_failures`: integer
- `max_memory_mb`: integer
- `max_cpu_percent`: float
- `cgroup_enforce`: bool (Linux only; applies hard limits via cgroup v2)
- `deny_gpu`: bool (best-effort GPU visibility disable via environment variables)

### `[[apps]]` fields

- `name`: string (recommended for `apply`)
- `command`: command string (required)
- All fields from `[defaults]` (same semantics)
- `disabled`: bool (skip this app)
- `profiles`: map of profile-specific overrides

### `[apps.profiles.<name>]` fields

- Same overrideable fields as `[[apps]]`
- `disabled` is supported

## Restart Policy Reference

- `always`: restart after any exit (until `max_restarts` is reached)
- `on_failure`: restart only after non-zero/failed exit
- `never`: never auto-restart

## Health Checks

Health checks are command-based:

```toml
health_cmd = "curl -fsS http://127.0.0.1:3000/health"
health_interval_secs = 15
health_timeout_secs = 3
health_max_failures = 3
```

Behavior:

- command executed periodically
- failure increments failure counter
- after `health_max_failures`, process is restarted

## Resource Limits

```toml
max_memory_mb = 512
max_cpu_percent = 80.0
cgroup_enforce = true
deny_gpu = true
```

Behavior:

- limits are checked during daemon maintenance ticks
- when exceeded, Oxmgr triggers restart logic
- if restart budget is exhausted, process is marked `errored`
- if `cgroup_enforce = true`, Linux cgroup v2 hard limits are applied at spawn time

## Dependencies and Start Ordering

You can combine `depends_on` and `start_order`:

- `depends_on` enforces dependency direction
- `start_order` is tie-break ordering among ready apps

Example:

```toml
depends_on = ["db", "redis"]
start_order = 20
```

## Instances

```toml
instances = 3
instance_var = "INSTANCE_ID"
```

Oxmgr expands one app into multiple managed processes:

- `api-0`, `api-1`, `api-2`
- env variable `INSTANCE_ID` set to `0/1/2`

## Node.js Cluster Mode

```toml
cluster_mode = true
cluster_instances = 4
```

Behavior:

- cluster mode applies Node.js cluster fan-out in a single managed process entry
- `cluster_instances` is optional; when omitted, Oxmgr uses all CPUs
- if `cluster_mode` is `false`, `cluster_instances` is ignored

Current command requirement:

- use Node command shape `node <script> [args...]`
- Node runtime flags before script path are not supported in cluster mode

## Conversion and Migration

Convert existing ecosystem JSON:

```bash
oxmgr convert ecosystem.config.json --out oxfile.toml --env prod
```

Then use:

```bash
oxmgr apply ./oxfile.toml --env prod
```

## Deploy Environments (Optional)

You can define deployment environments directly in `oxfile.toml`:

```toml
[deploy.production]
user = "ubuntu"
host = ["192.168.0.13", "192.168.0.14"]
repo = "git@github.com:Username/repository.git"
ref = "origin/main"
path = "/var/www/my-repository"
pre_setup = "echo setup-start"
post_setup = "echo setup-done"
pre_deploy_local = "echo local-prepare"
pre_deploy = "npm ci"
post_deploy = "oxmgr apply ./oxfile.toml --env production"
```

Then deploy with:

```bash
oxmgr deploy ./oxfile.toml production setup
oxmgr deploy ./oxfile.toml production
```

## Real Examples

See ready-to-use files in [`docs/examples`](/Users/vladimirurik/Documents/dev/rust/oxmgr/docs/examples):

- [`oxfile.minimal.toml`](/Users/vladimirurik/Documents/dev/rust/oxmgr/docs/examples/oxfile.minimal.toml)
- [`oxfile.web-stack.toml`](/Users/vladimirurik/Documents/dev/rust/oxmgr/docs/examples/oxfile.web-stack.toml)
- [`oxfile.profiles.toml`](/Users/vladimirurik/Documents/dev/rust/oxmgr/docs/examples/oxfile.profiles.toml)
- [`oxfile.monorepo.toml`](/Users/vladimirurik/Documents/dev/rust/oxmgr/docs/examples/oxfile.monorepo.toml)
- [`oxfile.apply-idempotent.toml`](/Users/vladimirurik/Documents/dev/rust/oxmgr/docs/examples/oxfile.apply-idempotent.toml)
