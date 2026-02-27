# CLI Reference

This page documents Oxmgr CLI commands and options.

## Most Used Commands

Runtime and monitoring:

- `oxmgr list` (aliases: `oxmgr ls`, `oxmgr ps`)
- `oxmgr status <name|id>`
- `oxmgr logs <name|id>` (alias: `oxmgr log`)
- `oxmgr ui`

Lifecycle operations:

- `oxmgr start "<command>" --name <name>`
- `oxmgr stop <name|id>`
- `oxmgr restart <name|id>` (alias: `oxmgr rs`)
- `oxmgr reload <name|id>`
- `oxmgr pull [name|id]`
- `oxmgr delete <name|id>` (alias: `oxmgr rm`)

Configuration workflow:

- `oxmgr validate <oxfile.toml>`
- `oxmgr apply <oxfile.toml>`
- `oxmgr import <source>`
- `oxmgr export <name|id>`

## Start

`oxmgr start "<command>"`

Common options:

- `--name <name>`
- `--restart <always|on-failure|never>` (default: `on-failure`)
- `--max-restarts <n>` (default: `10`)
- `--crash-restart-limit <n>` (default: `3`, `0` disables the 5-minute crash-loop cutoff)
- `--cwd <path>`
- `--env KEY=VALUE` (repeatable)
- `--watch` (watch working directory and restart on file changes)
- `--health-cmd <command>`
- `--health-interval <seconds>` (default: `30`)
- `--health-timeout <seconds>` (default: `5`)
- `--health-max-failures <n>` (default: `3`)
- `--kill-signal <signal>`
- `--stop-timeout <seconds>` (default: `5`)
- `--restart-delay <seconds>` (default: `0`)
- `--start-delay <seconds>` (default: `0`)
- `--cluster` (Node.js cluster mode)
- `--cluster-instances <n>` (optional worker count; default: all CPUs)
- `--namespace <name>`
- `--max-memory-mb <n>`
- `--max-cpu-percent <n>`
- `--cgroup-enforce`
- `--deny-gpu`

Cluster mode notes:

- Cluster mode currently supports command shape `node <script> [args...]`.
- Node runtime flags before script path are not supported in cluster mode.
- `--cluster-instances` requires `--cluster`.
- `--crash-restart-limit` counts only daemon-triggered auto restarts after unexpected exits.
- Manual `start`, `restart`, and `reload` reset the crash-loop counter.

## Lifecycle

- `oxmgr stop <name|id>`
- `oxmgr restart <name|id>` (alias: `oxmgr rs`)
- `oxmgr reload <name|id>`
- `oxmgr pull [name|id]`
- `oxmgr delete <name|id>` (alias: `oxmgr rm`)

`pull` updates from configured git repository and reloads/restarts the service only when commit changed.

Details and webhook flow: [Pull and Webhook Guide](./PULL_WEBHOOK.md).

## Inspect

- `oxmgr list` (aliases: `oxmgr ls`, `oxmgr ps`)
- `oxmgr status <name|id>`
- `oxmgr logs <name|id> [-f] [--lines <n>]` (alias: `oxmgr log`)
- `oxmgr ui [--interval-ms <n>]`

`list` includes runtime columns such as status, mode, uptime, CPU, RAM, and health.

`status` includes detailed metadata including watch, cluster mode, restart policy, crash-loop cutoff, limits, command, and log paths.

`ui` supports keyboard and mouse controls:

- `Esc` opens/closes menu
- arrows or `j/k` move selection
- `n` create process
- `s` stop selected
- `r` restart selected
- `l` reload selected
- `p` pull selected
- `t` preview latest log line
- `g` / `Space` refresh now
- `?` help overlay
- click row to select
- mouse wheel scrolls selection
- `q` quits

Full UI behavior and panel layout: [Terminal UI Guide](./UI.md).

## Config Commands

- `oxmgr import <source> [--env <profile>] [--only a,b] [--sha256 <hex>]`
- `oxmgr export <name|id> [--out <file>]`
- `oxmgr apply <path> [--env <profile>] [--only a,b] [--prune]`
- `oxmgr convert <ecosystem.json> --out <oxfile.toml> [--env <profile>]`
- `oxmgr validate <oxfile.toml> [--env <profile>] [--only a,b]`

Import source notes:

- Local `ecosystem.config.json` and `oxfile.toml` are supported.
- Local `.oxpkg` bundles are supported.
- Remote source must be `https://...` and currently supports `.oxpkg` bundles only.
- `--sha256` enables checksum pinning for remote imports.
- Remote URL import requires `curl` in `PATH`.

Bundle details: [Service Bundles](./BUNDLES.md).

## Deploy Commands

PM2-style invocation:

- `oxmgr deploy <config_file> <environment> <command>`

Alternative:

- `oxmgr deploy <environment> <command>`
- `oxmgr deploy --config <file> <environment> <command>`

Commands:

- `setup`
- `update`
- `revert [n]`
- `current|curr`
- `previous|prev`
- `list`
- `exec|run "<cmd>"`
- `<ref>` (deploy explicit git ref/tag/branch)

Flags:

- `--force` (for `update` / `<ref>`)

Full deployment configuration details: [Deployment Guide](./DEPLOY.md).

## Service and Daemon

- `oxmgr doctor`
- `oxmgr startup [--system <auto|systemd|launchd|task-scheduler>]`
- `oxmgr service <install|uninstall|status> [--system <...>]`
- `oxmgr daemon run`
- `oxmgr daemon stop`

Webhook endpoint (daemon HTTP API):

- `POST /pull/<name|id>`
- Header: `X-Oxmgr-Secret: <secret>` (or `Authorization: Bearer <secret>`)
- Daemon bind address: `OXMGR_API_ADDR` (default high localhost port)
