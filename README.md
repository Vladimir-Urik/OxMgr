# Oxmgr

[![CI](https://github.com/Vladimir-Urik/OxMgr/actions/workflows/ci.yml/badge.svg)](https://github.com/Vladimir-Urik/OxMgr/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/Vladimir-Urik/OxMgr?include_prereleases)](https://github.com/Vladimir-Urik/OxMgr/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](./LICENSE)

Oxmgr is a lightweight, cross-platform Rust process manager and PM2 alternative.

Use it to run, supervise, reload, and monitor long-running services on Linux, macOS, and Windows. Oxmgr is language-agnostic, so it works with Node.js, Python, Go, Rust binaries, and shell commands.

## Why Oxmgr

- Language-agnostic: manage any executable, not just Node.js apps
- Cross-platform: Linux, macOS, and Windows
- Low overhead: Rust daemon with persistent local state
- Practical operations: restart policies, health checks, logs, and CPU/RAM metrics
- Config-first workflows with idempotent `oxmgr apply`
- PM2 ecosystem compatibility via `ecosystem.config.json`
- Interactive terminal UI for day-to-day operations

## Core Features

- Start, stop, restart, reload, and delete managed processes
- Named services and namespaces
- Restart policies: `always`, `on-failure`, and `never`
- Health checks with automatic restart on repeated failures
- Log tailing, log rotation, and per-process stdout/stderr logs
- Best-effort zero-downtime reloads
- Git pull and webhook-driven update workflow
- Import and export bundles with `.oxpkg`
- Service installation for `systemd`, `launchd`, and Windows Task Scheduler

## Install

### npm

```bash
npm install -g oxmgr
```

### Homebrew

```bash
brew tap empellio/homebrew-tap
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
./target/release/oxmgr --help
```

For signed APT setup, local installation, and platform-specific notes, see [docs/install.md](./docs/install.md).

## Quick Start

Start a service:

```bash
oxmgr start "node server.js" --name api --restart always
```

Inspect and operate it:

```bash
oxmgr list
oxmgr status api
oxmgr logs api -f
oxmgr ui
```

Use a config file for repeatable setups:

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
oxmgr validate ./oxfile.toml
oxmgr apply ./oxfile.toml
```

## PM2 Migration

Oxmgr supports PM2-style `ecosystem.config.json`, which makes it easier to move existing PM2 setups without rewriting everything on day one.

Useful links:

- [Oxfile vs PM2 Ecosystem](./docs/OXFILE_VS_PM2.md)
- [Oxfile Specification](./docs/OXFILE.md)

## Documentation

- [Documentation Index](./docs/README.md)
- [Installation Guide](./docs/install.md)
- [User Guide](./docs/USAGE.md)
- [CLI Reference](./docs/CLI.md)
- [Terminal UI Guide](./docs/UI.md)
- [Pull and Webhook Guide](./docs/PULL_WEBHOOK.md)
- [Deployment Guide](./docs/DEPLOY.md)
- [Service Bundles](./docs/BUNDLES.md)
- [Examples](./docs/examples)

## Contributing

Issues, PRs, and documentation improvements are welcome. Start with [CONTRIBUTING.md](./CONTRIBUTING.md) for local setup, checks, and testing expectations.

## Community

Oxmgr is created and maintained by **Vladimír Urík**.

The project is developed under the open-source patronage of [Empellio](https://empellio.com).

## License

[MIT](./LICENSE)
