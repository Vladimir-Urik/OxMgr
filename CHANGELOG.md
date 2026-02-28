# Changelog

## 0.1.0 - 2026-02-28

First public release of Oxmgr.

This entry was assembled from a manual review of every non-merge commit from the initial project commit (`32fe539`, 2026-02-26) through the current `0.1.0` state (`82efba2`, 2026-02-28).

### What Oxmgr Is

Oxmgr is a lightweight, cross-platform, language-agnostic process manager written in Rust. It is positioned as a PM2 alternative that works for Node.js apps, Python services, Go programs, Rust binaries, and shell commands while keeping a small footprint and a practical operational model.

The project is built around a local daemon with persistent state, a CLI that can auto-start the daemon when needed, a native `oxfile.toml` desired-state workflow, and day-to-day operator features such as health checks, logs, reloads, process inspection, and deployment helpers.

### Highlights

- Cross-platform process management for Linux, macOS, and Windows.
- Core lifecycle commands: `start`, `stop`, `restart`, `reload`, `delete`, `list`, `status`, and `logs`.
- Background daemon with local IPC, persistent state, graceful shutdown, daemon stop support, and captured stdout/stderr logs.
- Config-first workflows with native `oxfile.toml`, profile overlays, defaults, dependency ordering, multi-instance expansion, selective apply, validation, and pruning.
- PM2 migration helpers through `ecosystem.config.json` import and conversion to native Oxfile format.
- Health checks, restart policies, crash-loop protection, working-directory watch mode, resource limits, and CPU/RAM monitoring.
- Linux cgroup v2 hard-limit enforcement and best-effort GPU denial support for constrained workloads.
- Git-aware operations with `pull`, per-service git metadata, webhook-triggered pulls, and reload/restart only when revisions change.
- Interactive terminal UI with fleet summary, keyboard and mouse controls, in-UI process creation, detailed process pane, and fullscreen log viewer.
- Bundle export/import via `.oxpkg`, including remote HTTPS bundle import with optional SHA-256 pinning.
- PM2-style remote deployment support with setup, update, revert, history inspection, one-off command execution, and multi-host parallelism.
- Service installation for `systemd`, `launchd`, and Windows Task Scheduler, plus guided startup instructions and diagnostics.
- Release and packaging pipeline for GitHub Releases, npm, Homebrew, Chocolatey, and Debian/Ubuntu APT.

### Changes Since The First Commit

#### Core Runtime Foundation

- Bootstrapped the project with a complete daemon/CLI architecture instead of a minimal skeleton.
- Shipped core process lifecycle management from day one: start, stop, restart, reload, delete, list, logs, and status.
- Added restart policies (`always`, `on-failure`, `never`), max restart budgets, graceful termination, CPU/RAM metrics, and best-effort zero-downtime reloads.
- Implemented persistent local state, per-process stdout/stderr logging, and daemon auto-start from the CLI when commands require it.
- Added Oxfile parsing, validation, idempotent `apply`, dependency-aware ordering, namespaces, instance expansion, and PM2 ecosystem import/convert support in the initial project foundation.

#### Platform Integration And Diagnostics

- Added daemon shutdown IPC support so the background runtime can be stopped cleanly.
- Expanded runtime logging and test logging to make failures and command output easier to inspect.
- Added `startup` guidance and full `service install|uninstall|status` flows for `systemd`, `launchd`, and Windows Task Scheduler.
- Improved platform-specific service generation with better systemd escaping, launchd path normalization, and safer Windows task termination timeouts.
- Added `doctor` to verify local directories, write access, daemon address resolution, state file validity, and daemon responsiveness.

#### Config Model And Runtime Safety

- Added Linux cgroup support for hard resource-limit enforcement and `deny_gpu` handling for best-effort GPU isolation.
- Added crash-loop protection through `crash_restart_limit`, including reset semantics on manual `start`, `restart`, and `reload`.
- Added config fingerprinting so `apply` can distinguish real process-definition drift from unchanged desired state more reliably.
- Improved working-directory handling during command execution and tightened error paths around import/start flows.
- Added test coverage for env parsing, health-check normalization, IPC response handling, state persistence, cgroup behavior, and end-to-end CLI flows.

#### Operator Experience

- Improved `list` and `status` output formatting and extracted shared UI rendering helpers.
- Added command aliases such as `ls`, `ps`, `rs`, `rm`, and `log`, along with more structured grouped help output.
- Introduced `oxmgr ui` with configurable refresh rate, fleet summary, process actions, create modal, help overlay, mouse support, and a fullscreen log viewer.
- Improved log source selection by tracking file modification times so both `logs` and the UI prefer the freshest output.
- Expanded user-facing documentation across installation, CLI reference, UI guide, usage guide, Oxfile guidance, bundle docs, and PM2 migration notes.

#### Git, Deploy, And Portability Workflows

- Added cluster mode for Node.js services with configurable worker count.
- Added bundle export/import and documented `.oxpkg` as the portable service definition format.
- Added PM2-style remote deploy support with config auto-discovery, lifecycle hooks, ref-based deploys, revert support, and parallel multi-host execution.
- Added `pull` for git-backed services plus a local webhook API (`POST /pull/<name|id>`) secured by hashed pull secrets.
- Added change-aware pull behavior so services reload or restart only when the checked-out revision actually changed.
- Added remote HTTPS bundle import with safer URL validation, maximum payload checks, and optional SHA-256 checksum pinning.

#### Release Engineering And Maintenance

- Added CI and release automation for GitHub Releases, platform binaries, Debian packages, npm publishing, Homebrew formula updates, Chocolatey packages, and APT repository publishing.
- Switched build version injection to a dynamic release-time build version.
- Refined GitHub Actions release conditions and updated macOS build targeting in the release workflow.
- Added download metrics automation and a static dashboard generator for package/release distribution visibility.
- Added `CONTRIBUTING.md`, Dependabot configuration, and dependency updates for `thiserror`, `nix`, `json5`, `toml`, and `sysinfo`.
- Refreshed installation instructions, README content, and package-manager-facing documentation ahead of the first public release.

### Notes

- Cluster mode currently supports `node <script> [args...]` style commands.
- Remote imports are intentionally limited to HTTPS `.oxpkg` bundles; raw remote config import is not supported.
- Linux cgroup hard enforcement is Linux-only, while the rest of the tool remains cross-platform.
