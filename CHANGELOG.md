# Changelog

## v0.1.4 - 2026-03-05

- This release focuses on Windows distribution improvements (Scoop), dependency updates, and refreshed benchmark snapshots since `v0.1.3`.

### Added

- Added Scoop distribution support in release automation with a dedicated `publish-scoop` job.
- Added `scripts/generate_scoop_manifest.sh` to generate the Scoop manifest (`oxmgr.json`) from release metadata and checksums.
- Added Scoop installation instructions to user docs (`README.md` and `docs/install.md`).

### Changed

- Updated release automation docs to include Scoop publishing details and required secrets (`SCOOP_BUCKET_TOKEN`, `SCOOP_BUCKET_REPO`).
- Improved release workflow packaging coverage by validating and publishing Windows Scoop manifest data from release artifacts.
- Maintained the official Scoop bucket target as `empellio/scoop-bucket`.

### Dependencies

- Bumped `dirs` from `5.0.1` to `6.0.0`.
- Bumped `tokio` from `1.49.0` to `1.50.0`.
- Bumped `sysinfo` from `0.38.2` to `0.38.3`.
- Bumped `toml` from `1.0.3+spec-1.1.0` to `1.0.4+spec-1.1.0`.
- Updated `Cargo.lock` accordingly.

### Notes

- No core runtime/process-manager behavior changes were introduced in this release; changes are focused on packaging, distribution, documentation, and dependency refreshes.


### What's Changed
* Bump dirs from 5.0.1 to 6.0.0 by @dependabot[bot] in https://github.com/Vladimir-Urik/OxMgr/pull/10
* Bump toml from 1.0.3+spec-1.1.0 to 1.0.4+spec-1.1.0 by @dependabot[bot] in https://github.com/Vladimir-Urik/OxMgr/pull/9
* Bump sysinfo from 0.38.2 to 0.38.3 by @dependabot[bot] in https://github.com/Vladimir-Urik/OxMgr/pull/8
* Bump tokio from 1.49.0 to 1.50.0 by @dependabot[bot] in https://github.com/Vladimir-Urik/OxMgr/pull/7

**Full Changelog**: https://github.com/Vladimir-Urik/OxMgr/compare/v0.1.3...v0.1.4


## v0.1.3 - 2026-03-04

- This release focuses on PM2 ecosystem compatibility, config-driven watch behavior, readiness-aware reloads, and Windows reliability fixes.

### Added

- Added direct support for PM2-style `ecosystem.config.{js,cjs,mjs,json}` across `validate`, `apply`, `import`, and `convert`.
- Added config-driven watch settings, including explicit watch paths, `ignore_watch` regexes, and restart debounce.
- Added readiness settings, including `wait_ready` and `ready_timeout`, across ecosystem config, `oxfile.toml`, bundles, CLI flags, validation, and status output.

### Fixed

- Fixed reload behavior so replacement processes must pass health-check readiness before cutover; if readiness fails or times out, the old process stays running.
- Fixed Windows HTTP metrics response handling by explicitly shutting down the stream after flushing, avoiding connection reset failures in tests.
- Improved CI reliability for process-manager tests on slower runners by extending long-running test fixtures.

### Validation and UX

- `oxmgr validate` now accepts both `oxfile.toml` and local ecosystem configs, including JS-based PM2 configs.
- Added validation for invalid watch combinations, relative watch paths without `cwd`, invalid `ignore_watch` patterns, and invalid readiness settings.
- Expanded `oxmgr status` output with watch paths, ignore patterns, watch delay, wait-ready, and ready-timeout details.

### Documentation

- Updated the README, CLI reference, and Oxfile docs to cover ecosystem JS support, config-driven watch settings, and readiness-aware reloads.

### Testing

- Added unit and end-to-end coverage for ecosystem JS parsing, profile overrides, watch validation, readiness-aware reload success and failure paths, delayed watch restarts, and Windows HTTP metrics behavior.

**Full Changelog**: https://github.com/Vladimir-Urik/OxMgr/compare/v0.1.2...v0.1.3


## v0.1.2 - 2026-03-03

This release focuses on observability, benchmark publishing, and project maintenance improvements.

### Added

- Added a Prometheus-compatible `GET /metrics` endpoint on the daemon HTTP API.
- Added per-process Prometheus metrics for process state, restart count, CPU, memory, PID, health status, and last-seen timestamps.
- Added endpoint-level test coverage for the new metrics API, including HTTP response checks and Prometheus label escaping cases.
- Added a machine-readable `benchmark.json` snapshot alongside the published benchmark report.
- Added a security policy with supported-version and vulnerability-reporting guidance.
- Added a Contributor Covenant Code of Conduct.
- Added GitHub issue templates for bug reports and feature requests.

### Improved

- Improved daemon readiness checks so `oxmgr` now verifies a real daemon ping response instead of only checking whether a TCP port is open.
- Improved benchmark automation so the scheduled workflow now refreshes and publishes both Markdown and JSON benchmark snapshots.
- Improved the benchmark harness with a stable JSON export format for downstream tooling and comparisons.

### Benchmarks

- Added `benchmark.json` as a tracked machine-readable benchmark snapshot.
- Updated the latest published benchmark snapshot in `BENCHMARK.md`.
- Updated the benchmark workflow artifacts to publish both summary and JSON outputs.

### Documentation

- Documented the new Prometheus metrics endpoint and daemon HTTP API behavior.
- Added Prometheus scrape examples and clarified `OXMGR_API_ADDR` usage across the docs.
- Updated README and docs index links to include the metrics guide and benchmark JSON snapshot.

### Project

- Added a formal security disclosure process.
- Added community contribution standards and better issue intake templates.

**Full Changelog**: https://github.com/Vladimir-Urik/OxMgr/compare/v0.1.1...v0.1.2



## v0.1.1 - 2026-03-01

This release focuses on restart behavior fixes, benchmark coverage, and documentation improvements.

### Fixed
- Fixed crash auto-restart behavior: `--restart-delay 0` now truly means immediate restart after an unexpected exit, with no hidden minimum delay.
- Improved daemon restart scheduling so pending restarts are handled more precisely.
- Added regression coverage for crash recovery and PID replacement, including end-to-end tests.

### Benchmarks
- Added an `oxmgr` vs `pm2` benchmark harness.
- Added a GitHub Actions workflow for scheduled and manual benchmark runs.
- Added `BENCHMARK.md` with the latest published benchmark snapshot.

### Documentation
- Added a new architecture overview.
- Added benchmark documentation and reproducible benchmark workflow docs.
- Clarified CLI and usage docs around `--restart-delay 0`.
- Expanded inline documentation across core modules.


**Full Changelog**: https://github.com/Vladimir-Urik/OxMgr/compare/v0.1.0...v0.1.1



## v0.1.0 - 2026-02-28

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
