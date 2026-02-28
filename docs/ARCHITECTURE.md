# Architecture Overview

This document explains how Oxmgr is structured internally and how the main runtime pieces work together.

## Design Goals

Oxmgr is designed as a lightweight, cross-platform process manager with a clear separation between:

- CLI input and command dispatch
- long-lived daemon state
- process lifecycle orchestration
- persistence, logging, and import/export formats

The implementation favours simple local primitives such as a localhost TCP IPC channel, JSON/TOML files, and explicit state transitions over a deeply layered service architecture.

## High-Level Flow

1. The `oxmgr` binary starts in `src/main.rs`.
2. CLI arguments are parsed in `src/cli.rs`.
3. `src/config.rs` resolves runtime paths, daemon addresses, and log policy.
4. Most commands are dispatched through `src/commands/mod.rs`.
5. If the command needs the daemon, `src/daemon.rs` ensures that it is running and then communicates through `src/ipc.rs`.
6. The daemon owns a single `ProcessManager` instance from `src/process_manager.rs`.
7. `ProcessManager` persists state through `src/storage.rs`, writes logs through `src/logging.rs`, and manages child processes described by types in `src/process.rs`.

## Core Modules

### `src/cli.rs`

Defines the user-facing command-line interface. This module is intentionally thin: it maps parsed flags into helper types such as `HealthCheck` and `ResourceLimits`, then leaves execution to the command layer.

### `src/commands/`

Contains one implementation module per top-level command. These modules translate CLI intent into daemon requests or local-only operations such as validation, conversion, and service installation.

### `src/daemon.rs`

Runs the foreground daemon event loop. The daemon listens on:

- a localhost TCP IPC endpoint for CLI requests
- a localhost HTTP endpoint for authenticated pull webhooks

The daemon serialises state changes through a single manager command channel, which keeps lifecycle transitions predictable.

### `src/process_manager.rs`

This is the operational core of Oxmgr. It is responsible for:

- starting and stopping processes
- tracking desired state versus observed runtime state
- handling reloads, delayed restarts, and crash-loop protection
- running health checks
- collecting CPU and memory metrics
- applying optional resource controls
- persisting state after mutations

If you need to understand runtime behaviour, this is the first file to read.

### `src/process.rs`

Defines the shared domain model:

- requested process configuration (`StartProcessSpec`)
- persisted/runtime process record (`ManagedProcess`)
- restart, health, and desired-state enums

These types are shared by the CLI, daemon, storage layer, importers, and IPC protocol.

### `src/storage.rs`

Persists daemon state to a JSON file under the Oxmgr home directory. Writes are performed through a temporary file and replace step so state updates are resilient to partial writes.

### `src/logging.rs`

Calculates per-process stdout/stderr log paths, rotates oversized logs, cleans up expired rotations, and reads recent log tails for status views and CLI commands.

## Configuration Inputs

Oxmgr accepts several ways to define managed services:

- direct CLI input through `oxmgr start`
- native `oxfile.toml` files parsed by `src/oxfile.rs`
- PM2-compatible `ecosystem.config.json` files parsed by `src/ecosystem.rs`
- portable `.oxpkg` bundles handled by `src/bundle.rs`

Import layers normalise external formats into a common process-spec representation before the daemon starts or updates services. This keeps the runtime logic independent of the source format.

## Process Lifecycle

The normal process lifecycle looks like this:

1. A `StartProcessSpec` is created from CLI input or imported configuration.
2. `ProcessManager` validates and normalises the process name and command line.
3. Log files are prepared and the child process is spawned.
4. Runtime metadata is stored in `ManagedProcess` and written to disk.
5. The daemon periodically:
   - refreshes metrics
   - evaluates file-watch fingerprints
   - runs health checks
   - executes scheduled restarts
6. When a child exits, an exit event is sent back to `ProcessManager`.
7. Restart policy, crash-loop limits, and desired state determine whether Oxmgr restarts the process or marks it as stopped, crashed, or errored.

## Persistence and Recovery

The daemon writes process state to disk so that a restart of Oxmgr does not lose service definitions. On daemon startup, `recover_processes()`:

- clears stale runtime-only fields such as PIDs and transient metrics
- attempts to clean up stale processes that were left behind
- restarts services whose desired state is still `running`

This means Oxmgr treats persisted configuration as authoritative, while live operating-system process IDs are always revalidated.

## IPC and Transport Safety

The CLI and daemon communicate using newline-delimited JSON messages over localhost TCP. The transport is intentionally simple and private to the local machine.

Before process data is returned to the CLI, Oxmgr redacts sensitive values such as:

- environment variables
- stored pull-webhook secret hashes

This keeps status responses useful without leaking secrets through normal tooling.

## Platform-Specific Concerns

- Linux can optionally enforce resource limits through cgroup v2 in `src/cgroup.rs`.
- macOS and Windows use the same high-level lifecycle code but skip Linux-specific cgroup enforcement.
- Service installation is delegated to platform-specific command implementations rather than being mixed into the daemon core.

## Where To Extend the Code

For common kinds of changes, start in these places:

- new CLI flag or subcommand: `src/cli.rs` and `src/commands/`
- new runtime lifecycle behaviour: `src/process_manager.rs`
- new persisted process field: `src/process.rs` and `src/storage.rs`
- new configuration format capability: `src/oxfile.rs` or `src/ecosystem.rs`
- log handling changes: `src/logging.rs`
- daemon protocol change: `src/ipc.rs` and the relevant command handler

Keep source-level rustdoc and user-facing docs in sync when changing behaviour, flags, or configuration semantics.
