# Contributing to Oxmgr

Thanks for contributing. Oxmgr targets Linux, macOS, and Windows, so changes should stay portable and easy to review.

## Development Setup

Prerequisites:

- Rust stable toolchain
- Git
- A local clone of this repository

Get started:

```bash
git clone https://github.com/Vladimir-Urik/OxMgr.git
cd OxMgr
cargo build
cargo run -- --help
```

If you want a release-style binary while developing:

```bash
cargo build --release
./target/release/oxmgr --help
```

## Project Layout

- `src/`: CLI, daemon, process lifecycle, config parsing, IPC, logging, storage
- `tests/e2e_cli.rs`: end-to-end CLI coverage
- `docs/`: user-facing guides, CLI docs, oxfile docs, deployment notes
- `packaging/`: npm and Chocolatey packaging assets
- `scripts/`: packaging/release helper scripts

For a higher-level architecture summary, see [README.md](./README.md).

## Daily Workflow

1. Create a focused branch for one change.
2. Make the smallest coherent change that solves the problem.
3. Add or update tests for behavior changes.
4. Update docs when flags, commands, config format, or workflows change.
5. Run the relevant checks before opening a PR.

## Local Checks

These match the core CI workflow:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
```

Recommended extra check:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## End-to-End Tests

The E2E suite is opt-in and skips by default unless `OXMGR_RUN_E2E=1` is set.

Unix shells:

```bash
OXMGR_RUN_E2E=1 cargo test --test e2e_cli -- --nocapture
```

PowerShell:

```powershell
$env:OXMGR_RUN_E2E = "1"
cargo test --test e2e_cli -- --nocapture --test-threads=1
```

Use the E2E suite when touching daemon behavior, lifecycle management, CLI flows, or cross-process interactions.

## Testing Expectations

- Parser or config changes should include focused tests near the affected module.
- CLI behavior changes should include integration coverage when practical.
- Daemon and process-management changes should prefer deterministic assertions over long sleeps.
- UI changes should update tests only where logic is covered; keep visual-only adjustments well explained in the PR.

## Documentation Expectations

Please update the relevant docs alongside code changes:

- `README.md` for user-visible behavior or project positioning changes
- `docs/CLI.md` for command or flag changes
- `docs/OXFILE.md` and `docs/examples/` for config-format changes
- `docs/UI.md`, `docs/PULL_WEBHOOK.md`, `docs/DEPLOY.md`, or other guides when workflows change

If behavior changes but docs stay untouched, explain why in the PR.

## Pull Requests

Open PRs with enough context for review:

- problem statement
- short design summary
- test evidence
- migration or backward-compatibility notes when applicable

Keep PRs focused. Avoid mixing unrelated refactors with behavior changes unless the refactor is required to make the change safe.

## Release Notes

Releases are tag-driven through GitHub Actions. For normal contributions, do not manually prepare a release or bump packaging versions just to ship a feature. If a change affects packaging or release automation, document that impact clearly in the PR and update the relevant files under `packaging/`, `scripts/`, or `docs/RELEASE.md`.
