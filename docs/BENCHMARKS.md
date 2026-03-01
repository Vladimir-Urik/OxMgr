# Benchmarks

This repository includes an automated `oxmgr` vs `pm2` benchmark harness.

The latest committed benchmark snapshot lives in [`/BENCHMARK.md`](../BENCHMARK.md).

It is designed to run both:

- locally on Linux or macOS
- automatically in GitHub Actions on `ubuntu-latest`

## What It Measures

The suite focuses on process-manager behavior instead of application throughput.

- empty-daemon boot time
- empty-daemon RSS
- config-driven startup time at scale
- time until all managed processes are online
- `oxmgr list` vs `pm2 jlist` latency
- single-app restart latency, split into:
  - command completion
  - replacement PID visible in manager state
  - ready event emitted by the workload
  - ready event visible to the benchmark
  - TCP endpoint serving the replacement PID
- crash recovery latency after `SIGKILL`, split into:
  - replacement PID visible in manager status
  - ready event emitted by the workload
  - ready event visible to the benchmark
  - TCP endpoint serving the replacement PID

The benchmark workload is a minimal idle Node.js process in [`bench/fixtures/idle.js`](../bench/fixtures/idle.js).

## Local Run

Prerequisites:

- Rust toolchain
- Node.js + npm
- Linux or macOS

Run the default suite:

```bash
python3 scripts/benchmark_oxmgr_vs_pm2.py
```

Useful options:

```bash
python3 scripts/benchmark_oxmgr_vs_pm2.py \
  --process-counts 1,25,100 \
  --scale-trials 5 \
  --restart-samples 10 \
  --crash-samples 10 \
  --keep-workspaces
```

By default the script:

- builds `target/release/oxmgr`
- uses `pm2` from `PATH` if present
- otherwise installs a local pinned `pm2` into `bench/.cache/tools/`
- writes reports into `bench/results/<timestamp>/`

Outputs:

- `report.json`: raw samples plus summary statistics
- `summary.md`: Markdown report suitable for GitHub summary or sharing

## GitHub Workflow

The workflow lives in [`.github/workflows/benchmark.yml`](../.github/workflows/benchmark.yml).

It:

- installs a pinned `pm2`
- builds `oxmgr`
- runs the same Python harness as local runs
- refreshes the tracked latest snapshot in [`/BENCHMARK.md`](../BENCHMARK.md)
- uploads `report.json` and `summary.md` as workflow artifacts
- publishes `summary.md` into the GitHub Actions step summary

## Interpreting Results

GitHub-hosted runners are noisy. Use these numbers as trend data:

- compare runs over time on the same workflow
- look at medians and p95, not a single sample
- prefer directionality over tiny deltas

If you want tighter numbers, run the same script on a dedicated machine or self-hosted runner.
