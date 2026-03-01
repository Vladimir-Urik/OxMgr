#!/usr/bin/env python3
"""Run reproducible oxmgr vs pm2 benchmarks locally or in CI."""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "bench"
FIXTURES_DIR = BENCH_DIR / "fixtures"
IDLE_FIXTURE = FIXTURES_DIR / "idle.js"
DEFAULT_PM2_VERSION = "5.4.3"
DEFAULT_LIST_SAMPLES = 7
DEFAULT_RESTART_SAMPLES = 7
DEFAULT_CRASH_SAMPLES = 7
DEFAULT_SCALE_TRIALS = 3
DEFAULT_BOOT_TRIALS = 3
READY_WAIT_STEP_SECS = 0.01
READY_HOST = "127.0.0.1"
READY_EVENT_NAME = "ready:tcp"


class BenchmarkError(RuntimeError):
    """Raised when benchmark setup or execution fails."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark oxmgr against pm2 with the same idle Node.js workloads."
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for JSON and Markdown reports. Defaults to bench/results/<timestamp>.",
    )
    parser.add_argument(
        "--process-counts",
        default="1,25,100",
        help="Comma-separated process counts for scale benchmarks.",
    )
    parser.add_argument(
        "--scale-trials",
        type=int,
        default=DEFAULT_SCALE_TRIALS,
        help="Trials per manager/process-count for scale benchmarks.",
    )
    parser.add_argument(
        "--boot-trials",
        type=int,
        default=DEFAULT_BOOT_TRIALS,
        help="Trials per manager for empty-daemon boot benchmark.",
    )
    parser.add_argument(
        "--list-samples",
        type=int,
        default=DEFAULT_LIST_SAMPLES,
        help="Warm list/jlist samples to record after startup within each scale trial.",
    )
    parser.add_argument(
        "--restart-samples",
        type=int,
        default=DEFAULT_RESTART_SAMPLES,
        help="Warm restart samples to record per manager.",
    )
    parser.add_argument(
        "--crash-samples",
        type=int,
        default=DEFAULT_CRASH_SAMPLES,
        help="Crash recovery samples to record per manager.",
    )
    parser.add_argument(
        "--pm2-version",
        default=DEFAULT_PM2_VERSION,
        help="pm2 version to install locally when pm2 is not already available.",
    )
    parser.add_argument(
        "--pm2-bin",
        help="Explicit pm2 binary or command string. Defaults to PATH lookup, then local install.",
    )
    parser.add_argument(
        "--oxmgr-bin",
        help="Explicit oxmgr binary path. Defaults to target/release/oxmgr after cargo build.",
    )
    parser.add_argument(
        "--node-bin",
        default=shutil.which("node") or "node",
        help="Node.js binary used for the benchmark workload.",
    )
    parser.add_argument(
        "--cargo-bin",
        default=shutil.which("cargo") or "cargo",
        help="Cargo binary used to build oxmgr when --oxmgr-bin is not provided.",
    )
    parser.add_argument(
        "--keep-workspaces",
        action="store_true",
        help="Keep per-trial temporary homes and generated configs under the output directory.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip cargo build and assume the selected oxmgr binary already exists.",
    )
    return parser.parse_args()


def ensure_executable(command: str, label: str) -> str:
    resolved = shutil.which(command)
    if not resolved:
        raise BenchmarkError(f"{label} not found in PATH: {command}")
    return resolved


def build_oxmgr(cargo_bin: str) -> Path:
    print("Building oxmgr release binary...", file=sys.stderr)
    run_command([cargo_bin, "build", "--release", "--bin", "oxmgr"], cwd=REPO_ROOT)
    binary = REPO_ROOT / "target" / "release" / "oxmgr"
    if not binary.exists():
        raise BenchmarkError(f"expected oxmgr binary at {binary}")
    return binary


def ensure_pm2(args: argparse.Namespace, tools_dir: Path) -> list[str]:
    if args.pm2_bin:
        return shlex.split(args.pm2_bin)

    pm2_in_path = shutil.which("pm2")
    if pm2_in_path:
        return [pm2_in_path]

    npm_bin = shutil.which("npm")
    if not npm_bin:
        raise BenchmarkError("pm2 is not installed and npm is unavailable for local bootstrap")

    install_root = tools_dir / f"pm2-{args.pm2_version}"
    pm2_path = install_root / "node_modules" / ".bin" / "pm2"
    if not pm2_path.exists():
        print(
            f"Installing pm2@{args.pm2_version} under {install_root}...",
            file=sys.stderr,
        )
        install_root.mkdir(parents=True, exist_ok=True)
        run_command(
            [
                npm_bin,
                "install",
                "--prefix",
                str(install_root),
                "--silent",
                "--no-audit",
                "--no-fund",
                f"pm2@{args.pm2_version}",
            ],
            cwd=REPO_ROOT,
        )
    if not pm2_path.exists():
        raise BenchmarkError(f"failed to install pm2 under {pm2_path}")
    return [str(pm2_path)]


def run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        timeout=timeout,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
    )


def time_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> tuple[float, subprocess.CompletedProcess[str]]:
    started = time.perf_counter()
    result = run_command(argv, cwd=cwd, env=env, timeout=timeout)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return elapsed_ms, result


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(predicate, timeout: float, step: float = 0.1, what: str = "condition") -> None:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if predicate():
            return
        time.sleep(step)
    if predicate():
        return
    raise BenchmarkError(f"timed out waiting for {what}")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def optional_command_output(argv: list[str], *, cwd: Path | None = None) -> str | None:
    try:
        return run_command(argv, cwd=cwd, timeout=30).stdout.strip()
    except Exception:
        return None


def quantile(values: list[float], percentile: float) -> float:
    if not values:
        return math.nan
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(ordered[lower])
    weight = rank - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def summarize_samples(values: list[float]) -> dict[str, float]:
    return {
        "count": float(len(values)),
        "min": float(min(values)),
        "median": float(statistics.median(values)),
        "mean": float(statistics.mean(values)),
        "p95": float(quantile(values, 0.95)),
        "max": float(max(values)),
    }


def format_float(value: float, digits: int = 1) -> str:
    if math.isnan(value):
        return "n/a"
    return f"{value:.{digits}f}"


def sanitize_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in value)


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def read_event_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        events.append(json.loads(raw_line))
    return events


def parse_key_value_lines(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def start_timed_action(action) -> tuple[threading.Thread, dict[str, Any]]:
    state: dict[str, Any] = {"done": False, "error": None, "elapsed_ms": math.nan}

    def runner() -> None:
        started = time.perf_counter()
        try:
            action()
        except Exception as error:  # pragma: no cover - exercised through callers
            state["error"] = error
        finally:
            state["elapsed_ms"] = (time.perf_counter() - started) * 1000.0
            state["done"] = True

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, state


def find_new_process_event(
    path: Path,
    start_index: int,
    old_pid: int,
    event_name: str,
) -> tuple[dict[str, Any], int] | None:
    events = read_event_lines(path)
    for event in events[start_index:]:
        try:
            event_pid = int(event.get("pid", -1))
        except (TypeError, ValueError):
            continue
        if event_pid == old_pid or event.get("event") != event_name:
            continue
        return event, len(events)
    return None


def probe_ready_pid(host: str, port: int) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=0.05) as conn:
            conn.settimeout(0.05)
            payload = conn.recv(64).decode("utf-8", errors="replace").strip()
    except OSError:
        return None
    if not payload:
        return None
    try:
        return int(payload)
    except ValueError:
        return None


def measure_lifecycle_transition(
    adapter: Any,
    workspace: TrialWorkspace,
    app_name: str,
    event_file: Path,
    ready_port: int,
    *,
    old_pid: int | None = None,
    action,
    action_label: str,
    timeout: float,
) -> dict[str, Any]:
    before_events = read_event_lines(event_file)
    before_event_count = len(before_events)
    if old_pid is None:
        old_pid = adapter.process_pid(workspace, app_name)
    started_perf = time.perf_counter()
    started_wall_ms = time.time() * 1000.0
    action_thread, action_state = start_timed_action(action)

    deadline = started_perf + timeout
    replacement_pid: int | None = None
    pid_visible_ms: float | None = None
    ready_event: dict[str, Any] | None = None
    ready_event_visible_ms: float | None = None
    ready_event_count_after = before_event_count
    tcp_ready_pid: int | None = None
    tcp_ready_ms: float | None = None

    while time.perf_counter() < deadline:
        if replacement_pid is None:
            try:
                current_pid = adapter.process_pid(workspace, app_name)
            except Exception:
                current_pid = None
            if current_pid is not None and current_pid != old_pid:
                replacement_pid = current_pid
                pid_visible_ms = (time.perf_counter() - started_perf) * 1000.0

        if ready_event is None:
            event_match = find_new_process_event(
                event_file,
                before_event_count,
                old_pid,
                READY_EVENT_NAME,
            )
            if event_match is not None:
                ready_event, ready_event_count_after = event_match
                ready_event_visible_ms = (time.perf_counter() - started_perf) * 1000.0

        if tcp_ready_ms is None:
            ready_pid = probe_ready_pid(READY_HOST, ready_port)
            if ready_pid is not None and ready_pid != old_pid:
                tcp_ready_pid = ready_pid
                tcp_ready_ms = (time.perf_counter() - started_perf) * 1000.0

        if (
            action_state["done"]
            and replacement_pid is not None
            and ready_event is not None
            and tcp_ready_ms is not None
        ):
            break

        time.sleep(READY_WAIT_STEP_SECS)

    remaining = max(0.0, deadline - time.perf_counter())
    action_thread.join(timeout=remaining)
    if not action_state["done"]:
        raise BenchmarkError(f"{action_label} timed out after {timeout:.1f}s")
    if action_state["error"] is not None:
        raise BenchmarkError(f"{action_label} failed: {action_state['error']}")
    if replacement_pid is None or pid_visible_ms is None:
        raise BenchmarkError(f"timed out waiting for {action_label} replacement pid")
    if ready_event is None or ready_event_visible_ms is None:
        raise BenchmarkError(f"timed out waiting for {action_label} ready event")
    if tcp_ready_ms is None:
        raise BenchmarkError(f"timed out waiting for {action_label} tcp ready")

    ready_event_pid = int(ready_event.get("pid", -1))
    ready_event_emitted_ms = max(float(ready_event.get("ts_ms", started_wall_ms)) - started_wall_ms, 0.0)

    return {
        "old_pid": old_pid,
        "replacement_pid": replacement_pid,
        "ready_event_pid": ready_event_pid,
        "tcp_ready_pid": tcp_ready_pid,
        "event_count_before": before_event_count,
        "event_count_after": ready_event_count_after,
        "command_ms": float(action_state["elapsed_ms"]),
        "pid_visible_ms": pid_visible_ms,
        "ready_event_emitted_ms": ready_event_emitted_ms,
        "ready_event_visible_ms": ready_event_visible_ms,
        "tcp_ready_ms": tcp_ready_ms,
    }


def read_ps_metric(pid: int, field: str) -> float:
    result = run_command(["ps", "-o", f"{field}=", "-p", str(pid)], timeout=10)
    output = result.stdout.strip()
    if not output:
        raise BenchmarkError(f"ps returned no {field} value for pid {pid}")
    return float(output)


def read_rss_kb(pid: int) -> int:
    return int(round(read_ps_metric(pid, "rss")))


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def terminate_pid(pid: int, timeout: float = 5.0) -> None:
    if not pid_exists(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return

    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if not pid_exists(pid):
            return
        time.sleep(0.1)

    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return


def benchmark_fixture_pids() -> list[int]:
    result = run_command(["ps", "-axo", "pid=,command="], timeout=30)
    pids: list[int] = []
    fixture_path = str(IDLE_FIXTURE)
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped or fixture_path not in stripped:
            continue
        pid_text, _, _command = stripped.partition(" ")
        try:
            pids.append(int(pid_text))
        except ValueError:
            continue
    return pids


def cleanup_fixture_processes() -> None:
    for pid in benchmark_fixture_pids():
        terminate_pid(pid, timeout=1.0)


def command_to_string(argv: list[str]) -> str:
    return " ".join(shell_quote(part) for part in argv)


def safe_remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


@dataclass
class TrialWorkspace:
    root: Path
    home_dir: Path
    work_dir: Path
    daemon_addr: str
    api_addr: str


def make_workspace(parent: Path, keep: bool, label: str) -> TrialWorkspace:
    workspace_root = Path(
        tempfile.mkdtemp(prefix=f"{sanitize_name(label)}-", dir=parent if keep else None)
    )
    if keep:
        workspace_root.mkdir(parents=True, exist_ok=True)
    home_dir = workspace_root / "home"
    work_dir = workspace_root / "work"
    home_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    daemon_port = available_port()
    api_port = available_port()
    return TrialWorkspace(
        root=workspace_root,
        home_dir=home_dir,
        work_dir=work_dir,
        daemon_addr=f"127.0.0.1:{daemon_port}",
        api_addr=f"127.0.0.1:{api_port}",
    )


class OxmgrAdapter:
    name = "oxmgr"

    def __init__(self, binary: Path, node_binary: str) -> None:
        self.binary = binary
        self.node_binary = node_binary
        self._daemon: subprocess.Popen[str] | None = None

    def base_env(self, workspace: TrialWorkspace) -> dict[str, str]:
        env = os.environ.copy()
        env["OXMGR_HOME"] = str(workspace.home_dir)
        env["OXMGR_DAEMON_ADDR"] = workspace.daemon_addr
        env["OXMGR_API_ADDR"] = workspace.api_addr
        env["OXMGR_LOG_MAX_SIZE_MB"] = "64"
        env["OXMGR_LOG_MAX_FILES"] = "2"
        env["OXMGR_LOG_MAX_DAYS"] = "1"
        return env

    def command(self, *extra: str) -> list[str]:
        return [str(self.binary), *extra]

    def daemon_pid(self) -> int:
        if self._daemon is None:
            raise BenchmarkError("oxmgr daemon process unavailable")
        return self._daemon.pid

    def boot(self, workspace: TrialWorkspace) -> dict[str, Any]:
        env = self.base_env(workspace)
        started = time.perf_counter()
        self._daemon = subprocess.Popen(
            self.command("daemon", "run"),
            cwd=workspace.work_dir,
            env=env,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_until(
            lambda: self._daemon is not None
            and self._daemon.poll() is None
            and self.is_ready(workspace),
            timeout=10.0,
            what="oxmgr daemon readiness",
        )
        boot_ms = (time.perf_counter() - started) * 1000.0
        daemon_pid = self.daemon_pid()
        return {
            "boot_ms": boot_ms,
            "daemon_pid": daemon_pid,
            "daemon_rss_kb": read_rss_kb(daemon_pid),
        }

    def is_ready(self, workspace: TrialWorkspace) -> bool:
        host, port_text = workspace.daemon_addr.rsplit(":", 1)
        try:
            with socket.create_connection((host, int(port_text)), timeout=0.2):
                pass
            return True
        except Exception:
            return False

    def generate_scale_config(
        self,
        workspace: TrialWorkspace,
        process_count: int,
        event_file: Path | None = None,
        ready_port: int | None = None,
    ) -> Path:
        lines = ["version = 1", ""]
        for index in range(process_count):
            app_name = f"bench-{index:03d}"
            env_lines = []
            if index == 0:
                env_entries = []
                if event_file is not None:
                    env_entries.append(f'BENCH_EVENT_FILE = "{event_file.as_posix()}"')
                if ready_port is not None:
                    env_entries.append(f'BENCH_READY_PORT = "{ready_port}"')
                    env_entries.append(f'BENCH_READY_HOST = "{READY_HOST}"')
                if env_entries:
                    env_lines = [f'env = {{ {", ".join(env_entries)} }}']
            command = f"{shell_quote(self.node_binary)} {shell_quote(str(IDLE_FIXTURE))}"
            lines.extend(
                [
                    "[[apps]]",
                    f'name = "{app_name}"',
                    f'command = "{command}"',
                    'restart_policy = "always"',
                    "max_restarts = 1000",
                    "crash_restart_limit = 1000",
                    "stop_timeout_secs = 1",
                    *env_lines,
                    "",
                ]
            )
        config_path = workspace.work_dir / "oxfile.toml"
        config_path.write_text("\n".join(lines), encoding="utf-8")
        return config_path

    def start_scale(self, workspace: TrialWorkspace, config_path: Path) -> float:
        elapsed_ms, _ = time_command(
            self.command("apply", str(config_path)),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=180,
        )
        return elapsed_ms

    def wait_processes_online(
        self,
        workspace: TrialWorkspace,
        process_count: int,
        timeout: float,
    ) -> tuple[float, dict[str, Any]]:
        started = time.perf_counter()

        def read_state() -> dict[str, Any] | None:
            state_path = workspace.home_dir / "state.json"
            if not state_path.exists():
                return None
            state = read_json(state_path)
            processes = state.get("processes", [])
            if len(processes) != process_count:
                return None
            if not all(
                process.get("status") == "running" and process.get("pid")
                for process in processes
            ):
                return None
            return state

        state_box: dict[str, Any] = {}

        def predicate() -> bool:
            state = read_state()
            if state is None:
                return False
            state_box["value"] = state
            return True

        wait_until(predicate, timeout=timeout, step=0.2, what="oxmgr processes online")
        settled_ms = (time.perf_counter() - started) * 1000.0
        return settled_ms, state_box["value"]

    def list_latency_sample(self, workspace: TrialWorkspace) -> float:
        elapsed_ms, _ = time_command(
            self.command("list"),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=60,
        )
        return elapsed_ms

    def process_status(self, workspace: TrialWorkspace, app_name: str) -> dict[str, str]:
        result = run_command(
            self.command("status", app_name),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=30,
        )
        return parse_key_value_lines(result.stdout)

    def process_pid(self, workspace: TrialWorkspace, app_name: str) -> int:
        fields = self.process_status(workspace, app_name)
        pid_text = fields.get("PID")
        if not pid_text or pid_text == "-":
            raise BenchmarkError(f"oxmgr status does not report a pid for {app_name}")
        return int(pid_text)

    def restart_one(self, workspace: TrialWorkspace, app_name: str) -> None:
        run_command(
            self.command("restart", app_name),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=60,
        )

    def wait_for_replacement_pid(
        self,
        workspace: TrialWorkspace,
        app_name: str,
        previous_pid: int,
        timeout: float,
    ) -> int:
        pid_box: dict[str, int] = {}

        def predicate() -> bool:
            try:
                current_pid = self.process_pid(workspace, app_name)
            except Exception:
                return False
            if current_pid == previous_pid:
                return False
            pid_box["value"] = current_pid
            return True

        wait_until(predicate, timeout=timeout, step=0.1, what=f"oxmgr replacement pid for {app_name}")
        return pid_box["value"]

    def cleanup(self, workspace: TrialWorkspace) -> None:
        env = self.base_env(workspace)
        try:
            run_command(
                self.command("daemon", "stop"),
                cwd=workspace.work_dir,
                env=env,
                timeout=30,
            )
        except Exception:
            pass
        if self._daemon is not None:
            try:
                self._daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._daemon.kill()
                self._daemon.wait(timeout=5)
            self._daemon = None


class Pm2Adapter:
    name = "pm2"

    def __init__(self, command: list[str], node_binary: str) -> None:
        self.command_prefix = command
        self.node_binary = node_binary

    def base_env(self, workspace: TrialWorkspace) -> dict[str, str]:
        env = os.environ.copy()
        env["PM2_HOME"] = str(workspace.home_dir)
        return env

    def command(self, *extra: str) -> list[str]:
        return [*self.command_prefix, *extra]

    def daemon_pid(self, workspace: TrialWorkspace) -> int:
        return int((workspace.home_dir / "pm2.pid").read_text(encoding="utf-8").strip())

    def boot(self, workspace: TrialWorkspace) -> dict[str, Any]:
        env = self.base_env(workspace)
        started = time.perf_counter()
        run_command(self.command("ping"), cwd=workspace.work_dir, env=env, timeout=60)
        wait_until(
            lambda: (workspace.home_dir / "pm2.pid").exists(),
            timeout=10.0,
            what="pm2 pid file",
        )
        daemon_pid = self.daemon_pid(workspace)
        boot_ms = (time.perf_counter() - started) * 1000.0
        return {
            "boot_ms": boot_ms,
            "daemon_pid": daemon_pid,
            "daemon_rss_kb": read_rss_kb(daemon_pid),
        }

    def generate_scale_config(
        self,
        workspace: TrialWorkspace,
        process_count: int,
        event_file: Path | None = None,
        ready_port: int | None = None,
    ) -> Path:
        apps = []
        for index in range(process_count):
            env = {}
            if index == 0:
                if event_file is not None:
                    env["BENCH_EVENT_FILE"] = str(event_file)
                if ready_port is not None:
                    env["BENCH_READY_PORT"] = str(ready_port)
                    env["BENCH_READY_HOST"] = READY_HOST
            apps.append(
                {
                    "name": f"bench-{index:03d}",
                    "script": str(IDLE_FIXTURE),
                    "exec_interpreter": self.node_binary,
                    "autorestart": True,
                    "max_restarts": 1000,
                    "kill_timeout": 1000,
                    "env": env,
                }
            )
        config_path = workspace.work_dir / "ecosystem.config.json"
        config_path.write_text(json.dumps({"apps": apps}, indent=2), encoding="utf-8")
        return config_path

    def start_scale(self, workspace: TrialWorkspace, config_path: Path) -> float:
        elapsed_ms, _ = time_command(
            self.command("start", str(config_path)),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=180,
        )
        return elapsed_ms

    def _jlist(self, workspace: TrialWorkspace) -> list[dict[str, Any]]:
        result = run_command(
            self.command("jlist"),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=60,
        )
        return json.loads(result.stdout)

    def wait_processes_online(
        self,
        workspace: TrialWorkspace,
        process_count: int,
        timeout: float,
    ) -> tuple[float, list[dict[str, Any]]]:
        started = time.perf_counter()
        state_box: dict[str, list[dict[str, Any]]] = {}

        def predicate() -> bool:
            try:
                state = self._jlist(workspace)
            except Exception:
                return False
            if len(state) != process_count:
                return False
            if not all(
                app.get("pm2_env", {}).get("status") == "online" and app.get("pid")
                for app in state
            ):
                return False
            state_box["value"] = state
            return True

        wait_until(predicate, timeout=timeout, step=0.2, what="pm2 processes online")
        settled_ms = (time.perf_counter() - started) * 1000.0
        return settled_ms, state_box["value"]

    def list_latency_sample(self, workspace: TrialWorkspace) -> float:
        elapsed_ms, _ = time_command(
            self.command("jlist"),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=60,
        )
        return elapsed_ms

    def process_pid(self, workspace: TrialWorkspace, app_name: str) -> int:
        for app in self._jlist(workspace):
            if app.get("name") == app_name and app.get("pid"):
                return int(app["pid"])
        raise BenchmarkError(f"pm2 process not found in jlist: {app_name}")

    def managed_pids(self, workspace: TrialWorkspace) -> list[int]:
        try:
            state = self._jlist(workspace)
        except Exception:
            return []
        return [
            int(app["pid"])
            for app in state
            if app.get("pid") and app.get("pm2_env", {}).get("status") == "online"
        ]

    def restart_one(self, workspace: TrialWorkspace, app_name: str) -> None:
        run_command(
            self.command("restart", app_name),
            cwd=workspace.work_dir,
            env=self.base_env(workspace),
            timeout=60,
        )

    def wait_for_replacement_pid(
        self,
        workspace: TrialWorkspace,
        app_name: str,
        previous_pid: int,
        timeout: float,
    ) -> int:
        pid_box: dict[str, int] = {}

        def predicate() -> bool:
            try:
                current_pid = self.process_pid(workspace, app_name)
            except Exception:
                return False
            if current_pid == previous_pid:
                return False
            pid_box["value"] = current_pid
            return True

        wait_until(predicate, timeout=timeout, step=0.1, what=f"pm2 replacement pid for {app_name}")
        return pid_box["value"]

    def cleanup(self, workspace: TrialWorkspace) -> None:
        env = self.base_env(workspace)
        managed_pids = self.managed_pids(workspace)
        daemon_pid = None
        if (workspace.home_dir / "pm2.pid").exists():
            try:
                daemon_pid = self.daemon_pid(workspace)
            except Exception:
                daemon_pid = None
        for argv in (self.command("delete", "all"), self.command("kill")):
            try:
                run_command(argv, cwd=workspace.work_dir, env=env, timeout=60)
            except Exception:
                pass
        if daemon_pid is not None:
            terminate_pid(daemon_pid, timeout=3.0)
        for pid in managed_pids:
            terminate_pid(pid, timeout=3.0)

def benchmark_boot(
    adapter: Any,
    workspaces_root: Path,
    keep_workspaces: bool,
    trials: int,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for index in range(trials):
        workspace = make_workspace(workspaces_root, keep_workspaces, f"{adapter.name}-boot-{index}")
        try:
            sample = adapter.boot(workspace)
            samples.append(sample)
        finally:
            adapter.cleanup(workspace)
            cleanup_fixture_processes()
            if not keep_workspaces:
                safe_remove_tree(workspace.root)

    boot_values = [sample["boot_ms"] for sample in samples]
    rss_values = [float(sample["daemon_rss_kb"]) for sample in samples]
    return {
        "samples": samples,
        "boot_ms": summarize_samples(boot_values),
        "daemon_rss_kb": summarize_samples(rss_values),
    }


def benchmark_scale(
    adapter: Any,
    workspaces_root: Path,
    keep_workspaces: bool,
    process_count: int,
    trials: int,
    list_samples: int,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for index in range(trials):
        workspace = make_workspace(
            workspaces_root,
            keep_workspaces,
            f"{adapter.name}-scale-{process_count}-{index}",
        )
        try:
            boot_info = adapter.boot(workspace)
            config_path = adapter.generate_scale_config(workspace, process_count)
            start_ms = adapter.start_scale(workspace, config_path)
            settle_ms, _state = adapter.wait_processes_online(workspace, process_count, timeout=180.0)
            list_latencies = [
                adapter.list_latency_sample(workspace) for _ in range(list_samples)
            ]
            daemon_pid = boot_info["daemon_pid"]
            samples.append(
                {
                    "process_count": process_count,
                    "start_ms": start_ms,
                    "settle_ms": settle_ms,
                    "daemon_pid": daemon_pid,
                    "daemon_rss_kb": read_rss_kb(daemon_pid),
                    "list_ms_samples": list_latencies,
                }
            )
        finally:
            adapter.cleanup(workspace)
            cleanup_fixture_processes()
            if not keep_workspaces:
                safe_remove_tree(workspace.root)

    return {
        "samples": samples,
        "start_ms": summarize_samples([sample["start_ms"] for sample in samples]),
        "settle_ms": summarize_samples([sample["settle_ms"] for sample in samples]),
        "daemon_rss_kb": summarize_samples([float(sample["daemon_rss_kb"]) for sample in samples]),
        "list_ms": summarize_samples(
            [value for sample in samples for value in sample["list_ms_samples"]]
        ),
    }


def benchmark_restart(
    adapter: Any,
    workspaces_root: Path,
    keep_workspaces: bool,
    samples: int,
) -> dict[str, Any]:
    workspace = make_workspace(workspaces_root, keep_workspaces, f"{adapter.name}-restart")
    app_name = "bench-000"
    try:
        adapter.boot(workspace)
        event_file = workspace.work_dir / "events.ndjson"
        ready_port = available_port()
        config_path = adapter.generate_scale_config(
            workspace,
            1,
            event_file=event_file,
            ready_port=ready_port,
        )
        adapter.start_scale(workspace, config_path)
        adapter.wait_processes_online(workspace, 1, timeout=90.0)

        sample_events: list[dict[str, Any]] = []
        for _ in range(samples):
            sample_events.append(
                measure_lifecycle_transition(
                    adapter,
                    workspace,
                    app_name,
                    event_file,
                    ready_port,
                    action=lambda: adapter.restart_one(workspace, app_name),
                    action_label=f"{adapter.name} restart",
                    timeout=90.0,
                )
            )

        return {
            "samples": sample_events,
            "command_ms": summarize_samples([sample["command_ms"] for sample in sample_events]),
            "pid_visible_ms": summarize_samples(
                [sample["pid_visible_ms"] for sample in sample_events]
            ),
            "ready_event_emitted_ms": summarize_samples(
                [sample["ready_event_emitted_ms"] for sample in sample_events]
            ),
            "ready_event_visible_ms": summarize_samples(
                [sample["ready_event_visible_ms"] for sample in sample_events]
            ),
            "tcp_ready_ms": summarize_samples([sample["tcp_ready_ms"] for sample in sample_events]),
            "restart_ms": summarize_samples(
                [sample["pid_visible_ms"] for sample in sample_events]
            ),
        }
    finally:
        adapter.cleanup(workspace)
        cleanup_fixture_processes()
        if not keep_workspaces:
            safe_remove_tree(workspace.root)


def benchmark_crash_recovery(
    adapter: Any,
    workspaces_root: Path,
    keep_workspaces: bool,
    samples: int,
) -> dict[str, Any]:
    workspace = make_workspace(workspaces_root, keep_workspaces, f"{adapter.name}-crash")
    app_name = "bench-000"
    event_file = workspace.work_dir / "events.ndjson"
    try:
        adapter.boot(workspace)
        ready_port = available_port()
        config_path = adapter.generate_scale_config(
            workspace,
            1,
            event_file=event_file,
            ready_port=ready_port,
        )
        adapter.start_scale(workspace, config_path)
        adapter.wait_processes_online(workspace, 1, timeout=90.0)

        sample_events: list[dict[str, Any]] = []
        for _ in range(samples):
            old_pid = adapter.process_pid(workspace, app_name)
            sample = measure_lifecycle_transition(
                adapter,
                workspace,
                app_name,
                event_file,
                ready_port,
                old_pid=old_pid,
                action=lambda pid=old_pid: os.kill(pid, signal.SIGKILL),
                action_label=f"{adapter.name} crash recovery",
                timeout=90.0,
            )
            sample["killed_pid"] = sample["old_pid"]
            sample["app_ready_ms"] = sample["tcp_ready_ms"]
            sample["recovery_ms"] = sample["tcp_ready_ms"]
            sample_events.append(sample)

        return {
            "samples": sample_events,
            "pid_visible_ms": summarize_samples(
                [sample["pid_visible_ms"] for sample in sample_events]
            ),
            "ready_event_emitted_ms": summarize_samples(
                [sample["ready_event_emitted_ms"] for sample in sample_events]
            ),
            "ready_event_visible_ms": summarize_samples(
                [sample["ready_event_visible_ms"] for sample in sample_events]
            ),
            "tcp_ready_ms": summarize_samples([sample["tcp_ready_ms"] for sample in sample_events]),
            "app_ready_ms": summarize_samples([sample["app_ready_ms"] for sample in sample_events]),
            "recovery_ms": summarize_samples([sample["recovery_ms"] for sample in sample_events]),
        }
    finally:
        adapter.cleanup(workspace)
        cleanup_fixture_processes()
        if not keep_workspaces:
            safe_remove_tree(workspace.root)


def ratio_line(
    oxmgr_value: float,
    pm2_value: float,
    *,
    lower_is_better: bool = True,
    suffix: str = "x",
) -> str:
    if pm2_value <= 0 or math.isnan(oxmgr_value) or math.isnan(pm2_value):
        return "n/a"
    if lower_is_better:
        ratio = pm2_value / oxmgr_value if oxmgr_value > 0 else math.nan
        return f"{format_float(ratio, 2)}{suffix} lower vs pm2"
    ratio = oxmgr_value / pm2_value if pm2_value > 0 else math.nan
    return f"{format_float(ratio, 2)}{suffix} higher vs pm2"


def build_markdown_report(report: dict[str, Any], process_counts: list[int]) -> str:
    boot = report["benchmarks"]["boot"]
    scale = report["benchmarks"]["scale"]
    restart = report["benchmarks"]["restart"]
    crash = report["benchmarks"]["crash_recovery"]

    lines = [
        "# Oxmgr vs PM2 Benchmarks",
        "",
        f"- Generated: {report['metadata']['generated_at_utc']}",
        f"- Host platform: {report['metadata']['platform']}",
        f"- Node.js: {report['metadata']['node_version']}",
        f"- pm2 command: `{report['metadata']['pm2_command']}`",
        f"- oxmgr binary: `{report['metadata']['oxmgr_binary']}`",
        "",
        "GitHub-hosted runners are noisy. Treat the numbers as trend signals, not absolute lab measurements.",
        "",
        "## Empty Daemon Boot",
        "",
        "| Manager | boot median (ms) | boot p95 (ms) | daemon RSS median (KB) |",
        "| --- | ---: | ---: | ---: |",
    ]
    for manager in ("oxmgr", "pm2"):
        boot_stats = boot[manager]["boot_ms"]
        rss_stats = boot[manager]["daemon_rss_kb"]
        lines.append(
            "| {manager} | {boot_median} | {boot_p95} | {rss_median} |".format(
                manager=manager,
                boot_median=format_float(boot_stats["median"]),
                boot_p95=format_float(boot_stats["p95"]),
                rss_median=format_float(rss_stats["median"]),
            )
        )

    lines.extend(
        [
            "",
            "## Scale: Start, Settle, List, RSS",
            "",
            "| Processes | Manager | start median (ms) | settle median (ms) | list median (ms) | daemon RSS median (KB) |",
            "| ---: | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for process_count in process_counts:
        for manager in ("oxmgr", "pm2"):
            stats = scale[manager][str(process_count)]
            lines.append(
                "| {count} | {manager} | {start} | {settle} | {list_ms} | {rss} |".format(
                    count=process_count,
                    manager=manager,
                    start=format_float(stats["start_ms"]["median"]),
                    settle=format_float(stats["settle_ms"]["median"]),
                    list_ms=format_float(stats["list_ms"]["median"]),
                    rss=format_float(stats["daemon_rss_kb"]["median"]),
                )
            )

    lines.extend(
        [
            "",
            "## Single-App Lifecycle",
            "",
            "| Scenario | Manager | median (ms) | p95 (ms) |",
            "| --- | --- | ---: | ---: |",
            "| restart command | oxmgr | {ox_restart_cmd_med} | {ox_restart_cmd_p95} |".format(
                ox_restart_cmd_med=format_float(restart["oxmgr"]["command_ms"]["median"]),
                ox_restart_cmd_p95=format_float(restart["oxmgr"]["command_ms"]["p95"]),
            ),
            "| restart command | pm2 | {pm2_restart_cmd_med} | {pm2_restart_cmd_p95} |".format(
                pm2_restart_cmd_med=format_float(restart["pm2"]["command_ms"]["median"]),
                pm2_restart_cmd_p95=format_float(restart["pm2"]["command_ms"]["p95"]),
            ),
            "| restart -> pid visible | oxmgr | {ox_restart_pid_med} | {ox_restart_pid_p95} |".format(
                ox_restart_pid_med=format_float(restart["oxmgr"]["pid_visible_ms"]["median"]),
                ox_restart_pid_p95=format_float(restart["oxmgr"]["pid_visible_ms"]["p95"]),
            ),
            "| restart -> pid visible | pm2 | {pm2_restart_pid_med} | {pm2_restart_pid_p95} |".format(
                pm2_restart_pid_med=format_float(restart["pm2"]["pid_visible_ms"]["median"]),
                pm2_restart_pid_p95=format_float(restart["pm2"]["pid_visible_ms"]["p95"]),
            ),
            "| restart -> ready event emitted | oxmgr | {ox_restart_event_emit_med} | {ox_restart_event_emit_p95} |".format(
                ox_restart_event_emit_med=format_float(
                    restart["oxmgr"]["ready_event_emitted_ms"]["median"]
                ),
                ox_restart_event_emit_p95=format_float(
                    restart["oxmgr"]["ready_event_emitted_ms"]["p95"]
                ),
            ),
            "| restart -> ready event emitted | pm2 | {pm2_restart_event_emit_med} | {pm2_restart_event_emit_p95} |".format(
                pm2_restart_event_emit_med=format_float(
                    restart["pm2"]["ready_event_emitted_ms"]["median"]
                ),
                pm2_restart_event_emit_p95=format_float(
                    restart["pm2"]["ready_event_emitted_ms"]["p95"]
                ),
            ),
            "| restart -> ready event visible | oxmgr | {ox_restart_event_vis_med} | {ox_restart_event_vis_p95} |".format(
                ox_restart_event_vis_med=format_float(
                    restart["oxmgr"]["ready_event_visible_ms"]["median"]
                ),
                ox_restart_event_vis_p95=format_float(
                    restart["oxmgr"]["ready_event_visible_ms"]["p95"]
                ),
            ),
            "| restart -> ready event visible | pm2 | {pm2_restart_event_vis_med} | {pm2_restart_event_vis_p95} |".format(
                pm2_restart_event_vis_med=format_float(
                    restart["pm2"]["ready_event_visible_ms"]["median"]
                ),
                pm2_restart_event_vis_p95=format_float(
                    restart["pm2"]["ready_event_visible_ms"]["p95"]
                ),
            ),
            "| restart -> tcp ready | oxmgr | {ox_restart_tcp_med} | {ox_restart_tcp_p95} |".format(
                ox_restart_tcp_med=format_float(restart["oxmgr"]["tcp_ready_ms"]["median"]),
                ox_restart_tcp_p95=format_float(restart["oxmgr"]["tcp_ready_ms"]["p95"]),
            ),
            "| restart -> tcp ready | pm2 | {pm2_restart_tcp_med} | {pm2_restart_tcp_p95} |".format(
                pm2_restart_tcp_med=format_float(restart["pm2"]["tcp_ready_ms"]["median"]),
                pm2_restart_tcp_p95=format_float(restart["pm2"]["tcp_ready_ms"]["p95"]),
            ),
            "| crash -> pid visible | oxmgr | {ox_pid_med} | {ox_pid_p95} |".format(
                ox_pid_med=format_float(crash["oxmgr"]["pid_visible_ms"]["median"]),
                ox_pid_p95=format_float(crash["oxmgr"]["pid_visible_ms"]["p95"]),
            ),
            "| crash -> pid visible | pm2 | {pm2_pid_med} | {pm2_pid_p95} |".format(
                pm2_pid_med=format_float(crash["pm2"]["pid_visible_ms"]["median"]),
                pm2_pid_p95=format_float(crash["pm2"]["pid_visible_ms"]["p95"]),
            ),
            "| crash -> ready event emitted | oxmgr | {ox_event_emit_med} | {ox_event_emit_p95} |".format(
                ox_event_emit_med=format_float(
                    crash["oxmgr"]["ready_event_emitted_ms"]["median"]
                ),
                ox_event_emit_p95=format_float(crash["oxmgr"]["ready_event_emitted_ms"]["p95"]),
            ),
            "| crash -> ready event emitted | pm2 | {pm2_event_emit_med} | {pm2_event_emit_p95} |".format(
                pm2_event_emit_med=format_float(
                    crash["pm2"]["ready_event_emitted_ms"]["median"]
                ),
                pm2_event_emit_p95=format_float(crash["pm2"]["ready_event_emitted_ms"]["p95"]),
            ),
            "| crash -> ready event visible | oxmgr | {ox_event_vis_med} | {ox_event_vis_p95} |".format(
                ox_event_vis_med=format_float(
                    crash["oxmgr"]["ready_event_visible_ms"]["median"]
                ),
                ox_event_vis_p95=format_float(crash["oxmgr"]["ready_event_visible_ms"]["p95"]),
            ),
            "| crash -> ready event visible | pm2 | {pm2_event_vis_med} | {pm2_event_vis_p95} |".format(
                pm2_event_vis_med=format_float(
                    crash["pm2"]["ready_event_visible_ms"]["median"]
                ),
                pm2_event_vis_p95=format_float(crash["pm2"]["ready_event_visible_ms"]["p95"]),
            ),
            "| crash -> tcp ready | oxmgr | {ox_ready_med} | {ox_ready_p95} |".format(
                ox_ready_med=format_float(crash["oxmgr"]["tcp_ready_ms"]["median"]),
                ox_ready_p95=format_float(crash["oxmgr"]["tcp_ready_ms"]["p95"]),
            ),
            "| crash -> tcp ready | pm2 | {pm2_ready_med} | {pm2_ready_p95} |".format(
                pm2_ready_med=format_float(crash["pm2"]["tcp_ready_ms"]["median"]),
                pm2_ready_p95=format_float(crash["pm2"]["tcp_ready_ms"]["p95"]),
            ),
            "",
            "## Quick Read",
            "",
            "- Empty-daemon boot: oxmgr {boot_delta}".format(
                boot_delta=ratio_line(
                    boot["oxmgr"]["boot_ms"]["median"],
                    boot["pm2"]["boot_ms"]["median"],
                )
            ),
            "- Empty-daemon RSS: oxmgr {rss_delta}".format(
                rss_delta=ratio_line(
                    boot["oxmgr"]["daemon_rss_kb"]["median"],
                    boot["pm2"]["daemon_rss_kb"]["median"],
                )
            ),
            "- Restart command latency: oxmgr {restart_cmd_delta}".format(
                restart_cmd_delta=ratio_line(
                    restart["oxmgr"]["command_ms"]["median"],
                    restart["pm2"]["command_ms"]["median"],
                )
            ),
            "- Restart TCP-ready latency: oxmgr {restart_tcp_delta}".format(
                restart_tcp_delta=ratio_line(
                    restart["oxmgr"]["tcp_ready_ms"]["median"],
                    restart["pm2"]["tcp_ready_ms"]["median"],
                )
            ),
            "- Crash replacement PID visibility: oxmgr {crash_pid_delta}".format(
                crash_pid_delta=ratio_line(
                    crash["oxmgr"]["pid_visible_ms"]["median"],
                    crash["pm2"]["pid_visible_ms"]["median"],
                )
            ),
            "- Crash ready-event emitted latency: oxmgr {crash_event_emit_delta}".format(
                crash_event_emit_delta=ratio_line(
                    crash["oxmgr"]["ready_event_emitted_ms"]["median"],
                    crash["pm2"]["ready_event_emitted_ms"]["median"],
                )
            ),
            "- Crash TCP-ready latency: oxmgr {crash_ready_delta}".format(
                crash_ready_delta=ratio_line(
                    crash["oxmgr"]["tcp_ready_ms"]["median"],
                    crash["pm2"]["tcp_ready_ms"]["median"],
                )
            ),
        ]
    )

    busiest_count = str(process_counts[-1])
    lines.append(
        "- Daemon RSS at {count} processes: oxmgr {delta}".format(
            count=busiest_count,
            delta=ratio_line(
                scale["oxmgr"][busiest_count]["daemon_rss_kb"]["median"],
                scale["pm2"][busiest_count]["daemon_rss_kb"]["median"],
            ),
        )
    )
    return "\n".join(lines) + "\n"


def collect_metadata(
    args: argparse.Namespace,
    output_dir: Path,
    oxmgr_binary: Path,
    pm2_command: list[str],
) -> dict[str, Any]:
    node_version = run_command([args.node_bin, "--version"], cwd=REPO_ROOT, timeout=30).stdout.strip()
    rustc_version = optional_command_output(["rustc", "--version"], cwd=REPO_ROOT)
    cargo_version = optional_command_output([args.cargo_bin, "--version"], cwd=REPO_ROOT)
    git_sha = optional_command_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": f"{sys.platform} ({os.uname().sysname} {os.uname().release})",
        "python_version": sys.version.split()[0],
        "node_version": node_version,
        "rustc_version": rustc_version,
        "cargo_version": cargo_version,
        "git_sha": git_sha,
        "output_dir": str(output_dir),
        "oxmgr_binary": str(oxmgr_binary),
        "pm2_command": command_to_string(pm2_command),
        "process_counts": parse_process_counts(args.process_counts),
        "boot_trials": args.boot_trials,
        "scale_trials": args.scale_trials,
        "list_samples": args.list_samples,
        "restart_samples": args.restart_samples,
        "crash_samples": args.crash_samples,
    }


def parse_process_counts(raw: str) -> list[int]:
    counts = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part)
        if value <= 0:
            raise BenchmarkError(f"process counts must be positive, got {value}")
        counts.append(value)
    if not counts:
        raise BenchmarkError("at least one process count is required")
    return counts


def main() -> int:
    args = parse_args()
    if sys.platform == "win32":
        raise BenchmarkError("benchmark harness currently supports Linux and macOS only")
    ensure_executable(args.node_bin, "node")
    ensure_executable("ps", "ps")
    process_counts = parse_process_counts(args.process_counts)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output_dir) if args.output_dir else BENCH_DIR / "results" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    tools_dir = BENCH_DIR / ".cache" / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    workspaces_root = output_dir / "workspaces"
    if args.keep_workspaces:
        workspaces_root.mkdir(parents=True, exist_ok=True)

    if args.oxmgr_bin:
        oxmgr_binary = Path(args.oxmgr_bin).resolve()
        if not oxmgr_binary.exists():
            raise BenchmarkError(f"oxmgr binary does not exist: {oxmgr_binary}")
    else:
        oxmgr_binary = REPO_ROOT / "target" / "release" / "oxmgr"
        if not args.skip_build or not oxmgr_binary.exists():
            ensure_executable(args.cargo_bin, "cargo")
            oxmgr_binary = build_oxmgr(args.cargo_bin)

    pm2_command = ensure_pm2(args, tools_dir)

    oxmgr = OxmgrAdapter(oxmgr_binary, args.node_bin)
    pm2 = Pm2Adapter(pm2_command, args.node_bin)
    adapters = [oxmgr, pm2]

    metadata = collect_metadata(args, output_dir, oxmgr_binary, pm2_command)
    report: dict[str, Any] = {
        "metadata": metadata,
        "benchmarks": {
            "boot": {},
            "scale": {adapter.name: {} for adapter in adapters},
            "restart": {},
            "crash_recovery": {},
        },
    }

    for adapter in adapters:
        print(f"[boot] {adapter.name}", file=sys.stderr)
        report["benchmarks"]["boot"][adapter.name] = benchmark_boot(
            adapter,
            workspaces_root,
            args.keep_workspaces,
            args.boot_trials,
        )

    for process_count in process_counts:
        for adapter in adapters:
            print(f"[scale] {adapter.name} processes={process_count}", file=sys.stderr)
            report["benchmarks"]["scale"][adapter.name][str(process_count)] = benchmark_scale(
                adapter,
                workspaces_root,
                args.keep_workspaces,
                process_count,
                args.scale_trials,
                args.list_samples,
            )

    for adapter in adapters:
        print(f"[restart] {adapter.name}", file=sys.stderr)
        report["benchmarks"]["restart"][adapter.name] = benchmark_restart(
            adapter,
            workspaces_root,
            args.keep_workspaces,
            args.restart_samples,
        )

    for adapter in adapters:
        print(f"[crash] {adapter.name}", file=sys.stderr)
        report["benchmarks"]["crash_recovery"][adapter.name] = benchmark_crash_recovery(
            adapter,
            workspaces_root,
            args.keep_workspaces,
            args.crash_samples,
        )

    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    markdown = build_markdown_report(report, process_counts)
    summary_path = output_dir / "summary.md"
    summary_path.write_text(markdown, encoding="utf-8")

    print(f"JSON report: {report_path}")
    print(f"Markdown summary: {summary_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1)
