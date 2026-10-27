import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { clockTime, commandLine, formatBytes, formatPercent, statusLabel, uptime } from "../format";
import type { Action, LogLine, ManagedProcess } from "../types";
import type { LiveState } from "../useLive";
import { useModal } from "../useModal";
import { CloseIcon, SearchIcon } from "./Icons";

const MAX_LINES = 5000;

interface Props {
  process: ManagedProcess;
  tab: "logs" | "details";
  nowSecs: number;
  busy: boolean;
  followLogs: LiveState["followLogs"];
  onTab: (tab: "logs" | "details") => void;
  onAction: (process: ManagedProcess, action: Action) => void;
  onClose: () => void;
}

export function ProcessDrawer({ process, tab, nowSecs, busy, followLogs, onTab, onAction, onClose }: Props) {
  const running = process.status === "running" || process.status === "restarting";
  const drawer = useRef<HTMLElement>(null);
  useModal(drawer, onClose);

  return (
    <div className="overlay" onClick={onClose}>
      <aside
        ref={drawer}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`Process ${process.name}`}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="drawer-head">
          <h2>{process.name}</h2>
          <span className={`pill ${process.status}`}>
            <span className="dot" />
            {statusLabel(process.status)}
          </span>
          <span className="spacer" />
          <button type="button" className="btn btn-sm" disabled={busy || !running} onClick={() => onAction(process, "reload")}>
            Reload
          </button>
          <button type="button" className="btn btn-sm" disabled={busy} onClick={() => onAction(process, "restart")}>
            {running ? "Restart" : "Start"}
          </button>
          <button type="button" className="btn btn-sm btn-danger" disabled={busy || !running} onClick={() => onAction(process, "stop")}>
            Stop
          </button>
          <button type="button" className="icon-btn" aria-label="Close" onClick={onClose}>
            <CloseIcon />
          </button>
        </div>

        <div className="drawer-body">
          <div className="stats">
            <Stat label="CPU" value={formatPercent(process.cpu_percent)} />
            <Stat label="Memory" value={formatBytes(process.memory_bytes)} />
            <Stat label="Uptime" value={uptime(process, nowSecs)} />
            <Stat label="PID" value={String(process.pid ?? "-")} />
            <Stat label="Restarts" value={`${process.restart_count} / ${process.max_restarts}`} />
          </div>

          <div className="segmented" role="tablist" aria-label="Process sections" style={{ alignSelf: "flex-start" }}>
            {(["logs", "details"] as const).map((name) => (
              <button
                key={name}
                type="button"
                role="tab"
                id={`tab-${name}`}
                aria-selected={tab === name}
                aria-controls="process-panel"
                onClick={() => onTab(name)}
              >
                {name === "logs" ? "Logs" : "Details"}
              </button>
            ))}
          </div>

          <div id="process-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="tab-panel">
            {tab === "logs" ? <Logs process={process} followLogs={followLogs} /> : <Details process={process} />}
          </div>
        </div>
      </aside>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

function Logs({ process, followLogs }: { process: ManagedProcess; followLogs: LiveState["followLogs"] }) {
  const crashed = process.status === "crashed" || process.status === "errored";
  const [stream, setStream] = useState<"stdout" | "stderr">(crashed ? "stderr" : "stdout");
  const [lines, setLines] = useState<LogLine[]>([]);
  const [filter, setFilter] = useState("");
  const [follow, setFollow] = useState(true);
  const [timestamps, setTimestamps] = useState(true);
  const [loading, setLoading] = useState(true);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    // Live lines that arrive before the file tail are held back: the tail is
    // read later on the server, so it may already contain some of them.
    let pending: LogLine[] | null = [];
    setLines([]);
    setLoading(true);

    const unsubscribe = followLogs(process.name, (line) => {
      if (line.stream !== stream) return;
      if (pending) pending.push(line);
      else setLines((prev) => [...prev, line].slice(-MAX_LINES));
    });
    api
      .tail(process.name, stream)
      .catch(() => [] as LogLine[])
      .then((tail) => {
        if (cancelled) return;
        const live = pending ?? [];
        pending = null;
        setLines([...tail, ...live.slice(overlap(tail, live))].slice(-MAX_LINES));
        setLoading(false);
      });

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [process.name, stream, followLogs]);

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return needle ? lines.filter((line) => line.text.toLowerCase().includes(needle)) : lines;
  }, [lines, filter]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [visible, follow]);

  return (
    <div className="terminal">
      <div className="terminal-bar">
        <div className="segmented" role="group" aria-label="Log stream">
          {(["stdout", "stderr"] as const).map((name) => (
            <button key={name} type="button" aria-pressed={stream === name} onClick={() => setStream(name)}>
              {name}
            </button>
          ))}
        </div>
        <label className="search">
          <SearchIcon />
          <span className="sr-only">Filter log lines</span>
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter lines…" className="mono" style={{ fontSize: 12 }} />
        </label>
        <label className="check">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          Follow
        </label>
        <label className="check">
          <input type="checkbox" checked={timestamps} onChange={(e) => setTimestamps(e.target.checked)} />
          Timestamps
        </label>
      </div>
      <div className="terminal-lines" ref={box} role="log" aria-live="off">
        {visible.map((line) => (
          <div key={line.key} className={`log-line ${line.stream}`}>
            {timestamps && <time>{line.time}</time>}
            <span>{line.text}</span>
          </div>
        ))}
        {!loading && visible.length === 0 && (
          <div className="log-line">
            <span className="muted">{filter ? "No lines match the filter." : `No ${stream} output yet.`}</span>
          </div>
        )}
      </div>
    </div>
  );
}

/** Number of leading `live` lines already present at the end of `tail`. */
function overlap(tail: LogLine[], live: LogLine[]): number {
  for (let size = Math.min(tail.length, live.length); size > 0; size -= 1) {
    const start = tail.length - size;
    if (live.slice(0, size).every((line, index) => line.text === tail[start + index]?.text)) {
      return size;
    }
  }
  return 0;
}

function Details({ process }: { process: ManagedProcess }) {
  const rows: [string, string][] = [
    ["ID", String(process.id)],
    ["Namespace", process.namespace ?? "-"],
    ["Command", commandLine(process)],
    ["Working dir", process.cwd ?? "-"],
    ["Desired state", process.desired_state],
    ["Health", process.health_status + (process.last_health_error ? ` · ${process.last_health_error}` : "")],
    ["Last exit code", process.last_exit_code === null ? "-" : String(process.last_exit_code)],
    ["Started", process.last_started_at ? clockTime(process.last_started_at) : "-"],
    ["Stopped", process.last_stopped_at ? clockTime(process.last_stopped_at) : "-"],
    ["Mode", process.cluster_mode ? `cluster × ${process.cluster_instances ?? "auto"}` : "single"],
    ["Watch", process.watch ? "on" : "off"],
    ["Cron restart", process.cron_restart ?? "-"],
    ["stdout log", process.stdout_log],
    ["stderr log", process.stderr_log],
  ];
  return (
    <>
      {process.last_error && (
        <div className="error-box">
          <code>{process.last_error}</code>
        </div>
      )}
      <dl className="kv">
        {rows.map(([key, value]) => (
          <div key={key} style={{ display: "contents" }}>
            <dt>{key}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </>
  );
}
