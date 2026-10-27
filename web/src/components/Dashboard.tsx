import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { clockTime, formatBytes, formatPercent, ISSUE_STATUSES, sparkline } from "../format";
import type { Action, BusEvent, ManagedProcess, ProcessStatus, Session } from "../types";
import { useLive } from "../useLive";
import { isModalOpen, useModal } from "../useModal";
import { EnvLabel } from "./EnvLabel";
import { LogoutIcon, Logo, SearchIcon, Sparkline } from "./Icons";
import { ProcessDrawer } from "./ProcessDrawer";
import { ProcessTable, type ProcessGroup } from "./ProcessTable";

type Filter = "all" | "running" | "issues" | "stopped";
type Confirm = { title: string; body: string; label: string; danger: boolean; run: () => Promise<void> };
type Toast = { id: number; text: string; bad: boolean };

// The predicate is called `accepts`, not `match`: a `.match(...)` call reads
// like String.prototype.match to static analysis (CodeQL js/regex-injection).
const FILTERS: { id: Filter; label: string; accepts: (s: ProcessStatus) => boolean }[] = [
  { id: "all", label: "All", accepts: () => true },
  { id: "running", label: "Running", accepts: (s) => s === "running" },
  { id: "issues", label: "Issues", accepts: (s) => ISSUE_STATUSES.includes(s) },
  { id: "stopped", label: "Stopped", accepts: (s) => s === "stopped" },
];

export function Dashboard({ session, onSignedOut }: { session: Session; onSignedOut: () => void }) {
  const live = useLive(onSignedOut);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [grouped, setGrouped] = useState(true);
  const [open, setOpen] = useState<{ name: string; tab: "logs" | "details" } | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [nowSecs, setNowSecs] = useState(() => Date.now() / 1000);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const timer = window.setInterval(() => setNowSecs(Date.now() / 1000), 1000);
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        Boolean(target?.isContentEditable);
      if (event.key === "/" && !typing && !isModalOpen()) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  const toast = useCallback((text: string, bad = false) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, text, bad }]);
    window.setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4000);
  }, []);

  const runAction = useCallback(
    async (target: string, action: Action) => {
      setBusy((prev) => new Set(prev).add(target));
      try {
        const result = await api.action(target, action);
        toast(result.message);
      } catch (err) {
        toast(err instanceof Error ? err.message : String(err), true);
      } finally {
        setBusy((prev) => {
          const next = new Set(prev);
          next.delete(target);
          return next;
        });
      }
    },
    [toast],
  );

  const onAction = useCallback(
    (process: ManagedProcess, action: Action) => {
      if (action === "stop" || (action === "restart" && process.status === "running")) {
        const verb = action === "stop" ? "Stop" : "Restart";
        setConfirm({
          title: `${verb} ${process.name}?`,
          body:
            action === "stop"
              ? `The process will be stopped and stays stopped until you start it again.`
              : `The process will be stopped and started again. Open connections may drop.`,
          label: verb,
          danger: action === "stop",
          run: () => runAction(process.name, action),
        });
      } else {
        void runAction(process.name, action);
      }
    },
    [runAction],
  );

  const processes = live.processes ?? [];
  const counts = useMemo(() => {
    const result: Record<Filter, number> = { all: 0, running: 0, issues: 0, stopped: 0 };
    for (const process of processes) {
      for (const f of FILTERS) if (f.accepts(process.status)) result[f.id] += 1;
    }
    return result;
  }, [processes]);

  const groups = useMemo<ProcessGroup[]>(() => {
    const needle = query.trim().toLowerCase();
    const accepts = FILTERS.find((f) => f.id === filter)!.accepts;
    const visible = processes
      .filter((p) => accepts(p.status))
      .filter(
        (p) =>
          !needle ||
          [p.name, p.namespace ?? "", p.command, String(p.pid ?? ""), String(p.id)].some((v) =>
            v.toLowerCase().includes(needle),
          ),
      )
      .sort((a, b) => Number(ISSUE_STATUSES.includes(b.status)) - Number(ISSUE_STATUSES.includes(a.status)) || a.id - b.id);
    if (!grouped) return [{ name: "all", processes: visible }];
    const byNamespace = new Map<string, ManagedProcess[]>();
    for (const process of visible) {
      const key = process.namespace ?? "default";
      byNamespace.set(key, [...(byNamespace.get(key) ?? []), process]);
    }
    return [...byNamespace.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, list]) => ({ name, processes: list }));
  }, [processes, query, filter, grouped]);

  const namespaces = new Set(processes.map((p) => p.namespace ?? "default")).size;
  const issues = processes.filter((p) => ISSUE_STATUSES.includes(p.status));
  const totalCpu = live.cpuHistory.at(-1) ?? 0;
  const totalMem = live.memHistory.at(-1) ?? 0;
  const openProcess = open ? processes.find((p) => p.name === open.name) : undefined;

  const signOut = async () => {
    try {
      await api.logout();
      onSignedOut();
    } catch (err) {
      toast(`Sign-out failed: ${err instanceof Error ? err.message : String(err)}`, true);
    }
  };

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <Logo />
          <span className="version">v{session.version}</span>
          <EnvLabel label={session.label} color={session.label_color} />
          <span className="live" aria-live="polite">
            <span className={`live-dot${live.connection === "live" ? "" : " warn"}`} />
            {live.connection === "live" ? "live" : live.connection === "connecting" ? "connecting" : "reconnecting"} · {window.location.host}
          </span>
          <span className="spacer" />
          <label className="search">
            <SearchIcon />
            <span className="sr-only">Search processes</span>
            <input
              ref={searchRef}
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search name, namespace, PID…"
            />
            <span className="kbd" aria-hidden="true">/</span>
          </label>
          <div className="top-actions">
          <button
            type="button"
            className="btn"
            disabled={processes.length === 0}
            onClick={() =>
              setConfirm({
                title: "Restart all processes?",
                body: `All ${processes.length} managed processes will be restarted. Stopped and crashed processes are started too.`,
                label: "Restart all",
                danger: false,
                run: () => runAction("all", "restart"),
              })
            }
          >
            Restart all
          </button>
          {session.auth_required && (
            <button type="button" className="icon-btn" aria-label="Sign out" title="Sign out" onClick={signOut}>
              <LogoutIcon />
            </button>
          )}
          </div>
        </div>
      </header>

      <main className="page">
        <div className="page-head">
          <div>
            <div className="eyebrow">Overview</div>
            <h1>
              {processes.length} {processes.length === 1 ? "process" : "processes"} · {namespaces}{" "}
              {namespaces === 1 ? "namespace" : "namespaces"}
            </h1>
          </div>
          <div className="meta">
            {live.updatedAt ? `updated ${Math.max(0, Math.round((nowSecs * 1000 - live.updatedAt) / 1000))} s ago` : "waiting for data…"}
          </div>
        </div>

        <section className="kpis" aria-label="Summary">
          <Kpi
            label="Running"
            value={String(counts.running)}
            unit={`/ ${processes.length}`}
            tag={counts.stopped ? `${counts.stopped} stopped` : ""}
            sub={counts.running === processes.length ? "everything is up" : `${processes.length - counts.running} not running`}
          />
          <Kpi
            label="Issues"
            value={String(issues.length)}
            tag={issues.map((p) => p.name).join(", ")}
            tagColor="var(--bad-text)"
            sub={issues.length ? issues.map((p) => p.status).join(", ") : "no crashed processes"}
          />
          <Kpi
            label="Total CPU"
            value={formatPercent(totalCpu).replace(" %", "")}
            unit="%"
            spark={sparkline(live.cpuHistory, 96, 32)}
            sparkColor="var(--accent)"
            sub={`peak ${formatPercent(Math.max(0, ...live.cpuHistory))} in the last ${live.cpuHistory.length} samples`}
          />
          <Kpi
            label="Total memory"
            value={formatBytes(totalMem).split(" ")[0] ?? "0"}
            unit={formatBytes(totalMem).split(" ")[1] ?? ""}
            spark={sparkline(live.memHistory, 96, 32)}
            sparkColor="var(--info)"
            sub="resident set of all processes"
          />
        </section>

        <div className="toolbar">
          <div className="segmented" role="group" aria-label="Filter by status">
            {FILTERS.map((f) => (
              <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                {f.label}
                <span className="count">{counts[f.id]}</span>
              </button>
            ))}
          </div>
          <span className="spacer" />
          <label className="select-label">
            Group
            <select value={grouped ? "namespace" : "none"} onChange={(e) => setGrouped(e.target.value === "namespace")}>
              <option value="namespace">by namespace</option>
              <option value="none">no grouping</option>
            </select>
          </label>
        </div>

        {live.processes === null ? (
          <div className="card empty">Connecting to the daemon…</div>
        ) : processes.length === 0 ? (
          <div className="card empty">
            No managed processes yet. Start one with <code className="mono">oxmgr start</code>.
          </div>
        ) : (
          <ProcessTable
            groups={groups}
            grouped={grouped}
            nowSecs={nowSecs + live.clockOffset}
            busy={busy}
            onAction={onAction}
            onOpen={(process, tab) => setOpen({ name: process.name, tab })}
          />
        )}

        <section className="card events" aria-label="Recent events">
          <h2>Recent events</h2>
          {live.events.length === 0 ? (
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>Lifecycle events appear here as they happen.</p>
          ) : (
            <div className="event-grid">
              {live.events.slice(0, 8).map((event, index) => (
                <EventItem key={`${event.at}-${index}`} event={event} />
              ))}
            </div>
          )}
        </section>
      </main>

      {open && openProcess && (
        <ProcessDrawer
          process={openProcess}
          tab={open.tab}
          nowSecs={nowSecs + live.clockOffset}
          busy={busy.has(openProcess.name)}
          followLogs={live.followLogs}
          onTab={(tab) => setOpen({ name: openProcess.name, tab })}
          onAction={onAction}
          onClose={() => setOpen(null)}
        />
      )}

      {confirm && <ConfirmDialog confirm={confirm} onClose={() => setConfirm(null)} />}

      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast${t.bad ? " bad" : ""}`}>
            {t.text}
          </div>
        ))}
      </div>
    </>
  );
}

function Kpi(props: {
  label: string;
  value: string;
  unit?: string;
  tag?: string;
  tagColor?: string;
  sub: string;
  spark?: string;
  sparkColor?: string;
}) {
  return (
    <div className="card kpi">
      <div className="kpi-top">
        <span className="kpi-label">{props.label}</span>
        {props.tag && (
          <span className="kpi-tag" style={props.tagColor ? { color: props.tagColor } : undefined}>
            {props.tag}
          </span>
        )}
      </div>
      <div className="kpi-row">
        <span className="kpi-value">
          {props.value}
          {props.unit && <small>{props.unit}</small>}
        </span>
        {props.spark && <Sparkline points={props.spark} color={props.sparkColor ?? "var(--accent)"} />}
      </div>
      <div className="kpi-sub">{props.sub}</div>
    </div>
  );
}

function EventItem({ event }: { event: BusEvent }) {
  const [kind, tone] = describe(event.event);
  const name = event.process?.name ?? "daemon";
  const detail =
    event.data?.exit_code !== undefined && event.data.exit_code !== null
      ? `exit ${event.data.exit_code}`
      : event.data?.error ?? event.data?.status ?? "";
  return (
    <div className="event">
      <time>{clockTime(event.at)}</time>
      <p title={`${kind} ${name} ${detail}`}>
        <span className={`kind ${tone}`}>{kind}</span>
        {name}
        {detail && <span className="muted"> · {detail}</span>}
      </p>
    </div>
  );
}

function describe(name: string): [string, "ok" | "bad" | "accent" | "plain"] {
  switch (name) {
    case "process:online":
    case "process:started":
      return ["started", "ok"];
    case "process:restarting":
      return ["restarting", "accent"];
    case "process:crashed":
      return ["crashed", "bad"];
    case "process:errored":
      return ["errored", "bad"];
    case "process:stopped":
      return ["stopped", "plain"];
    case "process:exited":
      return ["exited", "plain"];
    case "health:healthy":
      return ["healthy", "ok"];
    case "health:unhealthy":
      return ["unhealthy", "bad"];
    case "daemon:shutdown":
      return ["shutdown", "bad"];
    default:
      return [name, "plain"];
  }
}

function ConfirmDialog({ confirm, onClose }: { confirm: Confirm; onClose: () => void }) {
  const [running, setRunning] = useState(false);
  const dialog = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  // Destructive actions start on Cancel; an action in flight cannot be dismissed.
  useModal(dialog, onClose, { dismissible: !running, initialFocus: confirm.danger ? cancelRef : confirmRef });

  const go = async () => {
    setRunning(true);
    await confirm.run();
    onClose();
  };

  return (
    <div className="overlay center" onClick={() => !running && onClose()}>
      <div
        ref={dialog}
        className="dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-body"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id="confirm-title">{confirm.title}</h2>
        <p id="confirm-body">{confirm.body}</p>
        <div className="dialog-actions">
          <button ref={cancelRef} type="button" className="btn" disabled={running} onClick={onClose}>
            Cancel
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={`btn ${confirm.danger ? "btn-danger" : "btn-primary"}`}
            disabled={running}
            onClick={go}
          >
            {running ? "Working…" : confirm.label}
          </button>
        </div>
      </div>
    </div>
  );
}
