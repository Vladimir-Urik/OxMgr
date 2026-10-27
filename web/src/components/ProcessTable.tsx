import { Fragment, type MouseEvent } from "react";
import { commandLine, formatBytes, formatPercent, ISSUE_STATUSES, statusLabel, uptime } from "../format";
import type { Action, ManagedProcess } from "../types";
import { AlertIcon, PlayIcon, RestartIcon, StopIcon, TerminalIcon } from "./Icons";

export interface ProcessGroup {
  name: string;
  processes: ManagedProcess[];
}

interface Props {
  groups: ProcessGroup[];
  grouped: boolean;
  nowSecs: number;
  busy: Set<string>;
  onAction: (process: ManagedProcess, action: Action) => void;
  onOpen: (process: ManagedProcess, tab: "logs" | "details") => void;
}

export function ProcessTable({ groups, grouped, nowSecs, busy, onAction, onOpen }: Props) {
  const total = groups.reduce((sum, group) => sum + group.processes.length, 0);

  return (
    <div className="card table-wrap">
      <table className="procs">
        <thead>
          <tr>
            <th scope="col">Process</th>
            <th scope="col">Status</th>
            <th scope="col" className="num">PID</th>
            <th scope="col" className="num">Uptime</th>
            <th scope="col">CPU</th>
            <th scope="col" className="num">Memory</th>
            <th scope="col" className="num">Restarts</th>
            <th scope="col">Health</th>
            <th scope="col" style={{ textAlign: "right" }}>Actions</th>
          </tr>
        </thead>
        {total === 0 && (
          <tbody>
            <tr>
              <td colSpan={9} className="empty">No processes match the current filter.</td>
            </tr>
          </tbody>
        )}
        {groups.map((group) => (
          <tbody key={group.name}>
            {grouped && (
              <tr className="group-row">
                <td colSpan={9}>
                  {group.name} <span className="muted">· {group.processes.length}</span>
                </td>
              </tr>
            )}
            {group.processes.map((process) => (
              <Row
                key={process.id}
                process={process}
                nowSecs={nowSecs}
                busy={busy.has(process.name)}
                onAction={onAction}
                onOpen={onOpen}
              />
            ))}
          </tbody>
        ))}
      </table>
    </div>
  );
}

function Row({
  process,
  nowSecs,
  busy,
  onAction,
  onOpen,
}: {
  process: ManagedProcess;
  nowSecs: number;
  busy: boolean;
  onAction: Props["onAction"];
  onOpen: Props["onOpen"];
}) {
  const running = process.status === "running" || process.status === "restarting";
  const failed = ISSUE_STATUSES.includes(process.status);
  const error = failed ? process.last_error ?? process.last_health_error : null;
  const cpuWidth = Math.min(100, Math.max(running ? 3 : 0, process.cpu_percent * 4));
  const stop = (event: MouseEvent<HTMLTableCellElement>) => event.stopPropagation();

  return (
    <Fragment>
      <tr className="row" onClick={() => onOpen(process, "details")}>
        <td>
          <div className="proc-name">{process.name}</div>
          <div className="proc-cmd" title={commandLine(process)}>{commandLine(process)}</div>
        </td>
        <td>
          <span className={`pill ${process.status}`}>
            <span className="dot" />
            {statusLabel(process.status)}
          </span>
        </td>
        <td className="num">{process.pid ?? "-"}</td>
        <td className="num">{uptime(process, nowSecs)}</td>
        <td>
          <div className="cpu-cell">
            <div className="bar" aria-hidden="true">
              <span className={process.cpu_percent > 25 ? "hot" : undefined} style={{ width: `${cpuWidth}%` }} />
            </div>
            <span className="mono" style={{ fontSize: 12, width: 52, textAlign: "right", color: "#d4d4d8" }}>
              {formatPercent(process.cpu_percent)}
            </span>
          </div>
        </td>
        <td className="num">{formatBytes(process.memory_bytes)}</td>
        <td className="num">
          {process.restart_count}
          <span className="muted">/{process.max_restarts}</span>
        </td>
        <td>
          <span className={`health ${process.health_status}`}>{process.health_status}</span>
        </td>
        <td onClick={stop}>
          <div className="actions">
            {running ? (
              <button
                type="button"
                className="icon-btn"
                aria-label={`Restart ${process.name}`}
                title="Restart"
                disabled={busy}
                onClick={() => onAction(process, "restart")}
              >
                <RestartIcon />
              </button>
            ) : (
              <button
                type="button"
                className="icon-btn"
                aria-label={`Start ${process.name}`}
                title="Start"
                disabled={busy}
                onClick={() => onAction(process, "restart")}
              >
                <PlayIcon />
              </button>
            )}
            <button
              type="button"
              className="icon-btn danger"
              aria-label={`Stop ${process.name}`}
              title="Stop"
              disabled={busy || !running}
              onClick={() => onAction(process, "stop")}
            >
              <StopIcon width={13} height={13} />
            </button>
            <button type="button" className="btn btn-sm" onClick={() => onOpen(process, "logs")}>
              <TerminalIcon width={14} height={14} />
              Logs
            </button>
          </div>
        </td>
      </tr>
      {error && (
        <tr className="error-row">
          <td colSpan={9}>
            <div className="error-box">
              <AlertIcon width={16} height={16} style={{ color: "var(--bad)", flex: "none" }} />
              <code>{lastLines(error, 3)}</code>
              {process.last_exit_code !== null && <span className="muted">exit {process.last_exit_code}</span>}
              <button type="button" className="link-btn" onClick={() => onOpen(process, "logs")}>
                View stderr
              </button>
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  );
}

function lastLines(text: string, count: number): string {
  return text.trim().split("\n").slice(-count).join("\n");
}
