import type { ManagedProcess, ProcessStatus } from "./types";

export const LIVE_STATUSES: ProcessStatus[] = ["running", "restarting"];
export const ISSUE_STATUSES: ProcessStatus[] = ["crashed", "errored"];

export function formatDuration(totalSecs: number): string {
  const secs = Math.max(0, Math.floor(totalSecs));
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${secs}s`;
}

export function uptime(process: ManagedProcess, nowSecs: number): string {
  if (!LIVE_STATUSES.includes(process.status) || !process.last_started_at) return "-";
  return formatDuration(nowSecs - process.last_started_at);
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const digits = (value: number) => (value >= 100 || exp === 0 ? 0 : 1);
  let value = bytes / 1024 ** exp;
  // 1023.96 KB must read "1.0 MB", not "1024.0 KB".
  if (Number(value.toFixed(digits(value))) >= 1024 && exp < units.length - 1) {
    exp += 1;
    value = bytes / 1024 ** exp;
  }
  return `${value.toFixed(digits(value))} ${units[exp]}`;
}

export function formatPercent(value: number): string {
  return `${(Number.isFinite(value) ? value : 0).toFixed(1)} %`;
}

export function clockTime(epochSecs: number): string {
  return new Date(epochSecs * 1000).toLocaleTimeString([], { hour12: false });
}

export function commandLine(process: ManagedProcess): string {
  return [process.command, ...process.args].join(" ");
}

export function statusLabel(status: ProcessStatus): string {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

/** Log files prefix every line with `YYYY-MM-DD HH:MM:SS: `. */
const LOG_PREFIX = /^\d{4}-\d{2}-\d{2} (\d{2}:\d{2}:\d{2}): ?(.*)$/;

export function parseLogLine(line: string): { time: string; text: string } {
  const match = LOG_PREFIX.exec(line);
  return match ? { time: match[1] ?? "", text: match[2] ?? "" } : { time: "", text: line };
}

/** Points for a 0..1 sparkline polyline inside a width × height box. */
export function sparkline(values: number[], width: number, height: number): string {
  if (values.length < 2) return "";
  const max = Math.max(...values, 1e-9);
  return values
    .map((value, index) => {
      const x = (index * width) / (values.length - 1);
      const y = height - 2 - (value / max) * (height - 4);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

let lineKey = 0;

/** Unique React key for log lines, shared by file tails and live lines. */
export function nextLineKey(): number {
  lineKey += 1;
  return lineKey;
}
