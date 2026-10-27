import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { nextLineKey } from "./format";
import type { BusEvent, LogLine, ManagedProcess, ServerMessage } from "./types";

export type Connection = "connecting" | "live" | "reconnecting";

const HISTORY = 30;
const MAX_EVENTS = 40;

export interface LiveState {
  processes: ManagedProcess[] | null;
  events: BusEvent[];
  connection: Connection;
  updatedAt: number | null;
  cpuHistory: number[];
  memHistory: number[];
  /** Daemon clock minus browser clock, in seconds (uptimes use the daemon's clock). */
  clockOffset: number;
  /** Streams log lines of one process to `onLine`; returns the unsubscribe. */
  followLogs: (process: string, onLine: (line: LogLine) => void) => () => void;
}

/**
 * Keeps one WebSocket to `/api/ws` open (the session cookie authenticates it)
 * and reconnects with backoff. Calls `onSignedOut` when a reconnect finds the
 * session gone.
 */
export function useLive(onSignedOut: () => void): LiveState {
  const [processes, setProcesses] = useState<ManagedProcess[] | null>(null);
  const [events, setEvents] = useState<BusEvent[]>([]);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [cpuHistory, setCpuHistory] = useState<number[]>([]);
  const [memHistory, setMemHistory] = useState<number[]>([]);
  const [clockOffset, setClockOffset] = useState(0);

  const socketRef = useRef<WebSocket | null>(null);
  const logTarget = useRef<{ process: string; onLine: (line: LogLine) => void } | null>(null);
  const signedOutRef = useRef(onSignedOut);
  signedOutRef.current = onSignedOut;

  useEffect(() => {
    let closed = false;
    let attempt = 0;
    let retryTimer: number | undefined;

    const send = (message: object) => {
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(JSON.stringify(message));
      }
    };

    const connect = () => {
      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      const socket = new WebSocket(`${scheme}://${window.location.host}/api/ws`);
      socketRef.current = socket;

      socket.onopen = () => {
        attempt = 0;
        setConnection("live");
        if (logTarget.current) send({ type: "subscribe_logs", process: logTarget.current.process });
      };

      socket.onerror = () => {
        // onclose follows and schedules the reconnect.
      };

      socket.onmessage = (message) => {
        let data: ServerMessage;
        try {
          data = JSON.parse(String(message.data)) as ServerMessage;
        } catch {
          return;
        }
        switch (data.type) {
          case "processes": {
            setProcesses(data.data);
            setUpdatedAt(Date.now());
            if (typeof data.now === "number") setClockOffset(data.now - Date.now() / 1000);
            const cpu = data.data.reduce((sum, p) => sum + (p.cpu_percent || 0), 0);
            const mem = data.data.reduce((sum, p) => sum + (p.memory_bytes || 0), 0);
            setCpuHistory((prev) => [...prev, cpu].slice(-HISTORY));
            setMemHistory((prev) => [...prev, mem].slice(-HISTORY));
            break;
          }
          case "event":
            setEvents((prev) => [data.data, ...prev].slice(0, MAX_EVENTS));
            break;
          case "log": {
            const target = logTarget.current;
            if (target && target.process === data.process) {
              target.onLine({
                key: nextLineKey(),
                stream: data.stream,
                time: new Date(data.at * 1000).toLocaleTimeString([], { hour12: false }),
                text: data.line,
              });
            }
            break;
          }
          case "hello":
            break;
        }
      };

      socket.onclose = () => {
        if (closed) return;
        setConnection("reconnecting");
        attempt += 1;
        const delay = Math.min(1000 * 2 ** (attempt - 1), 10_000);
        retryTimer = window.setTimeout(async () => {
          try {
            const session = await api.session();
            if (closed) return;
            if (!session.authenticated) {
              signedOutRef.current();
              return;
            }
          } catch {
            // Daemon unreachable: keep retrying.
          }
          if (!closed) connect();
        }, delay);
      };
    };

    connect();
    return () => {
      closed = true;
      window.clearTimeout(retryTimer);
      socketRef.current?.close();
    };
  }, []);

  const followLogs = useCallback((process: string, onLine: (line: LogLine) => void) => {
    const entry = { process, onLine };
    logTarget.current = entry;
    const socket = socketRef.current;
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "subscribe_logs", process }));
    }
    return () => {
      // Compare identity: a newer subscription (stream switch, StrictMode
      // remount) may already have replaced this one for the same process.
      if (logTarget.current !== entry) return;
      logTarget.current = null;
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(JSON.stringify({ type: "unsubscribe_logs" }));
      }
    };
  }, []);

  return { processes, events, connection, updatedAt, cpuHistory, memHistory, clockOffset, followLogs };
}
