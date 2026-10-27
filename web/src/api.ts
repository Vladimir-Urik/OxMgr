import type { Action, LogLine, Session } from "./types";
import { nextLineKey, parseLogLine } from "./format";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

let unauthorizedHandler: (() => void) | null = null;

/** Called when an authenticated request comes back 401 (session expired or revoked). */
export function onUnauthorized(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: {
      // State-changing requests must carry this header (CSRF guard in the daemon).
      "X-Oxmgr-Request": "1",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  });
  const body = (await res.json().catch(() => null)) as
    | (T & { message?: string; retry_after?: number })
    | null;
  if (!res.ok) {
    if (res.status === 401 && path !== "/api/login") unauthorizedHandler?.();
    throw new ApiError(body?.message ?? `HTTP ${res.status}`, res.status, body?.retry_after);
  }
  return body as T;
}

export const api = {
  /** Resolves with the session even when signed out (401 carries the same body). */
  async session(): Promise<Session> {
    const res = await fetch("/api/session", { credentials: "same-origin" });
    if (res.status !== 200 && res.status !== 401) {
      throw new ApiError(`HTTP ${res.status}`, res.status);
    }
    return (await res.json()) as Session;
  },

  login(username: string, password: string, remember: boolean) {
    return request<{ ok: boolean }>("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password, remember }),
    });
  },

  logout() {
    return request<{ ok: boolean }>("/api/logout", { method: "POST" });
  },

  action(target: string, action: Action) {
    return request<{ ok: boolean; message: string }>(
      `/api/processes/${encodeURIComponent(target)}/${action}`,
      { method: "POST" },
    );
  },

  async tail(target: string, stream: "stdout" | "stderr", lines = 200): Promise<LogLine[]> {
    const body = await request<{ lines: string[] }>(
      `/api/processes/${encodeURIComponent(target)}/logs?stream=${stream}&lines=${lines}`,
    );
    return body.lines.map((line) => ({ key: nextLineKey(), stream, ...parseLogLine(line) }));
  },
};
