// Shapes sent by the daemon (src/daemon/dashboard.rs, src/process.rs, src/events.rs).

export type ProcessStatus = "running" | "stopped" | "crashed" | "restarting" | "errored";
export type HealthStatus = "unknown" | "healthy" | "unhealthy";

export interface ManagedProcess {
  id: number;
  name: string;
  command: string;
  args: string[];
  cwd: string | null;
  namespace: string | null;
  pid: number | null;
  status: ProcessStatus;
  desired_state: "running" | "stopped";
  restart_count: number;
  max_restarts: number;
  last_exit_code: number | null;
  stdout_log: string;
  stderr_log: string;
  health_status: HealthStatus;
  last_health_error: string | null;
  last_error: string | null;
  cpu_percent: number;
  memory_bytes: number;
  last_started_at: number | null;
  last_stopped_at: number | null;
  cluster_mode: boolean;
  cluster_instances: number | null;
  watch: boolean;
  cron_restart: string | null;
}

export interface Session {
  authenticated: boolean;
  auth_required: boolean;
  version: string;
  label: string | null;
  label_color: string | null;
  interval_ms: number;
}

export interface EventProcessInfo {
  id: number;
  name: string;
  namespace: string | null;
  pid: number | null;
}

export interface BusEvent {
  event: string;
  at: number;
  process?: EventProcessInfo;
  data?: {
    status?: string;
    exit_code?: number | null;
    signal?: string | null;
    restart_count?: number;
    delay_secs?: number;
    error?: string;
  };
}

export interface LogLine {
  /** Monotonic key for React lists. */
  key: number;
  time: string;
  text: string;
  stream: "stdout" | "stderr";
}

export type ServerMessage =
  | { type: "hello"; version: string; label: string | null; label_color: string | null; interval_ms: number }
  | { type: "processes"; now: number; data: ManagedProcess[] }
  | { type: "event"; data: BusEvent }
  | { type: "log"; process: string; stream: "stdout" | "stderr"; at: number; line: string };

export type Action = "restart" | "stop" | "reload";
