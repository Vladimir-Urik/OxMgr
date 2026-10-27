import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import type { Session } from "../types";
import { EnvLabel } from "./EnvLabel";
import { EyeIcon, InfoIcon, LockIcon, Logo } from "./Icons";

export function Login({ session, onSignedIn }: { session: Session; onSignedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [invalid, setInvalid] = useState(false);
  const [lockedFor, setLockedFor] = useState(0);

  useEffect(() => {
    if (lockedFor <= 0) return;
    const timer = window.setTimeout(() => setLockedFor((s) => s - 1), 1000);
    return () => window.clearTimeout(timer);
  }, [lockedFor]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || lockedFor > 0) return;
    setBusy(true);
    setError(null);
    setInvalid(false);
    try {
      await api.login(username, password, remember);
      onSignedIn();
    } catch (err) {
      const apiError = err instanceof ApiError ? err : null;
      if (apiError?.status === 429) {
        setLockedFor(apiError.retryAfter ?? 30);
      } else if (apiError?.status === 401) {
        setInvalid(true);
        setPassword("");
      }
      setError(apiError?.message ?? "Could not reach the daemon.");
    } finally {
      setBusy(false);
    }
  };

  const plainHttp = window.location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname);
  const buttonText = busy ? "Signing in…" : lockedFor > 0 ? `Locked · ${lockedFor} s` : "Sign in";

  return (
    <main className="login-page">
      <div className="login">
        <div className="login-top">
          <Logo />
          <EnvLabel label={session.label} color={session.label_color} />
        </div>

        <form className="card login-card" onSubmit={submit} noValidate>
          <div>
            <div className="eyebrow">Dashboard</div>
            <h1>Sign in</h1>
            <p>
              to the oxmgr daemon at <span className="mono" style={{ color: "#d4d4d8" }}>{window.location.host}</span>
            </p>
          </div>

          {error && (
            <div className="alert" role="alert">
              <InfoIcon width={16} height={16} style={{ flex: "none", marginTop: 1, color: "var(--bad)" }} />
              <span>{lockedFor > 0 ? `Too many failed attempts. Try again in ${lockedFor} seconds.` : error}</span>
            </div>
          )}

          <div className="field">
            <label htmlFor="username">Username</label>
            <div className="input">
              <input
                id="username"
                autoComplete="username"
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="field">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <label htmlFor="password">Password</label>
              <span className="hint">OXMGR_DASHBOARD_PASS</span>
            </div>
            <div className={`input${invalid ? " invalid" : ""}`}>
              <input
                id="password"
                type={reveal ? "text" : "password"}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={invalid}
                required
              />
              <button
                type="button"
                className="icon-btn"
                aria-label={reveal ? "Hide password" : "Show password"}
                aria-pressed={reveal}
                onClick={() => setReveal((v) => !v)}
              >
                <EyeIcon width={16} height={16} />
              </button>
            </div>
          </div>

          <label className="check" style={{ fontSize: 13 }}>
            <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            Keep me signed in for 12 hours
          </label>

          <button
            type="submit"
            className="btn btn-primary btn-block"
            disabled={busy || lockedFor > 0 || !username || !password}
          >
            {buttonText}
          </button>
        </form>

        {plainHttp && (
          <div className="notice">
            <LockIcon width={16} height={16} style={{ flex: "none", marginTop: 1, color: "var(--warn)" }} />
            <span>
              This connection uses plain HTTP. Put the dashboard behind a TLS reverse proxy before exposing it outside
              your network.
            </span>
          </div>
        )}

        <div className="login-foot">
          <span>oxmgr v{session.version}</span>
          <a href="https://github.com/Vladimir-Urik/OxMgr/blob/master/docs/UI.md#web-dashboard" target="_blank" rel="noreferrer">
            Dashboard docs
          </a>
        </div>
      </div>
    </main>
  );
}
