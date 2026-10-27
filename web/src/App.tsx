import { useCallback, useEffect, useState } from "react";
import { api, onUnauthorized } from "./api";
import { Dashboard } from "./components/Dashboard";
import { Login } from "./components/Login";
import type { Session } from "./types";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api
      .session()
      .then((next) => {
        setSession(next);
        setError(null);
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  useEffect(refresh, [refresh]);
  // Any API call answered 401 (expired or revoked session) re-checks the
  // session, which shows the sign-in screen when it is gone.
  useEffect(() => {
    onUnauthorized(refresh);
    return () => onUnauthorized(null);
  }, [refresh]);

  if (error) {
    return (
      <div className="splash" style={{ flexDirection: "column", gap: 16 }}>
        <span>Cannot reach the oxmgr daemon: {error}</span>
        <button type="button" className="btn" onClick={refresh}>
          Retry
        </button>
      </div>
    );
  }
  if (!session) {
    return <div className="splash">Loading…</div>;
  }
  if (!session.authenticated) {
    return <Login session={session} onSignedIn={refresh} />;
  }
  return <Dashboard session={session} onSignedOut={refresh} />;
}
