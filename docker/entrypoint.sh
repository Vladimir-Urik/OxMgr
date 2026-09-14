#!/bin/sh
# OxMgr container entrypoint.
#
# Seeds the daemon with the example oxfile (so the web dashboard has something
# to show), then hands PID 1 over to the daemon itself via `exec`.
#
# Why `exec` matters: without it this shell stays PID 1 and `docker stop`
# delivers SIGTERM to the shell, not to oxmgr. POSIX sh does not forward
# signals to background children, so the daemon would never run its graceful
# shutdown and managed processes would be killed abruptly at the end of the
# stop timeout. With `exec`, oxmgr *is* PID 1 and handles SIGTERM natively.
#
# Safe to re-run on an existing data volume: `apply` is idempotent for the
# demo case.
set -e

config="${OXMGR_CONFIG:-/opt/oxmgr/oxfile.example.toml}"

# Make sure the daemon IPC listener is not already occupied by a stale daemon
# from a previous run that kept the same OXMGR_HOME.
if [ -S "${OXMGR_HOME}/events.sock" ]; then
    echo "[entrypoint] removing stale event socket" >&2
    rm -f "${OXMGR_HOME}/events.sock"
fi

# Seed the daemon in the background. The daemon is started by `exec` below, so
# this waits for its IPC socket to come up and then applies the config through
# the normal CLI path.
if [ -n "$OXMGR_CONFIG" ] && [ -f "$config" ]; then
    (
        ready=0
        for _ in $(seq 1 100); do
            if oxmgr list >/dev/null 2>&1; then
                ready=1
                break
            fi
            sleep 0.2
        done

        if [ "$ready" -ne 1 ]; then
            echo "[entrypoint] daemon did not become ready; skipping seed" >&2
            exit 0
        fi

        echo "[entrypoint] applying ${config}" >&2
        # apply is idempotent; a non-zero exit (e.g. duplicate names on an
        # already seeded volume) is tolerated so the demo keeps running.
        oxmgr apply "$config" || echo "[entrypoint] apply reported a non-fatal error" >&2
        echo "[entrypoint] oxmgr ready - web dashboard on ${OXMGR_API_ADDR}" >&2
    ) &
fi

echo "[entrypoint] starting oxmgr daemon (ipc=${OXMGR_DAEMON_ADDR} api=${OXMGR_API_ADDR})" >&2

# Replace this shell with the daemon so it becomes PID 1 and receives SIGTERM
# from `docker stop` directly.
exec oxmgr daemon run
