# Pull, Webhook, and Metrics Guide

Oxmgr exposes a small daemon HTTP API for git pull automation and Prometheus scraping.

## Config

In `oxfile.toml`:

```toml
[[apps]]
name = "api"
command = "node server.js"
cwd = "/srv/api"
git_repo = "git@github.com:your-org/your-repo.git"
git_ref = "main"
pull_secret = "replace-with-long-random-secret"
```

Fields:

- `git_repo`: required for pull workflow
- `git_ref`: optional branch/tag/ref for explicit remote pull
- `pull_secret`: required for secure webhook trigger

`pull_secret` is stored as a SHA-256 hash in state.

## CLI Pull

```bash
# Pull one service
oxmgr pull api

# Pull all services that define git_repo
oxmgr pull
```

Behavior:

- If commit is unchanged: no restart/reload.
- If commit changed and service is running: `reload`.
- If commit changed and desired state is running but process is stopped: `restart`.
- If commit changed and desired state is stopped: checkout updates only.

## HTTP API

Endpoints:

- `POST /pull/<name|id>`
- `GET /metrics`

Auth for pull webhook:

- `X-Oxmgr-Secret: <secret>`
- or `Authorization: Bearer <secret>`

Bind address:

- `OXMGR_API_ADDR` (default: localhost high port)

Pull example:

```bash
curl -X POST \
  -H "X-Oxmgr-Secret: replace-with-long-random-secret" \
  http://127.0.0.1:51234/pull/api
```

Metrics example:

```bash
curl http://127.0.0.1:51234/metrics
```

The metrics endpoint returns Prometheus text exposition format with gauges and counters for:

- managed process count
- process metadata (`oxmgr_process_info`)
- process up/down state
- restart count
- CPU percent
- memory bytes
- current PID
- lifecycle status
- health-check status
- last-start timestamp
- last-metrics-refresh timestamp

Prometheus scrape example:

```yaml
scrape_configs:
  - job_name: oxmgr
    static_configs:
      - targets: ["127.0.0.1:51234"]
    metrics_path: /metrics
```

## Security

- Keep the API bound to localhost unless you intentionally expose it.
- Use long random secrets and rotate on incident response.
- Prefer SSH deploy keys with read-only repo access.
- If you expose the endpoint remotely, protect both webhook and metrics traffic with reverse-proxy auth, source IP filtering, or network policy.
