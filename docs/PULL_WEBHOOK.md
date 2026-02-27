# Pull and Webhook Guide

Oxmgr can pull git updates per service and apply them with minimal disruption.

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

## Webhook API

Endpoint:

- `POST /pull/<name|id>`

Auth headers:

- `X-Oxmgr-Secret: <secret>`
- or `Authorization: Bearer <secret>`

Bind address:

- `OXMGR_API_ADDR` (default: localhost high port)

Example:

```bash
curl -X POST \
  -H "X-Oxmgr-Secret: replace-with-long-random-secret" \
  http://127.0.0.1:51234/pull/api
```

## Security

- Keep API bound to localhost unless you intentionally expose it.
- Use long random secrets and rotate on incident response.
- Prefer SSH deploy keys with read-only repo access.
- Combine with CI/CD source IP controls or reverse-proxy auth when exposed.
