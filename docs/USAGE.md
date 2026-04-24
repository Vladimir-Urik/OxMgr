# User Guide

This guide is for day-to-day usage of `oxmgr` in production and on dev servers.

## 1) Start Managing a Service

```bash
oxmgr start "node server.js" --name api
```

Useful start options:

- `--restart always|on-failure|never`
- `--max-restarts <n>`
- `--crash-restart-limit <n>`
- `--cwd <path>`
- `--env KEY=VALUE`
- `--watch`
- `--cluster --cluster-instances <n>`

Crash-loop behavior:

- By default Oxmgr stops auto-restarting a service after `3` auto restarts inside `5` minutes.
- Manual `start`, `restart`, and `reload` reset that counter.
- Set `--crash-restart-limit 0` to disable the cutoff.
- Leave `--restart-delay` at `0` to restart immediately after an unexpected exit.

## 2) Inspect and Monitor

```bash
oxmgr list
oxmgr ps
oxmgr status api
oxmgr logs api
oxmgr log api -f
oxmgr logs all          # print recent logs for every process at once
oxmgr ui
```

Aliases:

- `list` -> `ls`, `ps`
- `logs` -> `log`

## 3) Operate Running Services

```bash
oxmgr stop api
oxmgr restart api
oxmgr rs api
oxmgr reload api
oxmgr pull api
oxmgr delete api
oxmgr rm api
oxmgr stop ./oxfile.toml
oxmgr restart ./oxfile.toml
oxmgr delete ./oxfile.toml
```

To stop or remove **all** managed processes at once:

```bash
oxmgr stop all
oxmgr restart all
oxmgr delete all   # or: oxmgr rm all
```

Aliases:

- `restart` -> `rs`
- `delete` -> `rm`

## 4) Use Config Files (Recommended)

Validate first:

```bash
oxmgr validate ./oxfile.toml --env prod
```

Apply desired state:

```bash
oxmgr apply ./oxfile.toml --env prod
oxmgr apply ./core.toml ./worker.toml --env prod
```

`apply` is idempotent and safe for repeated runs in CI/CD.

Validate the same merged config set before applying:

```bash
oxmgr validate ./core.toml ./worker.toml --env prod
```

## 5) Import / Export Service Definitions

```bash
oxmgr export api
oxmgr import ./api.oxpkg
oxmgr import https://example.com/api.oxpkg --sha256 <checksum>
```

## 6) UI Quick Keys

- Move: `j/k` or arrows
- New process: `n`
- Stop / Restart / Reload: `s` / `r` / `l`
- Pull selected: `p`
- Tail preview: `t`
- Help: `?`
- Menu: `Esc`
- Quit: `q`

## 7) Safe Production Flow

```bash
oxmgr validate ./oxfile.toml --env prod
oxmgr apply ./oxfile.toml --env prod
oxmgr status api
oxmgr logs api --lines 100
```

## 8) Help

```bash
oxmgr --help
oxmgr help
oxmgr <command> --help
```

`oxmgr help` is grouped by runtime, lifecycle, config, platform, and deploy commands.

## 9) Foreground Runtime (Docker / Kubernetes)

Use `runtime` when you want Oxmgr to run as the foreground process (similar to `pm2-runtime`):

```bash
oxmgr runtime ./oxfile.toml
```

PM2 files are supported too:

```bash
oxmgr runtime ./ecosystem.config.js
oxmgr runtime ./ecosystem.config.json
```

Useful flags:

- `--env <profile>`
- `--only a,b`
