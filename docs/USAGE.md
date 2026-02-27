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

## 2) Inspect and Monitor

```bash
oxmgr list
oxmgr ps
oxmgr status api
oxmgr logs api
oxmgr log api -f
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
```

`apply` is idempotent and safe for repeated runs in CI/CD.

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
