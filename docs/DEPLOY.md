# Deployment Guide

Oxmgr includes a PM2-like remote deployment system.

## Command Syntax

PM2-compatible form:

```bash
oxmgr deploy <configuration_file> <environment> <command>
```

Also supported:

```bash
oxmgr deploy <environment> <command>
oxmgr deploy --config <configuration_file> <environment> <command>
```

When config file is omitted, Oxmgr auto-detects:

- `ecosystem.config.js`
- `ecosystem.config.cjs`
- `ecosystem.config.json`
- `pm2.config.js`
- `pm2.config.cjs`
- `pm2.config.json`
- `oxfile.toml`

## Deploy Commands

```bash
oxmgr deploy production setup
oxmgr deploy production update
oxmgr deploy production revert 1
oxmgr deploy production current
oxmgr deploy production previous
oxmgr deploy production list
oxmgr deploy production exec "pm2 reload all"
oxmgr deploy production run "npm ci"
oxmgr deploy production v1.4.2
```

Supported actions:

- `setup`: provision remote server and clone repository
- `update`: fetch and deploy latest target
- `revert [n]`: revert to `n`th previous deployment (`1` by default)
- `current` / `curr`: print current deployed commit
- `previous` / `prev`: print previous deployed commit
- `list`: print deployment history
- `exec|run <cmd>`: execute one-off command on all target hosts
- `<ref>`: deploy explicit git ref/tag/branch

`--force` works with `update` (or explicit `<ref>`) and resets local checkout on remote before deploy.

## Deployment Config

Define deployment environments in a top-level `deploy` object/table.

Required fields per environment:

- `user`
- `host` (string or array)
- `path`

Required for `setup`/`update`/`revert`:

- `repo`

Optional fields:

- `ref`
- `port`
- `key`
- `pre-setup`
- `post-setup`
- `pre-deploy-local`
- `pre-deploy`
- `post-deploy`

## Ecosystem JS Example

```javascript
module.exports = {
  apps: [{ script: "api.js" }],
  deploy: {
    production: {
      user: "ubuntu",
      host: ["192.168.0.13", "192.168.0.14"],
      ref: "origin/main",
      repo: "git@github.com:Username/repository.git",
      path: "/var/www/my-repository",
      "pre-setup": "echo setup-start",
      "post-setup": "echo setup-done",
      "pre-deploy-local": "echo local-prepare",
      "pre-deploy": "npm ci",
      "post-deploy": "oxmgr apply ./oxfile.toml --env production"
    }
  }
};
```

## Oxfile TOML Example

```toml
[deploy.production]
user = "ubuntu"
host = ["192.168.0.13", "192.168.0.14"]
ref = "origin/main"
repo = "git@github.com:Username/repository.git"
path = "/var/www/my-repository"
pre_setup = "echo setup-start"
post_setup = "echo setup-done"
pre_deploy_local = "echo local-prepare"
pre_deploy = "npm ci"
post_deploy = "oxmgr apply ./oxfile.toml --env production"
```

## Lifecycle Hooks

- `pre-setup`: remote, before initial clone/setup
- `post-setup`: remote, after setup
- `pre-deploy-local`: local machine, before update
- `pre-deploy`: remote, before git checkout/reset
- `post-deploy`: remote, after deploy checkout

## Multi-Host Deployment

Use an array under `host`:

```json
"host": ["212.83.163.1", "212.83.163.2", "212.83.163.3"]
```

Oxmgr executes deployment operations on environment hosts in parallel.

## SSH Key Configuration

Specify a key file:

```json
"key": "/path/to/some.pem"
```

Oxmgr runs SSH as:

- `ssh -i <key> -p <port> <user>@<host> ...`

## Troubleshooting

- Verify remote host can clone the target repo manually.
- Verify SSH key is present on host and allowed in git provider.
- Use SSH config aliases when different repositories require different identities.
- For agent forwarding, configure local `~/.ssh/config` with `ForwardAgent yes`.
