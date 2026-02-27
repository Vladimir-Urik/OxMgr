# Installation Guide

This guide covers all supported installation paths for Oxmgr.

## Supported Platforms

- Linux
- macOS
- Windows

## Package Manager Install

### npm

```bash
npm install -g oxmgr
```

### yarn

```bash
yarn global add oxmgr
```

### Homebrew

```bash
brew tap Vladimir-Urik/OxMgr
brew install oxmgr
```

### Chocolatey

```powershell
choco install oxmgr -y
```

### APT (Debian/Ubuntu)

Unsigned repository (simple setup):

```bash
echo "deb [trusted=yes] https://vladimir-urik.github.io/OxMgr/apt stable main" | sudo tee /etc/apt/sources.list.d/oxmgr.list
sudo apt update
sudo apt install oxmgr
```

Signed repository (recommended):

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://vladimir-urik.github.io/OxMgr/apt/keyrings/oxmgr-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/oxmgr-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/oxmgr-archive-keyring.gpg] https://vladimir-urik.github.io/OxMgr/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/oxmgr.list
sudo apt update
sudo apt install oxmgr
```

## Install From Source

```bash
git clone https://github.com/Vladimir-Urik/OxMgr.git
cd OxMgr
cargo build --release
./target/release/oxmgr --help
```

## Post-Install Setup

### Validate configuration

```bash
oxmgr validate ./oxfile.toml --env prod
```

### Apply desired config

```bash
oxmgr apply ./oxfile.toml --env prod
```

### Install as system service

Oxmgr supports direct service management:

```bash
oxmgr service install --system auto
oxmgr service status --system auto
oxmgr service uninstall --system auto
```

`--system auto` resolves to:

- `systemd` on Linux
- `launchd` on macOS
- `task-scheduler` on Windows

## Verify Runtime

```bash
oxmgr list
oxmgr status <name>
oxmgr logs <name> -f
```

## Optional Environment Variables

- `OXMGR_HOME`: custom Oxmgr data directory
- `OXMGR_DAEMON_ADDR`: custom daemon address (`host:port`)
- `OXMGR_LOG_MAX_SIZE_MB`: log rotation size threshold
- `OXMGR_LOG_MAX_FILES`: number of rotated files to retain
- `OXMGR_LOG_MAX_DAYS`: rotated log retention period

## Upgrade

- Package manager installs: use your package manager's upgrade command.
- Source installs: pull latest changes and rebuild.

## Uninstall

1. Remove service:

```bash
oxmgr service uninstall --system auto
```

2. Remove package/binary via package manager or manually.

3. Optional cleanup of local state:

- Linux/macOS: `~/.local/share/oxmgr`
- Windows: `%LOCALAPPDATA%\\oxmgr`
