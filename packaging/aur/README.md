# AUR Packaging

This directory contains the metadata for the `oxmgr-bin` AUR package.

## Why `oxmgr-bin`


## Update for a new release

1. Fetch the release checksums:

   ```bash
   VERSION=0.1.6
   curl -fsSL "https://github.com/Vladimir-Urik/OxMgr/releases/download/v${VERSION}/oxmgr-v${VERSION}-x86_64-unknown-linux-musl.tar.gz.sha256"
   curl -fsSL "https://github.com/Vladimir-Urik/OxMgr/releases/download/v${VERSION}/oxmgr-v${VERSION}-aarch64-unknown-linux-musl.tar.gz.sha256"
   curl -fsSL "https://raw.githubusercontent.com/Vladimir-Urik/OxMgr/v${VERSION}/LICENSE" | shasum -a 256
   ```

2. Regenerate `PKGBUILD`:

   ```bash
   ./scripts/generate_aur_pkgbuild.sh \
     Vladimir-Urik/OxMgr \
     "${VERSION}" \
     <intel-sha256> \
     <arm-sha256> \
     <license-sha256> \
     > packaging/aur/PKGBUILD
   ```

3. Refresh `.SRCINFO` from an Arch environment:

   ```bash
   cd packaging/aur
   makepkg --printsrcinfo > .SRCINFO
   ```

4. Push the updated files to the AUR package repo:

   ```bash
   git clone ssh://aur@aur.archlinux.org/oxmgr-bin.git
   cp PKGBUILD .SRCINFO oxmgr-bin/
   cd oxmgr-bin
   git commit -am "oxmgr-bin ${VERSION}"
   git push
   ```

If `AUR_SSH_PRIVATE_KEY` is configured in GitHub Actions, `.github/workflows/release.yml` performs this update automatically for tagged releases.

## Install

Users can install the package with an AUR helper such as:

```bash
yay -S oxmgr-bin
```
