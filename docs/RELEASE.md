# Release Automation

Oxmgr release automation is defined in `.github/workflows/release.yml`.

## Trigger

Create and push a semver tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## What happens

- Build release binaries for:
  - `x86_64-unknown-linux-gnu`
  - `x86_64-apple-darwin`
  - `aarch64-apple-darwin`
  - `x86_64-pc-windows-msvc`
- Build Debian package (`oxmgr_<version>_amd64.deb`)
- Publish GitHub Release assets + `SHA256SUMS`
- Publish npm package (`oxmgr`) when `NPM_TOKEN` is set
- Update Homebrew tap formula when Homebrew secrets are set
- Publish Chocolatey package when `CHOCO_API_KEY` is set
- Publish APT repository index to `gh-pages/apt`

## Required repository settings

- Enable GitHub Actions
- Enable GitHub Pages (source: `gh-pages` branch)

## Required secrets

### For npm publish

- `NPM_TOKEN`

### For Homebrew publish

- `HOMEBREW_TAP_TOKEN`: PAT with write access to tap repo
- `HOMEBREW_TAP_REPO`: e.g. `my-org/homebrew-tap`

### For Chocolatey publish

- `CHOCO_API_KEY`

## Optional notes

- APT repository is published unsigned and intended for use with `trusted=yes`.
- If you need signed APT metadata, add GPG signing and key distribution in workflow.
