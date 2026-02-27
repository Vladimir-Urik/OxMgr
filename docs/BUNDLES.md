# Service Bundles

Oxmgr can export managed services into compact `.oxpkg` bundle files and import them locally or from a remote URL.

## Commands

- `oxmgr export <name|id> [--out <file>]`
- `oxmgr import <source> [--only a,b] [--sha256 <hex>]`

`<source>` can be:

- a local `.oxpkg` file
- a local `ecosystem.config.json` / `oxfile.toml`
- an `https://` URL that points to an `.oxpkg` bundle

## Examples

```bash
# Export one service by name to ./api.oxpkg
oxmgr export api

# Export one service by id to custom path
oxmgr export 12 --out ./releases/api-prod.oxpkg

# Import a local bundle
oxmgr import ./api.oxpkg

# Import from HTTPS URL with checksum pinning
oxmgr import https://example.com/api.oxpkg --sha256 0123abcd... --only api
```

## Security Defaults

- Remote imports require `https://` URLs.
- URL credentials (`https://user:pass@...`) are rejected.
- URL fragments are rejected.
- Remote payload size is limited (max `8 MiB`).
- Bundle payload has strict validation (schema, env keys, limits).
- Bundle integrity is checked with internal SHA-256 checksum.
- For remote URLs, use `--sha256` for explicit pinning.

## Runtime Requirement

Remote URL import uses `curl` from `PATH`.

