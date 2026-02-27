# Oxfile vs PM2 Ecosystem

Oxmgr supports both formats:

- PM2 ecosystem JSON (`ecosystem.config.json`) for migration compatibility.
- Oxmgr-native TOML (`oxfile.toml`) for long-term operations.

This page explains when and why to prefer `oxfile.toml`.

## Summary

Use ecosystem JSON when:

- you are migrating from PM2 and want minimal edits first.
- your team already has mature PM2 config conventions.

Use `oxfile.toml` when:

- you want a clean, typed, human-friendly config for Oxmgr-native features.
- you need profile overrides and dependency-oriented startup orchestration.
- you want better readability and reviewability in pull requests.

## Why Oxfile Is Preferred

1. Better readability for operations-heavy configs.
2. Native schema aligned with Oxmgr lifecycle semantics.
3. More explicit profile overrides (`[apps.profiles.<name>]`).
4. Dependency graph and start ordering designed for idempotent `oxmgr apply`.
5. First-class support for Oxmgr pull webhook settings (`git_repo`, `git_ref`, `pull_secret`).

## Practical Differences

| Topic | PM2 ecosystem JSON | Oxfile TOML |
|---|---|---|
| Primary goal | PM2 compatibility | Oxmgr-native operations |
| Readability at scale | medium | high |
| Profiles | `env_<name>` pattern | `[apps.profiles.<name>]` |
| Dependencies | limited/indirect | explicit `depends_on` |
| Start order | `priority` mappings | explicit `start_order` |
| Pull webhook fields | imported/translated | native fields |
| Apply idempotency clarity | medium | high |

## Migration Pattern

1. Import existing ecosystem config with `oxmgr import ./ecosystem.config.json`.
2. Convert once to native format with `oxmgr convert ecosystem.config.json --out oxfile.toml`.
3. Use `oxmgr validate ./oxfile.toml` in CI.
4. Reconcile using `oxmgr apply ./oxfile.toml --env <profile>`.

## Recommendation

Treat ecosystem JSON as a migration bridge.
Use `oxfile.toml` as the source of truth for production operations.
