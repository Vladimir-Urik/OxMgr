# syntax=docker/dockerfile:1
#
# OxMgr - lightweight language-agnostic process manager
#
# Multi-stage build: compiles the release binary in a Rust builder image, then
# copies it into a slim Alpine runtime image together with the web dashboard,
# example config, and entrypoint harness.
#
# Build:
#   docker build -t oxmgr .
#
# Run (standalone, demo dashboard):
#   docker run --rm -p 46001:46001 -e OXMGR_API_ADDR=0.0.0.0:46001 oxmgr

# ---------------------------------------------------------------------------
# Builder stage
# ---------------------------------------------------------------------------
FROM rust:1.97-alpine AS builder

# musl-compatible build toolchain for a static-ish binary.
RUN apk add --no-cache musl-dev build-base

WORKDIR /build

# Cache dependency compilation: copy manifests first, build deps, then source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked 2>/dev/null || true
COPY src ./src
COPY web ./web
COPY build.rs .
RUN touch src/main.rs && cargo build --release --locked

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache netcat-openbsd

RUN addgroup -S oxmgr && adduser -S oxmgr -G oxmgr

WORKDIR /opt/oxmgr

COPY --from=builder /build/target/release/oxmgr /usr/local/bin/oxmgr
COPY web/ /opt/oxmgr/web/
COPY docker/oxfile.example.toml /opt/oxmgr/oxfile.example.toml
COPY docker/entrypoint.sh /usr/local/bin/oxmgr-entrypoint
RUN chmod +x /usr/local/bin/oxmgr-entrypoint

# Defaults, overridable at runtime. The daemon binds two listeners:
#   OXMGR_DAEMON_ADDR  - local IPC for the `oxmgr` CLI
#   OXMGR_API_ADDR     - web dashboard + REST API + Prometheus metrics
ENV OXMGR_HOME=/var/lib/oxmgr \
    OXMGR_DAEMON_ADDR=127.0.0.1:45001 \
    OXMGR_API_ADDR=0.0.0.0:46001 \
    OXMGR_CONFIG=/opt/oxmgr/oxfile.example.toml \
    PORT=8080

RUN mkdir -p /var/lib/oxmgr/logs && \
    chown -R oxmgr:oxmgr /var/lib/oxmgr /opt/oxmgr

USER oxmgr

EXPOSE 46001 8080

# The entrypoint `exec`s the daemon, so oxmgr itself becomes PID 1 and handles
# SIGTERM from `docker stop` natively. No init wrapper is baked into the image:
# for zombie reaping use the runtime's own init (`docker run --init`, or
# `init: true` in compose), which mounts the platform's init binary instead of
# pinning one here.
ENTRYPOINT ["/usr/local/bin/oxmgr-entrypoint"]
STOPSIGNAL SIGTERM
