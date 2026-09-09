# Multi-stage Dockerfile for the Noble node.
# Builder produces release binaries; runtime is a slim Debian image with
# just the binaries, dashboard static files, and a non-root user.

# ── Builder stage ────────────────────────────────────────────────────────────
# `rust:1-slim-bookworm` floats to the latest stable 1.x. Crate compatibility
# (e.g. time 0.3.47 requiring edition2024 → Rust ≥1.85) shifts forward over
# time; reproducibility for our own code comes from Cargo.lock, not the
# toolchain pin.
FROM rust:1-slim-bookworm AS builder

# librocksdb-sys:  cmake + libclang for bindgen
# openssl-sys:     libssl-dev + pkg-config (system) OR make+perl (vendored)
#                  Workspace uses `openssl = { features = ["vendored"] }` so
#                  the vendored path applies — make+perl required.
# noble-tx-core:   cc crate compiles its C sources (pulled in by noble-faucet)
#
# No build script reads git metadata — `.git` is excluded from the build
# context, and nothing needs it. `git` stays installed only because some
# crates' build scripts fetch nothing but expect it on PATH; drop it if a
# future audit shows otherwise.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake perl pkg-config \
    llvm llvm-dev libclang-dev clang \
    libssl-dev openssl \
    ca-certificates git curl file procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# `.dockerignore` at the context root (NOBLEv1/, per `context: ..` in
# docker-compose.yml) keeps `target/` out. It previously lived beside this
# file as `docker/.dockerignore`, where Docker never reads it — so every
# build copied the whole 15 GB `target/` in, and the host's artifacts landed
# here where cargo could reuse them and emit a binary older than the source.
COPY . .

# Release build of the three runtime binaries.
#
# COMPILE_CORES caps concurrent rustc jobs so a shared cloud instance is not
# saturated by a build:
#
#   COMPILE_CORES=2 docker compose up -d --build
#   docker build --build-arg COMPILE_CORES=2 -f docker/Dockerfile ..
#
# Unset = cargo's default, one job per core.
#
# The cap lives here, in cargo, rather than in docker's --cpus/--cpuset-cpus:
# BuildKit ignores those flags entirely (they bind only on the legacy builder,
# DOCKER_BUILDKIT=0), so setting them would look like it worked and do
# nothing. The release profile is cargo's default — codegen-units=16, no LTO —
# so the build really is parallel rustc jobs, and bounding them bounds peak
# memory along with CPU.
# Unset, 0, or anything that is not a positive integer → cargo's default.
# 0 must not reach cargo: `-j 0` is an error, so an unvalidated pass-through
# would turn "no limit" into a failed build. Bad input is reported, never
# silently swallowed.
ARG COMPILE_CORES=""
RUN cores_valid=0; \
    case "$COMPILE_CORES" in \
      '') ;; \
      *[!0-9]*) echo "warning: COMPILE_CORES='$COMPILE_CORES' is not a positive integer — using all cores" ;; \
      *) [ "$COMPILE_CORES" -gt 0 ] && cores_valid=1 ;; \
    esac; \
    if [ "$cores_valid" = 1 ]; then \
      echo "cargo: limiting build to $COMPILE_CORES core(s)"; \
      export CARGO_BUILD_JOBS="$COMPILE_CORES"; \
    else \
      echo "cargo: building with all available cores"; \
    fi; \
    cargo build --release \
      --bin noble-node \
      --bin noble-tool \
      --bin noble-faucet

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# tini  : PID 1 with proper SIGTERM forwarding (clean RocksDB shutdown)
# curl  : healthcheck probe
# gosu  : drop privileges from root → noble in the entrypoint
# libssl3 + ca-certificates: TLS for outbound calls (Let's Encrypt, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 tini curl gosu \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10000 noble \
 && useradd  --system --uid 10000 --gid noble \
              --home /var/lib/noble --shell /usr/sbin/nologin noble \
 && mkdir -p /var/lib/noble /opt/noble \
 && chown -R noble:noble /var/lib/noble /opt/noble

COPY --from=builder /src/target/release/noble-node   /usr/local/bin/noble-node
COPY --from=builder /src/target/release/noble-tool   /usr/local/bin/noble-tool
COPY --from=builder /src/target/release/noble-faucet /usr/local/bin/noble-faucet
# detect_gui_dir() looks at `<binary_dir>/../noble-gui/` first. With binaries
# in /usr/local/bin, that resolves to /usr/local/noble-gui — matches the brew
# install layout.
COPY --from=builder /src/noble-gui                   /usr/local/noble-gui
COPY docker/entrypoint.sh                            /usr/local/bin/noble-entrypoint
RUN chmod +x /usr/local/bin/noble-entrypoint

# NOTE: no `USER noble` here. The container starts as root so the
# entrypoint can chown the bind-mounted data dir on first boot (Docker
# auto-creates missing bind sources owned by root). The entrypoint then
# `gosu`-drops to UID 10000 before exec'ing noble-node.
WORKDIR /var/lib/noble

# Documentation only; compose decides what crosses to the host.
EXPOSE 8780 8783 8784 8785 8786

# Healthcheck is a transport-level probe: did the RPC port accept a TCP
# connection and complete a TLS handshake? That's the correct notion of
# "healthy" for Docker. Application-level checks (setup_complete, auth,
# allowlist membership) are NOT the orchestrator's concern.
#
# Why not a JSON-RPC call? Noble's middleware enforces an IP allowlist
# (allowed_ips). Inside the container the probe's source IP is 127.0.0.1
# which is not in the operator's CIDR (e.g. 100.64.0.0/10 for Tailscale),
# so any RPC call returns 403 — the container would sit "unhealthy"
# despite being perfectly fine.
#
# `curl -ksS -o /dev/null` with no `-f` returns exit 0 for ANY HTTP
# response (incl. 403) and non-zero only when the connection failed.
# That's exactly what we want: "RPC port is alive."
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
  CMD curl -ksS -o /dev/null --max-time 2 https://127.0.0.1:8783/ \
   || curl -sS  -o /dev/null --max-time 2 http://127.0.0.1:8783/ \
   || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/noble-entrypoint"]
