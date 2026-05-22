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
# noble-core:      git for build.rs commit-sha embedding
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake perl pkg-config \
    llvm llvm-dev libclang-dev clang \
    libssl-dev openssl \
    ca-certificates git curl file procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Release build of the three runtime binaries.
RUN cargo build --release \
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
