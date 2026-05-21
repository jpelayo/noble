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
# libssl3 + ca-certificates: TLS for outbound calls (Let's Encrypt, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 tini curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10000 noble \
 && useradd  --system --uid 10000 --gid noble \
              --home /var/lib/noble --shell /usr/sbin/nologin noble \
 && mkdir -p /var/lib/noble /opt/noble \
 && chown -R noble:noble /var/lib/noble /opt/noble

COPY --from=builder /src/target/release/noble-node   /usr/local/bin/noble-node
COPY --from=builder /src/target/release/noble-tool   /usr/local/bin/noble-tool
COPY --from=builder /src/target/release/noble-faucet /usr/local/bin/noble-faucet
COPY --from=builder /src/noble-gui                   /opt/noble/noble-gui
COPY docker/entrypoint.sh                            /usr/local/bin/noble-entrypoint
RUN chmod +x /usr/local/bin/noble-entrypoint

USER noble
WORKDIR /var/lib/noble

# Documentation only; compose decides what crosses to the host.
EXPOSE 8780 8783 8784 8785 8786

# Healthcheck hits the no-auth noble_getSetupStatus JSON-RPC. Default uses
# HTTPS + -k since NOBLE_TLS_ENABLED defaults to true (mirroring the brew
# install). If you disable TLS (nginx-fronting override), the same probe
# still works against http://127.0.0.1:8783 because curl -k follows either.
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
  CMD sh -c '\
    curl -fskS -X POST https://127.0.0.1:8783/ \
         -H "Content-Type: application/json" \
         -d "{\"jsonrpc\":\"2.0\",\"method\":\"noble_getSetupStatus\",\"id\":1}" \
      || curl -fsS  -X POST http://127.0.0.1:8783/ \
              -H "Content-Type: application/json" \
              -d "{\"jsonrpc\":\"2.0\",\"method\":\"noble_getSetupStatus\",\"id\":1}" \
    ' | grep -q '"setup_complete":true' || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/noble-entrypoint"]
