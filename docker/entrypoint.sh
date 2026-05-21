#!/bin/sh
# Noble container entrypoint.
#
# Three jobs:
#   1. Handle one-shot subcommands (reset-chain, verify, shell)
#   2. On first boot (no noble.toml), render one from env vars
#   3. exec noble-node run
#
# POSIX sh — no bash-isms.

set -eu

NOBLE_DATA_DIR="${NOBLE_DATA_DIR:-/var/lib/noble}"
NOBLE_CONFIG="${NOBLE_DATA_DIR}/noble.toml"
mkdir -p "$NOBLE_DATA_DIR"

# ── One-shot subcommands ─────────────────────────────────────────────────────
# Invoked via:  docker compose run --rm noble <subcommand>
case "${1:-}" in
    reset-chain)
        echo "[entrypoint] reset-chain: wiping RocksDB, preserving keys/identity/TLS"
        exec noble-tool reset-chain --confirm --data-dir "$NOBLE_DATA_DIR"
        ;;
    verify)
        echo "[entrypoint] verify: running noble-tool verify-wire && verify-codec"
        noble-tool verify-wire
        exec noble-tool verify-codec
        ;;
    shell)
        exec /bin/sh
        ;;
    "")
        : # fall through to normal boot
        ;;
    *)
        # Unknown arg — pass straight to noble-node so power users can do
        # `docker compose run --rm noble noble-node --version` etc.
        exec "$@"
        ;;
esac

# ── First-boot config rendering ──────────────────────────────────────────────
if [ ! -f "$NOBLE_CONFIG" ]; then
    echo "[entrypoint] No noble.toml found at $NOBLE_CONFIG — rendering from env vars"

    # Render NOBLE_ALLOWED_IPS (CSV) into a TOML array.
    # Mirrors the brew formula's --with-192/--with-100/etc. behaviour.
    #
    # Loopback (127.0.0.1/32 and ::1/128) is ALWAYS prepended so that the
    # in-container HEALTHCHECK and `docker exec ... curl` debug probes
    # can reach the RPC regardless of the operator-supplied CIDR. Without
    # this, the healthcheck always returns 403.
    ALLOWED_IPS_TOML='["127.0.0.1/32", "::1/128"'
    if [ -z "${NOBLE_ALLOWED_IPS:-}" ]; then
        echo "[entrypoint] NOBLE_ALLOWED_IPS unset — localhost-only mode"
    else
        OLD_IFS="$IFS"; IFS=','
        for cidr in $NOBLE_ALLOWED_IPS; do
            cidr=$(echo "$cidr" | tr -d ' ')
            [ -z "$cidr" ] && continue
            ALLOWED_IPS_TOML="${ALLOWED_IPS_TOML}, \"${cidr}\""
        done
        IFS="$OLD_IFS"
        echo "[entrypoint] NOBLE_ALLOWED_IPS=${NOBLE_ALLOWED_IPS} (plus loopback)"
    fi
    ALLOWED_IPS_TOML="${ALLOWED_IPS_TOML}]"
    echo "[entrypoint] allowed_ips = ${ALLOWED_IPS_TOML}"

    # Render NOBLE_EXTRA_DATA_DIRS (CSV) into a TOML array.
    #
    # Audit Fix #S2 (0.118): each CSV entry can now carry an optional
    # `:target_gb` suffix to declare Shape B:
    #   /var/lib/noble/warm            → Shape A (auto-detect target)
    #   /var/lib/noble/cold:0          → Shape B, unlimited spillover
    #   /var/lib/noble/warm:4000       → Shape B, 4 TiB cap
    # The last entry MUST be unlimited (S1) unless the operator sets
    # NOBLE_ALLOW_BOUNDED_FINAL_TIER=1.
    #
    # Each directory is mkdir'd here so the node's startup validator
    # sees them as existing absolute paths.
    if [ -z "${NOBLE_EXTRA_DATA_DIRS:-}" ]; then
        EXTRA_DIRS_TOML='[]'
    else
        EXTRA_DIRS_TOML='['
        first=1
        OLD_IFS="$IFS"; IFS=','
        for entry in $NOBLE_EXTRA_DATA_DIRS; do
            entry=$(echo "$entry" | tr -d ' ')
            [ -z "$entry" ] && continue
            # Split on the last colon: `path:size_gb`. No colon → Shape A.
            case "$entry" in
                *:*)
                    d="${entry%:*}"
                    gb="${entry##*:}"
                    # Reject non-numeric gb (operator typo such as
                    # /mnt/data:foo). Empty d is also bogus.
                    if [ -z "$d" ] || ! echo "$gb" | grep -qE '^[0-9]+$'; then
                        echo "[entrypoint] WARN: malformed NOBLE_EXTRA_DATA_DIRS entry '$entry' (expected path or path:gb) — skipping" >&2
                        continue
                    fi
                    mkdir -p "$d"
                    if [ $first -eq 1 ]; then
                        EXTRA_DIRS_TOML="${EXTRA_DIRS_TOML}{ path = \"${d}\", target_gb = ${gb} }"
                        first=0
                    else
                        EXTRA_DIRS_TOML="${EXTRA_DIRS_TOML}, { path = \"${d}\", target_gb = ${gb} }"
                    fi
                    ;;
                *)
                    mkdir -p "$entry"
                    if [ $first -eq 1 ]; then
                        EXTRA_DIRS_TOML="${EXTRA_DIRS_TOML}\"${entry}\""
                        first=0
                    else
                        EXTRA_DIRS_TOML="${EXTRA_DIRS_TOML}, \"${entry}\""
                    fi
                    ;;
            esac
        done
        IFS="$OLD_IFS"
        EXTRA_DIRS_TOML="${EXTRA_DIRS_TOML}]"
        echo "[entrypoint] NOBLE_EXTRA_DATA_DIRS=${NOBLE_EXTRA_DATA_DIRS}"
    fi
    echo "[entrypoint] extra_data_dirs = ${EXTRA_DIRS_TOML}"
    echo "[entrypoint] reconcile_mode  = ${NOBLE_RECONCILE_MODE:-auto}"
    cat > "$NOBLE_CONFIG" <<EOF
# Generated by docker/entrypoint.sh on first boot.
# Edit and restart the container to change. To re-render: delete this file
# (noble-tool reset-chain does NOT delete noble.toml — it preserves config).

[node]
role = "${NOBLE_ROLE:-observer}"

[identity]
node_name = "${NOBLE_NODE_NAME:-noble-docker}"
org_type = "${NOBLE_ORG_TYPE:-Individual}"
org_name = "${NOBLE_ORG_NAME:-}"
contact_email = "${NOBLE_CONTACT_EMAIL:-}"
website = "${NOBLE_WEBSITE:-}"
wants_to_validate = ${NOBLE_WANTS_TO_VALIDATE:-false}
wants_to_vote = ${NOBLE_WANTS_TO_VOTE:-false}

[network]
listen_addr = "/ip4/0.0.0.0/tcp/8780"
seeds = [${NOBLE_SEED_PEERS_TOML:-}]
max_peers = ${NOBLE_MAX_PEERS:-32}

[storage]
data_dir = "${NOBLE_DATA_DIR}"
cache_size_mb = ${NOBLE_CACHE_MB:-256}
compression = ${NOBLE_COMPRESSION:-true}
pruning_mode = "${NOBLE_PRUNING_MODE:-archive}"
keep_blocks = ${NOBLE_KEEP_BLOCKS:-0}
# Multi-path sharding tiers (Phase 7). Each entry can be a path
# string (Shape A — target auto-detected at boot) or a `{ path,
# target_gb }` table (Shape B — explicit per-tier quota).
extra_data_dirs = ${EXTRA_DIRS_TOML}
# Reconciliation behaviour: "auto" (default) | "verify" | "off".
reconcile_mode = "${NOBLE_RECONCILE_MODE:-auto}"

[consensus]
voting_strategy = "${NOBLE_VOTING_STRATEGY:-weighted_probability}"
min_fee_rate = ${NOBLE_MIN_FEE_RATE:-1}

[api]
rpc_addr = "0.0.0.0:8783"
ws_addr = "0.0.0.0:8784"
gui_addr = "0.0.0.0:8785"
# App-layer CIDR allowlist. Set via NOBLE_ALLOWED_IPS (CSV). Empty → localhost.
allowed_ips = ${ALLOWED_IPS_TOML}
tls_enabled = ${NOBLE_TLS_ENABLED:-true}
totp_enabled = ${NOBLE_TOTP_ENABLED:-false}
remote_setup = false

[rewards]
reward_address = "${NOBLE_REWARD_ADDRESS:-}"

[security]
encryption_mode = "${NOBLE_ENCRYPTION_MODE:-automatic}"

[faucet]
discovery_enabled = ${NOBLE_FAUCET_DISCOVERY:-true}
server_enabled = ${NOBLE_FAUCET_SERVER:-false}
server_port = 8786
EOF
    echo "[entrypoint] noble.toml rendered"
else
    echo "[entrypoint] noble.toml exists at $NOBLE_CONFIG — no bootstrap needed"
fi

echo "[entrypoint] starting noble-node run $NOBLE_CONFIG"
exec noble-node run "$NOBLE_CONFIG"
