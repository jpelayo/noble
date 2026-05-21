# Noble — Docker deployment

A Docker mechanism for the Noble blockchain node, alongside (not replacing)
the Homebrew install. The **default layout mirrors `brew install noble`**:
noble serves self-signed TLS directly, with an app-level CIDR allowlist
(`NOBLE_ALLOWED_IPS`). One URL — `https://<server-ip>:8785` — same as brew.

An optional override (`docker-compose.override.yml.npm`) switches to the
nginx-proxy-manager fronting layout for public deployments with a real cert.

## Quick start (brew-mirror default)

```sh
cd docker

# Pick your access pattern (same semantics as brew --with-X flags):
NOBLE_ALLOWED_IPS=192.168.0.0/16  docker compose up -d --build   # home LAN
NOBLE_ALLOWED_IPS=100.64.0.0/10   docker compose up -d --build   # Tailscale
NOBLE_ALLOWED_IPS=10.0.0.0/8      docker compose up -d --build   # corporate
docker compose up -d --build                                     # localhost only

docker compose logs -f noble                  # watch first-boot config render
docker compose ps                             # status should become "healthy" in ~30s

open https://<server-ip>:8785                 # complete GUI wizard
```

Self-signed cert: accept the browser warning once. Same as brew's flow.

### Mapping to brew flags

| Brew | Docker |
|---|---|
| `brew install --HEAD noble --with-192` | `NOBLE_ALLOWED_IPS=192.168.0.0/16` |
| `brew install --HEAD noble --with-100` | `NOBLE_ALLOWED_IPS=100.64.0.0/10` |
| `brew install --HEAD noble --with-10`  | `NOBLE_ALLOWED_IPS=10.0.0.0/8`    |
| `brew install --HEAD noble --with-172` | `NOBLE_ALLOWED_IPS=172.16.0.0/12` |
| `brew install --HEAD noble --localonly` (default) | (unset → 127.0.0.1/32) |

Multiple CIDRs supported as CSV:
`NOBLE_ALLOWED_IPS=192.168.0.0/16,100.64.0.0/10`.

## Topology (default)

```
Public Internet (or LAN / tailnet)
  ├─ 8780/tcp  → noble (libp2p P2P, direct)
  ├─ 8783/tcp  → noble JSON-RPC (HTTPS, self-signed)
  ├─ 8784/tcp  → noble WebSocket (WSS, self-signed)
  ├─ 8785/tcp  → noble Dashboard GUI (HTTPS, self-signed)
  └─ 8786/tcp  → noble Faucet HTTPS (when NOBLE_FAUCET_SERVER=true)

Access control: noble's app-layer CIDR allowlist (NOBLE_ALLOWED_IPS).
TLS: noble's own self-signed cert (regenerated on first boot).
```

Same as brew — single TLS layer, single allowlist, single URL.

## nginx-proxy-manager fronting (opt-in, for public deployments)

This is the "real cert + public DNS" mode. It replaces noble's self-signed
TLS with a Let's Encrypt cert terminated by nginx, and removes the
host-published RPC/WS/GUI/faucet ports (only P2P stays public).

### Activate the override

```sh
cp docker/docker-compose.override.yml.npm docker/docker-compose.override.yml
docker compose up -d --build
```

The override flips `NOBLE_TLS_ENABLED=false`, sets `NOBLE_ALLOWED_IPS` to the
docker bridge range (172.16/12), drops the four GUI/RPC ports, and joins the
external `proxy` network.

### Prerequisites

- nginx-proxy-manager running on the same host, attached to the external
  network named `proxy` (create with `docker network create proxy` if
  needed).
- DNS A record `noble.example.com` → server public IP.
- Host firewall: 443/tcp open (nginx) and 8780/tcp open (P2P).

### Steps

1. **Verify noble is reachable from the `proxy` network** (after `compose up`):
   ```sh
   docker exec -it nginx-proxy-manager curl -fsS \
     -X POST http://noble:8785/rpc \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","method":"noble_getNodeInfo","id":1}'
   ```
   Expect JSON containing `result.version`, `result.chain_id`, etc.

2. **Add a Proxy Host in NPM UI**:
   - **Domain Names**: `noble.example.com`
   - **Scheme**: `http` (NOT https — noble serves plain HTTP inside the network)
   - **Forward Hostname / IP**: `noble`
   - **Forward Port**: `8785`
   - **Cache Assets**: off
   - **Block Common Exploits**: on
   - **Websockets Support**: **ON** ← critical
   - **SSL** tab:
     - Request a new SSL Certificate (Let's Encrypt)
     - Force SSL: on
     - HTTP/2 Support: on
     - HSTS Enabled: on (after end-to-end verification)
   - **Advanced** tab (optional, for large RPC payloads):
     ```
     client_max_body_size 16m;
     proxy_read_timeout 90s;
     proxy_send_timeout 90s;
     ```

3. **Test from the public internet**:
   ```sh
   curl -fsS -X POST https://noble.example.com/rpc \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","method":"noble_getNodeInfo","id":1}'
   # Then open https://noble.example.com/ — dashboard loads with nginx's cert
   ```

4. **(Optional) Faucet host**:
   - Domain: `faucet.example.com` · Scheme: `http` · Host: `noble` · Port: `8786`
   - Websockets Support: off · SSL: same Let's Encrypt flow
   - Requires `NOBLE_FAUCET_SERVER=true` in `.env`.

### Optional Mode B — P2P also through nginx

By default P2P (8780) is host-published, dialed directly by other validators.
If you want nginx to be the single ingress point for everything:

1. Edit `docker-compose.yml` and **remove** the `- "8780:8780"` line.
2. In NPM UI → **Streams** tab → Add Stream:
   - **Incoming Port**: `8780`
   - **Forward Host**: `noble`
   - **Forward Port**: `8780`
   - **TCP Forwarding**: ON · UDP Forwarding: OFF

**Trade-off**: without a PROXY-protocol shim in noble (not yet implemented),
libp2p will see every peer as coming from nginx's IP — peer-IP reputation
and unique-peer counts collapse. Acceptable for casual deployment, **not
recommended for production validators**.

## Tailscale-only admin port (optional)

To reach the dashboard directly via tailnet for local debugging without
nginx, edit `docker-compose.yml`:

```yaml
    ports:
      - "8780:8780"
      - "100.x.x.x:8785:8785"   # bind to your Tailscale interface IP only
```

Replace `100.x.x.x` with the host's Tailscale IP. Do **not** bind to
`0.0.0.0` — that exposes the dashboard publicly, bypassing nginx and
inviting SSL confusion.

## Faucet as a separate sidecar (advanced, optional)

By default the faucet runs **inside** noble-node when
`NOBLE_FAUCET_SERVER=true` — same process, same data dir, no
cross-process secrets. The recipes above assume that mode.

If you want the faucet as a **separate container** (e.g. different
resource limits, restart policy, or scaling), give the faucet container
read access to the node's data dir and point it at the node via
`NOBLE_NODE_DATA_DIR`. The faucet then reads chain_meta, its
passphrase, and the admin bearer directly from the node's keystore on
disk — zero RPC handoff for secrets.

Add a second service alongside `noble:` in `docker-compose.yml`:

```yaml
  faucet:
    image: noble:latest
    container_name: noble-faucet
    restart: unless-stopped
    depends_on:
      noble:
        condition: service_healthy
    command: ["noble-faucet", "--listen", "0.0.0.0:8786", "--rpc-url", "https://noble:8783"]
    environment:
      # Local-FS secret bootstrap — read chain_meta + passphrase + admin
      # token directly from the node's on-disk keystore. Tighter than the
      # legacy RPC-based handoff; no secret crosses the wire.
      NOBLE_NODE_DATA_DIR: /var/lib/noble
    volumes:
      # Read-only mount of the node's data dir. The keystore + chain_meta
      # files are already chmod 0600 on the host side.
      - noble-data:/var/lib/noble:ro
      # Faucet keeps its own writable dir for its signing wallet + DB.
      - faucet-data:/var/lib/noble-faucet
    networks:
      - default
      - proxy
```

And add the new volume next to `noble-data`:

```yaml
volumes:
  noble-data:
    name: noble-data
  faucet-data:
    name: faucet-data
```

**Why this is better than legacy RPC handoff**:
- Secrets never traverse the loopback HTTPS port — they're read from
  files the node already protects with `0600` permissions.
- Admin token rotation propagates within ~60 s via filesystem mtime
  watch (no extra RPC traffic).
- Faucet refuses to operate as an unauthenticated admin surface even
  if the node briefly becomes unreachable.

**Operational requirement**: the faucet container must run as a UID
that can read the node's `keystore.noble` and `.chain_meta` (both
chmod 0600, owned by the node's user). Both containers use UID 10000
in the noble image, so the read-only mount works out of the box.

**Legacy mode** (without `NOBLE_NODE_DATA_DIR`): the faucet falls back
to the RPC handoff and logs a one-time `task = "faucet_secrets"` WARN
on boot. Continues to work; you just lose the secret-on-the-wire
hardening. The RPC path will be removed in a future release —
consider this the migration window.

## Operational one-shots

The entrypoint recognises these as the first argument:

```sh
# Wipe RocksDB but preserve keys/identity/TLS (clean re-sync)
docker compose run --rm noble reset-chain

# Run codec self-checks (boot-time sanity)
docker compose run --rm noble verify

# Drop into a shell inside the container
docker compose run --rm noble shell

# Any other binary directly (power-user override)
docker compose run --rm noble noble-tool --version
```

## Environment variables

Full list in `.env.example`. Categories:

- **Identity**: `NOBLE_NODE_NAME`, `NOBLE_ORG_TYPE`, `NOBLE_ORG_NAME`,
  `NOBLE_CONTACT_EMAIL`, `NOBLE_WEBSITE`, `NOBLE_WANTS_TO_VALIDATE`,
  `NOBLE_WANTS_TO_VOTE`
- **Role**: `NOBLE_ROLE` (Observer / Validator / BlockProducer / Voter /
  ArchiveNode / Gateway / VotingGateway / LightClient)
- **Network**: `NOBLE_SEED_PEERS_TOML` (quoted TOML CSV), `NOBLE_MAX_PEERS`
- **Rewards**: `NOBLE_REWARD_ADDRESS`
- **Storage**: `NOBLE_PRUNING_MODE`, `NOBLE_KEEP_BLOCKS`, `NOBLE_CACHE_MB`,
  `NOBLE_COMPRESSION`
- **Consensus**: `NOBLE_VOTING_STRATEGY`, `NOBLE_MIN_FEE_RATE`
- **TLS / Auth**: `NOBLE_TLS_ENABLED` (false → nginx terminates),
  `NOBLE_TOTP_ENABLED`, `NOBLE_ENCRYPTION_MODE`
- **Faucet**: `NOBLE_FAUCET_DISCOVERY`, `NOBLE_FAUCET_SERVER`

Config is rendered on first boot and persists in the named volume. To
re-render, delete `/var/lib/noble/noble.toml` inside the container (the
volume keeps everything else; or use `reset-chain` to also wipe RocksDB).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker compose up` fails: `network proxy not found` | NPM not running, or `proxy` network has a different name | Start NPM, or rename the network: `docker network create proxy` |
| Healthcheck stays "starting" past 30s | First-boot keystore generation took longer than `start-period` | `docker compose logs noble` and wait; raise `start-period` if persistent |
| nginx 502 Bad Gateway | NPM used `https://` upstream (proxy_pass tried to verify self-signed cert) | Switch Scheme to `http` in NPM Proxy Host |
| WebSocket fails with 426 / 400 | NPM "Websockets Support" toggle off | Toggle it on; save; reload |
| Dashboard "Mixed Content" warning | Browser loaded `https://` page but JS tried `http://` for RPC | Re-check Proxy Host SSL config; ensure noble's `/rpc` is used (relative path) not an absolute http URL |
| Peer count stays at 0 | Port 8780 not actually reachable from internet | `nc -vz <server-ip> 8780` from outside; check host firewall |
| RocksDB lock error on boot | Brew service also running on the same data dir | `brew services stop noble`; or use a different `NOBLE_DATA_DIR` |
| `Permission denied` on volume | Host bind-mount with mismatched UID | Container runs as UID 10000; either `chown -R 10000:10000 <host-dir>` or use the named volume default |

## Coexistence with Homebrew install

The brew formula and this Docker image are independent. They install the
same binary into different namespaces (`/opt/homebrew/bin` vs the image's
`/usr/local/bin`). Only one can run at a time on the same host because
both want port 8780 and the same data dir lock — but switching between
them is just:

```sh
brew services stop noble && docker compose up -d
# or
docker compose down && brew services start noble
```

Each keeps its own data dir; no cross-contamination.
