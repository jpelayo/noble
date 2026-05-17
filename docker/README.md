# Noble — Docker deployment

A Docker mechanism for the Noble blockchain node, alongside (not replacing)
the Homebrew install. Targets the **nginx-proxy-manager** (NPM) edge-proxy
pattern: noble joins a pre-existing external `proxy` network and nginx
reaches it by service name.

## Quick start

```sh
cd docker
cp .env.example .env
$EDITOR .env                                  # set name, reward addr, seed peers
docker compose up -d --build
docker compose logs -f noble                  # watch first-boot config render
docker compose ps                             # status should become "healthy" in ~30s
```

## Topology

```
Public Internet
  ├─ 443/tcp   → nginx-proxy-manager (TLS termination, Let's Encrypt)
  └─ 8780/tcp  → noble (libp2p P2P, direct)

Host
  └─ docker bridge `proxy` (external, shared with nginx)
       ├─ nginx-proxy-manager
       └─ noble (8785 = dashboard + /rpc + /ws proxy)
```

**Only two public ports.** Everything else (RPC 8783, WS 8784, dashboard
8785, faucet 8786) is reachable only from inside the `proxy` docker network,
which nginx is already attached to.

**One nginx upstream is enough**: noble's dashboard at 8785 has built-in
`/rpc → 8783` and `/ws → 8784` reverse proxies. Point nginx at
`http://noble:8785` for everything.

## nginx-proxy-manager setup

### Prerequisites

- nginx-proxy-manager running on the same host, attached to the external
  network named `proxy`.
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
