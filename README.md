# NOBLE

> The peer-to-peer server that powers the **NOBLE** chain — *Neutral Open Blockchain Environment*.

NOBLE is an open protocol for notarizing documents: write a file's SHA-256 checksum to a public, time-ordered chain and prove, later, that the document existed and was not altered. This repository holds the **node software** — the daemon that copies the chain, talks to peers, validates incoming transactions and blocks, and (optionally) helps build the next one — together with its command-line tools, its web dashboard and the client libraries the NOBLE apps are built on.

## What a node does

A NOBLE node connects to other nodes automatically and can take on one or more roles. Each role is opt-in.

- **Observer** — copies the chain and answers queries from wallets and other nodes. The cheapest role to run, and the default.
- **Gateway** — accepts transactions from end-user applications over the wire and broadcasts them into the mempool.
- **Validator** — assembles new blocks from the mempool and proposes them every cycle.
- **Voter** — casts votes that decide which proposed block wins for a given cycle. Often also a validator.

The same binary runs every role; the configuration decides which are active.

## Consensus and cadence

NOBLE uses **Proof of Reputation**, not Proof of Work. Each node keeps its own list of validators it trusts, and every cycle the network votes on which proposed block wins. No mining, no energy race, no specialized hardware. Behave well, reputation grows. Sign something false or go silent at the wrong time, reputation drops, and the rest of the network drifts away.

A cycle is **16 minutes**, split into four 4-minute phases:

1. **Proposal** — validators build and broadcast candidate blocks.
2. **Voting** — first-round votes are cast and collected.
3. **Reflection** — second-round confirmation votes are cast and collected.
4. **Propagation** — the winning block spreads and is committed at the cycle boundary.

At most one block is added per cycle. A block is final once **three more blocks** sit on top of it — about **48 minutes** later. Until then, transactions surface as `pending` → `maturing` → `complete`.

## Network parameters

| | |
|---|---|
| Block time | 16 minutes (4 × 4-min phases) |
| Finality | 3 confirmations (~48 min) |
| Block size | 8 MB |
| Transaction size | 8 KB max |
| Throughput | 6–12 transactions per second, depending on transaction size |
| Document fingerprint | SHA-256 |
| Total supply | 20 800 000 NOBLE |
| Initial block subsidy | 80 NOBLE |
| Halving | every 130 000 blocks (~4 years) |
| Smallest unit | 1 groat = 0.00000001 NOBLE |

## Why run one

- **Light hardware.** The chain fits on a regular disk, and the cycle gives every node ample time to participate honestly without burning power.
- **Permissionless.** Joining is a matter of running the binary and pointing it at a peer. No registration, no whitelist, no gatekeeper.
- **Sovereign.** A node you run is a copy of the chain that no one else can take offline.
- **Earn a subsidy.** Validators that win a cycle receive the block subsidy, paid in NOBLE. Transaction fees are shared between the winning validator and the gateways that relayed them.
- **Bitcoin inspired, ungoverned.** Hard cap, halving schedule, peer-to-peer mesh. No company behind it, no foundation to lobby, no committee with a kill switch.

---

## Install

The build produces three binaries: `noble-node` (the daemon), `noble-tool` (wallet, chain and maintenance utilities) and `noble-faucet` (an optional standalone faucet).

### Homebrew (macOS and Linux)

```sh
brew tap jpelayo/noble https://github.com/jpelayo/noble.git
brew install --HEAD jpelayo/noble/noble
brew services start noble
```

Or, from a checkout of this repository, `brew install --HEAD --formula Formula/noble.rb`.

This installs the binaries, the dashboard, shell completions and a background service (launchd on macOS, systemd on Linux). The dashboard and RPC accept connections from this machine only. To allow a network, pass it at install time:

```sh
brew install --HEAD jpelayo/noble/noble --with-192   # 192.168.0.0/16  home LAN
brew install --HEAD jpelayo/noble/noble --with-10    # 10.0.0.0/8      corporate LAN
brew install --HEAD jpelayo/noble/noble --with-100   # 100.64.0.0/10   Tailscale
```

### Docker

```sh
cd docker
docker compose up -d --build
```

Optional variables, set inline on the same command:

- `NOBLE_ALLOWED_IPS=192.168.0.0/16` — who may reach the dashboard and RPC (default: localhost only).
- `COMPILE_CORES=2` — cap the CPU cores used while compiling. Unset or `0` uses every core.

Behind a reverse proxy such as nginx-proxy-manager, copy `docker/docker-compose.override.yml.npm` to `docker/docker-compose.override.yml`: it keeps only the peer-to-peer port public, turns off the node's own TLS and joins the proxy's `proxy` network. Its header lists every change.

### From source

Requires Rust 1.80 or newer, CMake, pkg-config and OpenSSL 3.

```sh
cargo build --release --bin noble-node --bin noble-tool --bin noble-faucet
```

The binaries land in `target/release/`.

## Configure

All settings live in one TOML file. [`noble.toml`](noble.toml) at the root of this repository is the reference copy with every default; any key you leave out falls back to the same value. Homebrew installs it at `$(brew --prefix)/etc/noble/noble.toml`.

To set up identity, wallet and optional two-factor authentication interactively:

```sh
noble-node setup
```

Or open the dashboard on first start, at `https://127.0.0.1:8785`, and follow the setup screens.

The settings you are most likely to change:

| Section | Key | Purpose |
|---|---|---|
| `[node]` | `role` | `observer` (default) or `validator` |
| `[network]` | `seeds` | peers to contact first |
| `[network]` | `advertised_addr` | the address other nodes should dial back; set it behind NAT, VPN or containers |
| `[api]` | `allowed_ips` | networks allowed to reach the dashboard and RPC |
| `[identity]` | `node_name`, `wants_to_validate`, `wants_to_vote` | how the node presents itself to peers |
| `[rewards]` | `reward_address` | where subsidy and fees are paid |

Anything set under `[identity]` is broadcast to every peer. Use a generic contact address rather than a personal one.

## Run

```sh
noble-node run noble.toml        # start (add --daemon to run in the background)
noble-node status                # height, peers, sync state
noble-node stop
```

Run `noble-node --help` and `noble-tool --help` for every command, including `peers`, `consensus`, `tls-fingerprint`, `wallet`, `chain-info` and `reset-chain`.

## Peer discovery

On start the node dials the addresses in `[network] seeds`, then learns further peers from the ones it reaches. You can add a peer at any time from the dashboard's **Network** page or with the `noble_dialPeer` RPC method; a bare IP such as `192.168.5.20` is read as `/ip4/192.168.5.20/tcp/8780`. Peers on a different chain — one with a different genesis — are recognised and kept apart.

## Validator setup

1. Set `[node] role = "validator"`, plus `wants_to_validate = true` and `wants_to_vote = true` under `[identity]`.
2. Set `[rewards] reward_address` to an address you control.
3. Keep the node online through whole cycles. Reputation grows with honest, steady participation and falls with missed or contradictory votes.

Every node chooses which validators it trusts (the `noble_addValidator` RPC method, or the dashboard's **Consensus** page), so a new validator gains weight as other operators add it to their lists.

## Ports and networking

| Port | Service | Default exposure |
|---|---|---|
| 8780 | Peer-to-peer (libp2p) | all interfaces — the only port that must be reachable from the internet |
| 8783 | JSON-RPC over HTTPS | localhost |
| 8784 | WebSocket subscriptions over WSS | localhost |
| 8785 | Dashboard (HTTPS; proxies `/rpc` and `/ws`) | localhost |
| 8786 | Faucet HTTP | all interfaces; on by default (`[faucet] server_enabled`) |
| 8787 | Prometheus metrics | off |

The node serves a self-signed TLS certificate by default. `noble-node tls-fingerprint` prints its SHA-256 fingerprint, so you can check it before trusting it in a browser.

## RPC reference

JSON-RPC 2.0 over HTTPS on port 8783. Method names start with `noble_`, and every request must carry the header `Gatekeeper: noble`.

```sh
curl -sk https://127.0.0.1:8783 \
  -H 'Content-Type: application/json' -H 'Gatekeeper: noble' \
  -d '{"jsonrpc":"2.0","id":1,"method":"noble_getSyncStatus","params":[]}'
```

Common methods:

| Area | Methods |
|---|---|
| Chain | `noble_getBlockCount`, `noble_getLatestBlock`, `noble_getBlock` |
| Documents | `noble_lookupChecksum`, `noble_verifyDocument` |
| Transactions | `noble_getTransaction`, `noble_submitTransaction`, `noble_estimateFee`, `noble_getMempoolInfo` |
| Network | `noble_getSyncStatus`, `noble_getPeerInfo`, `noble_dialPeer` |
| Consensus | `noble_getCycleStatus`, `noble_getValidatorList` |
| Node | `noble_getNodeInfo` |

Live updates (new blocks, transactions, cycle phases, peer changes) are pushed over WebSocket on port 8784. Browsers reach both through the dashboard on port 8785, which adds the header for them.

## Logs and metrics

The node writes a size-capped, rotating log to the path set in `[logging] file_path` (Homebrew: `$(brew --prefix)/var/log/noble-node.log`) and prints the effective path at startup. Set `[metrics] enabled = true` to expose Prometheus metrics on `127.0.0.1:8787`.

## Repository layout

| Path | Contents |
|---|---|
| `noble-core` | blocks, transactions, addresses, chain constants |
| `noble-codec`, `noble-wire` | the in-house CBOR codec and the frozen wire format |
| `noble-crypto` | keys, signatures, hashing, file encryption |
| `noble-storage` | RocksDB storage and pruning |
| `noble-mempool` | transaction pool and relay policy |
| `noble-consensus` | cycles, voting, reputation, finality |
| `noble-network` | libp2p networking, peer management, sync |
| `noble-api` | JSON-RPC and WebSocket server |
| `noble-node` | the daemon: configuration, setup, healing |
| `noble-wallet` | keystore and transaction builder |
| `noble-tool`, `noble-faucet` | command-line tools and the faucet |
| `noble-gui` | the dashboard (plain HTML, CSS and JavaScript; no build step) |
| `noble-client` | client libraries and the official apps |
| `noble-website` | the project website |
| `fuzz` | fuzzing targets |
| `docker`, `Formula` | container and Homebrew packaging |

## Contributing

Run the test suite before sending changes:

```sh
cargo test --workspace
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
