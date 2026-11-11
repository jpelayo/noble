# NOBLE

NOBLE (Neutral Open Blockchain Environment) is an open protocol for notarizing documents. A document's SHA-256 checksum is written to a public, time-ordered chain, which later proves that the document existed at that time and has not been altered.

This repository contains the NOBLE node: the daemon that keeps a copy of the chain, exchanges data with peers, validates transactions and blocks, and can take part in producing new blocks. It also contains the command-line tools, the web dashboard and the client libraries used by the NOBLE apps.

## Node roles

A node connects to other nodes automatically. Every role is opt-in, and a single binary runs all of them. The configuration decides which roles are active.

| Role | What it does |
|---|---|
| Observer | Keeps a copy of the chain and answers queries from wallets and other nodes. This is the default and the least demanding role. |
| Gateway | Accepts transactions from end-user applications and relays them to the network. |
| Validator | Builds blocks from pending transactions and proposes one every cycle. |
| Voter | Votes on which proposed block wins each cycle. A voter is usually also a validator. |

## Consensus

NOBLE uses Proof of Reputation instead of Proof of Work. There is no mining and no specialized hardware. Each node keeps its own list of validators it trusts, and every cycle the network votes on which proposed block wins. Validators that behave honestly gain reputation. Validators that sign false data or fall silent at the wrong time lose it, and the network stops relying on them.

Each cycle lasts 16 minutes and is divided into four phases of 4 minutes:

| Phase | What happens |
|---|---|
| 1. Proposal | Validators build and broadcast candidate blocks. |
| 2. Voting | First-round votes are cast and collected. |
| 3. Reflection | Second-round confirmation votes are cast and collected. |
| 4. Propagation | The winning block reaches every node and is committed at the end of the cycle. |

At most one block is added per cycle. A block becomes final when three more blocks have been added on top of it, about 48 minutes later. A transaction is reported as `pending` while it waits to be included, `maturing` once it is in a block, and `complete` once that block is final.

## Network parameters

| Parameter | Value |
|---|---|
| Block time | 16 minutes (four phases of 4 minutes) |
| Finality | 3 confirmations, about 48 minutes |
| Maximum block size | 8 MB |
| Maximum transaction size | 8 KB |
| Throughput | 6 to 12 transactions per second, depending on transaction size |
| Document fingerprint | SHA-256 |
| Total supply | 20 800 000 NOBLE |
| Initial block subsidy | 80 NOBLE |
| Halving | Every 130 000 blocks, about 4 years |
| Smallest unit | 1 groat = 0.00000001 NOBLE |

## Why run a node

- **Modest hardware.** The chain fits on an ordinary disk, and the 16-minute cycle gives every node ample time to take part without wasting energy.
- **Permissionless.** Run the binary and point it at a peer. There is no registration and no whitelist.
- **Independent.** Your node holds a full copy of the chain that nobody else can take offline.
- **Rewards.** The validator whose block wins a cycle receives the block subsidy in NOBLE. Transaction fees are shared between that validator and the gateways that relayed the transactions.
- **Inspired by Bitcoin, ungoverned.** A hard cap, a halving schedule and a peer-to-peer network. No company behind it, no foundation to lobby and no committee that can shut it down.

## Installation

The build produces three binaries:

| Binary | Purpose |
|---|---|
| `noble-node` | The node daemon. |
| `noble-tool` | Wallet, chain and maintenance commands. |
| `noble-faucet` | An optional standalone faucet. |

### Homebrew (macOS and Linux)

```sh
brew tap jpelayo/noble https://github.com/jpelayo/noble.git
brew install --HEAD jpelayo/noble/noble
brew services start noble
```

To install from a local checkout instead, run `brew install --HEAD --formula Formula/noble.rb`.

Homebrew installs the binaries, the dashboard, shell completions and a background service (launchd on macOS, systemd on Linux). By default the dashboard and the RPC accept connections only from the same machine. To allow a network, add an option at install time:

```sh
brew install --HEAD jpelayo/noble/noble --with-192   # 192.168.0.0/16, home LAN
brew install --HEAD jpelayo/noble/noble --with-10    # 10.0.0.0/8, corporate LAN
brew install --HEAD jpelayo/noble/noble --with-100   # 100.64.0.0/10, Tailscale
```

### Docker

```sh
cd docker
docker compose up -d --build
```

Two optional variables can be set on the same command line:

| Variable | Effect |
|---|---|
| `NOBLE_ALLOWED_IPS=192.168.0.0/16` | Networks allowed to reach the dashboard and the RPC. Without it, only localhost is allowed. |
| `COMPILE_CORES=2` | Limits the CPU cores used during compilation. Unset or `0` uses all cores. |

To run behind a reverse proxy such as nginx-proxy-manager, copy `docker/docker-compose.override.yml.npm` to `docker/docker-compose.override.yml`. The override keeps only the peer-to-peer port public, disables the node's own TLS and attaches the container to the external `proxy` network. Its header describes each change.

### From source

Requirements: Rust 1.80 or newer, CMake, pkg-config and OpenSSL 3.

```sh
cargo build --release --bin noble-node --bin noble-tool --bin noble-faucet
```

The binaries are written to `target/release/`.

## Configuration

All settings are in a single TOML file. The [`noble.toml`](noble.toml) file at the root of this repository lists every setting with its default value, and any setting left out of your own file takes that default. Homebrew installs the configuration at `$(brew --prefix)/etc/noble/noble.toml`.

To configure the node identity, the wallet and optional two-factor authentication interactively, run:

```sh
noble-node setup
```

Alternatively, start the node and open the dashboard at `https://127.0.0.1:8785`, which guides you through the same steps.

The most commonly changed settings:

| Section | Setting | Purpose |
|---|---|---|
| `[node]` | `role` | `observer` (default) or `validator`. |
| `[network]` | `seeds` | Peers to contact at startup. |
| `[network]` | `advertised_addr` | The address other nodes use to reach this one. Set it when the node runs behind NAT, a VPN or a container. |
| `[api]` | `allowed_ips` | Networks allowed to reach the dashboard and the RPC. |
| `[identity]` | `node_name`, `wants_to_validate`, `wants_to_vote` | How the node presents itself to peers. |
| `[rewards]` | `reward_address` | The address that receives subsidies and fees. |

Everything under `[identity]` is broadcast to all peers, so use a generic contact address rather than a personal one.

## Running the node

```sh
noble-node run noble.toml    # start in the foreground; add --daemon to run in the background
noble-node status            # show height, peers and sync state
noble-node stop              # stop a running node
```

`noble-node --help` and `noble-tool --help` list all commands, including `peers`, `consensus`, `tls-fingerprint`, `wallet`, `chain-info` and `reset-chain`.

## Peer discovery

At startup the node connects to the addresses listed in `[network] seeds` and learns about further peers from them. You can add a peer at any time on the dashboard's Network page or with the `noble_dialPeer` RPC method. A bare IP address such as `192.168.5.20` is interpreted as `/ip4/192.168.5.20/tcp/8780`. Peers that belong to a different chain, meaning one with a different genesis block, are detected and kept separate.

## Becoming a validator

1. In the configuration, set `role = "validator"` under `[node]`, and set `wants_to_validate = true` and `wants_to_vote = true` under `[identity]`.
2. Set `reward_address` under `[rewards]` to an address you control.
3. Keep the node online for complete cycles. Reputation increases with steady, honest participation and decreases with missed or contradictory votes.

Each node decides which validators it trusts, using the dashboard's Consensus page or the `noble_addValidator` RPC method. A new validator gains weight as other operators add it to their lists.

## Ports

| Port | Service | Default exposure |
|---|---|---|
| 8780 | Peer-to-peer (libp2p) | All interfaces. This is the only port that must be reachable from the internet. |
| 8783 | JSON-RPC over HTTPS | Localhost only. |
| 8784 | WebSocket subscriptions over WSS | Localhost only. |
| 8785 | Dashboard over HTTPS, which also serves `/rpc` and `/ws` | Localhost only. |
| 8786 | Faucet over HTTP | All interfaces. Enabled by default (`[faucet] server_enabled`). |
| 8787 | Prometheus metrics | Disabled. |

The node uses a self-signed TLS certificate by default. Run `noble-node tls-fingerprint` to print its SHA-256 fingerprint and compare it with the one your browser shows.

## RPC

The node exposes JSON-RPC 2.0 over HTTPS on port 8783. Method names begin with `noble_`, and every request must include the header `Gatekeeper: noble`.

```sh
curl -sk https://127.0.0.1:8783 \
  -H 'Content-Type: application/json' \
  -H 'Gatekeeper: noble' \
  -d '{"jsonrpc":"2.0","id":1,"method":"noble_getSyncStatus","params":[]}'
```

Frequently used methods:

| Area | Methods |
|---|---|
| Chain | `noble_getBlockCount`, `noble_getLatestBlock`, `noble_getBlock` |
| Documents | `noble_lookupChecksum`, `noble_verifyDocument` |
| Transactions | `noble_getTransaction`, `noble_submitTransaction`, `noble_estimateFee`, `noble_getMempoolInfo` |
| Network | `noble_getSyncStatus`, `noble_getPeerInfo`, `noble_dialPeer` |
| Consensus | `noble_getCycleStatus`, `noble_getValidatorList` |
| Node | `noble_getNodeInfo` |

Real-time events (new blocks, new transactions, cycle phases and peer changes) are published over WebSocket on port 8784. Browsers reach both services through the dashboard on port 8785, which adds the required header.

## Logs and metrics

The node writes a rotating, size-limited log to the path set in `[logging] file_path` and prints that path at startup. With Homebrew, the log is at `$(brew --prefix)/var/log/noble-node.log`. To expose Prometheus metrics on `127.0.0.1:8787`, set `enabled = true` under `[metrics]`.

## Repository layout

| Path | Contents |
|---|---|
| `noble-core` | Blocks, transactions, addresses and chain constants. |
| `noble-codec`, `noble-wire` | The CBOR codec and the frozen wire format. |
| `noble-crypto` | Keys, signatures, hashing and file encryption. |
| `noble-storage` | RocksDB storage and pruning. |
| `noble-mempool` | Transaction pool and relay policy. |
| `noble-consensus` | Cycles, voting, reputation and finality. |
| `noble-network` | libp2p networking, peer management and synchronization. |
| `noble-api` | JSON-RPC and WebSocket server. |
| `noble-node` | The node daemon: configuration, setup and chain recovery. |
| `noble-wallet` | Keystore and transaction builder. |
| `noble-tool`, `noble-faucet` | Command-line tools and the faucet. |
| `noble-gui` | The dashboard, written in plain HTML, CSS and JavaScript with no build step. |
| `noble-client` | Client libraries and the official apps. |
| `noble-website` | The project website. |
| `fuzz` | Fuzzing targets. |
| `docker`, `Formula` | Docker and Homebrew packaging. |

## Contributing

Run the full test suite before submitting changes:

```sh
cargo test --workspace
```

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
