/**
 * NOBLE Dashboard — Mock RPC & WebSocket Layer
 *
 * JSON shapes exactly match serde serialization of Rust types.
 * When noble-api is built, swap imports in app.js — zero other changes needed.
 *
 * Type alignment:
 *   Hash256        → 64-char hex string
 *   NoblePublicKey → { "Ed25519": [u8; 32] } or { "Secp256k1": [u8; 33] }
 *   SignatureEnvelope → { scheme_id: u8, public_key: [u8], signature: [u8] }
 *   scheme_id: 0x00 = Ed25519, 0x01 = secp256k1
 */

// ── Constants ──
// Mock chain ID — real value is derived from the genesis block hash at runtime.
const MOCK_CHAIN_ID = 0x4E4F424C;
const CYCLE_DURATION_SECS = 1200;
const MIN_TX_FEE = 1000;
const PROTOCOL_VERSION = 1;
const GENESIS_TIMESTAMP = 1700000000;

// ── Helpers ──

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomBytes(len) {
  return Array.from(crypto.getRandomValues(new Uint8Array(len)));
}

function bytesToHexLocal(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hashFromHeight(height) {
  // Deterministic hash based on height for reproducibility
  const base = height.toString(16).padStart(8, '0');
  return (base + randomHex(28)).slice(0, 64);
}

function deterministicHash(seed) {
  let hash = '';
  for (let i = 0; i < 64; i++) {
    hash += ((seed * 7 + i * 13) % 16).toString(16);
  }
  return hash;
}

function makePublicKey(seed) {
  const bytes = [];
  for (let i = 0; i < 32; i++) bytes.push((seed * 3 + i * 7) % 256);
  // Real API returns nbl1q… bech32 string for Ed25519 keys.
  // Mock produces a fake nbl1q… string from the deterministic bytes.
  const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  return 'nbl1q' + hex;
}

function makeSignatureEnvelope(seed) {
  const pubKey = [];
  for (let i = 0; i < 32; i++) pubKey.push((seed * 5 + i * 11) % 256);
  const sig = [];
  for (let i = 0; i < 64; i++) sig.push((seed * 7 + i * 3) % 256);
  return {
    scheme_id: 0x00, // Ed25519
    public_key: pubKey,
    signature: sig,
  };
}

function makeMetadataEntry(docType) {
  return {
    key: 'doc_type',
    value: Array.from(new TextEncoder().encode(docType)),
  };
}

/** Build a schema-described metadata set (slot 0 = schema descriptor). */
function makeSchemaMetadata(seed) {
  const templates = [
    // Template A: public description + public URL
    {
      schema: '0:pub:utf8:opt:schema\n1:pub:utf8:opt:description\n2:pub:utf8:opt:doc_url',
      slots: [
        { key: 'description', value: `Certificate of Completion — Course ${seed % 100}` },
        { key: 'doc_url', value: `https://docs.example.com/certs/${seed}.pdf` },
      ],
    },
    // Template B: description + DER cert + encrypted URL
    {
      schema: '0:pub:utf8:opt:schema\n1:pub:b64:opt:description\n2:pub:der:opt:cert_pubkey\n3:priv:ecies:opt:doc_url_enc',
      slots: [
        { key: 'description', value: btoa(`Notarized contract #${seed}`) },
        { key: 'cert_pubkey', value: 'der-placeholder' },
        { key: 'doc_url_enc', value: 'ecies-placeholder' },
      ],
    },
    // Template C: multiple public + hex field
    {
      schema: '0:pub:utf8:opt:schema\n1:pub:utf8:opt:title\n2:pub:utf8:opt:issuer\n3:pub:hex:opt:fingerprint',
      slots: [
        { key: 'title', value: `Patent Application ${2024 + (seed % 5)}-${seed % 10000}` },
        { key: 'issuer', value: ['WIPO', 'USPTO', 'EPO', 'CNIPA'][seed % 4] },
        { key: 'fingerprint', value: 'hex-placeholder' },
      ],
    },
  ];

  const tpl = templates[seed % templates.length];
  const enc = new TextEncoder();

  // Slot 0: schema descriptor (always UTF-8 bytes → byte array)
  const entries = [
    { key: 'schema', value: Array.from(enc.encode(tpl.schema)) },
  ];

  for (const slot of tpl.slots) {
    let value;
    if (slot.value === 'der-placeholder') {
      // Mock DER: 128 random-looking bytes
      value = [];
      for (let i = 0; i < 128; i++) value.push((seed * 7 + i * 13) % 256);
    } else if (slot.value === 'ecies-placeholder') {
      // Mock encrypted: 64 random-looking bytes
      value = [];
      for (let i = 0; i < 64; i++) value.push((seed * 11 + i * 3) % 256);
    } else if (slot.value === 'hex-placeholder') {
      // Mock hex fingerprint: 32 bytes
      value = [];
      for (let i = 0; i < 32; i++) value.push((seed * 5 + i * 17) % 256);
    } else {
      value = Array.from(enc.encode(slot.value));
    }
    entries.push({ key: slot.key, value });
  }

  return entries;
}

function makeTransaction(seed, timestamp) {
  const fee = MIN_TX_FEE + Math.floor(Math.abs(Math.sin(seed)) * 50000);

  // ~15% of transactions use schema-described metadata
  let metadata;
  if (seed % 7 === 0) {
    metadata = makeSchemaMetadata(seed);
  } else {
    const docTypes = ['certificate', 'diploma', 'contract', 'invoice', 'receipt', 'deed', 'license', 'patent'];
    metadata = [makeMetadataEntry(docTypes[seed % docTypes.length])];

    if (seed % 3 === 0) {
      metadata.push({
        key: 'issuer',
        value: Array.from(new TextEncoder().encode(`org-${seed % 100}`)),
      });
    }
  }

  // ~20% of transactions have encrypted locators
  const hasLocator = seed % 5 === 0;
  // ~10% have external attestations
  const hasAttestations = seed % 10 === 0;

  const attestations = hasAttestations ? [{
    scheme: ['pkcs7', 'smime', 'pgp', 'x509'][seed % 4],
    scope: ['hash', 'locator', 'both'][seed % 3],
    signer_fingerprint: deterministicHash(seed * 43),
    signature_size: 128 + (seed % 384),
  }] : [];

  // ~30% have a gateway address (fee split: 50% to gateway node)
  const hasGateway = seed % 3 === 0;
  const gateway_address = hasGateway ? deterministicHash(seed * 59).slice(0, 66) : null;

  // UTXO model: outputs with value + address, inputs referencing prior UTXOs
  const outputValue = fee + 500_000 + Math.floor(Math.abs(Math.cos(seed)) * 5_000_000);
  const changeValue = Math.floor(Math.abs(Math.sin(seed * 3)) * 200_000);
  const totalOutput = outputValue + changeValue;

  const outputs = [
    { value: outputValue, address: deterministicHash(seed * 61).slice(0, 40) },
  ];
  if (changeValue > 0) {
    outputs.push({ value: changeValue, address: deterministicHash(seed * 63).slice(0, 40) });
  }

  const inputs = [
    { txid: deterministicHash(seed * 71), vout: seed % 4 },
  ];
  if (seed % 5 === 0) {
    inputs.push({ txid: deterministicHash(seed * 73), vout: (seed + 1) % 3 });
  }

  // signer = hex-encoded public key (matches real API TransactionResponse.signer)
  const sigEnv = makeSignatureEnvelope(seed);
  const signerHex = bytesToHexLocal(sigEnv.public_key);

  return {
    tx_type: 0x00, // notarization (matches real API)
    checksum: deterministicHash(seed * 17),
    timestamp,
    total_output: totalOutput,
    inputs,
    outputs,
    signer: signerHex,
    signer_name: null, // populated by backend name resolver in production
    publisher_sig: sigEnv, // kept for backward compat with legacy GUI paths
    additional_sigs: seed % 4 === 0 ? [makeSignatureEnvelope(seed + 1000)] : [],
    metadata,
    has_encrypted_locator: hasLocator,
    locator_recipient_count: hasLocator ? 1 + (seed % 3) : 0,
    attestation_count: attestations.length,
    attestations,
    gateway_address,
  };
}

function makeBlockHeader(height, prevHash, txCount, timestamp, validatorSeed) {
  return {
    version: PROTOCOL_VERSION,
    prev_block_hash: prevHash,
    merkle_root: deterministicHash(height * 31),
    timestamp,
    height,
    tx_count: txCount,
    validator_id: makePublicKey(validatorSeed),
    validator_name: 'Mock Validator',
    validator_sig: makeSignatureEnvelope(validatorSeed + height),
  };
}

// ── Mock Validators (PoR reputation model) ──
// R(V) = 0.4 * B(V) + 0.3 * U(V) + 0.3 * T(V)
//   B(V) = block_acceptance_rate (accepted / cycles_active)
//   U(V) = uptime (reachable / total_cycles)
//   T(V) = trust_score (avg reputation of nodes listing this validator)

const VALIDATOR_NAMES = [
  'noble-alpha', 'noble-beta', 'noble-gamma', 'noble-delta', 'noble-epsilon',
  'noble-zeta', 'noble-eta', 'noble-theta', 'noble-iota', 'noble-kappa',
  'noble-lambda', 'noble-mu', 'noble-nu', 'noble-xi', 'noble-omicron',
];

const VALIDATORS = Array.from({ length: 15 }, (_, i) => {
  const blockAcceptanceRate = Math.max(0.15, 0.97 - i * 0.045 + (Math.sin(i) * 0.03));
  const uptime = Math.max(0.20, 0.99 - i * 0.04 + (Math.cos(i) * 0.02));
  const trustScore = Math.max(0.10, 0.88 - i * 0.05 + (Math.sin(i * 2) * 0.04));
  const reputation = 0.4 * blockAcceptanceRate + 0.3 * uptime + 0.3 * trustScore;
  const cyclesActive = 1000 - i * 50 + Math.floor(Math.abs(Math.sin(i)) * 100);
  const blocksAccepted = Math.floor(cyclesActive * blockAcceptanceRate);
  const totalCycles = 1000;
  const cyclesReachable = Math.floor(totalCycles * uptime);
  const isOnline = i < 12; // last 3 are offline
  const now = Math.floor(Date.now() / 1000);

  const MOCK_IPS = [
    '/ip4/203.0.113.1/tcp/8780', '/ip4/198.51.100.2/tcp/8780', '/ip4/52.1.100.50/tcp/8780',
    '/ip4/18.4.86.10/tcp/8780', '/ip4/85.91.200.12/tcp/8780', '/ip4/192.0.2.55/tcp/8780',
    '/ip4/10.0.0.1/tcp/8780', '/ip4/172.16.0.1/tcp/8780', '/ip4/100.64.0.1/tcp/8780',
    '/ip4/198.18.0.1/tcp/8780', '/ip4/203.0.113.42/tcp/8780', '/ip4/198.51.100.7/tcp/8780',
    '/ip4/192.0.2.100/tcp/8780', '/ip4/203.0.113.200/tcp/8780', '/ip4/198.51.100.99/tcp/8780',
  ];
  const MOCK_COUNTRIES = ['USA', 'GBR', 'DEU', 'JPN', 'ESP', 'FRA', 'CHE', 'CAN', 'AUS', 'NLD', 'ITA', 'BRA', 'KOR', 'SGP', 'NOR'];

  return {
    public_key: makePublicKey(i * 100),
    name: VALIDATOR_NAMES[i],
    host_address: MOCK_IPS[i] || null,
    country_code: MOCK_COUNTRIES[i] || null,
    status: isOnline ? 'alive' : 'unreachable',
    reputation_score: parseFloat(reputation.toFixed(4)),
    reputation_breakdown: {
      block_acceptance_rate: parseFloat(blockAcceptanceRate.toFixed(4)),
      uptime: parseFloat(uptime.toFixed(4)),
      trust_score: parseFloat(trustScore.toFixed(4)),
    },
    blocks_produced: blocksAccepted,
    blocks_accepted: blocksAccepted,
    cycles_active: cyclesActive,
    cycles_reachable: cyclesReachable,
    total_cycles: totalCycles,
    listers_count: 15 - i + Math.floor(Math.abs(Math.sin(i * 3)) * 5),
    joined_cycle: Math.floor((now - (200 - i * 12) * CYCLE_DURATION_SECS) / CYCLE_DURATION_SECS),
    last_active: isOnline ? now - i * 120 : now - 86400 * (i - 11),
    proposed_this_cycle: isOnline && i < 5,
    wants_to_validate: true,
  };
});

// ── Mock Peers ──

const PEER_IDS = Array.from({ length: 23 }, (_, i) =>
  `12D3KooW${randomHex(16).slice(0, 20)}${i.toString().padStart(2, '0')}`
);

const MOCK_NODE_NAMES = [
  'noble-eu-west-1', 'noble-us-east-2', 'berlin-validator', 'tokyo-relay',
  'noble-ap-south', 'zurich-node', 'paris-witness', 'sydney-full',
  null, null, null, 'london-archive', 'noble-ca-central', null,
  'singapore-relay', 'mumbai-validator', null, null,
  'sao-paulo-node', null, null, 'nyc-node', 'oslo-watcher',
];

const MOCK_COUNTRIES = [
  'DEU', 'USA', 'DEU', 'JPN', 'IND', 'CHE', 'FRA', 'AUS',
  'GBR', 'CAN', null, 'GBR', 'CAN', null,
  'SGP', 'IND', null, 'BRA',
  'BRA', null, null, 'USA', 'NOR',
];

function makePeers(chainHeight) {
  const BAN_REASONS = [
    { category: 'InvalidTransaction', subject: 'failed T8: metadata key too long (128 chars max)' },
    { category: 'ProtocolViolation', subject: 'chain_id mismatch: expected 1, got 42' },
    { category: 'DuplicateProposal', subject: 'double proposal (evidence verified): height 42' },
    { category: 'InvalidVote', subject: 'vote equivocation (evidence verified) in round 1' },
  ];
  return PEER_IDS.map((peerId, i) => {
    const banScore = i === 22 ? 15 : i === 21 ? 5 : 0;
    const octet = 10 + i;
    return {
      peer_id: peerId,
      direction: i < 8 ? 'Outbound' : 'Inbound',
      addr: `/ip4/203.0.113.${octet}/tcp/8780`,
      node_name: MOCK_NODE_NAMES[i] || null,
      country_code: MOCK_COUNTRIES[i] || null,
      connected_at: Math.floor(Date.now() / 1000) - (3600 + i * 120),
      ban_score: banScore,
      misbehavior_categories: banScore > 0 ? [BAN_REASONS[i % BAN_REASONS.length].category] : [],
      last_ban_reason: banScore > 0 ? BAN_REASONS[i % BAN_REASONS.length] : null,
    };
  });
}

// ── Generate Linked Chain ──

function generateChain(numBlocks) {
  const blocks = [];
  const txIndex = new Map();    // tx_id → { block_height, tx }
  const checksumIndex = new Map(); // checksum → [{ block_height, tx_id, timestamp }]
  const versionChainIndex = new Map(); // prev_checksum → [successor_tx_id]
  const publisherIndex = new Map(); // signerHex → [{ tx_id, checksum, block_height, timestamp, version }]

  let prevHash = '0'.repeat(64); // genesis prev_block_hash

  // Collect checksums for version chain linking (populated in first pass)
  const allChecksums = [];

  for (let h = 0; h < numBlocks; h++) {
    const timestamp = GENESIS_TIMESTAMP + h * CYCLE_DURATION_SECS;
    const txCount = 1 + Math.floor(Math.abs(Math.sin(h * 0.7)) * 15);
    const validatorSeed = (h % VALIDATORS.length) * 100;

    const transactions = [];
    for (let t = 0; t < txCount; t++) {
      const tx = makeTransaction(h * 100 + t, timestamp - 60 + t);

      // ~10% of notarization txs (h > 10) are versioned docs referencing an earlier checksum
      let version = null;
      let prevChecksum = null;
      if (h > 10 && t % 10 === 3 && allChecksums.length > 5) {
        // Pick a deterministic earlier checksum as prev_checksum
        const prevIdx = (h * 7 + t * 3) % allChecksums.length;
        prevChecksum = allChecksums[prevIdx];
        version = 2 + (h % 5); // versions 2-6
        tx.metadata.push(
          { key: 'doc:prev_checksum', value: Array.from(new TextEncoder().encode(prevChecksum)) },
          { key: 'doc:version', value: Array.from(new TextEncoder().encode(String(version))) },
        );
      }

      transactions.push(tx);

      const txId = deterministicHash((h * 100 + t) * 23);
      txIndex.set(txId, { block_height: h, tx, tx_id: txId });

      if (!checksumIndex.has(tx.checksum)) checksumIndex.set(tx.checksum, []);
      checksumIndex.get(tx.checksum).push({
        block_height: h,
        tx_id: txId,
        timestamp: tx.timestamp,
        has_encrypted_locator: tx.has_encrypted_locator,
        locator_recipient_count: tx.locator_recipient_count,
        attestation_count: tx.attestation_count,
        attestations: tx.attestations,
        version,
        prev_checksum: prevChecksum,
      });

      // Build version chain index
      if (prevChecksum) {
        if (!versionChainIndex.has(prevChecksum)) versionChainIndex.set(prevChecksum, []);
        versionChainIndex.get(prevChecksum).push(txId);
      }

      // Build publisher index (notarization txs only, tx_type=0)
      if (tx.tx_type === 0) {
        const signerHex = bytesToHexLocal(tx.publisher_sig.public_key);
        if (!publisherIndex.has(signerHex)) publisherIndex.set(signerHex, []);
        publisherIndex.get(signerHex).push({
          tx_id: txId,
          checksum: tx.checksum,
          block_height: h,
          timestamp: tx.timestamp,
          version,
        });
      }

      allChecksums.push(tx.checksum);
    }

    const header = makeBlockHeader(h, prevHash, txCount, timestamp, validatorSeed);
    const blockHash = deterministicHash(h * 41);
    blocks.push({ header, transactions, _hash: blockHash });

    prevHash = blockHash;
  }

  return { blocks, txIndex, checksumIndex, versionChainIndex, publisherIndex };
}

// ── Generate Mock Mempool ──

function generateMempool(count, chainHeight) {
  const now = Math.floor(Date.now() / 1000);
  const entries = [];
  for (let i = 0; i < count; i++) {
    const seed = chainHeight * 1000 + i;
    const tx = makeTransaction(seed, now - Math.floor(Math.random() * 300));
    // Mempool computes fee from UTXO lookups (implicit in UTXO model)
    const mempoolFee = MIN_TX_FEE + Math.floor(Math.abs(Math.sin(seed)) * 50000);
    entries.push({
      tx,
      tx_id: deterministicHash(seed * 29),
      size_bytes: 256 + Math.floor(Math.random() * 512),
      fee: mempoolFee,
      received_at: now - Math.floor(Math.random() * 300),
    });
  }
  return entries;
}

// ── MockRpcClient ──

export class MockRpcClient {
  #chain;
  #mempool;
  #peers;
  #validators;
  #latencyMin;
  #latencyMax;
  #authEnabled = false;
  #authToken = null;
  #totpSecret = null;
  #allowedIps = [];
  #mockFirstRun = true;
  #storageConfig = null;
  #peerMemory = null;
  #pkiStatus = { configured: false, cn: null, fingerprint: null, expiry: null, bound_at: null };

  constructor({ latencyMin = 50, latencyMax = 150, firstRun = false } = {}) {
    const { blocks, txIndex, checksumIndex, versionChainIndex, publisherIndex } = generateChain(100);
    this.#chain = { blocks, txIndex, checksumIndex, versionChainIndex, publisherIndex };
    this.#mempool = generateMempool(50, 99);
    this.#peers = makePeers(99);
    this.#validators = [...VALIDATORS]; // mutable copy per instance
    this.#latencyMin = latencyMin;
    this.#latencyMax = latencyMax;
    this.#mockFirstRun = firstRun;
  }

  /** Enable/disable mock auth. When enabled, setAuthToken must be called first. */
  setMockAuthEnabled(enabled) { this.#authEnabled = enabled; }

  /** Mock setAuthToken — stores the hash for validation. */
  async setAuthToken(code) {
    if (!code) { this.#authToken = null; return; }
    const encoded = new TextEncoder().encode(code);
    const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    this.#authToken = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** Check whether an auth token is currently set. */
  hasAuthToken() { return this.#authToken !== null; }

  /** Build a version chain via BFS starting from a root checksum. Returns null if no chain. */
  #buildVersionChain(checksum) {
    const rootRecords = this.#chain.checksumIndex.get(checksum);
    if (!rootRecords || rootRecords.length === 0) return null;

    const successors = this.#chain.versionChainIndex.get(checksum) || [];
    const hasPrev = rootRecords[0].prev_checksum != null;

    // No chain if no successors and root doesn't reference a prev_checksum
    if (successors.length === 0 && !hasPrev) return null;

    const first = rootRecords[0];
    const versions = [{
      checksum,
      tx_id: first.tx_id,
      block_height: first.block_height,
      timestamp: first.timestamp,
      version: first.version || 1,
    }];
    const queue = [checksum];
    const visited = new Set([checksum]);
    while (queue.length > 0 && versions.length < 100) {
      const current = queue.shift();
      const succTxIds = this.#chain.versionChainIndex.get(current) || [];
      for (const succTxId of succTxIds) {
        if (versions.length >= 100) break;
        const entry = this.#chain.txIndex.get(succTxId);
        if (!entry) continue;
        const succChecksum = entry.tx.checksum;
        const verMeta = entry.tx.metadata.find(m => m.key === 'doc:version');
        const ver = verMeta ? parseInt(new TextDecoder().decode(new Uint8Array(verMeta.value)), 10) : null;
        versions.push({
          checksum: succChecksum,
          tx_id: succTxId,
          block_height: entry.block_height,
          timestamp: entry.tx.timestamp,
          version: ver,
        });
        if (!visited.has(succChecksum)) {
          visited.add(succChecksum);
          queue.push(succChecksum);
        }
      }
    }
    return versions;
  }

  get chainHeight() {
    return this.#chain.blocks.length - 1;
  }

  async call(method, params = {}) {
    // Simulate network latency
    await new Promise(r =>
      setTimeout(r, this.#latencyMin + Math.random() * (this.#latencyMax - this.#latencyMin))
    );

    // Mock auth check
    if (this.#authEnabled && !this.#authToken) {
      throw { code: -32012, message: 'authentication required' };
    }

    switch (method) {
      case 'noble_getLatestBlock': {
        const b = this.#chain.blocks[this.#chain.blocks.length - 1];
        return { header: b.header, transactions: b.transactions };
      }

      case 'noble_getBlockCount':
        return { height: this.chainHeight, block_hash: this.#chain.blocks[this.chainHeight]._hash };

      case 'noble_getBlock': {
        const b = this.#findBlock(params.height ?? params.hash);
        if (!b) throw { code: -32602, message: 'Block not found' };
        return { header: b.header, transactions: b.transactions };
      }

      case 'noble_getBlockHeader': {
        const b = this.#findBlock(params.height ?? params.hash);
        if (!b) throw { code: -32602, message: 'Block not found' };
        return b.header;
      }

      case 'noble_getBlockRange': {
        // Positional: [start_height, count]
        const start = Array.isArray(params) ? (params[0] ?? 0) : (params.start ?? 0);
        const count = Array.isArray(params) ? (params[1] ?? 50) : ((params.end ?? start + 49) - start + 1);
        const end = Math.min(start + count - 1, this.chainHeight);
        const epoch = this.#chain.blocks.length > 1 ? this.#chain.blocks[1].header.timestamp : 0;
        return this.#chain.blocks.slice(start, end + 1).map(b => ({
          height: b.header.height,
          hash: b._hash,
          prev_hash: b.header.prev_hash,
          merkle_root: b.header.merkle_root,
          timestamp: b.header.timestamp,
          tx_count: b.header.tx_count,
          validator_id: b.header.validator_id,
          validator_name: 'Mock Validator',
          cycle: epoch ? Math.floor((b.header.timestamp - epoch) / 1200) : null,
        }));
      }

      case 'noble_getChainStats': {
        const totalTx = this.#chain.blocks.reduce((s, b) => s + b.transactions.length, 0);
        return {
          chain_id: MOCK_CHAIN_ID,
          height: this.chainHeight,
          total_transactions: totalTx,
          avg_block_interval: CYCLE_DURATION_SECS,
          avg_tx_per_block: Math.round(totalTx / this.#chain.blocks.length),
          total_blocks: this.#chain.blocks.length,
        };
      }

      case 'noble_getTransaction': {
        const entry = this.#chain.txIndex.get(params.tx_id);
        if (!entry) throw { code: -32602, message: 'Transaction not found' };
        return {
          tx: entry.tx,
          tx_id: entry.tx_id,
          block_height: entry.block_height,
          confirmations: this.chainHeight - entry.block_height + 1,
          status: 'confirmed',
        };
      }

      case 'noble_getTransactionReceipt': {
        const entry = this.#chain.txIndex.get(params.tx_id);
        if (!entry) throw { code: -32602, message: 'Transaction not found' };
        return {
          transaction: entry.tx,
          tx_id: entry.tx_id,
          status: 'confirmed',
          block_height: entry.block_height,
          block_hash: this.#chain.blocks[entry.block_height]?.hash || null,
          tx_index: 0,
          confirmations: this.chainHeight - entry.block_height + 1,
        };
      }

      case 'noble_getTransactionStatus': {
        const entry = this.#chain.txIndex.get(params.tx_id);
        if (!entry) {
          const mp = this.#mempool.find(m => m.tx_id === params.tx_id);
          if (mp) return { status: 'pending', tx_id: params.tx_id };
          throw { code: -32602, message: 'Transaction not found' };
        }
        return {
          status: 'confirmed',
          tx_id: params.tx_id,
          block_height: entry.block_height,
          confirmations: this.chainHeight - entry.block_height + 1,
        };
      }

      case 'noble_lookupChecksum': {
        const records = this.#chain.checksumIndex.get(params.checksum);
        if (!records || records.length === 0) return { found: false, records: [], version_chain: null };
        const vc = this.#buildVersionChain(params.checksum);
        return { found: true, records, version_chain: vc };
      }

      case 'noble_verifyDocument': {
        const records = this.#chain.checksumIndex.get(params.checksum);
        const vc = (records && records.length > 0) ? this.#buildVersionChain(params.checksum) : null;
        return {
          checksum: params.checksum,
          registered: !!records && records.length > 0,
          registrations: records || [],
          first_seen: records?.[0]?.timestamp ?? null,
          version_chain: vc,
        };
      }

      case 'noble_getDocumentHistory': {
        const records = this.#chain.checksumIndex.get(params.checksum);
        return { checksum: params.checksum, history: records || [] };
      }

      case 'noble_getDocumentVersions': {
        const rootRecords = this.#chain.checksumIndex.get(params.checksum);
        if (!rootRecords || rootRecords.length === 0) {
          throw { code: -32602, message: 'Checksum not found' };
        }
        const versions = this.#buildVersionChain(params.checksum) || [];
        return { root_checksum: params.checksum, versions, count: versions.length };
      }

      case 'noble_getDocumentsByPublisher': {
        const pubkey = params.public_key;
        const docs = this.#chain.publisherIndex.get(pubkey) || [];
        return { publisher: pubkey, documents: docs, count: docs.length };
      }

      case 'noble_decryptLocator': {
        const entry = this.#chain.txIndex.get(params.tx_id);
        if (!entry) throw { code: -32602, message: 'Transaction not found' };
        if (!entry.tx.has_encrypted_locator) {
          throw { code: -32602, message: 'Transaction has no encrypted locator' };
        }
        // Mock: return a deterministic URL based on the checksum
        const mockUrl = `https://storage.example.com/docs/${entry.tx.checksum.slice(0, 16)}.pdf`;
        return {
          tx_id: params.tx_id,
          plaintext: mockUrl,
          locator_metadata: {
            has_locator: true,
            recipient_count: entry.tx.locator_recipient_count || 1,
            encryption_scheme: 'ECIES-X25519',
          },
        };
      }

      case 'noble_getSetupStatus':
        return { setup_complete: !this.#mockFirstRun };

      case 'noble_uploadPkcs12': {
        if (!params.file_data || !params.passphrase) {
          throw { code: -32602, message: 'Missing file_data or passphrase' };
        }
        const cn = 'Acme Corp';
        const fp = deterministicHash(42).slice(0, 40);
        return {
          success: true,
          cn,
          fingerprint: fp,
          expiry: '2027-03-15T00:00:00Z',
          chain_length: 3,
          issuer_cn: 'DigiCert Global Root G2',
        };
      }

      case 'noble_bindPkiIdentity': {
        if (!params.fingerprint) throw { code: -32602, message: 'Missing fingerprint' };
        const now = Math.floor(Date.now() / 1000);
        this.#pkiStatus = {
          configured: true,
          cn: 'Acme Corp',
          fingerprint: params.fingerprint,
          expiry: '2027-03-15T00:00:00Z',
          bound_at: now,
        };
        return { success: true, bound_at: now };
      }

      case 'noble_getPkiStatus':
        return this.#pkiStatus;

      case 'noble_removePkiBinding': {
        this.#pkiStatus = { configured: false, cn: null, fingerprint: null, expiry: null, bound_at: null };
        return { success: true };
      }

      case 'noble_estimateFee':
        return {
          min_fee: MIN_TX_FEE,
          recommended_fee: MIN_TX_FEE * 2,
          high_priority_fee: MIN_TX_FEE * 5,
        };

      case 'noble_getMempoolInfo': {
        const fees = this.#mempool.map(e => e.fee);
        const totalBytes = this.#mempool.reduce((s, e) => s + e.size_bytes, 0);
        return {
          count: this.#mempool.length,
          total_bytes: totalBytes,
          min_fee: Math.min(...fees),
          max_fee: Math.max(...fees),
          avg_fee: Math.round(fees.reduce((a, b) => a + b, 0) / fees.length),
          fee_histogram: this.#buildFeeHistogram(),
          entries: this.#mempool.slice(0, 20),
        };
      }

      case 'noble_getPeerInfo':
        return this.#peers;

      case 'noble_getNetworkInfo':
        return {
          peer_count: this.#peers.length,
          inbound: this.#peers.filter(p => p.direction === 'Inbound').length,
          outbound: this.#peers.filter(p => p.direction === 'Outbound').length,
          banned: 0,
          max_peers: 50,
          protocol_version: PROTOCOL_VERSION,
          chain_id: MOCK_CHAIN_ID,
        };

      case 'noble_getSyncStatus':
        return {
          synced: true,
          current_height: this.chainHeight,
          highest_known: this.chainHeight,
          progress: 1.0,
          state: 'Complete',
        };

      case 'noble_getValidatorList':
        return {
          selection_policy: 'weighted_random',
          validators: this.#validators,
        };

      case 'noble_addValidator': {
        const hexKey = params.public_key;
        if (!hexKey || hexKey.length !== 64) throw { code: -32602, message: 'Invalid public key: expected 64 hex characters (Ed25519)' };
        const keyBytes = [];
        for (let i = 0; i < hexKey.length; i += 2) keyBytes.push(parseInt(hexKey.slice(i, i + 2), 16));
        const mockNbl1Key = 'nbl1q' + hexKey;
        const exists = this.#validators.find(v => v.public_key === mockNbl1Key);
        if (exists) throw { code: -32602, message: `Validator already in list: ${exists.name}` };
        const now = Math.floor(Date.now() / 1000);
        const newValidator = {
          public_key: mockNbl1Key,
          name: params.name || `validator-${hexKey.slice(0, 8)}`,
          host_address: null,
          country_code: null,
          status: 'alive',
          reputation_score: 0,
          reputation_breakdown: { block_acceptance_rate: 0, uptime: 0, trust_score: 0 },
          blocks_produced: 0,
          blocks_accepted: 0,
          cycles_active: 0,
          cycles_reachable: 0,
          total_cycles: 0,
          listers_count: 1,
          joined_cycle: Math.floor(now / CYCLE_DURATION_SECS),
          last_active: now,
          proposed_this_cycle: false,
          wants_to_validate: true,
        };
        this.#validators.push(newValidator);
        return { success: true, validator: newValidator };
      }

      case 'noble_removeValidator': {
        const pubkey = params.public_key;
        const idx = this.#validators.findIndex(v => v.public_key === pubkey);
        if (idx === -1) throw { code: -32602, message: 'Validator not found in list' };
        const removed = this.#validators.splice(idx, 1)[0];
        return { success: true, removed_name: removed.name };
      }

      case 'noble_getReputationScore': {
        const validator = this.#validators.find(v => v.public_key === params.pubkey);
        if (!validator) throw { code: -32602, message: 'Validator not found' };
        return {
          validator: params.pubkey,
          reputation: validator.reputation_score,
          breakdown: validator.reputation_breakdown,
          blocks_accepted: validator.blocks_accepted,
          cycles_active: validator.cycles_active,
          cycles_reachable: validator.cycles_reachable,
          total_cycles: validator.total_cycles,
          listers_count: validator.listers_count,
        };
      }

      case 'noble_getCycleStatus': {
        const now = Math.floor(Date.now() / 1000);
        const elapsed = now % CYCLE_DURATION_SECS;
        const phaseLen = CYCLE_DURATION_SECS / 4;
        const phaseIndex = Math.min(3, Math.floor(elapsed / phaseLen));
        const phases = ['Block Proposal', 'Voting', 'Reflection', 'Propagation'];
        const remaining = phaseLen - (elapsed % phaseLen);
        const cycleRemaining = CYCLE_DURATION_SECS - elapsed;
        const epoch = this.#chain.blocks.length > 1 ? this.#chain.blocks[1].header.timestamp : now;
        return {
          phase: phases[phaseIndex],
          phase_index: phaseIndex,
          phase_remaining_secs: remaining,
          cycle_remaining_secs: cycleRemaining,
          cycle_number: Math.floor((now - epoch) / CYCLE_DURATION_SECS),
          genesis_timestamp: epoch,
          current_validator: this.#validators[0].public_key,
        };
      }

      case 'noble_getCycleHistory': {
        const now = Math.floor(Date.now() / 1000);
        const currentCycle = Math.floor(now / CYCLE_DURATION_SECS);
        const elapsed = now % CYCLE_DURATION_SECS;
        const phaseLen = CYCLE_DURATION_SECS / 4;
        const currentPhaseIndex = Math.min(3, Math.floor(elapsed / phaseLen));

        // Generate history for last 3 cycles (current + 2 past)
        const cycles = [];
        for (let offset = 2; offset >= 0; offset--) {
          const cn = currentCycle - offset;
          const isCurrent = offset === 0;

          // Deterministic proposals per cycle based on cycle number
          const proposerCount = (cn % 3 === 0) ? 3 : (cn % 3 === 1) ? 1 : 2;
          const proposals = [];
          for (let p = 0; p < proposerCount; p++) {
            const onlineVals = this.#validators.filter(v => v.status === 'alive');
            const vi = (cn * 3 + p) % Math.max(1, onlineVals.length);
            const val = onlineVals[vi] || this.#validators[0];
            proposals.push({
              validator: val.name,
              validator_index: vi,
              block_hash: deterministicHash(cn * 100 + p),
              tx_count: 3 + ((cn * 7 + p * 13) % 12),
              reputation: val.reputation_score,
            });
          }

          // Votes: distribute 23 peer votes among proposals (weighted by reputation)
          const totalRep = proposals.reduce((s, p) => s + p.reputation, 0);
          const votes = proposals.map((p, idx) => {
            const base = Math.round(23 * p.reputation / totalRep);
            return {
              validator: p.validator,
              block_hash: p.block_hash,
              vote_count: idx === 0 ? Math.max(base, 23 - proposals.slice(1).reduce((s, _, j) =>
                s + Math.round(23 * proposals[j + 1].reputation / totalRep), 0)) : base,
            };
          });

          // Winner is the one with most votes
          votes.sort((a, b) => b.vote_count - a.vote_count);
          const winner = votes[0];
          // Simulate an indeterminate cycle every 5th historical cycle
          const isIndeterminate = !isCurrent && (offset % 5 === 3);
          const disambiguation = false; // Always false (v0.28.0: no hash tiebreaker)

          // Build phase states for the cycle (4 phases)
          const phaseNames = ['Block Proposal', 'Voting', 'Reflection', 'Propagation'];
          const phaseStates = [];
          for (let ph = 0; ph < 4; ph++) {
            let state;
            if (isCurrent && ph > currentPhaseIndex) {
              state = 'pending';
            } else if (isCurrent && ph === currentPhaseIndex) {
              state = 'active';
            } else {
              state = 'complete';
            }

            const phaseData = {
              name: phaseNames[ph],
              state,
            };

            if (ph === 0) {
              // Block Proposal: proposals submitted
              phaseData.proposals = proposals.map(p => ({
                validator: p.validator,
                tx_count: p.tx_count,
                block_hash: p.block_hash,
              }));
            } else if (ph === 1) {
              // Voting: votes cast
              phaseData.votes = state !== 'pending' ? votes : [];
              phaseData.total_voters = state !== 'pending' ? 23 : 0;
            } else if (ph === 2) {
              // Reflection: winner determined (null for indeterminate cycles)
              phaseData.winner = (!isIndeterminate && state !== 'pending') ? winner.validator : null;
              phaseData.winning_hash = (!isIndeterminate && state !== 'pending') ? winner.block_hash : null;
              phaseData.disambiguation = disambiguation;
            } else {
              // Propagation: finalization (false for indeterminate cycles)
              phaseData.finalized = !isIndeterminate && state === 'complete';
              phaseData.block_hash = (!isIndeterminate && state === 'complete') ? winner.block_hash : null;
            }

            phaseStates.push(phaseData);
          }

          cycles.push({
            cycle_number: cn,
            is_current: isCurrent,
            status: isIndeterminate ? 'indeterminate' : (isCurrent ? 'active' : 'finalized'),
            phases: phaseStates,
            proposals_count: proposals.length,
            disambiguation,
            winner: isIndeterminate ? null : (isCurrent && currentPhaseIndex < 2 ? null : winner.validator),
            winning_hash: isIndeterminate ? null : (isCurrent && currentPhaseIndex < 2 ? null : winner.block_hash),
          });
        }

        return { cycles };
      }

      case 'noble_getVotingStrategy':
        return {
          round1_strategy: this._votingR1 || 'first_valid',
          round1_params: this._votingR1Params || null,
          round2_strategy: this._votingR2 || 'follow_majority',
          round2_params: this._votingR2Params || null,
        };

      case 'noble_setVotingStrategy': {
        const { round, strategy, params: stratParams } = params;
        if (round === 1) {
          this._votingR1 = strategy;
          this._votingR1Params = stratParams;
        } else {
          this._votingR2 = strategy;
          this._votingR2Params = stratParams;
        }
        return {
          round1_strategy: this._votingR1 || 'first_valid',
          round1_params: this._votingR1Params || null,
          round2_strategy: this._votingR2 || 'follow_majority',
          round2_params: this._votingR2Params || null,
        };
      }

      case 'noble_getVoteTallies': {
        const now = Math.floor(Date.now() / 1000);
        const cycle = Math.floor(now / CYCLE_DURATION_SECS);
        const elapsed = now % CYCLE_DURATION_SECS;
        const phaseLen = CYCLE_DURATION_SECS / 4;
        const phaseIndex = Math.min(3, Math.floor(elapsed / phaseLen));
        const phases = ['Block Proposal', 'Voting', 'Reflection', 'Propagation'];
        // Always return candidates so manual vote dropdown has options
        const tallies = [
          { block_hash: 'a1b2c3d4e5f6'.padEnd(64, '0'), validator: 'noble-alpha', validator_key: 'aa'.repeat(33), vote_count: phaseIndex >= 1 ? 3 : 0 },
          { block_hash: 'f6e5d4c3b2a1'.padEnd(64, '0'), validator: 'noble-beta', validator_key: 'bb'.repeat(33), vote_count: phaseIndex >= 1 ? 1 : 0 },
        ];
        return { cycle, phase: phases[phaseIndex], tallies };
      }

      case 'noble_castVote':
        return true;

      case 'noble_getNodeInfo': {
        // validator_pubkey: use the first validator's key hex (simulates this node being a validator)
        const selfVal = this.#validators[0];
        const selfKeyHex = selfVal ? selfVal.public_key : null;
        return {
          version: window.NOBLE_VERSION || '0.0.0',
          software_version: window.NOBLE_VERSION || '0.0.0',
          protocol_version: PROTOCOL_VERSION,
          chain_id: MOCK_CHAIN_ID,
          genesis_hash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
          uptime_secs: 86400 * 3 + 7200 + 1800,
          storage_bytes: 256 * 1024 * 1024,
          storage_capacity_bytes: 1024 * 1024 * 1024,
          rpc_port: 8783,
          ws_port: 8784,
          p2p_port: 8780,
          data_dir: '/var/noble/data',
          config_path: '/etc/noble/noble.toml',
          totp_enabled: this.#authEnabled,
          validator_pubkey: selfKeyHex,
          validator_pubkey_display: selfKeyHex, // mock: same as hex (real API returns bech32)
          peer_id: '12D3KooWMockPeerIdForDevMode',
          network_name: '34E9E7A4',
          latest_network_version: null,
          sync_behind: false,
          sync_target_height: 0,
          sync_current_height: 0,
          sync_progress_pct: 0,
          faucet_address: 'nbl1pqduas3vtyxcajqs3sg2vuwj7x62lkdvsh2dry23zn37844mu7v4yvz9376a',
          faucet_enabled: true,
        };
      }

      case 'noble_getWalletInfo': {
        // First-run mode: no keys yet
        if (this.#mockFirstRun) {
          return {
            key_count: 0,
            public_key: null,
            address: null,
            balance: 0,
            available: 0,
            pending: 0,
            total_earned: 0,
            total_outgoing: 0,
            blocks_validated: 0,
            first_active: null,
          };
        }
        const walletKey = this.#validators[0].public_key; // bech32 string (nbl1q...)
        const address = walletKey; // real API returns bech32 address
        const blocksValidated = this.#validators[0].blocks_produced;
        // Subsidy: 100 NOBLE (100_000_000 atomic) per block
        const subsidyPerBlock = 100_000_000;
        // Average fee per block ~15,000 atomic
        const avgFeePerBlock = 15_000;
        const totalSubsidy = blocksValidated * subsidyPerBlock;
        const totalFees = blocksValidated * avgFeePerBlock;
        const totalEarned = totalSubsidy + totalFees;
        // A few outgoing transfers
        const totalOutgoing = 500_000_000; // 500 NOBLE sent
        const balance = totalEarned - totalOutgoing;
        // Last 6 blocks are pending (not yet deep enough)
        const pendingBlocks = Math.min(6, blocksValidated);
        const pending = pendingBlocks * (subsidyPerBlock + avgFeePerBlock);
        const available = Math.max(0, balance - pending);

        return {
          key_count: 1,
          public_key: walletKey,
          address,
          balance,
          available,
          pending,
          total_earned: totalEarned,
          total_outgoing: totalOutgoing,
          blocks_validated: blocksValidated,
          first_active: GENESIS_TIMESTAMP + 100 * CYCLE_DURATION_SECS,
        };
      }

      case 'noble_listAddresses': {
        const walletKey = this.#validators[0].public_key; // bech32 string
        // Real API returns bech32 pubkey_hex via pk.to_address()
        return { keys: [{ pubkey_hex: walletKey, scheme: 'ed25519', bitcoin_addresses: [] }] };
      }

      case 'noble_getWalletTransactions': {
        const txs = [];
        const now = Math.floor(Date.now() / 1000);
        const chainHeight = this.chainHeight;
        const subsidyPerBlock = 100_000_000;
        let runningBalance = 0;

        // Generate transaction history from validated blocks
        // This node validated every Nth block (based on validator count)
        const validatorCount = this.#validators.length;
        const blocksWon = [];
        for (let h = 0; h <= chainHeight; h++) {
          if (h % validatorCount === 0) blocksWon.push(h);
        }

        // For each won block: one validation_subsidy tx + one fee tx (validator or gateway share)
        for (const h of blocksWon) {
          const block = this.#chain.blocks[h];
          if (!block) continue;
          // Fee is implicit in UTXO model; approximate from total_output for mock wallet
          const totalFees = block.transactions.reduce((s, tx) => s + Math.floor(tx.total_output * 0.01), 0);
          const confirmations = chainHeight - h;
          const txCount = block.transactions.length;

          // Subsidy → validation_subsidy
          runningBalance += subsidyPerBlock;
          txs.push({
            type: 'validation_subsidy',
            direction: 'incoming',
            amount: subsidyPerBlock,
            running_balance: runningBalance,
            timestamp: block.header.timestamp,
            block_height: h,
            tx_id: deterministicHash(h * 41 + 7777),
            description: `Block #${h} validation reward (${(subsidyPerBlock / 1_000_000).toFixed(0)} NOBLE)`,
            confirmations,
            status: confirmations >= 6 ? 'confirmed' : 'pending',
          });

          if (totalFees > 0) {
            // ~60% of blocks: validator fee share; ~40%: gateway fee share
            const hasGatewayTxs = block.transactions.some(tx => tx.gateway_address);
            const gatewayTxCount = block.transactions.filter(tx => tx.gateway_address).length;

            if (hasGatewayTxs && h % 5 < 2) {
              // Gateway fee share (this node was the accepting gateway)
              const gatewayShare = Math.floor(totalFees / 2);
              runningBalance += gatewayShare;
              txs.push({
                type: 'fee_gateway',
                direction: 'incoming',
                amount: gatewayShare,
                running_balance: runningBalance,
                timestamp: block.header.timestamp + 1,
                block_height: h,
                tx_id: deterministicHash(h * 41 + 8888),
                description: `Block #${h} gateway fee share (${gatewayTxCount} gateway txs)`,
                confirmations,
                status: confirmations >= 6 ? 'confirmed' : 'pending',
              });
            } else {
              // Validator fee share
              const validatorShare = hasGatewayTxs ? Math.ceil(totalFees / 2) : totalFees;
              runningBalance += validatorShare;
              txs.push({
                type: 'fee_validation',
                direction: 'incoming',
                amount: validatorShare,
                running_balance: runningBalance,
                timestamp: block.header.timestamp + 1,
                block_height: h,
                tx_id: deterministicHash(h * 41 + 8888),
                description: `Block #${h} validator fee share (${txCount} txs)`,
                confirmations,
                status: confirmations >= 6 ? 'confirmed' : 'pending',
              });
            }
          }
        }

        // Outgoing transfers: mix of payment_sent and doc_registration
        const outgoing = [
          { amount: 200_000_000, desc: 'Payment to noble1b7e2...f4a9', ago: 86400 * 5, id: 1001, type: 'payment_sent' },
          { amount: 1100_000_000, desc: 'Payment to noble1c3d8...e2b7', ago: 86400 * 3, id: 1002, type: 'payment_sent' },
          { amount: 1_050_000, desc: 'Document registration: a8f3c2d1...', ago: 86400 * 2, id: 1005, type: 'doc_registration' },
          { amount: 100_000_000, desc: 'Payment to noble1d9f1...a3c5', ago: 86400, id: 1003, type: 'payment_sent' },
          { amount: 1_050_000, desc: 'Document registration: 7b2e9f04...', ago: 3600 * 12, id: 1006, type: 'doc_registration' },
          { amount: 100_000_000, desc: 'Payment to noble1e4a7...d8f2', ago: 3600 * 6, id: 1004, type: 'payment_sent' },
        ];

        for (const out of outgoing) {
          runningBalance -= out.amount;
          txs.push({
            type: out.type,
            direction: 'outgoing',
            amount: out.amount,
            running_balance: runningBalance,
            timestamp: now - out.ago,
            block_height: chainHeight - Math.floor(out.ago / CYCLE_DURATION_SECS),
            tx_id: deterministicHash(out.id * 9999),
            description: out.desc,
            confirmations: Math.floor(out.ago / CYCLE_DURATION_SECS),
            status: 'confirmed',
          });
        }

        // Incoming transfer → payment_received
        runningBalance += 25_000_000;
        txs.push({
          type: 'payment_received',
          direction: 'incoming',
          amount: 25_000_000,
          running_balance: runningBalance,
          timestamp: now - 86400 * 2,
          block_height: chainHeight - 96,
          tx_id: deterministicHash(2001 * 9999),
          description: 'Payment from noble1a8f3...c2d1',
          confirmations: 96,
          status: 'confirmed',
        });

        // Sort by timestamp descending (newest first)
        txs.sort((a, b) => b.timestamp - a.timestamp);

        // Recalculate running balance in reverse chronological order
        let bal = 0;
        const sorted = [...txs].sort((a, b) => a.timestamp - b.timestamp);
        for (const tx of sorted) {
          if (tx.direction === 'incoming') bal += tx.amount;
          else bal -= tx.amount;
          tx.running_balance = bal;
        }

        return { transactions: txs, total: txs.length };
      }

      case 'noble_getNodeIdentity':
        if (this.#mockFirstRun) {
          return {
            node_name: '',
            org_type: '',
            org_name: '',
            node_role: '',
            contact_email: '',
            website: '',
            host_address: '',
            country_code: '',
            governance_class: '',
            wants_to_validate: false,
            wants_to_vote: false,
            p2p_port: 8780,
            pki_attestation: null,
            pkcs12_configured: false,
          };
        }
        return {
          node_name: 'noble-dev-01',
          org_type: 'Individual',
          org_name: '',
          node_role: 'FullNode',
          contact_email: '',
          website: '',
          host_address: '',
          country_code: '',
          governance_class: 'individual',
          wants_to_validate: false,
          wants_to_vote: false,
          p2p_port: 8780,
          pki_attestation: null,
          pkcs12_configured: false,
        };

      case 'noble_setNodeIdentity':
        this.#mockFirstRun = false;
        return {
          success: true,
          validator_pubkey: params.wants_to_validate ? randomHex(32) : null,
        };

      case 'noble_setRewardAddress': {
        const addr = (params.address || '').trim();
        if (!addr) throw { code: -32602, message: 'address is required' };
        // Detect address type from prefix
        let addrType = 'Unknown';
        if (addr.startsWith('bc1q')) addrType = 'P2WPKH';
        else if (addr.startsWith('bc1p')) addrType = 'P2TR';
        else if (addr.startsWith('1')) addrType = 'P2PKH';
        else if (/^[0-9a-fA-F]+$/.test(addr)) addrType = 'Noble';
        return { success: true, address_type: addrType };
      }

      case 'noble_getPeerAnnounces':
        return [
          {
            peer_id: '12D3KooWA1b2c3d4e5f6g7h8i9j0',
            node_name: 'MIT Blockchain Lab',
            org_type: 'PrivateAcademic',
            governance_class: 'private',
            node_role: 'ArchiveNode',
            contact_email: 'blockchain@mit.edu',
            website: 'https://blockchain.mit.edu',
            host_address: '/ip4/18.4.86.10/tcp/8780',
            country_code: 'USA',
            identity_key: '00' + randomHex(32),
            last_seen: Math.floor(Date.now() / 1000) - 120,
            wants_to_validate: false,
            wants_to_vote: true,
            pki_attestation: {
              scheme: 'pkcs7',
              scope: 'identity',
              signer_fingerprint: deterministicHash(101).slice(0, 64),
              signer_cn: 'Massachusetts Institute of Technology',
            },
          },
          {
            peer_id: '12D3KooWB2c3d4e5f6g7h8i9j0k1',
            node_name: 'Treasury Node Alpha',
            org_type: 'PublicNational',
            governance_class: 'public',
            node_role: 'Validator',
            contact_email: 'nodes@treasury.gov',
            website: 'https://treasury.gov/blockchain',
            host_address: '/ip4/52.1.100.50/tcp/8780',
            country_code: 'USA',
            identity_key: '00' + randomHex(32),
            last_seen: Math.floor(Date.now() / 1000) - 300,
            wants_to_validate: true,
            wants_to_vote: true,
            pki_attestation: {
              scheme: 'pkcs7',
              scope: 'identity',
              signer_fingerprint: deterministicHash(202).slice(0, 64),
              signer_cn: 'U.S. Department of the Treasury',
            },
          },
          {
            peer_id: '12D3KooWC3d4e5f6g7h8i9j0k1l2',
            node_name: 'Acme Corp Node',
            org_type: 'PrivateCorporation',
            governance_class: 'private',
            node_role: 'FullNode',
            contact_email: 'infra@acme.com',
            website: 'https://acme.com',
            host_address: '/ip4/203.0.113.42/tcp/8780',
            country_code: 'GBR',
            identity_key: '00' + randomHex(32),
            last_seen: Math.floor(Date.now() / 1000) - 60,
            wants_to_validate: false,
            wants_to_vote: false,
          },
          {
            peer_id: '12D3KooWD4e5f6g7h8i9j0k1l2m3',
            node_name: 'OpenNoble Community',
            org_type: 'PrivateNonProfit',
            governance_class: 'private',
            node_role: 'FullNode',
            contact_email: 'admin@opennoble.org',
            website: 'https://opennoble.org',
            host_address: '/ip4/198.51.100.7/tcp/8780',
            country_code: 'DEU',
            identity_key: '00' + randomHex(32),
            last_seen: Math.floor(Date.now() / 1000) - 45,
            wants_to_validate: true,
            wants_to_vote: false,
          },
          {
            peer_id: '12D3KooWE5f6g7h8i9j0k1l2m3n4',
            node_name: 'City of Barcelona',
            org_type: 'PublicRegional',
            governance_class: 'public',
            node_role: 'Validator',
            contact_email: 'blockchain@bcn.cat',
            website: 'https://ajuntament.barcelona.cat',
            host_address: '/ip4/85.91.200.12/tcp/8780',
            country_code: 'ESP',
            identity_key: '00' + randomHex(32),
            last_seen: Math.floor(Date.now() / 1000) - 180,
            wants_to_validate: true,
            wants_to_vote: true,
          },
          {
            peer_id: '12D3KooWF6g7h8i9j0k1l2m3n4o5',
            node_name: 'National Museum Archive',
            org_type: 'PublicInstitution',
            governance_class: 'public',
            node_role: 'ArchiveNode',
            contact_email: 'digital@nationalmuseum.org',
            website: '',
            host_address: '',
            identity_key: '00' + randomHex(32),
            last_seen: Math.floor(Date.now() / 1000) - 600,
            wants_to_validate: false,
            wants_to_vote: true,
          },
        ];

      case 'noble_getPeerMemory': {
        if (!this.#peerMemory) {
          const now = Math.floor(Date.now() / 1000);
          this.#peerMemory = [
            {
              identity_key: makePublicKey(200),
              first_seen: now - 86400 * 10,
              last_seen: now - 120,
              connection_count: 47,
              peer_id: '12D3KooWA1b2c3d4e5f6g7h8i9j0',
              last_addr: '/ip4/18.4.86.10/tcp/8780',
              node_name: 'MIT Blockchain Lab',
              org_type: 'PrivateAcademic',
              node_role: 'ArchiveNode',
              wants_to_validate: false,
              wants_to_vote: true,
            },
            {
              identity_key: makePublicKey(201),
              first_seen: now - 86400 * 30,
              last_seen: now - 300,
              connection_count: 120,
              peer_id: '12D3KooWB2c3d4e5f6g7h8i9j0k1',
              last_addr: '/ip4/52.1.100.50/tcp/8780',
              node_name: 'Treasury Node Alpha',
              org_type: 'PublicNational',
              node_role: 'Validator',
              wants_to_validate: true,
              wants_to_vote: true,
            },
            {
              identity_key: makePublicKey(202),
              first_seen: now - 86400 * 5,
              last_seen: now - 60,
              connection_count: 12,
              peer_id: '12D3KooWC3d4e5f6g7h8i9j0k1l2',
              last_addr: '/ip4/203.0.113.42/tcp/8780',
              node_name: 'Acme Corp Node',
              org_type: 'PrivateCorporation',
              node_role: 'FullNode',
              wants_to_validate: false,
              wants_to_vote: false,
            },
            {
              identity_key: makePublicKey(203),
              first_seen: now - 86400 * 60,
              last_seen: now - 86400 * 8,
              connection_count: 3,
              peer_id: '12D3KooWG7h8i9j0k1l2m3n4o5p6',
              last_addr: '/ip4/10.0.0.1/tcp/8780',
              node_name: 'Stale Observer',
              org_type: 'Individual',
              node_role: 'LightClient',
              wants_to_validate: false,
              wants_to_vote: false,
            },
            {
              identity_key: makePublicKey(204),
              first_seen: now - 86400 * 15,
              last_seen: now - 45,
              connection_count: 34,
              peer_id: '12D3KooWD4e5f6g7h8i9j0k1l2m3',
              last_addr: '/ip4/198.51.100.7/tcp/8780',
              node_name: 'OpenNoble Community',
              org_type: 'PrivateNonProfit',
              node_role: 'FullNode',
              wants_to_validate: true,
              wants_to_vote: false,
            },
            {
              identity_key: makePublicKey(205),
              first_seen: now - 86400 * 20,
              last_seen: now - 180,
              connection_count: 67,
              peer_id: '12D3KooWE5f6g7h8i9j0k1l2m3n4',
              last_addr: '/ip4/85.91.200.12/tcp/8780',
              node_name: 'City of Barcelona',
              org_type: 'PublicRegional',
              node_role: 'Validator',
              wants_to_validate: true,
              wants_to_vote: true,
            },
          ];
        }
        return this.#peerMemory;
      }

      case 'noble_removePeerRecord':
        return { success: true };

      case 'noble_pruneStalePeers':
        return { pruned: 1 };

      case 'noble_setTraceFilter': {
        const filter = params.filter || 'info';
        const durationMinutes = params.duration_minutes;
        const validDurations = [1, 5, 15, 30, 60, 120, 360, 720, 1440];
        if (durationMinutes != null && !validDurations.includes(durationMinutes)) {
          throw { code: -32602, message: `Invalid duration: ${durationMinutes}` };
        }
        if (filter === 'off') {
          this._traceSession = null;
          return { active: false, filter: 'off', expires_at: null, remaining_seconds: null };
        }
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = durationMinutes ? now + durationMinutes * 60 : null;
        this._traceSession = { filter, expires_at: expiresAt, started_at: now };
        return {
          active: true,
          filter,
          expires_at: expiresAt,
          remaining_seconds: durationMinutes ? durationMinutes * 60 : null,
        };
      }

      case 'noble_getTraceBuffer': {
        const lastN = params.last_n || 200;
        const entries = this._generateTraceEntries(lastN, params.level, params.task);
        return {
          entries,
          total_in_buffer: 847 + Math.floor(Math.random() * 200),
          capacity: 50000,
          current_filter: this._traceSession?.filter || 'info',
          session_active: !!this._traceSession,
          remaining_seconds: this._traceSessionRemaining(),
        };
      }

      case 'noble_clearTraceBuffer':
        return { cleared: true };

      case 'noble_getTraceStatus': {
        const session = this._traceSession;
        const remaining = this._traceSessionRemaining();
        return {
          session_active: !!session && (remaining === null || remaining > 0),
          current_filter: session?.filter || 'info',
          remaining_seconds: remaining,
          buffer_size: 847 + Math.floor(Math.random() * 200),
          buffer_capacity: 50000,
        };
      }

      case 'noble_getAllowedIps':
        return {
          allowed_ips: this.#allowedIps,
          remote_access_enabled: this.#allowedIps.length > 0,
        };

      case 'noble_setAllowedIps': {
        const newList = params.allowed_ips || [];
        const wasRemote = this.#allowedIps.length > 0;
        this.#allowedIps = newList;
        const isRemote = newList.length > 0;
        const msg = wasRemote !== isRemote
          ? `Allowed IPs updated (${newList.length} entries). Note: bind address change requires node restart.`
          : `Allowed IPs updated (${newList.length} entries)`;
        return { success: true, message: msg };
      }

      case 'noble_generateMnemonic': {
        const wc = params.word_count || 24;
        if (wc !== 12 && wc !== 24) throw { code: -32602, message: 'word_count must be 12 or 24' };
        // Generate a fake mnemonic (not cryptographically valid, just for UI testing)
        const wordList = [
          'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
          'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
          'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
        ];
        const words = [];
        for (let i = 0; i < wc; i++) words.push(wordList[i % wordList.length]);
        const pubkey = randomHex(32);
        return {
          mnemonic: words.join(' '),
          address: '02' + pubkey,
          scheme_id: 2,
          word_count: wc,
          private_key: randomHex(32),
          public_key: '02' + pubkey,
          wire_hex: '02' + '02' + pubkey,
          bitcoin_addresses: [
            { address_type: 'p2pkh', address: '1' + randomHex(24).slice(0, 33) },
            { address_type: 'p2wpkh', address: 'bc1q' + randomHex(20).slice(0, 38) },
            { address_type: 'p2tr', address: 'bc1p' + randomHex(32).slice(0, 58) },
          ],
        };
      }

      case 'noble_importMnemonic': {
        const words = (params.mnemonic || '').trim().split(/\s+/);
        if (words.length !== 12 && words.length !== 24) {
          throw { code: -32602, message: 'Mnemonic must be 12 or 24 words' };
        }
        const impPubkey = randomHex(32);
        return {
          address: '02' + impPubkey,
          scheme_id: 2,
          already_exists: Math.random() > 0.5,
          private_key: randomHex(32),
          public_key: '02' + impPubkey,
          wire_hex: '02' + '02' + impPubkey,
          bitcoin_addresses: [
            { address_type: 'p2pkh', address: '1' + randomHex(24).slice(0, 33) },
            { address_type: 'p2wpkh', address: 'bc1q' + randomHex(20).slice(0, 38) },
            { address_type: 'p2tr', address: 'bc1p' + randomHex(32).slice(0, 58) },
          ],
        };
      }

      case 'noble_getStorageInfo': {
        const tip = this.#chain.blocks[this.#chain.blocks.length - 1];
        return {
          chain_height: tip ? tip.header.height : 0,
          pruning_mode: this.#storageConfig?.pruning_mode || 'archive',
          keep_blocks: this.#storageConfig?.keep_blocks || 10000,
          pruned_up_to: 0,
          lowest_full_height: 0,
        };
      }

      case 'noble_getPruningStatus':
        return {
          mode: this.#storageConfig?.pruning_mode || 'archive',
          blocks_pruned: 0,
          transactions_removed: 0,
          lowest_full_height: 0,
          more_remaining: false,
        };

      case 'noble_getStorageStats':
        return {
          data_dir: '~/.noble/data',
          total_db_bytes: 44_350_000,
          available_bytes: 250_685_440_000,
          total_volume_bytes: 499_963_174_912,
          cache_size_bytes: 67_108_864,
          compression_enabled: true,
          column_families: [
            { name: 'blocks',           estimated_bytes: 28_900_000, estimated_keys: 1247 },
            { name: 'block_hashes',     estimated_bytes: 3_200_000,  estimated_keys: 1247 },
            { name: 'tx_index',         estimated_bytes: 5_100_000,  estimated_keys: 3890 },
            { name: 'checksum_index',   estimated_bytes: 2_800_000,  estimated_keys: 2105 },
            { name: 'chain_state',      estimated_bytes: 4_096,      estimated_keys: 3 },
            { name: 'validator_state',  estimated_bytes: 12_288,     estimated_keys: 5 },
            { name: 'address_balances', estimated_bytes: 890_000,    estimated_keys: 412 },
            { name: 'address_history',  estimated_bytes: 2_340_000,  estimated_keys: 7820 },
            { name: 'bans',             estimated_bytes: 1_024,      estimated_keys: 2 },
            { name: 'peer_memory',      estimated_bytes: 48_000,     estimated_keys: 23 },
            { name: 'version_chain',    estimated_bytes: 680_000,    estimated_keys: 1540 },
            { name: 'publisher_index',  estimated_bytes: 374_592,    estimated_keys: 198 },
          ],
        };

      case 'noble_getStorageConfig':
        return this.#storageConfig || {
          data_dir: '~/.noble/data',
          cache_size_mb: 256,
          compression: true,
          pruning_mode: 'archive',
          keep_blocks: 10000,
          max_db_size_gb: 0,
          volumes: [],
        };

      case 'noble_setStorageConfig': {
        this.#storageConfig = {
          data_dir: params.data_dir || '~/.noble/data',
          cache_size_mb: params.cache_size_mb || 256,
          compression: params.compression !== false,
          pruning_mode: params.pruning_mode || 'archive',
          keep_blocks: params.keep_blocks || 10000,
          max_db_size_gb: params.max_db_size_gb || 0,
          volumes: params.volumes || [],
        };
        return { success: true };
      }

      case 'noble_checkDataDir': {
        const path = params.path || '';
        // Mock: always succeed with a simulated disk check
        return {
          exists: true,
          writable: true,
          available_bytes: 107_374_182_400, // ~100 GB
          error: null,
        };
      }

      case 'noble_setConfigValue': {
        const section = params.section || '';
        const key = params.key || '';
        const value = params.value || '';
        // Mock: accept any whitelisted section.key pair (matches backend whitelist)
        const whitelist = [
          ['network', 'listen_addr'], ['network', 'max_peers'],
          ['api', 'rpc_port'], ['api', 'gui_port'],
          ['storage', 'data_dir'], ['storage', 'cache_size_mb'], ['storage', 'compression'],
          ['storage', 'pruning_mode'], ['storage', 'keep_blocks'],
          ['security', 'encryption_mode'],
        ];
        if (!whitelist.some(([s, k]) => s === section && k === key)) {
          throw { code: -32602, message: `Config key not whitelisted: ${section}.${key}` };
        }
        return { success: true, restart_required: true };
      }

      case 'noble_getTotpStatus':
        return { enabled: false, scope: 'all' };

      case 'noble_enableTotp':
        return {
          secret_base32: 'JBSWY3DPEHPK3PXP',
          otpauth_uri: 'otpauth://totp/Noble:node?secret=JBSWY3DPEHPK3PXP&issuer=Noble',
        };

      case 'noble_getValidatorKeyInfo':
        return {
          enabled: true,
          pubkey_hex: '01' + randomHex(32),
          scheme: 'ed25519',
          key_path: '/data/noble/validator.key',
        };

      case 'noble_getGatewayInfo':
        return {
          enabled: true,
          gateway_key: '02' + randomHex(32),
          key_source: 'wallet_auto',
        };

      case 'noble_getTlsCertInfo':
        return {
          enabled: true,
          fingerprint: randomHex(32),
          expires_at: '2027-01-01T00:00:00Z',
          days_remaining: 300,
          sans: ['localhost', '127.0.0.1', '::1'],
          auto_generated: true,
          plaintext_mode: false,
        };

      case 'noble_regenerateTlsCert':
        return {
          fingerprint: randomHex(32),
          expires_at: '2028-01-01T00:00:00Z',
          restart_required: true,
        };

      case 'noble_uploadTlsCert':
        return {
          fingerprint: randomHex(32),
          expires_at: '2028-06-15T00:00:00Z',
          sans: ['mynode.example.com', '192.168.1.100'],
          auto_generated: false,
          restart_required: true,
        };

      case 'noble_getEncryptionStatus':
        return {
          mode: 'automatic',
          chain_meta_exists: true,
          is_locked: false,
        };

      case 'noble_setEncryptionMode': {
        const mode = params.mode || 'automatic';
        if (mode !== 'automatic' && mode !== 'manual') {
          throw { code: -32602, message: `Invalid mode: ${mode}` };
        }
        return {
          success: true,
          restart_required: true,
          message: `Encryption mode switched to '${mode}'. Restart recommended.`,
        };
      }

      case 'noble_getDetectedForks':
        return {
          local_height: 42,
          local_tip: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          peer_count: 5,
          highest_known: 58,
          forks: [
            { tip_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890', height: 42, peers: 3, is_local: true, agrees_with_local: true },
            { tip_hash: '9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba', height: 58, peers: 2, is_local: false, agrees_with_local: null },
          ],
        };

      case 'noble_getDiscoveredBlockchains':
        return {
          blockchains: [
            { chain_id: '0x34E9E7A4', peer_addresses: ['/ip4/192.168.1.100/tcp/8780'], first_seen: 1709712000, last_seen: 1709715600 },
          ],
        };

      case 'noble_resetChain':
        return { reset: true, previous_height: 42 };

      case 'noble_backupChain':
        return { path: '/tmp/noble-backup-20260304-120000.tar.gz', size_bytes: 8_347_291 };

      case 'noble_detectExternalIp':
        return { ip: '203.0.113.42', multiaddr: '/ip4/203.0.113.42/tcp/8780', source: 'https://ipinfo.io/ip' };

      case 'noble_dialPeer': {
        let addr = params.multiaddr || '';
        if (!addr.startsWith('/')) {
          addr = /[a-zA-Z]/.test(addr) ? `/dns4/${addr}/tcp/8780` : `/ip4/${addr}/tcp/8780`;
        }
        if (!/^\/(ip[46]|dns[46])\//.test(addr)) throw { code: -32602, message: 'Invalid multiaddr' };
        // Simulate adding a synthetic peer entry
        const dialPeerId = '12D3KooW' + randomHex(16).slice(0, 20) + 'XX';
        const dialNow = Math.floor(Date.now() / 1000);
        if (!this.#peers) this.#peers = [];
        this.#peers.push({
          peer_id: dialPeerId,
          direction: 'Outbound',
          addr,
          node_name: null,
          country_code: null,
          connected_at: dialNow,
          ban_score: 0,
          last_ban_reason: null,
        });
        // Also add to peer memory so they appear in candidates after announce
        if (!this.#peerMemory) this.#peerMemory = [];
        this.#peerMemory.push({
          identity_key: randomHex(32),
          first_seen: dialNow,
          last_seen: dialNow,
          connection_count: 1,
          peer_id: dialPeerId,
          last_addr: addr,
          node_name: null,
          org_type: null,
          node_role: 'FullNode',
          wants_to_validate: true,
          wants_to_vote: false,
        });
        return { success: true, message: `Connected to ${addr}` };
      }

      case 'noble_getSeeds':
        return { seeds: this._mockSeeds || [] };

      case 'noble_addSeed': {
        let seedAddr = params.multiaddr || '';
        if (!seedAddr.startsWith('/')) {
          seedAddr = /[a-zA-Z]/.test(seedAddr) ? `/dns4/${seedAddr}/tcp/8780` : `/ip4/${seedAddr}/tcp/8780`;
        }
        if (!/^\/(ip[46]|dns[46])\//.test(seedAddr)) throw { code: -32602, message: 'Invalid multiaddr' };
        if (!this._mockSeeds) this._mockSeeds = [];
        if (!this._mockSeeds.includes(seedAddr)) this._mockSeeds.push(seedAddr);
        return { seeds: [...this._mockSeeds] };
      }

      case 'noble_removeSeed': {
        const rmAddr = params.multiaddr || '';
        if (this._mockSeeds) this._mockSeeds = this._mockSeeds.filter(s => s !== rmAddr);
        return { seeds: this._mockSeeds ? [...this._mockSeeds] : [] };
      }

      case 'noble_rotateTotpSecret': {
        if (!params.current_code_hash || params.current_code_hash.length !== 64) {
          throw { code: -32012, message: 'authentication required' };
        }
        const newSecret = randomHex(20).toUpperCase();
        this.#totpSecret = newSecret;
        return {
          secret_base32: newSecret,
          otpauth_uri: `otpauth://totp/NOBLE:NOBLE%20Node?secret=${newSecret}&issuer=NOBLE&algorithm=SHA1&digits=6&period=30`,
        };
      }

      default:
        throw { code: -32601, message: `Method not found: ${method}` };
    }
  }

  _traceSessionRemaining() {
    if (!this._traceSession || !this._traceSession.expires_at) return null;
    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, this._traceSession.expires_at - now);
  }

  _generateTraceEntries(count, levelFilter, taskFilter) {
    const levels = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR'];
    const targets = [
      'noble_core::validation', 'noble_crypto::ed25519', 'noble_storage::rocks',
      'noble_mempool::pool', 'noble_consensus::cycle_engine', 'noble_network::service',
      'noble_api::server', 'noble_wallet::keystore', 'noble_node::node',
      'noble_consensus::vote_manager', 'noble_network::peer_manager',
    ];
    const tasks = [
      'block_validation', 'mempool_admit', 'consensus_step', 'peer_connect',
      'sync_headers', 'tx_verify', 'rpc_request', 'gossip_receive',
    ];
    const messages = [
      'Validating transaction T7: fee check passed',
      'Block #{{h}} committed to storage ({{n}} txs)',
      'Peer 12D3KooW...a3f2 connected (outbound)',
      'CycleEngine step: Proposals & Voting → Reflection & Propagation',
      'Mempool admit: 8-step validation passed for tx {{id}}',
      'Ed25519 signature verified in 0.12ms',
      'RPC request: noble_getBlockCount (2ms)',
      'GossipSub: received tx announcement from 3 peers',
      'Vote received for candidate block {{hash}}',
      'Headers-first sync: fetched 10 headers from peer',
      'Balance delta applied: +50000000 for validator key',
      'SigCache hit ratio: 94.2% (1847/1960)',
      'Evicted 3 expired transactions from mempool',
      'Peer ban score increased: +5 (invalid block)',
      'CBOR deserialization: 342 bytes in 0.08ms',
    ];

    const now = Math.floor(Date.now() / 1000);
    const entries = [];
    for (let i = 0; i < count; i++) {
      const seed = now * 100 + i;
      const level = levels[seed % 5 < 2 ? 2 : seed % 5]; // bias towards INFO
      if (levelFilter && level !== levelFilter) continue;
      const task = tasks[seed % tasks.length];
      if (taskFilter && task !== taskFilter) continue;

      const msg = messages[seed % messages.length]
        .replace('{{h}}', String(99 + (seed % 20)))
        .replace('{{n}}', String(1 + (seed % 15)))
        .replace('{{id}}', deterministicHash(seed).slice(0, 16))
        .replace('{{hash}}', deterministicHash(seed * 3).slice(0, 16));

      entries.push({
        timestamp: now - (count - i) * 2,
        level,
        target: targets[seed % targets.length],
        message: msg,
        fields: { task },
        span_stack: [],
      });
    }
    return entries.slice(-count);
  }

  #findBlock(heightOrHash) {
    if (typeof heightOrHash === 'number') {
      return this.#chain.blocks[heightOrHash];
    }
    return this.#chain.blocks.find(b => b._hash === heightOrHash);
  }

  #buildFeeHistogram() {
    const buckets = [
      { label: '1K-2K', min: 1000, max: 2000, count: 0 },
      { label: '2K-5K', min: 2000, max: 5000, count: 0 },
      { label: '5K-10K', min: 5000, max: 10000, count: 0 },
      { label: '10K-25K', min: 10000, max: 25000, count: 0 },
      { label: '25K+', min: 25000, max: Infinity, count: 0 },
    ];
    for (const entry of this.#mempool) {
      for (const bucket of buckets) {
        if (entry.fee >= bucket.min && entry.fee < bucket.max) {
          bucket.count++;
          break;
        }
      }
    }
    return buckets.map(b => ({ label: b.label, count: b.count }));
  }

  // Advance chain by one block (called by MockWsManager)
  _produceBlock() {
    const h = this.#chain.blocks.length;
    const prevHash = this.#chain.blocks[h - 1]._hash;
    const timestamp = Math.floor(Date.now() / 1000);
    const txCount = 1 + Math.floor(Math.random() * 10);
    const validatorSeed = (h % this.#validators.length) * 100;

    const transactions = [];
    for (let t = 0; t < txCount; t++) {
      const tx = makeTransaction(h * 100 + t, timestamp - 30 + t);
      transactions.push(tx);

      const txId = deterministicHash((h * 100 + t) * 23);
      this.#chain.txIndex.set(txId, { block_height: h, tx, tx_id: txId });

      if (!this.#chain.checksumIndex.has(tx.checksum)) this.#chain.checksumIndex.set(tx.checksum, []);
      this.#chain.checksumIndex.get(tx.checksum).push({
        block_height: h,
        tx_id: txId,
        timestamp: tx.timestamp,
      });

      // Update publisher index (notarization txs only)
      if (tx.tx_type === 0) {
        const signerHex = bytesToHexLocal(tx.publisher_sig.public_key);
        if (!this.#chain.publisherIndex.has(signerHex)) this.#chain.publisherIndex.set(signerHex, []);
        this.#chain.publisherIndex.get(signerHex).push({
          tx_id: txId,
          checksum: tx.checksum,
          block_height: h,
          timestamp: tx.timestamp,
          version: null,
        });
      }
    }

    const header = makeBlockHeader(h, prevHash, txCount, timestamp, validatorSeed);
    const blockHash = deterministicHash(h * 41);
    this.#chain.blocks.push({ header, transactions, _hash: blockHash });

    // Refresh mempool and peers
    this.#mempool = generateMempool(40 + Math.floor(Math.random() * 20), h);
    this.#peers = makePeers(h);

    return { header, transactions, hash: blockHash };
  }

  // Add a pending tx to the mempool (called by MockWsManager)
  _addPendingTx() {
    const now = Math.floor(Date.now() / 1000);
    const seed = now * 1000 + Math.floor(Math.random() * 1000);
    const tx = makeTransaction(seed, now);
    // Mempool computes fee from UTXO lookups (implicit in UTXO model)
    const mempoolFee = MIN_TX_FEE + Math.floor(Math.abs(Math.sin(seed)) * 50000);
    const entry = {
      tx,
      tx_id: deterministicHash(seed * 29),
      size_bytes: 256 + Math.floor(Math.random() * 512),
      fee: mempoolFee,
      received_at: now,
    };
    this.#mempool.unshift(entry);
    if (this.#mempool.length > 80) this.#mempool.pop();
    return entry;
  }
}

// ── MockWsManager ──

export class MockWsManager {
  #handlers = new Map();
  #intervals = [];
  #rpc;
  #onStatusChange = null;

  constructor(rpc, { onStatusChange } = {}) {
    this.#rpc = rpc;
    this.#onStatusChange = onStatusChange;
  }

  connect() {
    // Simulate connection
    this.#onStatusChange?.('connecting');
    setTimeout(() => this.#onStatusChange?.('connected'), 200);

    // Produce a new block every 30 seconds
    this.#intervals.push(setInterval(() => {
      const block = this.#rpc._produceBlock();
      const handler = this.#handlers.get('newBlocks');
      if (handler) handler(block);
    }, 30_000));

    // Mempool stats every 10 seconds
    this.#intervals.push(setInterval(async () => {
      const handler = this.#handlers.get('mempoolStats');
      if (handler) {
        const info = await this.#rpc.call('noble_getMempoolInfo');
        handler(info);
      }
    }, 10_000));

    // New transactions every 5 seconds
    this.#intervals.push(setInterval(() => {
      const entry = this.#rpc._addPendingTx();
      const handler = this.#handlers.get('newTransactions');
      if (handler) handler(entry);
    }, 5_000));

    // Cycle phase change (check every second, fire on change)
    let lastPhase = null;
    this.#intervals.push(setInterval(async () => {
      const handler = this.#handlers.get('cyclePhaseChange');
      if (handler) {
        const status = await this.#rpc.call('noble_getCycleStatus');
        if (status.phase !== lastPhase) {
          lastPhase = status.phase;
          handler(status);
        }
      }
    }, 1_000));
  }

  subscribe(topic, callback) {
    this.#handlers.set(topic, callback);
  }

  unsubscribe(topic) {
    this.#handlers.delete(topic);
  }

  disconnect() {
    for (const id of this.#intervals) clearInterval(id);
    this.#intervals = [];
    this.#onStatusChange?.('disconnected');
  }
}
