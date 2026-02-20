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

// ── Constants (from noble-core/src/constants.rs) ──
const MAINNET_CHAIN_ID = 0x4E4F424C;
const CYCLE_DURATION_SECS = 1800;
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
  return { Ed25519: bytes };
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

  return {
    version: PROTOCOL_VERSION,
    checksum: deterministicHash(seed * 17),
    timestamp,
    fee,
    publisher_sig: makeSignatureEnvelope(seed),
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

  return {
    public_key: makePublicKey(i * 100),
    name: VALIDATOR_NAMES[i],
    status: isOnline ? 'online' : 'offline',
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
  };
});

// ── Mock Peers ──

const PEER_IDS = Array.from({ length: 23 }, (_, i) =>
  `12D3KooW${randomHex(16).slice(0, 20)}${i.toString().padStart(2, '0')}`
);

function makePeers(chainHeight) {
  return PEER_IDS.map((peerId, i) => ({
    peer_id: peerId,
    direction: i < 8 ? 'Outbound' : 'Inbound',
    ban_score: i === 22 ? 15 : i === 21 ? 5 : 0,
    chain_tip: [chainHeight - (i % 3), deterministicHash(chainHeight - (i % 3))],
    latency_ms: 20 + Math.floor(Math.random() * 180),
  }));
}

// ── Generate Linked Chain ──

function generateChain(numBlocks) {
  const blocks = [];
  const txIndex = new Map();    // tx_id → { block_height, tx }
  const checksumIndex = new Map(); // checksum → [{ block_height, tx_id, timestamp }]

  let prevHash = '0'.repeat(64); // genesis prev_block_hash

  for (let h = 0; h < numBlocks; h++) {
    const timestamp = GENESIS_TIMESTAMP + h * CYCLE_DURATION_SECS;
    const txCount = 1 + Math.floor(Math.abs(Math.sin(h * 0.7)) * 15);
    const validatorSeed = (h % VALIDATORS.length) * 100;

    const transactions = [];
    for (let t = 0; t < txCount; t++) {
      const tx = makeTransaction(h * 100 + t, timestamp - 60 + t);
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
      });
    }

    const header = makeBlockHeader(h, prevHash, txCount, timestamp, validatorSeed);
    const blockHash = deterministicHash(h * 41);
    blocks.push({ header, transactions, _hash: blockHash });

    prevHash = blockHash;
  }

  return { blocks, txIndex, checksumIndex };
}

// ── Generate Mock Mempool ──

function generateMempool(count, chainHeight) {
  const now = Math.floor(Date.now() / 1000);
  const entries = [];
  for (let i = 0; i < count; i++) {
    const seed = chainHeight * 1000 + i;
    const tx = makeTransaction(seed, now - Math.floor(Math.random() * 300));
    entries.push({
      tx,
      tx_id: deterministicHash(seed * 29),
      size_bytes: 256 + Math.floor(Math.random() * 512),
      fee: tx.fee,
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

  constructor({ latencyMin = 50, latencyMax = 150 } = {}) {
    const { blocks, txIndex, checksumIndex } = generateChain(100);
    this.#chain = { blocks, txIndex, checksumIndex };
    this.#mempool = generateMempool(50, 99);
    this.#peers = makePeers(99);
    this.#validators = [...VALIDATORS]; // mutable copy per instance
    this.#latencyMin = latencyMin;
    this.#latencyMax = latencyMax;
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
        const start = params.start ?? 0;
        const end = Math.min(params.end ?? start + 49, this.chainHeight);
        return this.#chain.blocks.slice(start, end + 1).map(b => ({
          header: b.header,
          hash: b._hash,
        }));
      }

      case 'noble_getChainStats': {
        const totalTx = this.#chain.blocks.reduce((s, b) => s + b.transactions.length, 0);
        return {
          chain_id: MAINNET_CHAIN_ID,
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
        if (!records || records.length === 0) return { found: false, records: [] };
        return { found: true, records };
      }

      case 'noble_verifyDocument': {
        const records = this.#chain.checksumIndex.get(params.checksum);
        return {
          checksum: params.checksum,
          registered: !!records && records.length > 0,
          registrations: records || [],
          first_seen: records?.[0]?.timestamp ?? null,
        };
      }

      case 'noble_getDocumentHistory': {
        const records = this.#chain.checksumIndex.get(params.checksum);
        return { checksum: params.checksum, history: records || [] };
      }

      case 'noble_decryptLocator': {
        const entry = this.#chain.txIndex.get(params.tx_id);
        if (!entry) throw { code: -32602, message: 'Transaction not found' };
        if (!entry.tx.has_encrypted_locator) {
          throw { code: -32602, message: 'Transaction has no encrypted locator' };
        }
        // Mock: return a deterministic URL based on the checksum
        const mockUrl = `https://storage.example.com/docs/${entry.tx.checksum.slice(0, 16)}.pdf`;
        return { tx_id: params.tx_id, plaintext: mockUrl };
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
          protocol_version: PROTOCOL_VERSION,
          chain_id: MAINNET_CHAIN_ID,
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
        const exists = this.#validators.find(v => {
          const k = v.public_key.Ed25519 || v.public_key.Secp256k1 || [];
          return k.map(b => b.toString(16).padStart(2, '0')).join('') === hexKey;
        });
        if (exists) throw { code: -32602, message: `Validator already in list: ${exists.name}` };
        const now = Math.floor(Date.now() / 1000);
        const newValidator = {
          public_key: { Ed25519: keyBytes },
          name: params.name || `validator-${hexKey.slice(0, 8)}`,
          status: 'online',
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
        };
        this.#validators.push(newValidator);
        return { success: true, validator: newValidator };
      }

      case 'noble_removeValidator': {
        const pubkey = params.public_key;
        const idx = this.#validators.findIndex(v => {
          const k = v.public_key.Ed25519 || v.public_key.Secp256k1 || [];
          return k.map(b => b.toString(16).padStart(2, '0')).join('') === pubkey;
        });
        if (idx === -1) throw { code: -32602, message: 'Validator not found in list' };
        const removed = this.#validators.splice(idx, 1)[0];
        return { success: true, removed_name: removed.name };
      }

      case 'noble_getReputationScore': {
        const validator = this.#validators.find(v => {
          const key = v.public_key.Ed25519 || v.public_key.Secp256k1 || [];
          const hex = key.map(b => b.toString(16).padStart(2, '0')).join('');
          return hex === params.pubkey;
        });
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
        const phaseIndex = Math.floor(elapsed / phaseLen);
        const phases = ['Proposal', 'Voting', 'Confirmation', 'Finalization'];
        const remaining = phaseLen - (elapsed % phaseLen);
        const cycleRemaining = CYCLE_DURATION_SECS - elapsed;
        return {
          phase: phases[phaseIndex],
          phase_index: phaseIndex,
          phase_remaining_secs: remaining,
          cycle_remaining_secs: cycleRemaining,
          cycle_number: Math.floor(now / CYCLE_DURATION_SECS),
          current_validator: this.#validators[0].public_key,
        };
      }

      case 'noble_getCycleHistory': {
        const now = Math.floor(Date.now() / 1000);
        const currentCycle = Math.floor(now / CYCLE_DURATION_SECS);
        const elapsed = now % CYCLE_DURATION_SECS;
        const phaseLen = CYCLE_DURATION_SECS / 4;
        const currentPhaseIndex = Math.floor(elapsed / phaseLen);

        // Generate history for last 3 cycles (current + 2 past)
        const cycles = [];
        for (let offset = 2; offset >= 0; offset--) {
          const cn = currentCycle - offset;
          const isCurrent = offset === 0;

          // Deterministic proposals per cycle based on cycle number
          const proposerCount = (cn % 3 === 0) ? 3 : (cn % 3 === 1) ? 1 : 2;
          const proposals = [];
          for (let p = 0; p < proposerCount; p++) {
            const onlineVals = this.#validators.filter(v => v.status === 'online');
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
          const disambiguation = proposals.length > 1;

          // Build phase states for the cycle
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
              name: ['Proposal', 'Voting', 'Confirmation', 'Finalization'][ph],
              state,
            };

            if (ph === 0) {
              phaseData.proposals = proposals.map(p => ({
                validator: p.validator,
                tx_count: p.tx_count,
                block_hash: p.block_hash,
              }));
            } else if (ph === 1) {
              phaseData.votes = state !== 'pending' ? votes : [];
              phaseData.total_voters = state !== 'pending' ? 23 : 0;
            } else if (ph === 2) {
              phaseData.winner = state !== 'pending' ? winner.validator : null;
              phaseData.winning_hash = state !== 'pending' ? winner.block_hash : null;
              phaseData.disambiguation = disambiguation;
            } else if (ph === 3) {
              phaseData.finalized = state === 'complete';
              phaseData.block_hash = state === 'complete' ? winner.block_hash : null;
            }

            phaseStates.push(phaseData);
          }

          cycles.push({
            cycle_number: cn,
            is_current: isCurrent,
            status: isCurrent ? 'active' : 'finalized',
            phases: phaseStates,
            proposals_count: proposals.length,
            disambiguation,
            winner: isCurrent && currentPhaseIndex < 2 ? null : winner.validator,
            winning_hash: isCurrent && currentPhaseIndex < 2 ? null : winner.block_hash,
          });
        }

        return { cycles };
      }

      case 'noble_getNodeInfo':
        return {
          version: '0.1.0',
          protocol_version: PROTOCOL_VERSION,
          chain_id: MAINNET_CHAIN_ID,
          uptime_secs: 86400 * 3 + 7200 + 1800,
          storage_bytes: 256 * 1024 * 1024,
          storage_capacity_bytes: 1024 * 1024 * 1024,
          rpc_port: 8783,
          ws_port: 8784,
          p2p_port: 8780,
          data_dir: '/var/noble/data',
        };

      case 'noble_getWalletInfo': {
        const walletKey = this.#validators[0].public_key;
        const keyBytes = walletKey.Ed25519 || walletKey.Secp256k1 || [];
        const keyHex = keyBytes.map(b => b.toString(16).padStart(2, '0')).join('');
        // Address = first 20 bytes of public key hex, prefixed with "noble1"
        const address = 'noble1' + keyHex.slice(0, 40);
        const blocksValidated = this.#validators[0].blocks_produced;
        // Subsidy: 50 NOBLE (50_000_000 atomic) per block
        const subsidyPerBlock = 50_000_000;
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

      case 'noble_getWalletTransactions': {
        const txs = [];
        const now = Math.floor(Date.now() / 1000);
        const chainHeight = this.chainHeight;
        const subsidyPerBlock = 50_000_000;
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
          const totalFees = block.transactions.reduce((s, tx) => s + tx.fee, 0);
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
          { amount: 150_000_000, desc: 'Payment to noble1c3d8...e2b7', ago: 86400 * 3, id: 1002, type: 'payment_sent' },
          { amount: 1_050_000, desc: 'Document registration: a8f3c2d1...', ago: 86400 * 2, id: 1005, type: 'doc_registration' },
          { amount: 100_000_000, desc: 'Payment to noble1d9f1...a3c5', ago: 86400, id: 1003, type: 'payment_sent' },
          { amount: 1_050_000, desc: 'Document registration: 7b2e9f04...', ago: 3600 * 12, id: 1006, type: 'doc_registration' },
          { amount: 50_000_000, desc: 'Payment to noble1e4a7...d8f2', ago: 3600 * 6, id: 1004, type: 'payment_sent' },
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
        return {
          node_name: 'noble-dev-01',
          org_type: 'Individual',
          org_name: '',
          node_role: 'FullNode',
          contact_email: '',
          website: '',
          host_address: '',
          governance_class: 'individual',
          wants_to_validate: false,
          wants_to_vote: false,
          pki_attestation: null,
          pkcs12_configured: false,
        };

      case 'noble_setNodeIdentity':
        return { success: true };

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
        const now = Math.floor(Date.now() / 1000);
        return [
          {
            identity_key: randomHex(32),
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
            identity_key: randomHex(32),
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
            identity_key: randomHex(32),
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
            identity_key: randomHex(32),
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
            identity_key: randomHex(32),
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
            identity_key: randomHex(32),
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
        return {
          mnemonic: words.join(' '),
          address: '02' + randomHex(32),
          scheme_id: 2,
          word_count: wc,
        };
      }

      case 'noble_importMnemonic': {
        const words = (params.mnemonic || '').trim().split(/\s+/);
        if (words.length !== 12 && words.length !== 24) {
          throw { code: -32602, message: 'Mnemonic must be 12 or 24 words' };
        }
        return {
          address: '02' + randomHex(32),
          scheme_id: 2,
          already_exists: Math.random() > 0.5,
        };
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
      'CycleEngine step: Proposal → Voting',
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
    const entry = {
      tx,
      tx_id: deterministicHash(seed * 29),
      size_bytes: 256 + Math.floor(Math.random() * 512),
      fee: tx.fee,
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
