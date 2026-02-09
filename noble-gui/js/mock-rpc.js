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

function makeTransaction(seed, timestamp) {
  const fee = MIN_TX_FEE + Math.floor(Math.abs(Math.sin(seed)) * 50000);
  const docTypes = ['certificate', 'diploma', 'contract', 'invoice', 'receipt', 'deed', 'license', 'patent'];
  const metadata = [makeMetadataEntry(docTypes[seed % docTypes.length])];

  if (seed % 3 === 0) {
    metadata.push({
      key: 'issuer',
      value: Array.from(new TextEncoder().encode(`org-${seed % 100}`)),
    });
  }

  return {
    version: PROTOCOL_VERSION,
    checksum: deterministicHash(seed * 17),
    timestamp,
    fee,
    publisher_sig: makeSignatureEnvelope(seed),
    additional_sigs: seed % 4 === 0 ? [makeSignatureEnvelope(seed + 1000)] : [],
    metadata,
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

  constructor({ latencyMin = 50, latencyMax = 150 } = {}) {
    const { blocks, txIndex, checksumIndex } = generateChain(100);
    this.#chain = { blocks, txIndex, checksumIndex };
    this.#mempool = generateMempool(50, 99);
    this.#peers = makePeers(99);
    this.#validators = [...VALIDATORS]; // mutable copy per instance
    this.#latencyMin = latencyMin;
    this.#latencyMax = latencyMax;
  }

  get chainHeight() {
    return this.#chain.blocks.length - 1;
  }

  async call(method, params = {}) {
    // Simulate network latency
    await new Promise(r =>
      setTimeout(r, this.#latencyMin + Math.random() * (this.#latencyMax - this.#latencyMin))
    );

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
          rpc_port: 9332,
          ws_port: 9334,
          p2p_port: 9333,
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

        // For each won block: one subsidy tx + one fee_income tx
        for (const h of blocksWon) {
          const block = this.#chain.blocks[h];
          if (!block) continue;
          const feeIncome = block.transactions.reduce((s, tx) => s + tx.fee, 0);
          const confirmations = chainHeight - h;

          runningBalance += subsidyPerBlock;
          txs.push({
            type: 'subsidy',
            direction: 'incoming',
            amount: subsidyPerBlock,
            running_balance: runningBalance,
            timestamp: block.header.timestamp,
            block_height: h,
            tx_id: deterministicHash(h * 41 + 7777),
            description: `Block #${h} validation reward`,
            confirmations,
            status: confirmations >= 6 ? 'confirmed' : 'pending',
          });

          if (feeIncome > 0) {
            runningBalance += feeIncome;
            txs.push({
              type: 'fee_income',
              direction: 'incoming',
              amount: feeIncome,
              running_balance: runningBalance,
              timestamp: block.header.timestamp + 1,
              block_height: h,
              tx_id: deterministicHash(h * 41 + 8888),
              description: `Block #${h} tx fees (${block.transactions.length} txs)`,
              confirmations,
              status: confirmations >= 6 ? 'confirmed' : 'pending',
            });
          }
        }

        // Add a few outgoing transfers (sent to other addresses)
        const outgoing = [
          { amount: 200_000_000, desc: 'Transfer to cold storage', ago: 86400 * 5, id: 1001 },
          { amount: 150_000_000, desc: 'Operational payment', ago: 86400 * 3, id: 1002 },
          { amount: 100_000_000, desc: 'Transfer to exchange', ago: 86400, id: 1003 },
          { amount: 50_000_000, desc: 'Service fee payment', ago: 3600 * 6, id: 1004 },
        ];

        for (const out of outgoing) {
          runningBalance -= out.amount;
          txs.push({
            type: 'transfer_out',
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

        // Add one incoming transfer (received from another wallet)
        runningBalance += 25_000_000;
        txs.push({
          type: 'transfer_in',
          direction: 'incoming',
          amount: 25_000_000,
          running_balance: runningBalance,
          timestamp: now - 86400 * 2,
          block_height: chainHeight - 96,
          tx_id: deterministicHash(2001 * 9999),
          description: 'Received from noble1a8f3...c2d1',
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

      default:
        throw { code: -32601, message: `Method not found: ${method}` };
    }
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
