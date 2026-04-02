// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction (T1-T17) and block (B1-B12) validation pipelines.

use std::collections::HashSet;

use noble_codec::NobleCbor;
use noble_crypto::{is_recognized_scheme, Hash256, NoblePublicKey, SCHEME_BIP137};

use crate::block::{Block, BlockHeader};
use crate::constants::*;
use crate::error::ValidationError;
use crate::merkle::compute_merkle_root;
use crate::metadata::{validate_metadata, validate_version_metadata};
use crate::transaction::Transaction;

/// Temporal context for validation — determines how time-dependent checks
/// (T4, T-EXPIRY, B6, B13) are evaluated.
#[derive(Debug, Clone, Copy)]
pub enum TimeContext {
    /// Live proposals: wall clock is the reference for all time checks.
    /// T4:  abs_diff(tx.timestamp, wall_clock) ≤ MAX_TX_TIMESTAMP_SKEW
    /// T-EXPIRY: wall_clock > expires_at → reject
    /// B6:  block.timestamp within ±skew of wall_clock
    /// B13: median check active
    RealTime { wall_clock: u64 },

    /// Historical sync imports: the block's own timestamp is the canonical
    /// reference for T4 and T-EXPIRY.  Wall clock used only for B6 future-guard.
    /// T4:  abs_diff(tx.timestamp, block_time) ≤ SYNC_TX_TIMESTAMP_TOLERANCE
    /// T-EXPIRY: skipped (proposer validated at creation time)
    /// B6:  block.timestamp ≤ wall_clock + SYNC_BLOCK_FUTURE_TOLERANCE (future only)
    /// B13: skipped (recent timestamps unreliable after rollback)
    Historical { block_time: u64, wall_clock: u64 },
}

/// Relaxed T4 tolerance for historical sync imports (2h vs 1h real-time).
pub const SYNC_TX_TIMESTAMP_TOLERANCE: u64 = 7200;
/// Relaxed B6 future tolerance for historical sync imports (10min vs 5min real-time).
pub const SYNC_BLOCK_FUTURE_TOLERANCE: u64 = 600;

/// Context needed for transaction validation.
pub struct TxValidationContext {
    /// Chain ID for tx_id computation.
    pub chain_id: u32,
    /// Temporal context: real-time (wall clock) or historical (block timestamp).
    pub time_context: TimeContext,
    /// Current chain height (for activation-gated rules like T32).
    pub chain_height: u64,
}

/// Context needed for block validation.
pub struct BlockValidationContext<'a> {
    /// Chain ID for tx_id computation.
    pub chain_id: u32,
    /// Temporal context: real-time (wall clock) or historical (block timestamp).
    pub time_context: TimeContext,
    /// Parent block header (None for genesis).
    pub parent: Option<&'a BlockHeader>,
    /// The node's local trusted validator list.
    pub validator_list: &'a [NoblePublicKey],
}

/// Validate a BIP-137 (Bitcoin Signed Message) signature on a transaction (T26).
///
/// BIP-137 transactions use a recoverable signature format where the public key
/// is recovered from the signature itself. The message being signed is a canonical
/// string constructed from the transaction fields, hashed with the Bitcoin double-SHA256
/// message format.
///
/// Checks:
/// - scheme_id == SCHEME_BIP137 (0x03)
/// - Signature length == 65 bytes
/// - Message is reconstructed from tx fields
/// - Public key is recovered from the recoverable signature
/// - Recovered key matches the declared public key
fn validate_bip137_signature(tx: &Transaction, _chain_id: u32) -> Result<(), ValidationError> {
    use noble_crypto::bip137;

    let sig = &tx.issuer_sig;

    // Ensure correct scheme
    if sig.scheme_id != SCHEME_BIP137 {
        return Err(ValidationError::IssuerSigInvalid(
            "T26: expected SCHEME_BIP137 (0x03)".to_string(),
        ));
    }

    // Signature must be exactly 65 bytes
    if sig.signature.len() != bip137::BIP137_SIG_LEN {
        return Err(ValidationError::IssuerSigInvalid(format!(
            "T26: BIP-137 signature must be {} bytes, got {}",
            bip137::BIP137_SIG_LEN,
            sig.signature.len()
        )));
    }

    // Reconstruct the canonical message from tx fields (UTXO model).
    // For BIP-137, we use output[0] as recipient and total_output_value as amount.
    // Fee is implicit (not in the BIP-137 message — the signature commits via SigningPayload).
    let is_transfer_msg = crate::tx_types::handler_for(tx.tx_type)
        .map_or(false, |h| h.uses_transfer_bip137_message());
    let message = if is_transfer_msg {
        let recipient_hex = tx.outputs.first()
            .map(|o| hex::encode(o.address.to_wire_bytes()))
            .unwrap_or_default();
        let amount = tx.outputs.first().map_or(0, |o| o.value);
        bip137::transfer_message(
            &recipient_hex,
            amount,
            tx.timestamp,
            0, // fee is implicit in UTXO model
            tx.version,
        )
    } else {
        bip137::notarization_message(&tx.checksum.to_string(), tx.timestamp, 0, tx.version)
    };

    // Recover the public key from the BIP-137 signature
    let recovered_pk = bip137::verify_bip137(&sig.signature, &message)
        .map_err(|e| ValidationError::IssuerSigInvalid(format!("T26: {e}")))?;

    // Compare recovered key with declared public key
    if recovered_pk != sig.public_key {
        return Err(ValidationError::IssuerSigInvalid(
            "T26: recovered public key does not match declared signer".to_string(),
        ));
    }

    Ok(())
}

/// Validate transaction size limits and counts (T1, T7b, T8b).
fn validate_tx_size_and_counts(tx: &Transaction) -> Result<(), ValidationError> {
    // T7b: Limit on additional signatures (C-sigs) — cheap check before serialization
    if tx.additional_sigs.len() > MAX_ADDITIONAL_SIGS {
        return Err(ValidationError::TooManyAdditionalSigs {
            count: tx.additional_sigs.len(),
            max: MAX_ADDITIONAL_SIGS,
        });
    }
    tracing::trace!("T7b: additional sigs count check passed");

    // T8b: Limit on metadata entries (C-meta) — cheap check before serialization
    if tx.metadata.len() > MAX_METADATA_ENTRIES {
        return Err(ValidationError::TooManyMetadataEntries {
            count: tx.metadata.len(),
            max: MAX_METADATA_ENTRIES,
        });
    }
    tracing::trace!("T8b: metadata entries count check passed");

    // T1: Size check (serde CBOR — conservative ceiling; C encoder produces
    // slightly smaller output, so passing this check guarantees passing C-based
    // size checks. Cannot use noble-tx-core here due to cyclic dependency.)
    let serialized = tx.to_cbor().map_err(|e| {
        tracing::debug!("transaction serialization failed: {e}");
        ValidationError::Internal("transaction serialization failed".into())
    })?;
    if serialized.len() > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size: serialized.len(),
            max: MAX_TX_SIZE,
        });
    }
    tracing::trace!(size = serialized.len(), "T1: size check passed");

    Ok(())
}

/// Validate transaction protocol fields (T2, T4, T5).
fn validate_tx_protocol_fields(
    tx: &Transaction,
    ctx: &TxValidationContext,
) -> Result<(), ValidationError> {
    // T2: Version check
    if tx.version != PROTOCOL_VERSION {
        return Err(ValidationError::UnknownVersion(tx.version));
    }
    tracing::trace!("T2: version check passed");

    // T3: Checksum is [u8; 32] — enforced at compile time by Hash256
    tracing::trace!("T3: checksum type enforced at compile time");

    // T4: Timestamp skew — reference time depends on context.
    match ctx.time_context {
        TimeContext::RealTime { wall_clock } => {
            let diff = tx.timestamp.abs_diff(wall_clock);
            if diff > MAX_TX_TIMESTAMP_SKEW {
                return Err(ValidationError::TimestampOutOfRange {
                    tx_time: tx.timestamp,
                    current_time: wall_clock,
                    max_skew: MAX_TX_TIMESTAMP_SKEW,
                });
            }
            tracing::trace!(skew = diff, "T4: timestamp skew check passed (real-time)");
        }
        TimeContext::Historical { block_time, .. } => {
            // Validate tx was fresh when the block was created (relaxed tolerance).
            let diff = tx.timestamp.abs_diff(block_time);
            if diff > SYNC_TX_TIMESTAMP_TOLERANCE {
                return Err(ValidationError::TimestampOutOfRange {
                    tx_time: tx.timestamp,
                    current_time: block_time,
                    max_skew: SYNC_TX_TIMESTAMP_TOLERANCE,
                });
            }
            tracing::trace!(skew = diff, "T4: timestamp skew check passed (historical)");
        }
    }

    // T5: Issuer scheme recognized
    if !is_recognized_scheme(tx.issuer_sig.scheme_id) {
        return Err(ValidationError::UnrecognizedScheme(
            tx.issuer_sig.scheme_id,
        ));
    }
    tracing::trace!(
        scheme_id = tx.issuer_sig.scheme_id,
        "T5: issuer scheme recognized"
    );

    Ok(())
}

/// Validate transaction signatures (T6, T7, T26).
fn validate_tx_signatures(
    tx: &Transaction,
    ctx: &TxValidationContext,
) -> Result<(), ValidationError> {
    // AUD3-D7: Chain-aware signing message prevents cross-chain replay.
    let signing_msg = tx
        .compute_signing_message_for_chain(ctx.chain_id)
        .map_err(|e| {
            tracing::debug!("signing message computation failed: {e}");
            ValidationError::Internal("signing message computation failed".into())
        })?;

    // T6/T26: Issuer signature verification
    if tx.issuer_sig.scheme_id == SCHEME_BIP137 {
        // T26: BIP-137 recoverable signature — uses Bitcoin Signed Message format
        validate_bip137_signature(tx, ctx.chain_id)?;
        tracing::trace!("T26: BIP-137 issuer signature verified");
    } else {
        tx.issuer_sig
            .verify_standalone(&signing_msg)
            .map_err(|e| {
                tracing::debug!("issuer signature verification failed: {e}");
                ValidationError::IssuerSigInvalid("signature verification failed".into())
            })?;
        tracing::trace!("T6: issuer signature verified");
    }

    // T7: Additional signature verification
    for (i, sig) in tx.additional_sigs.iter().enumerate() {
        if !is_recognized_scheme(sig.scheme_id) {
            return Err(ValidationError::AdditionalSigInvalid {
                index: i,
                reason: format!("unrecognized scheme {:#04x}", sig.scheme_id),
            });
        }
        sig.verify_standalone(&signing_msg).map_err(|e| {
            tracing::debug!("additional signature {i} verification failed: {e}");
            ValidationError::AdditionalSigInvalid {
                index: i,
                reason: "signature verification failed".into(),
            }
        })?;
    }
    tracing::trace!(
        count = tx.additional_sigs.len(),
        "T7: additional signatures verified"
    );

    Ok(())
}

/// Validate transaction type constraints and advanced fields (T13-T25).
///
/// Uses the [`tx_types`] registry to look up per-type rules instead of
/// hardcoded if-chains. See `noble-core/src/tx_types/` for each handler.
fn validate_tx_type_and_advanced(tx: &Transaction) -> Result<(), ValidationError> {
    // T13: tx_type must be recognized
    let handler = crate::tx_types::handler_for(tx.tx_type)
        .ok_or(ValidationError::UnknownTxType(tx.tx_type))?;
    tracing::trace!(tx_type = tx.tx_type, name = handler.name(), "T13: tx_type recognized");

    // U4: Coinbase must have exactly one null input
    if handler.is_coinbase() {
        if tx.inputs.len() != 1 || !tx.inputs[0].prev_output.is_coinbase() {
            return Err(ValidationError::Internal("U4: coinbase must have exactly one null input".into()));
        }
    }

    // U10: Non-coinbase must NOT have null inputs
    if !handler.is_coinbase() {
        for input in &tx.inputs {
            if input.prev_output.is_coinbase() {
                return Err(ValidationError::Internal("U10: non-coinbase tx has null input".into()));
            }
        }
    }

    // U1b: Input count limit (DoS prevention — limits UTXO lookup cost per tx).
    if tx.inputs.len() > crate::constants::MAX_TX_INPUTS {
        return Err(ValidationError::Internal(format!(
            "U1b: too many inputs ({}, max {})", tx.inputs.len(), crate::constants::MAX_TX_INPUTS
        )));
    }

    // U1c: Output count limit (UTXO set pollution prevention).
    if tx.outputs.len() > crate::constants::MAX_TX_OUTPUTS {
        return Err(ValidationError::Internal(format!(
            "U1c: too many outputs ({}, max {})", tx.outputs.len(), crate::constants::MAX_TX_OUTPUTS
        )));
    }

    // U2: No duplicate inputs within transaction
    {
        let mut seen = HashSet::new();
        for input in &tx.inputs {
            if !seen.insert(&input.prev_output) {
                return Err(ValidationError::Internal("U2: duplicate input outpoint".into()));
            }
        }
    }

    // U8: All output values must be > 0 and <= MAX_SUPPLY
    for out in &tx.outputs {
        if out.value == 0 {
            return Err(ValidationError::Internal("U7: output value is zero".into()));
        }
        if out.value > MAX_SUPPLY {
            return Err(ValidationError::Internal("U8: output value exceeds MAX_SUPPLY".into()));
        }
    }

    // Type-driven output requirement
    if handler.requires_outputs() && tx.outputs.is_empty() {
        return Err(ValidationError::TransferMissingRecipient);
    }

    // Non-coinbase must have at least one input
    if !handler.is_coinbase() && tx.inputs.is_empty() {
        return Err(ValidationError::Internal("non-coinbase tx has no inputs".into()));
    }

    // Type-driven checksum rules
    if handler.requires_zero_checksum() && tx.checksum != Hash256::ZERO {
        return Err(ValidationError::NonDocumentWithChecksum(tx.tx_type));
    }
    if handler.requires_checksum() && tx.checksum == Hash256::ZERO {
        return Err(ValidationError::NotarizationWithZeroChecksum);
    }
    tracing::trace!("T27/T28: checksum rules passed");

    // T22: encrypted_locator only allowed when handler permits
    if !handler.allows_encrypted_locator() && tx.encrypted_locator.is_some() {
        return Err(ValidationError::LocatorOnNonNotarization);
    }
    tracing::trace!("T22: encrypted_locator check passed");

    // T23: external_attestations only allowed when handler permits
    if !handler.allows_external_attestations() && !tx.external_attestations.is_empty() {
        return Err(ValidationError::AttestationsOnNonNotarization);
    }
    tracing::trace!("T23: external_attestations check passed");

    // T33: contract_data only allowed when handler permits
    if !handler.allows_contract_data() && tx.contract_data.is_some() {
        return Err(ValidationError::Internal("contract_data not allowed on this tx type".into()));
    }
    tracing::trace!("T33: contract_data check passed");

    // T25: Gateway address wire bytes validation
    // Use NobleAddress (not NoblePublicKey) to accept Bitcoin prefixes 0x80/0x81
    if let Some(ref gw) = tx.gateway_address {
        crate::NobleAddress::from_wire_bytes(gw).map_err(|e| {
            tracing::debug!("gateway address validation failed: {e}");
            ValidationError::InvalidGatewayAddress("invalid address wire bytes".into())
        })?;
    }
    tracing::trace!("T25: gateway_address check passed");

    Ok(())
}

/// Validate a transaction against rules T1-T17.
///
/// Returns Ok(()) if all checks pass, or the first validation error encountered.
#[tracing::instrument(skip(tx, ctx), fields(task = "tx_validation"))]
pub fn validate_transaction(
    tx: &Transaction,
    claimed_tx_id: &noble_crypto::Hash256,
    ctx: &TxValidationContext,
) -> Result<(), ValidationError> {
    // T-EXPIRY: Reject expired transactions.
    // In Historical mode, skip — the proposer enforced T-EXPIRY at creation time.
    // Post-sync verification catches any inconsistency via peer alignment.
    if let TimeContext::RealTime { wall_clock } = ctx.time_context {
        if let Some(expires_at) = tx.expires_at {
            if wall_clock > expires_at {
                return Err(ValidationError::Internal(format!(
                    "transaction expired: expires_at={expires_at}, current_time={wall_clock}",
                )));
            }
        }
    }

    validate_tx_size_and_counts(tx)?;
    validate_tx_protocol_fields(tx, ctx)?;
    validate_tx_signatures(tx, ctx)?;

    // T8: Metadata bounds validation (T9 duplicate-key check removed by decree)
    validate_metadata(&tx.metadata)?;
    tracing::trace!("T8: metadata validation passed");

    // T29/T30: Version metadata validation (only for types with version chains)
    if crate::tx_types::handler_for(tx.tx_type).map_or(false, |h| h.validates_version_chain()) {
        validate_version_metadata(&tx.metadata)?;
        tracing::trace!("T29/T30: version metadata validation passed");
    }

    // T31: Locked transaction must have required metadata keys
    if tx.tx_type == crate::constants::TX_TYPE_LOCKED {
        let has = |key: &str| tx.metadata.iter().any(|m| m.key == key);
        if !has(crate::locked_tx::META_LOCKED_CHECKSUM) {
            return Err(ValidationError::Internal("locked tx missing locked:checksum".into()));
        }
        if !has(crate::locked_tx::META_LOCKED_SALT) {
            return Err(ValidationError::Internal("locked tx missing locked:salt".into()));
        }
        if !has(crate::locked_tx::META_LOCKED_NONCE) {
            return Err(ValidationError::Internal("locked tx missing locked:nonce".into()));
        }
        tracing::trace!("T31: locked tx metadata check passed");
    }

    // T32: Unlocking transaction must have required metadata keys
    if tx.tx_type == crate::constants::TX_TYPE_UNLOCKING {
        let find = |key: &str| tx.metadata.iter().find(|m| m.key == key);
        let txid_entry = find(crate::locked_tx::META_UNLOCK_TXID)
            .ok_or_else(|| ValidationError::Internal("unlocking tx missing unlock:txid".into()))?;
        // Must be 64 hex chars (32-byte tx_id)
        let txid_str = std::str::from_utf8(&txid_entry.value).unwrap_or("");
        if txid_str.len() != 64 || hex::decode(txid_str).is_err() {
            return Err(ValidationError::Internal("unlock:txid must be 64 hex chars".into()));
        }
        if find(crate::locked_tx::META_UNLOCK_PASSWORD).is_none() {
            return Err(ValidationError::Internal("unlocking tx missing unlock:password".into()));
        }
        tracing::trace!("T32: unlocking tx metadata check passed");
    }

    // T10: tx_id verification
    let computed_id = tx.compute_tx_id(ctx.chain_id).map_err(|e| {
        tracing::debug!("tx_id computation failed: {e}");
        ValidationError::Internal("tx_id computation failed".into())
    })?;
    if computed_id != *claimed_tx_id {
        return Err(ValidationError::TxIdMismatch {
            claimed: claimed_tx_id.to_string(),
            computed: computed_id.to_string(),
        });
    }
    tracing::trace!("T10: tx_id verification passed");

    // T11: Fee check — in UTXO model, fee = sum(inputs) - sum(outputs).
    // This is a STATEFUL check (needs UTXO values). Deferred to commit_block / mempool.
    // Stateless: only verify that non-coinbase txs have inputs (fee > 0 requires inputs).
    tracing::trace!("T11: fee check deferred to stateful validation");

    // T12: Low-S enforcement for secp256k1 is handled by noble-crypto::secp256k1::verify()
    // which is called in T6 and T7 above.

    validate_tx_type_and_advanced(tx)?;

    // T31/T32: Source address ownership + activation enforcement (S34)
    validate_source_address(tx, ctx.chain_height)?;

    // T18-T20: Validator identity checks deferred to consensus (needs validator list)

    tracing::debug!("transaction validation passed");
    Ok(())
}

/// Validate source address — NO-OP in UTXO model.
///
/// In the account model, `source_address` indicated which balance bucket to debit.
/// In the UTXO model, the debit source is determined by which UTXOs are in the inputs.
/// This function is retained for API compatibility but does nothing.
pub fn validate_source_address(_tx: &Transaction, _chain_height: u64) -> Result<(), ValidationError> {
    // UTXO model: no source_address field. Debit is implicit from input UTXOs.
    Ok(())
}


/// Compute the median of a slice of timestamps.
///
/// Returns 0 for an empty slice.
pub fn median_timestamp(timestamps: &[u64]) -> u64 {
    if timestamps.is_empty() {
        return 0;
    }
    let mut sorted = timestamps.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// Validate a block's timestamp against B5, B6, and B13 (median-of-11).
///
/// This consolidates all timestamp checks into one function for the consensus layer:
/// - Monotonicity (B5): `block_timestamp > parent_timestamp` (always)
/// - Median-of-11 (B13): `block_timestamp >= median(recent_timestamps)` (RealTime only)
/// - Future skew (B6): `block_timestamp <= wall_clock + tolerance` (always, tolerance varies)
/// - Past skew (B6): `wall_clock <= block_timestamp + tolerance` (RealTime only)
#[tracing::instrument(skip(recent_timestamps), fields(task = "block_validation"))]
pub fn validate_block_timestamp(
    block_timestamp: u64,
    parent_timestamp: u64,
    recent_timestamps: &[u64],
    time_context: TimeContext,
) -> Result<(), ValidationError> {
    // B5: Monotonicity — always enforced, no relaxation.
    if block_timestamp <= parent_timestamp {
        return Err(ValidationError::TimestampNotAfterParent {
            block_time: block_timestamp,
            parent_time: parent_timestamp,
        });
    }

    match time_context {
        TimeContext::RealTime { wall_clock } => {
            // B13: Median-of-11
            if !recent_timestamps.is_empty() {
                let median = median_timestamp(recent_timestamps);
                if block_timestamp < median {
                    return Err(ValidationError::BlockTimestampBeforeMedian {
                        block_time: block_timestamp,
                        median,
                    });
                }
            }
            // B6: Future skew (strict)
            if block_timestamp > wall_clock + MAX_BLOCK_FUTURE_SKEW {
                return Err(ValidationError::BlockTimestampSkew {
                    block_time: block_timestamp,
                    current_time: wall_clock,
                });
            }
            // B6: Past skew (strict)
            if wall_clock > block_timestamp + MAX_BLOCK_PAST_SKEW {
                return Err(ValidationError::BlockTimestampSkew {
                    block_time: block_timestamp,
                    current_time: wall_clock,
                });
            }
        }
        TimeContext::Historical { wall_clock, .. } => {
            // B13: Skipped — recent timestamps are unreliable after rollback.
            // B6: Future guard only (relaxed tolerance) — no importing future blocks.
            if block_timestamp > wall_clock + SYNC_BLOCK_FUTURE_TOLERANCE {
                return Err(ValidationError::BlockTimestampSkew {
                    block_time: block_timestamp,
                    current_time: wall_clock,
                });
            }
            // B6: Past skew NOT checked — historical blocks ARE old.
            // B5 monotonicity (above) enforces temporal ordering.
        }
    }

    Ok(())
}

/// Validate a block against rules B1-B12.
///
/// Returns Ok(()) if all checks pass, or the first validation error encountered.
#[tracing::instrument(skip(block, ctx), fields(task = "block_validation", height = block.header.height))]
pub fn validate_block(block: &Block, ctx: &BlockValidationContext) -> Result<(), ValidationError> {
    let header = &block.header;

    // B1: Size check
    let serialized = block.to_cbor().map_err(|e| {
        tracing::debug!("block serialization failed: {e}");
        ValidationError::Internal("block serialization failed".into())
    })?;
    if serialized.len() > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            size: serialized.len(),
            max: MAX_BLOCK_SIZE,
        });
    }
    tracing::trace!(size = serialized.len(), "B1: block size check passed");

    // B2: prev_block_hash
    if let Some(parent) = ctx.parent {
        let parent_hash = parent.compute_block_hash().map_err(|e| {
            tracing::debug!("block hash computation failed: {e}");
            ValidationError::Internal("block hash computation failed".into())
        })?;
        if header.prev_block_hash != parent_hash {
            return Err(ValidationError::PrevHashMismatch);
        }
        tracing::trace!("B2: prev_block_hash matches parent");

        // B3: Height
        if header.height != parent.height + 1 {
            return Err(ValidationError::HeightMismatch {
                height: header.height,
                expected: parent.height + 1,
            });
        }
        tracing::trace!("B3: height is sequential");

        // B5: Timestamp after parent
        if header.timestamp <= parent.timestamp {
            return Err(ValidationError::TimestampNotAfterParent {
                block_time: header.timestamp,
                parent_time: parent.timestamp,
            });
        }
        tracing::trace!("B5: timestamp after parent");
    }

    // B4: Merkle root
    let tx_ids: Result<Vec<_>, _> = block
        .transactions
        .iter()
        .map(|tx| {
            tx.compute_tx_id(ctx.chain_id).map_err(|e| {
                tracing::debug!("tx_id computation failed: {e}");
                ValidationError::Internal("tx_id computation failed".into())
            })
        })
        .collect();
    let tx_ids = tx_ids?;

    // Check for duplicate tx_ids within the block (C-duptx)
    {
        let mut seen = HashSet::with_capacity(tx_ids.len());
        for (i, id) in tx_ids.iter().enumerate() {
            if !seen.insert(id) {
                // Find the first occurrence
                let first = tx_ids.iter().position(|x| x == id).unwrap();
                return Err(ValidationError::DuplicateTxInBlock { first, second: i });
            }
        }
    }
    tracing::trace!("C-duptx: no duplicate tx_ids in block");

    let computed_root = compute_merkle_root(&tx_ids);
    if header.merkle_root != computed_root {
        return Err(ValidationError::MerkleRootMismatch);
    }
    tracing::trace!("B4: merkle root verified");

    // B6: Timestamp skew — dispatches on TimeContext.
    match ctx.time_context {
        TimeContext::RealTime { wall_clock } => {
            if header.timestamp > wall_clock + MAX_BLOCK_FUTURE_SKEW {
                return Err(ValidationError::BlockTimestampSkew {
                    block_time: header.timestamp,
                    current_time: wall_clock,
                });
            }
            if wall_clock > header.timestamp + MAX_BLOCK_PAST_SKEW {
                return Err(ValidationError::BlockTimestampSkew {
                    block_time: header.timestamp,
                    current_time: wall_clock,
                });
            }
            tracing::trace!("B6: timestamp skew check passed (real-time)");
        }
        TimeContext::Historical { wall_clock, .. } => {
            // Future guard only (relaxed tolerance).
            if header.timestamp > wall_clock + SYNC_BLOCK_FUTURE_TOLERANCE {
                return Err(ValidationError::BlockTimestampSkew {
                    block_time: header.timestamp,
                    current_time: wall_clock,
                });
            }
            // Past skew not checked — historical blocks are old by definition.
            tracing::trace!("B6: future guard passed (historical)");
        }
    }

    // B7: tx_count
    if header.tx_count != block.transactions.len() as u32 {
        return Err(ValidationError::TxCountMismatch {
            claimed: header.tx_count,
            actual: block.transactions.len() as u32,
        });
    }
    tracing::trace!(tx_count = header.tx_count, "B7: tx_count matches");

    // B8: Validator signature
    let signing_msg = header.compute_signing_message().map_err(|e| {
        tracing::debug!("signing message computation failed: {e}");
        ValidationError::Internal("signing message computation failed".into())
    })?;
    header
        .validator_id
        .verify(&signing_msg, &header.validator_sig)
        .map_err(|e| {
            tracing::debug!("validator signature verification failed: {e}");
            ValidationError::ValidatorSigInvalid("signature verification failed".into())
        })?;
    tracing::trace!("B8: validator signature verified");

    // B9: Validator in list
    if !ctx.validator_list.contains(&header.validator_id) {
        return Err(ValidationError::ValidatorNotTrusted);
    }
    tracing::trace!("B9: validator is trusted");

    // B10: One block per cycle — deferred to consensus layer (needs cycle state)

    // U9: Block Reward + Fee Distribution enforcement
    // (skip genesis blocks at height 0 — they have no transactions)
    if header.height > 0 {
        // U9a: Block must have at least one transaction (the block reward)
        if block.transactions.is_empty() {
            return Err(ValidationError::Internal("block has no transactions (missing block reward)".into()));
        }
        // U9b: First transaction must be Block Reward (type 0x10) with coinbase input
        if !block.transactions[0].is_coinbase() || block.transactions[0].tx_type != crate::constants::TX_TYPE_COINBASE {
            return Err(ValidationError::Internal("U9: first transaction must be block reward (type 0x10)".into()));
        }
        // U9c: Exactly one Block Reward per block
        let reward_count = block.transactions.iter().filter(|tx| tx.tx_type == crate::constants::TX_TYPE_COINBASE).count();
        if reward_count != 1 {
            return Err(ValidationError::Internal(format!(
                "U9: block must have exactly 1 block reward, found {reward_count}"
            )));
        }
        // U9d: At most one Fee Distribution per block (type 0x11), must be at index 1
        let fee_count = block.transactions.iter().filter(|tx| tx.tx_type == crate::constants::TX_TYPE_FEE).count();
        if fee_count > 1 {
            return Err(ValidationError::Internal(format!(
                "U9: block must have at most 1 fee distribution, found {fee_count}"
            )));
        }
        if fee_count == 1 && block.transactions.get(1).map(|tx| tx.tx_type) != Some(crate::constants::TX_TYPE_FEE) {
            return Err(ValidationError::Internal("U9: fee distribution must be at index 1".into()));
        }
        // U9e: No other coinbase-input txs besides Block Reward and Fee Distribution
        let coinbase_input_count = block.transactions.iter().filter(|tx| tx.is_coinbase()).count();
        let expected_coinbase_inputs = 1 + fee_count;
        if coinbase_input_count != expected_coinbase_inputs {
            return Err(ValidationError::Internal(format!(
                "U9: unexpected coinbase-input tx count: got {coinbase_input_count}, expected {expected_coinbase_inputs}"
            )));
        }
        tracing::trace!("U9: block reward + fee distribution structure validated");
    }

    // B11: All transactions valid
    for (i, tx) in block.transactions.iter().enumerate() {
        let tx_id = tx.compute_tx_id(ctx.chain_id).map_err(|e| {
            tracing::debug!("tx_id computation failed: {e}");
            ValidationError::Internal("tx_id computation failed".into())
        })?;
        let tx_time_ctx = match ctx.time_context {
            TimeContext::RealTime { wall_clock } => TimeContext::RealTime { wall_clock },
            TimeContext::Historical { wall_clock, .. } => TimeContext::Historical {
                block_time: block.header.timestamp,
                wall_clock,
            },
        };
        let tx_ctx = TxValidationContext {
            chain_id: ctx.chain_id,
            time_context: tx_time_ctx,
            chain_height: block.header.height,
        };
        validate_transaction(tx, &tx_id, &tx_ctx).map_err(|e| {
            ValidationError::InvalidTransaction {
                index: i,
                source: Box::new(e),
            }
        })?;
    }
    tracing::trace!(
        count = block.transactions.len(),
        "B11: all transactions valid"
    );

    // B12: Validator scheme recognized
    if !is_recognized_scheme(header.validator_id.scheme_id()) {
        return Err(ValidationError::ValidatorSchemeUnrecognized(
            header.validator_id.scheme_id(),
        ));
    }
    tracing::trace!("B12: validator scheme recognized");

    tracing::debug!(
        height = header.height,
        tx_count = header.tx_count,
        "block validation passed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{build_genesis, derive_chain_id, GENESIS_TIMESTAMP};
    use crate::utxo::{OutPoint, TxIn, TxOut};
    use noble_crypto::{
        secp256k1, sha256, Hash256, NoblePrivateKey, NobleSigner, SignatureEnvelope, SCHEME_SECP256K1,
    };

    fn test_chain_id() -> u32 {
        use std::sync::LazyLock;
        static ID: LazyLock<u32> = LazyLock::new(|| {
            let block = build_genesis(GENESIS_TIMESTAMP, b"noble-test-genesis");
            let hash = block.header.compute_block_hash().unwrap();
            derive_chain_id(&hash)
        });
        *ID
    }

    // --- Test helpers ---

    fn make_signed_tx(sk: &[u8], pk: &[u8]) -> (Transaction, noble_crypto::Hash256) {
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let checksum = sha256(b"test document");
        let timestamp = 1_700_000_000u64;

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x01; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum,
            timestamp,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };

        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    fn default_tx_ctx() -> TxValidationContext {
        TxValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            chain_height: 0,
        }
    }

    // --- T1: Size ---

    #[test]
    fn t1_valid_size() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk);
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- T2: Version ---

    #[test]
    fn t2_wrong_version() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.version = 99;
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::UnknownVersion(99))));
    }

    // --- T4: Timestamp ---

    #[test]
    fn t4_timestamp_too_far_future() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.timestamp = 1_700_000_000 + MAX_TX_TIMESTAMP_SKEW + 1;
        // Re-sign with new timestamp
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TimestampOutOfRange { .. })
        ));
    }

    #[test]
    fn t4_timestamp_within_window() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.timestamp = 1_700_000_000 + MAX_TX_TIMESTAMP_SKEW; // At the boundary
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- T5: Scheme ---

    #[test]
    fn t5_unknown_scheme() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.issuer_sig.scheme_id = 0xFF;
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::UnrecognizedScheme(0xFF))
        ));
    }

    // --- T6: Issuer signature ---

    #[test]
    fn t6_invalid_issuer_sig() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.issuer_sig.signature = vec![0u8; 64]; // Bad sig
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::IssuerSigInvalid(_))
        ));
    }

    // --- T7: Additional signature ---

    #[test]
    fn t7_invalid_additional_sig() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.additional_sigs.push(SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: pk.to_vec(),
            signature: vec![0u8; 64], // Bad
        });
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::AdditionalSigInvalid { index: 0, .. })
        ));
    }

    // --- T10: tx_id mismatch ---

    #[test]
    fn t10_tx_id_mismatch() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, _) = make_signed_tx(&sk, &pk);
        let wrong_id = Hash256::from_bytes([0xFF; 32]);
        let result = validate_transaction(&tx, &wrong_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::TxIdMismatch { .. })));
    }

    // --- T11: Fee ---

    #[test]
    fn t11_fee_deferred_to_stateful_validation() {
        // In the UTXO model, fee = sum(inputs) - sum(outputs) and is checked
        // during stateful validation (requires UTXO lookup). Stateless validation
        // only verifies that non-coinbase txs have inputs.
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk);
        // Stateless validation should pass — fee check is deferred.
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t11_fee_at_minimum() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk); // Uses MIN_TX_FEE
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- Block validation helpers ---

    fn make_valid_block(txs: Vec<(Transaction, Hash256)>) -> (Block, NoblePrivateKey) {
        let (val_sk, val_pk) = secp256k1::generate_keypair();
        let val_priv = NoblePrivateKey::Secp256k1(val_sk);
        let val_pub = NoblePublicKey::Secp256k1(val_pk.clone());

        let transactions: Vec<Transaction> = txs.iter().map(|(tx, _)| tx.clone()).collect();
        let tx_ids: Vec<Hash256> = txs.iter().map(|(_, id)| *id).collect();
        let merkle_root = compute_merkle_root(&tx_ids);

        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1_700_000_000,
            height: 0,
            tx_count: transactions.len() as u32,
            validator_id: val_pub,
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: val_pk,
                signature: vec![],
            },
        };

        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();

        (
            Block {
                header,
                transactions,
            },
            val_priv,
        )
    }

    // --- B2: prev_block_hash ---

    #[test]
    fn b2_prev_hash_mismatch() {
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (mut block, val_priv) = make_valid_block(vec![tx]);

        // Set up a parent with a different hash
        let parent_header = block.header.clone();
        block.header.height = 1;
        block.header.prev_block_hash = Hash256::from_bytes([0xFF; 32]); // Wrong

        // Re-sign
        let msg = block.header.compute_signing_message().unwrap();
        block.header.validator_sig = val_priv.sign(&msg).unwrap();

        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: Some(&parent_header),
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(result, Err(ValidationError::PrevHashMismatch)));
    }

    // --- B7: tx_count ---

    #[test]
    fn b7_tx_count_mismatch() {
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (mut block, val_priv) = make_valid_block(vec![tx]);
        block.header.tx_count = 99; // Wrong

        // Re-sign
        let msg = block.header.compute_signing_message().unwrap();
        block.header.validator_sig = val_priv.sign(&msg).unwrap();

        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(
            result,
            Err(ValidationError::TxCountMismatch { .. })
        ));
    }

    // --- B8: Validator signature ---

    #[test]
    fn b8_invalid_validator_sig() {
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (mut block, _) = make_valid_block(vec![tx]);
        block.header.validator_sig.signature = vec![0u8; 64];

        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(
            result,
            Err(ValidationError::ValidatorSigInvalid(_))
        ));
    }

    // --- B9: Validator not trusted ---

    #[test]
    fn b9_validator_not_in_list() {
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (block, _) = make_valid_block(vec![tx]);

        // Empty validator list
        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(result, Err(ValidationError::ValidatorNotTrusted)));
    }

    // --- Valid block ---

    #[test]
    fn valid_block_with_transaction() {
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (block, _) = make_valid_block(vec![tx]);

        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        assert!(validate_block(&block, &ctx).is_ok());
    }

    #[test]
    fn valid_empty_block() {
        let (block, _) = make_valid_block(vec![]);
        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        assert!(validate_block(&block, &ctx).is_ok());
    }

    // --- B11: Invalid transaction in block ---

    // --- T13-T17: Transfer type checks ---

    fn make_transfer_tx(
        sk: &[u8],
        pk: &[u8],
        recipient_pk: &[u8],
    ) -> (Transaction, noble_crypto::Hash256) {
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let recipient = NoblePublicKey::Secp256k1(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x02; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 100_000,
                address: crate::NobleAddress::Noble(recipient),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn t13_unknown_tx_type() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.tx_type = 0xFF;
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::UnknownTxType(0xFF))));
    }

    #[test]
    fn t13_valid_notarization_type() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk);
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t13_valid_transfer_type() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recipient_pk) = secp256k1::generate_keypair();
        let (tx, tx_id) = make_transfer_tx(&sk, &pk, &recipient_pk);
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t14_transfer_missing_recipient() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x03; 32]), vout: 0 },
            }],
            outputs: vec![], // No outputs = missing recipient
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TransferMissingRecipient)
        ));
    }

    #[test]
    fn t15_transfer_zero_output_value_rejected() {
        // In UTXO model, a zero-value output is rejected by U7.
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recipient_pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let recipient = NoblePublicKey::Secp256k1(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x04; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 0, // zero value
                address: crate::NobleAddress::Noble(recipient),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            result.is_err(),
            "transfer with zero-value output must be rejected: {result:?}"
        );
    }

    #[test]
    fn t15_transfer_empty_outputs_rejected() {
        // In UTXO model, a transfer with no outputs has no recipient.
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x05; 32]), vout: 0 },
            }],
            outputs: vec![], // no outputs
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TransferMissingRecipient)
        ));
    }

    #[test]
    fn t17_notarization_with_change_output_accepted() {
        // In UTXO model, notarizations can have outputs (change back to sender).
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let sender = NoblePublicKey::Secp256k1(pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x06; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 99_000, // change output
                address: crate::NobleAddress::Noble(sender),
            }],
            checksum: sha256(b"test document"),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(result.is_ok(), "notarization with change output should pass: {result:?}");
    }

    #[test]
    fn t24_self_transfer_allowed_in_utxo() {
        // In UTXO model, sending to your own address is valid (consolidating UTXOs).
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let self_addr = crate::NobleAddress::Noble(NoblePublicKey::Secp256k1(pk.to_vec()));
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x07; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 100_000,
                address: self_addr,
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(result.is_ok(), "self-transfer is valid in UTXO model: {result:?}");
    }

    #[test]
    fn t17_notarization_without_outputs_accepted() {
        // In UTXO model, notarization can have zero outputs (entire input is fee).
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x08; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: sha256(b"test document"),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(result.is_ok(), "notarization without outputs should pass: {result:?}");
    }

    // --- validate_block_timestamp (B5/B6/B13) ---

    #[test]
    fn b5_block_timestamp_before_parent_rejected() {
        let result = validate_block_timestamp(
            999,   // block timestamp
            1_000, // parent timestamp (higher)
            &[],
            TimeContext::RealTime { wall_clock: 1_700_000_000 },
        );
        assert!(matches!(
            result,
            Err(ValidationError::TimestampNotAfterParent { .. })
        ));
    }

    #[test]
    fn b13_block_timestamp_before_median_rejected() {
        // Median of [100, 200, 300, 400, 500] = 300
        let recent = vec![100, 200, 300, 400, 500];
        let result = validate_block_timestamp(
            250, // below median of 300
            200, // parent (ok, 250 > 200)
            &recent,
            TimeContext::RealTime { wall_clock: 1_700_000_000 },
        );
        assert!(matches!(
            result,
            Err(ValidationError::BlockTimestampBeforeMedian { .. })
        ));
    }

    #[test]
    fn b6_block_timestamp_too_far_future() {
        let now = 1_700_000_000;
        let result = validate_block_timestamp(
            now + MAX_BLOCK_FUTURE_SKEW + 1, now, &[],
            TimeContext::RealTime { wall_clock: now },
        );
        assert!(matches!(
            result,
            Err(ValidationError::BlockTimestampSkew { .. })
        ));
    }

    #[test]
    fn valid_block_timestamp_passes_all_checks() {
        let now = 1_700_000_000;
        let recent = vec![now - 100, now - 90, now - 80, now - 70, now - 60];
        let result = validate_block_timestamp(
            now + 10, // slightly in the future
            now,      // parent
            &recent,
            TimeContext::RealTime { wall_clock: now + 10 },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn median_timestamp_odd_count() {
        assert_eq!(median_timestamp(&[3, 1, 2]), 2);
        assert_eq!(median_timestamp(&[10, 30, 20, 40, 50]), 30);
    }

    #[test]
    fn median_timestamp_even_count() {
        // For even count, picks the upper-middle element
        assert_eq!(median_timestamp(&[1, 2, 3, 4]), 3);
    }

    #[test]
    fn median_timestamp_empty() {
        assert_eq!(median_timestamp(&[]), 0);
    }

    // --- T22: Encrypted locator on non-notarization ---

    #[test]
    fn t22_locator_on_transfer_rejected() {
        use crate::encrypted_locator::{EncryptedLocator, LocatorRecipient};

        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recipient_pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let recipient = NoblePublicKey::Secp256k1(recipient_pk.to_vec());
        let locator = EncryptedLocator {
            ciphertext: vec![0u8; 48],
            nonce: [0u8; 12],
            recipients: vec![LocatorRecipient {
                recipient: NoblePublicKey::Secp256k1(pk.to_vec()),
                ephemeral_pubkey: vec![0u8; 32],
                encrypted_key: vec![0u8; 48],
                key_nonce: [0u8; 12],
            }],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x09; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 100_000,
                address: crate::NobleAddress::Noble(recipient),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: Some(locator),
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::LocatorOnNonNotarization)
        ));
    }

    #[test]
    fn t22_locator_on_notarization_accepted() {
        use crate::encrypted_locator::{EncryptedLocator, LocatorRecipient};

        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let locator = EncryptedLocator {
            ciphertext: vec![0u8; 48],
            nonce: [0u8; 12],
            recipients: vec![LocatorRecipient {
                recipient: NoblePublicKey::Secp256k1(pk.to_vec()),
                ephemeral_pubkey: vec![0u8; 32],
                encrypted_key: vec![0u8; 48],
                key_nonce: [0u8; 12],
            }],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x0A; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: sha256(b"test document"),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: Some(locator),
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- T23: External attestations on non-notarization ---

    #[test]
    fn t23_attestations_on_transfer_rejected() {
        use crate::encrypted_locator::ExternalAttestation;

        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recipient_pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let recipient = NoblePublicKey::Secp256k1(recipient_pk.to_vec());
        let attestation = ExternalAttestation {
            scheme: "pkcs7".into(),
            scope: "hash".into(),
            signer_fingerprint: [0xAA; 32],
            signature_data: vec![0u8; 128],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x0B; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 100_000,
                address: crate::NobleAddress::Noble(recipient),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![attestation],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::AttestationsOnNonNotarization)
        ));
    }

    #[test]
    fn t23_attestations_on_notarization_accepted() {
        use crate::encrypted_locator::ExternalAttestation;

        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let attestation = ExternalAttestation {
            scheme: "smime".into(),
            scope: "both".into(),
            signer_fingerprint: [0xBB; 32],
            signature_data: vec![0u8; 256],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x0C; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: sha256(b"attested document"),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![attestation],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- CBOR backward compatibility ---

    #[test]
    fn tx_without_locator_deserializes() {
        // Transaction without encrypted_locator/external_attestations (backward compat)
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, _) = make_signed_tx(&sk, &pk);
        assert!(tx.encrypted_locator.is_none());
        assert!(tx.external_attestations.is_empty());

        // CBOR roundtrip preserves defaults
        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        assert_eq!(tx, decoded);
        assert!(decoded.encrypted_locator.is_none());
        assert!(decoded.external_attestations.is_empty());
    }

    // --- Phase 2 audit remediation tests ---

    #[test]
    fn t7b_too_many_additional_sigs() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);

        // Add MAX_ADDITIONAL_SIGS + 1 valid signatures
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        for _ in 0..=MAX_ADDITIONAL_SIGS {
            let (extra_sk, _) = secp256k1::generate_keypair();
            let extra_priv = NoblePrivateKey::Secp256k1(extra_sk);
            tx.additional_sigs.push(extra_priv.sign(&msg).unwrap());
        }
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::TooManyAdditionalSigs { .. })),
            "too many additional sigs: {result:?}"
        );
    }

    #[test]
    fn t8b_too_many_metadata_entries() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);

        // Add MAX_METADATA_ENTRIES + 1 entries
        for i in 0..=MAX_METADATA_ENTRIES {
            tx.metadata.push(crate::metadata::MetadataEntry {
                key: format!("key{i}"),
                value: b"val".to_vec(),
            });
        }
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::TooManyMetadataEntries { .. })),
            "too many metadata entries: {result:?}"
        );
    }

    #[test]
    fn duplicate_tx_in_block_rejected() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk);

        // Create a block with the same transaction twice
        let (val_sk, val_pk) = secp256k1::generate_keypair();
        let val_priv = NoblePrivateKey::Secp256k1(val_sk);
        let val_pub = NoblePublicKey::Secp256k1(val_pk.clone());

        let transactions = vec![tx.clone(), tx.clone()];
        let merkle_root = compute_merkle_root(&[tx_id, tx_id]);

        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1_700_000_000,
            height: 0,
            tx_count: 2,
            validator_id: val_pub,
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: val_pk,
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();

        let block = Block {
            header,
            transactions,
        };
        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(
            matches!(result, Err(ValidationError::DuplicateTxInBlock { .. })),
            "duplicate tx in block: {result:?}"
        );
    }

    #[test]
    fn t17b_key_rotation_missing_new_key_rejected() {
        // In UTXO model, key rotation requires at least one output (new key in outputs[0].address).
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_KEY_ROTATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x0D; 32]), vout: 0 },
            }],
            outputs: vec![], // Missing new key output
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::KeyRotationMissingNewKey)),
            "key rotation without outputs must be rejected: {result:?}"
        );
    }

    #[test]
    fn t17b_key_rotation_with_new_key_accepted() {
        // In UTXO model, key rotation carries the new key in outputs[0].address.
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, new_pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let new_key = NoblePublicKey::Secp256k1(new_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_KEY_ROTATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x0E; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 1, // dust output carrying the new key
                address: crate::NobleAddress::Noble(new_key),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn b11_invalid_tx_in_block() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        // Corrupt the signature to make it invalid (T6)
        tx.issuer_sig.signature = vec![0u8; 64];
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let (block, _) = make_valid_block(vec![(tx, tx_id)]);
        let ctx = BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: TimeContext::RealTime { wall_clock: 1_700_000_000 },
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidTransaction { index: 0, .. })
        ));
    }

    // --- T25: gateway_address validation ---

    #[test]
    fn t25_valid_gateway_address_accepted() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, gw_pk) = secp256k1::generate_keypair();
        let gw_key = NoblePublicKey::Secp256k1(gw_pk);
        let gw_wire = gw_key.to_wire_bytes();

        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x0F; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: sha256(b"gw-valid"),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: Some(gw_wire),
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t25_invalid_gateway_address_rejected() {
        let (sk, pk) = secp256k1::generate_keypair();

        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x10; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: sha256(b"gw-invalid"),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: Some(vec![0xFF, 0x01, 0x02]), // invalid wire bytes
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidGatewayAddress(_))
        ));
    }

    // --- T26: BIP-137 Bitcoin Signed Message ---

    fn make_bip137_notarization_tx() -> (Transaction, noble_crypto::Hash256) {
        use noble_crypto::bip137;
        use noble_crypto::SCHEME_BIP137;

        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&sk).unwrap();
        let compressed_pk = signing_key.verifying_key().to_sec1_bytes().to_vec();

        let checksum = sha256(b"bip137 test document");
        let timestamp = 1_700_000_000u64;

        // In UTXO model, fee is implicit (0 in BIP-137 message).
        let message =
            bip137::notarization_message(&checksum.to_string(), timestamp, 0, PROTOCOL_VERSION);
        let sig = bip137::sign_bip137(&sk, &message).unwrap();

        let tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x11; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum,
            timestamp,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_BIP137,
                public_key: compressed_pk,
                signature: sig.to_vec(),
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn t26_valid_bip137_notarization_passes() {
        let (tx, tx_id) = make_bip137_notarization_tx();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t26_bip137_wrong_checksum_fails() {
        let (mut tx, _) = make_bip137_notarization_tx();
        // Tamper with the checksum — signature won't match
        tx.checksum = sha256(b"tampered document");
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::IssuerSigInvalid(_))),
            "wrong checksum must fail BIP-137 validation: {result:?}"
        );
    }

    #[test]
    fn t26_bip137_non_65_byte_sig_fails() {
        use noble_crypto::SCHEME_BIP137;

        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&sk).unwrap();
        let compressed_pk = signing_key.verifying_key().to_sec1_bytes().to_vec();

        let checksum = sha256(b"short sig test");
        let tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x12; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_BIP137,
                public_key: compressed_pk,
                signature: vec![0u8; 32], // Wrong length
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::IssuerSigInvalid(_))),
            "non-65-byte BIP-137 sig must be rejected: {result:?}"
        );
    }

    // --- T27: Transfer with non-zero checksum ---

    #[test]
    fn t27_transfer_nonzero_checksum_rejected() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recipient_pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let recipient = NoblePublicKey::Secp256k1(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x13; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 100_000,
                address: crate::NobleAddress::Noble(recipient),
            }],
            checksum: sha256(b"should not be here"), // non-zero checksum on transfer
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::TransferWithNonZeroChecksum)),
            "transfer with non-zero checksum must be rejected: {result:?}"
        );
    }

    // --- T28: Notarization with zero checksum ---

    #[test]
    fn t28_notarization_zero_checksum_rejected() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x14; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: Hash256::ZERO, // zero checksum on notarization
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(result, Err(ValidationError::NotarizationWithZeroChecksum)),
            "notarization with zero checksum must be rejected: {result:?}"
        );
    }

    // --- T27b: Key rotation with non-zero checksum ---

    #[test]
    fn t27b_key_rotation_nonzero_checksum_rejected() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, new_pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let new_key = NoblePublicKey::Secp256k1(new_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_KEY_ROTATION,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x15; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 1,
                address: crate::NobleAddress::Noble(new_key),
            }],
            checksum: sha256(b"should not be here"), // non-zero checksum on key rotation
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(
            matches!(
                result,
                Err(ValidationError::NonDocumentWithChecksum(
                    TX_TYPE_KEY_ROTATION
                ))
            ),
            "key rotation with non-zero checksum must be rejected: {result:?}"
        );
    }

    // --- T25 gateway address Bitcoin prefix tests (Finding 1) ---

    #[test]
    fn t25_gateway_bitcoin_hash160_valid() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);

        // Set a valid Bitcoin Hash160 gateway address (0x80 prefix + 20 bytes)
        let mut gateway = vec![0x80u8];
        gateway.extend_from_slice(&[0xab; 20]);
        tx.gateway_address = Some(gateway);

        // Re-sign for chain
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let ctx = default_tx_ctx();
        let result = validate_transaction(&tx, &tx_id, &ctx);
        assert!(result.is_ok(), "Hash160 gateway should pass T25: {result:?}");
    }

    #[test]
    fn t25_gateway_bitcoin_taproot_valid() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);

        // Set a valid Bitcoin Taproot gateway address (0x81 prefix + 32 bytes)
        let mut gateway = vec![0x81u8];
        gateway.extend_from_slice(&[0xcd; 32]);
        tx.gateway_address = Some(gateway);

        // Re-sign for chain
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let ctx = default_tx_ctx();
        let result = validate_transaction(&tx, &tx_id, &ctx);
        assert!(
            result.is_ok(),
            "Taproot gateway should pass T25: {result:?}"
        );
    }

    #[test]
    fn t25_gateway_invalid_prefix_rejected() {
        let (sk, pk) = secp256k1::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);

        // Set an invalid gateway address with unknown prefix 0xFF
        let mut gateway = vec![0xFFu8];
        gateway.extend_from_slice(&[0x00; 32]);
        tx.gateway_address = Some(gateway);

        // Re-sign for chain
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let ctx = default_tx_ctx();
        let result = validate_transaction(&tx, &tx_id, &ctx);
        assert!(
            matches!(result, Err(ValidationError::InvalidGatewayAddress(_))),
            "Unknown prefix 0xFF should be rejected: {result:?}"
        );
    }

    // --- T31/T32: Source address validation tests (S34) ---

    /// Helper: create a signed secp256k1 transfer transaction.
    fn make_secp_transfer(
        recipient: crate::NobleAddress,
        amount: u64,
    ) -> (Transaction, Hash256, Vec<u8>) {
        use noble_crypto::SCHEME_SECP256K1;

        let (sk, _) = noble_crypto::secp256k1::generate_keypair();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&sk).unwrap();
        let compressed_pk = signing_key.verifying_key().to_sec1_bytes().to_vec();

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x16; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: amount,
                address: recipient,
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: compressed_pk.clone(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };

        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let sig = noble_crypto::secp256k1::sign(&sk, &msg).unwrap();
        tx.issuer_sig.signature = sig;
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id, compressed_pk)
    }

    // --- T31/T32: Source address validation removed in UTXO model ---
    // In UTXO model, the debit source is determined by input UTXOs, not a source_address field.
    // These tests verify that secp256k1 transfers work correctly.

    #[test]
    fn t31_secp256k1_transfer_passes() {
        // secp256k1 transfer in UTXO model (no source_address needed).
        let (_, other_pk) = secp256k1::generate_keypair();
        let recipient = crate::NobleAddress::Noble(NoblePublicKey::Secp256k1(other_pk.to_vec()));
        let (tx, tx_id, _) = make_secp_transfer(recipient, 100);
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(result.is_ok(), "secp256k1 transfer should pass: {result:?}");
    }

    #[test]
    fn t32_secp256k1_transfer_passes() {
        // secp256k1 transfer in UTXO model (manual construction).
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, other_pk) = secp256k1::generate_keypair();
        let recipient = crate::NobleAddress::Noble(NoblePublicKey::Secp256k1(other_pk.to_vec()));

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x17; 32]), vout: 0 },
            }],
            outputs: vec![TxOut {
                value: 100,
                address: recipient,
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        expires_at: None,
        };
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(result.is_ok(), "secp256k1 transfer should pass: {result:?}");
    }
}
