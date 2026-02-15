// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction (T1-T17) and block (B1-B12) validation pipelines.

use noble_codec::NobleCbor;
use noble_crypto::{is_recognized_scheme, NoblePublicKey};

use crate::block::{Block, BlockHeader};
use crate::constants::*;
use crate::error::ValidationError;
use crate::merkle::compute_merkle_root;
use crate::metadata::validate_metadata;
use crate::transaction::Transaction;

/// Context needed for transaction validation.
pub struct TxValidationContext {
    /// Chain ID for tx_id computation.
    pub chain_id: u32,
    /// Current wall-clock time (Unix seconds).
    pub current_time: u64,
}

/// Context needed for block validation.
pub struct BlockValidationContext<'a> {
    /// Chain ID for tx_id computation.
    pub chain_id: u32,
    /// Current wall-clock time (Unix seconds).
    pub current_time: u64,
    /// Parent block header (None for genesis).
    pub parent: Option<&'a BlockHeader>,
    /// The node's local trusted validator list.
    pub validator_list: &'a [NoblePublicKey],
}

/// Validate a transaction against rules T1-T17.
///
/// Returns Ok(()) if all checks pass, or the first validation error encountered.
pub fn validate_transaction(
    tx: &Transaction,
    claimed_tx_id: &noble_crypto::Hash256,
    ctx: &TxValidationContext,
) -> Result<(), ValidationError> {
    // T1: Size check
    let serialized = tx
        .to_cbor()
        .map_err(|e| ValidationError::Internal(e.to_string()))?;
    if serialized.len() > MAX_TX_SIZE {
        return Err(ValidationError::TxTooLarge {
            size: serialized.len(),
            max: MAX_TX_SIZE,
        });
    }

    // T2: Version check
    if tx.version != PROTOCOL_VERSION {
        return Err(ValidationError::UnknownVersion(tx.version));
    }

    // T3: Checksum is [u8; 32] — enforced at compile time by Hash256

    // T4: Timestamp skew
    let diff = tx.timestamp.abs_diff(ctx.current_time);
    if diff > MAX_TX_TIMESTAMP_SKEW {
        return Err(ValidationError::TimestampOutOfRange {
            tx_time: tx.timestamp,
            current_time: ctx.current_time,
            max_skew: MAX_TX_TIMESTAMP_SKEW,
        });
    }

    // T5: Publisher scheme recognized
    if !is_recognized_scheme(tx.publisher_sig.scheme_id) {
        return Err(ValidationError::UnrecognizedScheme(
            tx.publisher_sig.scheme_id,
        ));
    }

    // T6: Publisher signature verification
    let signing_msg = tx
        .compute_signing_message()
        .map_err(|e| ValidationError::Internal(e.to_string()))?;
    tx.publisher_sig
        .verify_standalone(&signing_msg)
        .map_err(|e| ValidationError::PublisherSigInvalid(e.to_string()))?;

    // T7: Additional signature verification
    for (i, sig) in tx.additional_sigs.iter().enumerate() {
        if !is_recognized_scheme(sig.scheme_id) {
            return Err(ValidationError::AdditionalSigInvalid {
                index: i,
                reason: format!("unrecognized scheme {:#04x}", sig.scheme_id),
            });
        }
        sig.verify_standalone(&signing_msg)
            .map_err(|e| ValidationError::AdditionalSigInvalid {
                index: i,
                reason: e.to_string(),
            })?;
    }

    // T8 + T9: Metadata validation
    validate_metadata(&tx.metadata)?;

    // T10: tx_id verification
    let computed_id = tx
        .compute_tx_id(ctx.chain_id)
        .map_err(|e| ValidationError::Internal(e.to_string()))?;
    if computed_id != *claimed_tx_id {
        return Err(ValidationError::TxIdMismatch {
            claimed: claimed_tx_id.to_string(),
            computed: computed_id.to_string(),
        });
    }

    // T11: Fee check
    if tx.fee < MIN_TX_FEE {
        return Err(ValidationError::FeeTooLow {
            fee: tx.fee,
            min_fee: MIN_TX_FEE,
        });
    }

    // T12: Low-S enforcement for secp256k1 is handled by noble-crypto::secp256k1::verify()
    // which is called in T6 and T7 above.

    // T13: tx_type must be recognized
    if tx.tx_type != TX_TYPE_NOTARIZATION
        && tx.tx_type != TX_TYPE_TRANSFER
        && tx.tx_type != TX_TYPE_KEY_ROTATION
    {
        return Err(ValidationError::UnknownTxType(tx.tx_type));
    }

    // T14: Transfer requires recipient
    if tx.tx_type == TX_TYPE_TRANSFER && tx.recipient.is_none() {
        return Err(ValidationError::TransferMissingRecipient);
    }

    // T15: Transfer requires amount > 0
    if tx.tx_type == TX_TYPE_TRANSFER && matches!(tx.amount, None | Some(0)) {
        return Err(ValidationError::TransferInvalidAmount);
    }

    // T16: Balance check is deferred to commit time (needs chain state)

    // T17: Notarization must NOT have recipient or amount
    if tx.tx_type == TX_TYPE_NOTARIZATION && (tx.recipient.is_some() || tx.amount.is_some()) {
        return Err(ValidationError::NotarizationHasTransferFields);
    }

    // T22: encrypted_locator only allowed on notarization
    if tx.tx_type != TX_TYPE_NOTARIZATION && tx.encrypted_locator.is_some() {
        return Err(ValidationError::LocatorOnNonNotarization);
    }

    // T23: external_attestations only allowed on notarization
    if tx.tx_type != TX_TYPE_NOTARIZATION && !tx.external_attestations.is_empty() {
        return Err(ValidationError::AttestationsOnNonNotarization);
    }

    // T21: Key rotation requires new key in recipient field
    if tx.tx_type == TX_TYPE_KEY_ROTATION && tx.recipient.is_none() {
        return Err(ValidationError::KeyRotationMissingNewKey);
    }

    // T18-T20: Validator identity checks deferred to consensus (needs validator list)

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
/// - Monotonicity (B5): `block_timestamp > parent_timestamp`
/// - Median-of-11 (B13): `block_timestamp >= median(recent_timestamps)`
/// - Future skew (B6): `block_timestamp <= now + MAX_BLOCK_FUTURE_SKEW`
/// - Past skew (B6): `now <= block_timestamp + MAX_BLOCK_PAST_SKEW`
pub fn validate_block_timestamp(
    block_timestamp: u64,
    parent_timestamp: u64,
    recent_timestamps: &[u64],
    current_time: u64,
) -> Result<(), ValidationError> {
    // B5: Monotonicity
    if block_timestamp <= parent_timestamp {
        return Err(ValidationError::TimestampNotAfterParent {
            block_time: block_timestamp,
            parent_time: parent_timestamp,
        });
    }

    // B13: Median-of-11 (only if we have recent timestamps)
    if !recent_timestamps.is_empty() {
        let median = median_timestamp(recent_timestamps);
        if block_timestamp < median {
            return Err(ValidationError::BlockTimestampBeforeMedian {
                block_time: block_timestamp,
                median,
            });
        }
    }

    // B6: Future skew
    if block_timestamp > current_time + MAX_BLOCK_FUTURE_SKEW {
        return Err(ValidationError::BlockTimestampSkew {
            block_time: block_timestamp,
            current_time,
        });
    }
    // B6: Past skew
    if current_time > block_timestamp + MAX_BLOCK_PAST_SKEW {
        return Err(ValidationError::BlockTimestampSkew {
            block_time: block_timestamp,
            current_time,
        });
    }

    Ok(())
}

/// Validate a block against rules B1-B12.
///
/// Returns Ok(()) if all checks pass, or the first validation error encountered.
pub fn validate_block(block: &Block, ctx: &BlockValidationContext) -> Result<(), ValidationError> {
    let header = &block.header;

    // B1: Size check
    let serialized = block
        .to_cbor()
        .map_err(|e| ValidationError::Internal(e.to_string()))?;
    if serialized.len() > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            size: serialized.len(),
            max: MAX_BLOCK_SIZE,
        });
    }

    // B2: prev_block_hash
    if let Some(parent) = ctx.parent {
        let parent_hash = parent
            .compute_block_hash()
            .map_err(|e| ValidationError::Internal(e.to_string()))?;
        if header.prev_block_hash != parent_hash {
            return Err(ValidationError::PrevHashMismatch);
        }

        // B3: Height
        if header.height != parent.height + 1 {
            return Err(ValidationError::HeightMismatch {
                height: header.height,
                expected: parent.height + 1,
            });
        }

        // B5: Timestamp after parent
        if header.timestamp <= parent.timestamp {
            return Err(ValidationError::TimestampNotAfterParent {
                block_time: header.timestamp,
                parent_time: parent.timestamp,
            });
        }
    }

    // B4: Merkle root
    let tx_ids: Result<Vec<_>, _> = block
        .transactions
        .iter()
        .map(|tx| {
            tx.compute_tx_id(ctx.chain_id)
                .map_err(|e| ValidationError::Internal(e.to_string()))
        })
        .collect();
    let tx_ids = tx_ids?;
    let computed_root = compute_merkle_root(&tx_ids);
    if header.merkle_root != computed_root {
        return Err(ValidationError::MerkleRootMismatch);
    }

    // B6: Timestamp skew
    if header.timestamp > ctx.current_time + MAX_BLOCK_FUTURE_SKEW {
        return Err(ValidationError::BlockTimestampSkew {
            block_time: header.timestamp,
            current_time: ctx.current_time,
        });
    }
    if ctx.current_time > header.timestamp + MAX_BLOCK_PAST_SKEW {
        return Err(ValidationError::BlockTimestampSkew {
            block_time: header.timestamp,
            current_time: ctx.current_time,
        });
    }

    // B7: tx_count
    if header.tx_count != block.transactions.len() as u32 {
        return Err(ValidationError::TxCountMismatch {
            claimed: header.tx_count,
            actual: block.transactions.len() as u32,
        });
    }

    // B8: Validator signature
    let signing_msg = header
        .compute_signing_message()
        .map_err(|e| ValidationError::Internal(e.to_string()))?;
    header
        .validator_id
        .verify(&signing_msg, &header.validator_sig)
        .map_err(|e| ValidationError::ValidatorSigInvalid(e.to_string()))?;

    // B9: Validator in list
    if !ctx.validator_list.contains(&header.validator_id) {
        return Err(ValidationError::ValidatorNotTrusted);
    }

    // B10: One block per cycle — deferred to consensus layer (needs cycle state)

    // B11: All transactions valid
    for (i, tx) in block.transactions.iter().enumerate() {
        let tx_id = tx
            .compute_tx_id(ctx.chain_id)
            .map_err(|e| ValidationError::Internal(e.to_string()))?;
        let tx_ctx = TxValidationContext {
            chain_id: ctx.chain_id,
            current_time: ctx.current_time,
        };
        validate_transaction(tx, &tx_id, &tx_ctx).map_err(|e| {
            ValidationError::InvalidTransaction {
                index: i,
                source: Box::new(e),
            }
        })?;
    }

    // B12: Validator scheme recognized
    if !is_recognized_scheme(header.validator_id.scheme_id()) {
        return Err(ValidationError::ValidatorSchemeUnrecognized(
            header.validator_id.scheme_id(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{
        ed25519, sha256, Hash256, NoblePrivateKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

    // --- Test helpers ---

    fn make_signed_tx(sk: &[u8], pk: &[u8]) -> (Transaction, noble_crypto::Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(b"test document");
        let timestamp = 1_700_000_000u64;
        let fee = MIN_TX_FEE;

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum,
            timestamp,
            fee,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };

        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    fn default_tx_ctx() -> TxValidationContext {
        TxValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
        }
    }

    // --- T1: Size ---

    #[test]
    fn t1_valid_size() {
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk);
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- T2: Version ---

    #[test]
    fn t2_wrong_version() {
        let (sk, pk) = ed25519::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.version = 99;
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::UnknownVersion(99))));
    }

    // --- T4: Timestamp ---

    #[test]
    fn t4_timestamp_too_far_future() {
        let (sk, pk) = ed25519::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.timestamp = 1_700_000_000 + MAX_TX_TIMESTAMP_SKEW + 1;
        // Re-sign with new timestamp
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TimestampOutOfRange { .. })
        ));
    }

    #[test]
    fn t4_timestamp_within_window() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.timestamp = 1_700_000_000 + MAX_TX_TIMESTAMP_SKEW; // At the boundary
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- T5: Scheme ---

    #[test]
    fn t5_unknown_scheme() {
        let (sk, pk) = ed25519::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.publisher_sig.scheme_id = 0xFF;
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::UnrecognizedScheme(0xFF))
        ));
    }

    // --- T6: Publisher signature ---

    #[test]
    fn t6_invalid_publisher_sig() {
        let (sk, pk) = ed25519::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.publisher_sig.signature = vec![0u8; 64]; // Bad sig
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::PublisherSigInvalid(_))
        ));
    }

    // --- T7: Additional signature ---

    #[test]
    fn t7_invalid_additional_sig() {
        let (sk, pk) = ed25519::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.additional_sigs.push(SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![0u8; 64], // Bad
        });
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::AdditionalSigInvalid { index: 0, .. })
        ));
    }

    // --- T10: tx_id mismatch ---

    #[test]
    fn t10_tx_id_mismatch() {
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, _) = make_signed_tx(&sk, &pk);
        let wrong_id = Hash256::from_bytes([0xFF; 32]);
        let result = validate_transaction(&tx, &wrong_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::TxIdMismatch { .. })));
    }

    // --- T11: Fee ---

    #[test]
    fn t11_fee_too_low() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.fee = MIN_TX_FEE - 1;
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::FeeTooLow { .. })));
    }

    #[test]
    fn t11_fee_at_minimum() {
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk); // Uses MIN_TX_FEE
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- Block validation helpers ---

    fn make_valid_block(txs: Vec<(Transaction, Hash256)>) -> (Block, NoblePrivateKey) {
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let val_priv = NoblePrivateKey::Ed25519(val_sk);
        let val_pub = NoblePublicKey::Ed25519(val_pk.clone());

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
                scheme_id: SCHEME_ED25519,
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
        let (sk, pk) = ed25519::generate_keypair();
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
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
            parent: Some(&parent_header),
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(result, Err(ValidationError::PrevHashMismatch)));
    }

    // --- B7: tx_count ---

    #[test]
    fn b7_tx_count_mismatch() {
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (mut block, val_priv) = make_valid_block(vec![tx]);
        block.header.tx_count = 99; // Wrong

        // Re-sign
        let msg = block.header.compute_signing_message().unwrap();
        block.header.validator_sig = val_priv.sign(&msg).unwrap();

        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
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
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (mut block, _) = make_valid_block(vec![tx]);
        block.header.validator_sig.signature = vec![0u8; 64];

        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
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
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (block, _) = make_valid_block(vec![tx]);

        // Empty validator list
        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
            parent: None,
            validator_list: &[],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(result, Err(ValidationError::ValidatorNotTrusted)));
    }

    // --- Valid block ---

    #[test]
    fn valid_block_with_transaction() {
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk);
        let (block, _) = make_valid_block(vec![tx]);

        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        assert!(validate_block(&block, &ctx).is_ok());
    }

    #[test]
    fn valid_empty_block() {
        let (block, _) = make_valid_block(vec![]);
        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
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
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recipient),
            amount: Some(100_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn t13_unknown_tx_type() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.tx_type = 0xFF;
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(result, Err(ValidationError::UnknownTxType(0xFF))));
    }

    #[test]
    fn t13_valid_notarization_type() {
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk);
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t13_valid_transfer_type() {
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recipient_pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_transfer_tx(&sk, &pk, &recipient_pk);
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    #[test]
    fn t14_transfer_missing_recipient() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: None,
            amount: Some(100_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TransferMissingRecipient)
        ));
    }

    #[test]
    fn t15_transfer_missing_amount() {
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recipient_pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recipient),
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TransferInvalidAmount)
        ));
    }

    #[test]
    fn t15_transfer_zero_amount() {
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recipient_pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recipient),
            amount: Some(0),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::TransferInvalidAmount)
        ));
    }

    #[test]
    fn t17_notarization_with_recipient() {
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recipient_pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum: sha256(b"test document"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recipient),
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::NotarizationHasTransferFields)
        ));
    }

    #[test]
    fn t17_notarization_with_amount() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum: sha256(b"test document"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: None,
            amount: Some(100),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::NotarizationHasTransferFields)
        ));
    }

    // --- validate_block_timestamp (B5/B6/B13) ---

    #[test]
    fn b5_block_timestamp_before_parent_rejected() {
        let result = validate_block_timestamp(
            999,   // block timestamp
            1_000, // parent timestamp (higher)
            &[],
            1_700_000_000,
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
            1_700_000_000,
        );
        assert!(matches!(
            result,
            Err(ValidationError::BlockTimestampBeforeMedian { .. })
        ));
    }

    #[test]
    fn b6_block_timestamp_too_far_future() {
        let now = 1_700_000_000;
        let result = validate_block_timestamp(now + MAX_BLOCK_FUTURE_SKEW + 1, now, &[], now);
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
            now + 10,
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

        let (sk, pk) = ed25519::generate_keypair();
        let (_, recipient_pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let locator = EncryptedLocator {
            ciphertext: vec![0u8; 48],
            nonce: [0u8; 12],
            recipients: vec![LocatorRecipient {
                recipient: NoblePublicKey::Ed25519(pk.to_vec()),
                ephemeral_pubkey: vec![0u8; 32],
                encrypted_key: vec![0u8; 48],
                key_nonce: [0u8; 12],
            }],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recipient),
            amount: Some(100_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: Some(locator),
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::LocatorOnNonNotarization)
        ));
    }

    #[test]
    fn t22_locator_on_notarization_accepted() {
        use crate::encrypted_locator::{EncryptedLocator, LocatorRecipient};

        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let locator = EncryptedLocator {
            ciphertext: vec![0u8; 48],
            nonce: [0u8; 12],
            recipients: vec![LocatorRecipient {
                recipient: NoblePublicKey::Ed25519(pk.to_vec()),
                ephemeral_pubkey: vec![0u8; 32],
                encrypted_key: vec![0u8; 48],
                key_nonce: [0u8; 12],
            }],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            checksum: sha256(b"test document"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: Some(locator),
            external_attestations: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- T23: External attestations on non-notarization ---

    #[test]
    fn t23_attestations_on_transfer_rejected() {
        use crate::encrypted_locator::ExternalAttestation;

        let (sk, pk) = ed25519::generate_keypair();
        let (_, recipient_pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let attestation = ExternalAttestation {
            scheme: "pkcs7".into(),
            scope: "hash".into(),
            signer_fingerprint: [0xAA; 32],
            signature_data: vec![0u8; 128],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recipient),
            amount: Some(100_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![attestation],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        let result = validate_transaction(&tx, &tx_id, &default_tx_ctx());
        assert!(matches!(
            result,
            Err(ValidationError::AttestationsOnNonNotarization)
        ));
    }

    #[test]
    fn t23_attestations_on_notarization_accepted() {
        use crate::encrypted_locator::ExternalAttestation;

        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let attestation = ExternalAttestation {
            scheme: "smime".into(),
            scope: "both".into(),
            signer_fingerprint: [0xBB; 32],
            signature_data: vec![0u8; 256],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            checksum: sha256(b"attested document"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![attestation],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        assert!(validate_transaction(&tx, &tx_id, &default_tx_ctx()).is_ok());
    }

    // --- CBOR backward compatibility ---

    #[test]
    fn tx_without_locator_deserializes() {
        // Transaction without encrypted_locator/external_attestations (backward compat)
        let (sk, pk) = ed25519::generate_keypair();
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

    #[test]
    fn b11_invalid_tx_in_block() {
        let (sk, pk) = ed25519::generate_keypair();
        let (mut tx, _) = make_signed_tx(&sk, &pk);
        tx.fee = 0; // Invalid fee, but don't re-sign (will fail T11)
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();

        let (block, _) = make_valid_block(vec![(tx, tx_id)]);
        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
            parent: None,
            validator_list: &[block.header.validator_id.clone()],
        };
        let result = validate_block(&block, &ctx);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidTransaction { index: 0, .. })
        ));
    }
}
