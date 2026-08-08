// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Stateful transaction validation: input ownership and value conservation.
//!
//! Structural validation ([`crate::validation::validate_transaction`]) cannot
//! decide these rules because input *values* and *owners* live in the UTXO set,
//! not in the transaction. This module holds the rules that need resolved
//! inputs, while staying **pure**: the caller resolves outpoints and passes the
//! entries in; nothing here reads storage.
//!
//! # Why one shared function
//!
//! Ownership and conservation must be enforced identically at every stateful
//! acceptance path — mempool admission, block commit (both storage backends),
//! and sync import. Historically they were enforced at *none* of them: a
//! transaction carries a single issuer signature verified against its own
//! embedded key, so nothing tied the signer to the addresses of the coins being
//! spent, and RocksDB accepted `outputs > inputs` while MemoryStorage rejected
//! it. Both classes of bug are only avoidable if every path calls the same
//! validator, so backends cannot drift apart.

use std::collections::HashSet;

use noble_crypto::{NoblePublicKey, SCHEME_BIP137, SCHEME_SECP256K1};

use crate::address::NobleAddress;
use crate::error::ValidationError;
use crate::transaction::Transaction;
use crate::utxo::{OutPoint, UtxoEntry};

/// One transaction input paired with the UTXO it consumes.
///
/// Borrowed so callers can build these over their own storage view or an
/// in-block overlay without cloning the UTXO set.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedInput<'a> {
    /// The outpoint being consumed.
    pub outpoint: &'a OutPoint,
    /// The UTXO entry that outpoint resolves to.
    pub utxo: &'a UtxoEntry,
    /// Whether this UTXO was created by an earlier transaction in the *same
    /// block* currently being validated.
    ///
    /// Such outputs are exempt from the maturity rule — that is what makes
    /// intra-block UTXO chaining (a child spending its parent's output in one
    /// block, i.e. CPFP) possible. Both storage backends already implement this
    /// exemption, so the shared validator must honour it or it would reject
    /// blocks the chain currently accepts.
    ///
    /// Callers that resolve only against the *persistent* UTXO set — mempool
    /// admission in particular, where in-mempool parents are handled by the
    /// pool's own dependency tracking — must set this to `false`.
    pub same_block: bool,
}

impl<'a> ResolvedInput<'a> {
    /// A resolved input read from the persistent UTXO set (maturity applies).
    pub fn confirmed(outpoint: &'a OutPoint, utxo: &'a UtxoEntry) -> Self {
        Self { outpoint, utxo, same_block: false }
    }

    /// A resolved input created earlier in the same block (maturity exempt).
    pub fn same_block(outpoint: &'a OutPoint, utxo: &'a UtxoEntry) -> Self {
        Self { outpoint, utxo, same_block: true }
    }
}

/// Value accounting for one validated transaction, in atomic units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionAccounting {
    /// Sum of consumed input values.
    pub input_total: u64,
    /// Sum of created output values.
    pub output_total: u64,
    /// `input_total - output_total`. Never negative: conservation is checked first.
    pub fee: u64,
}

/// Whether `tx_type` mints by protocol rule rather than consuming inputs.
///
/// Coinbase and fee-distribution outputs are created from the block subsidy and
/// collected fees, so they legitimately have no owned inputs and must never be
/// measured against the conservation rule. They are checked by the commit-time
/// reward rules instead.
pub fn is_minting_tx_type(tx_type: u8) -> bool {
    tx_type == crate::constants::TX_TYPE_COINBASE || tx_type == crate::constants::TX_TYPE_FEE
}

/// The public key that must control every input of `tx`.
///
/// Both supported issuer schemes carry the signer's key in the envelope:
/// secp256k1 verifies against it directly, and BIP-137 recovers a key from the
/// recoverable signature and requires it to equal this field
/// (`validation::validate_bip137_signature`). Any other scheme cannot be mapped
/// to an address, so it is an error rather than a silent `false` — refusing to
/// guess is what keeps an unsupported scheme from spending someone's coins.
pub fn issuer_public_key(tx: &Transaction) -> Result<NoblePublicKey, ValidationError> {
    match tx.issuer_sig.scheme_id {
        SCHEME_SECP256K1 | SCHEME_BIP137 => {
            Ok(NoblePublicKey::Secp256k1(tx.issuer_sig.public_key.clone()))
        }
        scheme => Err(ValidationError::UnsupportedIssuerScheme { scheme }),
    }
}

/// Validate resolved inputs: ownership, maturity, and value conservation.
///
/// `spend_height` is the height at which the spend is being evaluated (the
/// chain tip for mempool admission, the block's own height at commit).
///
/// Checks run cheapest-first and in a fixed order so every path produces the
/// same error for the same defect:
///
/// 1. reject minting types (coinbase / fee distribution),
/// 2. resolved count matches the transaction's input count,
/// 3. each resolved outpoint is the one the transaction references at that index,
/// 4. no outpoint is consumed twice,
/// 5. **every consumed UTXO is controlled by the issuer** (C1),
/// 6. every consumed UTXO is mature,
/// 7. totals accumulate without overflow,
/// 8. **outputs never exceed inputs** (C2).
///
/// Returns the exact fee on success. Never reads storage, never mutates, never
/// treats a missing input as zero value, and never uses saturating arithmetic
/// for protocol totals — a saturating sum would silently forgive an overflow
/// that must reject.
pub fn validate_resolved_inputs(
    tx: &Transaction,
    resolved: &[ResolvedInput<'_>],
    spend_height: u64,
) -> Result<TransactionAccounting, ValidationError> {
    // 1. Minting types are not measured against conservation.
    if is_minting_tx_type(tx.tx_type) {
        return Err(ValidationError::NotARegularInputTransaction(tx.tx_type));
    }

    // 2. The caller must resolve every input — no partial views.
    if resolved.len() != tx.inputs.len() {
        return Err(ValidationError::ResolvedInputCountMismatch {
            expected: tx.inputs.len(),
            actual: resolved.len(),
        });
    }

    let issuer = issuer_public_key(tx)?;
    let mut seen: HashSet<&OutPoint> = HashSet::with_capacity(resolved.len());
    let mut input_total: u64 = 0;

    for (index, entry) in resolved.iter().enumerate() {
        // 3. Positional correspondence: the resolved entry must be for the
        //    outpoint this transaction actually references at this index,
        //    otherwise ownership could be proven against an unrelated UTXO.
        if entry.outpoint != &tx.inputs[index].prev_output {
            return Err(ValidationError::ResolvedOutpointMismatch { index });
        }

        // 4. Re-check duplicates here even though the stateless layer also
        //    rejects them: this function is the last line before value moves.
        if !seen.insert(entry.outpoint) {
            return Err(ValidationError::DuplicateResolvedOutpoint { index });
        }

        // 5. C1 — ownership. One key controls its Noble address and the
        //    Bitcoin Hash160/Taproot forms derived from it.
        if !entry.utxo.address.is_controlled_by(&issuer) {
            return Err(ValidationError::InputOwnershipMismatch {
                index,
                outpoint: format!("{}:{}", entry.outpoint.txid, entry.outpoint.vout),
            });
        }

        // 6. Maturity (all outputs, not just coinbase). Outputs created earlier
        //    in this same block are exempt — see `ResolvedInput::same_block`.
        if !entry.same_block && !entry.utxo.is_mature(spend_height) {
            return Err(ValidationError::InputImmature {
                index,
                created_height: entry.utxo.height,
                spend_height,
            });
        }

        input_total = input_total
            .checked_add(entry.utxo.value)
            .ok_or(ValidationError::InputValueOverflow)?;
    }

    // 7. Output total, checked.
    let mut output_total: u64 = 0;
    for out in &tx.outputs {
        output_total = output_total
            .checked_add(out.value)
            .ok_or(ValidationError::OutputValueOverflow)?;
    }

    // 8. C2 — conservation. Everything not paid out is the fee.
    let fee = input_total.checked_sub(output_total).ok_or(
        ValidationError::OutputsExceedInputs {
            inputs: input_total,
            outputs: output_total,
        },
    )?;

    Ok(TransactionAccounting {
        input_total,
        output_total,
        fee,
    })
}

/// Convenience matcher used by wallets/tests: does `issuer` control `address`?
pub fn address_is_controlled_by(issuer: &NoblePublicKey, address: &NobleAddress) -> bool {
    address.is_controlled_by(issuer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{COINBASE_MATURITY, TX_TYPE_COINBASE, TX_TYPE_TRANSFER};
    use crate::metadata::MetadataEntry;
    use crate::utxo::{TxIn, TxOut};
    use noble_crypto::{Hash256, SignatureEnvelope};

    /// Spend height used by every test: the maturity gate (`COINBASE_MATURITY`)
    /// rejects inputs *before* ownership or value are examined, so tests run at
    /// height 0 would pass vacuously and prove nothing about C1/C2.
    const SPEND_HEIGHT: u64 = COINBASE_MATURITY + 10;

    fn keypair() -> (Vec<u8>, NoblePublicKey) {
        let (_sk, pk) = noble_crypto::secp256k1::generate_keypair();
        (pk.clone(), NoblePublicKey::Secp256k1(pk))
    }

    fn outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint { txid: Hash256::from_bytes([seed; 32]), vout }
    }

    fn utxo(value: u64, address: NobleAddress) -> UtxoEntry {
        UtxoEntry { value, address, height: 0, is_coinbase: false }
    }

    fn tx_with(tx_type: u8, issuer_pk: &[u8], inputs: Vec<OutPoint>, outputs: Vec<u64>) -> Transaction {
        let out_addr = NobleAddress::Noble(NoblePublicKey::Secp256k1(issuer_pk.to_vec()));
        Transaction {
            version: 1,
            tx_type,
            inputs: inputs.into_iter().map(|prev_output| TxIn { prev_output }).collect(),
            outputs: outputs
                .into_iter()
                .map(|value| TxOut { value, address: out_addr.clone() })
                .collect(),
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: issuer_pk.to_vec(),
                signature: vec![0u8; 64],
            },
            additional_sigs: Vec::new(),
            declared_cosigners: Vec::new(),
            metadata: Vec::<MetadataEntry>::new(),
            encrypted_locator: None,
            expires_at: None,
            external_attestations: Vec::new(),
            gateway_address: None,
            contract_data: None,
        }
    }

    #[test]
    fn issuer_owned_inputs_accepted_and_fee_is_exact() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(1, 0);
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![900]);

        let acct = validate_resolved_inputs(
            &tx,
            &[ResolvedInput::confirmed(&op, &entry)],
            SPEND_HEIGHT,
        )
        .expect("issuer-owned, mature, conserving tx must validate");

        assert_eq!(acct.input_total, 1_000);
        assert_eq!(acct.output_total, 900);
        assert_eq!(acct.fee, 100);
    }

    #[test]
    fn input_owned_by_another_key_is_rejected() {
        // The whole point of C1: a valid signature over the payload must not be
        // sufficient to spend coins belonging to a different address.
        let (issuer_bytes, _issuer) = keypair();
        let (_victim_bytes, victim) = keypair();
        let op = outpoint(2, 0);
        let entry = utxo(5_000, NobleAddress::Noble(victim));
        let tx = tx_with(TX_TYPE_TRANSFER, &issuer_bytes, vec![op.clone()], vec![4_000]);

        let err = validate_resolved_inputs(
            &tx,
            &[ResolvedInput::confirmed(&op, &entry)],
            SPEND_HEIGHT,
        )
        .expect_err("spending another address's UTXO must be rejected");

        assert!(
            matches!(err, ValidationError::InputOwnershipMismatch { index: 0, .. }),
            "expected ownership mismatch, got {err:?}"
        );
    }

    #[test]
    fn hash160_and_taproot_aliases_of_the_issuer_are_owned() {
        // One secp256k1 key controls three address forms; all must match, or
        // honest coins held under a Bitcoin-format address would freeze.
        let (pk_bytes, pk) = keypair();
        for address in [
            NobleAddress::bitcoin_hash160_for_pubkey(&pk).unwrap(),
            NobleAddress::bitcoin_taproot_for_pubkey(&pk).unwrap(),
        ] {
            let op = outpoint(3, 0);
            let entry = utxo(2_000, address.clone());
            let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![1_500]);

            let acct = validate_resolved_inputs(
                &tx,
                &[ResolvedInput::confirmed(&op, &entry)],
                SPEND_HEIGHT,
            )
            .unwrap_or_else(|e| panic!("alias {address:?} must be owned by its key: {e:?}"));
            assert_eq!(acct.fee, 500);
        }
    }

    #[test]
    fn alias_of_a_different_key_is_not_owned() {
        let (issuer_bytes, _issuer) = keypair();
        let (_other_bytes, other) = keypair();
        let foreign = NobleAddress::bitcoin_hash160_for_pubkey(&other).unwrap();
        let op = outpoint(4, 0);
        let entry = utxo(2_000, foreign);
        let tx = tx_with(TX_TYPE_TRANSFER, &issuer_bytes, vec![op.clone()], vec![1_000]);

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT),
            Err(ValidationError::InputOwnershipMismatch { .. })
        ));
    }

    #[test]
    fn outputs_exceeding_inputs_are_rejected() {
        // C2: this is the RocksDB minting hole.
        let (pk_bytes, pk) = keypair();
        let op = outpoint(5, 0);
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![1_001]);

        let err = validate_resolved_inputs(
            &tx,
            &[ResolvedInput::confirmed(&op, &entry)],
            SPEND_HEIGHT,
        )
        .expect_err("minting must be rejected");

        assert!(
            matches!(err, ValidationError::OutputsExceedInputs { inputs: 1_000, outputs: 1_001 }),
            "expected conservation failure, got {err:?}"
        );
    }

    #[test]
    fn outputs_equal_to_inputs_are_accepted_with_zero_fee() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(6, 0);
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![1_000]);

        let acct =
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT)
                .expect("exact conservation is valid here; the fee floor is a policy rule");
        assert_eq!(acct.fee, 0);
    }

    #[test]
    fn input_sum_overflow_is_rejected_not_wrapped() {
        let (pk_bytes, pk) = keypair();
        let (op_a, op_b) = (outpoint(7, 0), outpoint(7, 1));
        let addr = NobleAddress::Noble(pk);
        let (a, b) = (utxo(u64::MAX, addr.clone()), utxo(2, addr));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op_a.clone(), op_b.clone()], vec![1]);

        assert!(matches!(
            validate_resolved_inputs(
                &tx,
                &[
                    ResolvedInput::confirmed(&op_a, &a),
                    ResolvedInput::confirmed(&op_b, &b),
                ],
                SPEND_HEIGHT,
            ),
            Err(ValidationError::InputValueOverflow)
        ));
    }

    #[test]
    fn output_sum_overflow_is_rejected_not_wrapped() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(8, 0);
        let entry = utxo(10, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![u64::MAX, 5]);

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT),
            Err(ValidationError::OutputValueOverflow)
        ));
    }

    #[test]
    fn immature_input_is_rejected() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(9, 0);
        let mut entry = utxo(1_000, NobleAddress::Noble(pk));
        entry.height = SPEND_HEIGHT; // zero confirmations
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![900]);

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT),
            Err(ValidationError::InputImmature { index: 0, .. })
        ));
    }

    #[test]
    fn same_block_output_is_exempt_from_maturity() {
        // Intra-block UTXO chaining (CPFP): a child spends its parent's output
        // in the same block. Both storage backends already allow this, so the
        // shared validator must too — otherwise blocks the chain accepts today
        // would start being rejected.
        let (pk_bytes, pk) = keypair();
        let op = outpoint(16, 0);
        let mut entry = utxo(1_000, NobleAddress::Noble(pk));
        entry.height = SPEND_HEIGHT; // created in the block being validated
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![900]);

        // Same outpoint, resolved the two different ways:
        assert!(
            matches!(
                validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT),
                Err(ValidationError::InputImmature { .. })
            ),
            "a zero-confirmation UTXO from the persistent set must stay immature"
        );
        let acct = validate_resolved_inputs(
            &tx,
            &[ResolvedInput::same_block(&op, &entry)],
            SPEND_HEIGHT,
        )
        .expect("an output created earlier in this same block is spendable");
        assert_eq!(acct.fee, 100);
    }

    #[test]
    fn same_block_exemption_does_not_bypass_ownership() {
        // The maturity exemption must not become a general escape hatch.
        let (issuer_bytes, _issuer) = keypair();
        let (_victim_bytes, victim) = keypair();
        let op = outpoint(17, 0);
        let mut entry = utxo(1_000, NobleAddress::Noble(victim));
        entry.height = SPEND_HEIGHT;
        let tx = tx_with(TX_TYPE_TRANSFER, &issuer_bytes, vec![op.clone()], vec![900]);

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::same_block(&op, &entry)], SPEND_HEIGHT),
            Err(ValidationError::InputOwnershipMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_outpoint_is_rejected() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(10, 0);
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone(), op.clone()], vec![500]);

        assert!(matches!(
            validate_resolved_inputs(
                &tx,
                &[
                    ResolvedInput::confirmed(&op, &entry),
                    ResolvedInput::confirmed(&op, &entry),
                ],
                SPEND_HEIGHT,
            ),
            Err(ValidationError::DuplicateResolvedOutpoint { index: 1 })
        ));
    }

    #[test]
    fn resolved_count_mismatch_is_rejected() {
        let (pk_bytes, pk) = keypair();
        let (op_a, op_b) = (outpoint(11, 0), outpoint(11, 1));
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op_a.clone(), op_b], vec![500]);

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op_a, &entry)], SPEND_HEIGHT),
            Err(ValidationError::ResolvedInputCountMismatch { expected: 2, actual: 1 })
        ));
    }

    #[test]
    fn resolved_entry_for_the_wrong_outpoint_is_rejected() {
        // Guards against proving ownership against a UTXO the tx never referenced.
        let (pk_bytes, pk) = keypair();
        let (referenced, unrelated) = (outpoint(12, 0), outpoint(13, 0));
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![referenced], vec![500]);

        assert!(matches!(
            validate_resolved_inputs(
                &tx,
                &[ResolvedInput::confirmed(&unrelated, &entry)],
                SPEND_HEIGHT,
            ),
            Err(ValidationError::ResolvedOutpointMismatch { index: 0 })
        ));
    }

    #[test]
    fn minting_types_are_refused_by_this_validator() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(14, 0);
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let tx = tx_with(TX_TYPE_COINBASE, &pk_bytes, vec![op.clone()], vec![5_000]);

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT),
            Err(ValidationError::NotARegularInputTransaction(TX_TYPE_COINBASE))
        ));
    }

    #[test]
    fn unsupported_issuer_scheme_errors_rather_than_denying_ownership() {
        let (pk_bytes, pk) = keypair();
        let op = outpoint(15, 0);
        let entry = utxo(1_000, NobleAddress::Noble(pk));
        let mut tx = tx_with(TX_TYPE_TRANSFER, &pk_bytes, vec![op.clone()], vec![900]);
        tx.issuer_sig.scheme_id = 0x7F;

        assert!(matches!(
            validate_resolved_inputs(&tx, &[ResolvedInput::confirmed(&op, &entry)], SPEND_HEIGHT),
            Err(ValidationError::UnsupportedIssuerScheme { scheme: 0x7F })
        ));
    }
}
