// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction building and signing using actual noble-core types.
//! Serializes via noble-codec (serde CBOR) — identical bytes to what the node produces.

use noble_core::address::NobleAddress;
use noble_core::metadata::MetadataEntry;
use noble_core::transaction::Transaction;
use noble_core::utxo::{OutPoint, TxIn, TxOut};
use noble_core::{
    DEFAULT_TX_TTL_SECS, PROTOCOL_VERSION, TX_TYPE_NOTARIZATION, TX_TYPE_TRANSFER,
};
use noble_crypto::{Hash256, SignatureEnvelope, SCHEME_SECP256K1};

use crate::coin_selection::{self, Utxo};
use serde::{Deserialize, Serialize};

/// Input parameters for building a transfer transaction.
#[derive(Debug, Deserialize)]
pub struct TransferParams {
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub utxos: Vec<Utxo>,
    pub change_address: String,
    pub private_key: String,
    pub chain_id: u32,
}

/// Input parameters for building a notarization transaction.
#[derive(Debug, Deserialize)]
pub struct NotarizationParams {
    pub checksum: String,
    pub metadata: Vec<MetadataKV>,
    pub fee: u64,
    pub utxos: Vec<Utxo>,
    pub change_address: String,
    pub private_key: String,
    pub chain_id: u32,
}

#[derive(Debug, Deserialize)]
pub struct MetadataKV {
    pub key: String,
    pub value: String,
}

/// Result of building a transaction.
#[derive(Debug, Serialize)]
pub struct TxResult {
    pub tx_hex: String,
    pub tx_id: String,
}

/// Build and sign a transfer transaction.
pub fn sign_transfer(params: TransferParams) -> Result<TxResult, String> {
    let recipient = parse_address(&params.recipient)?;
    let change_addr = parse_address(&params.change_address)?;
    let private_key = hex::decode(&params.private_key)
        .map_err(|e| format!("invalid private_key hex: {e}"))?;

    let target = params.amount.checked_add(params.fee)
        .ok_or("amount + fee overflow")?;
    let selected = coin_selection::select(&params.utxos, target)?;

    let total_input: u64 = selected.iter().map(|u| u.value).fold(0u64, |a, v| a.saturating_add(v));
    let change = total_input.saturating_sub(params.amount).saturating_sub(params.fee);

    let timestamp = now();

    let mut outputs = vec![TxOut {
        value: params.amount,
        address: recipient,
    }];
    if change > noble_core::DUST_THRESHOLD {
        outputs.push(TxOut {
            value: change,
            address: change_addr,
        });
    }

    let inputs = build_inputs(&selected)?;

    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_TRANSFER,
        inputs,
        outputs,
        checksum: Hash256::ZERO,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: 0,
            public_key: vec![],
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        expires_at: Some(timestamp + DEFAULT_TX_TTL_SECS),
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };

    sign_and_encode(&mut tx, &private_key, params.chain_id)
}

/// Build and sign a notarization transaction.
pub fn sign_notarization(params: NotarizationParams) -> Result<TxResult, String> {
    let checksum = Hash256::from_hex(&params.checksum)
        .map_err(|e| format!("invalid checksum: {e}"))?;
    let change_addr = parse_address(&params.change_address)?;
    let private_key = hex::decode(&params.private_key)
        .map_err(|e| format!("invalid private_key hex: {e}"))?;

    let selected = coin_selection::select(&params.utxos, params.fee)?;
    let total_input: u64 = selected.iter().map(|u| u.value).fold(0u64, |a, v| a.saturating_add(v));
    let change = total_input.saturating_sub(params.fee);

    let timestamp = now();

    let metadata: Vec<MetadataEntry> = params.metadata.iter().map(|kv| {
        MetadataEntry {
            key: kv.key.clone(),
            value: kv.value.as_bytes().to_vec(),
        }
    }).collect();

    let mut outputs = Vec::new();
    if change > noble_core::DUST_THRESHOLD {
        outputs.push(TxOut {
            value: change,
            address: change_addr,
        });
    }

    let inputs = build_inputs(&selected)?;

    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_NOTARIZATION,
        inputs,
        outputs,
        checksum,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: 0,
            public_key: vec![],
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata,
        encrypted_locator: None,
        expires_at: Some(timestamp + DEFAULT_TX_TTL_SECS),
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };

    sign_and_encode(&mut tx, &private_key, params.chain_id)
}

/// Generate a BIP-39 mnemonic.
pub fn generate_mnemonic(word_count: usize) -> Result<Vec<String>, String> {
    use bip39::Mnemonic;
    let mnemonic = Mnemonic::generate(word_count)
        .map_err(|e| format!("mnemonic generation failed: {e}"))?;
    Ok(mnemonic.word_iter().map(|w| w.to_string()).collect())
}

/// Derive a secp256k1 keypair from a BIP-39 mnemonic at m/44'/9999'/0'/0/0.
pub fn derive_keypair(mnemonic_words: &[String]) -> Result<(String, String), String> {
    use bip32::secp256k1::elliptic_curve::sec1::ToEncodedPoint;

    let phrase = mnemonic_words.join(" ");
    let mnemonic = bip39::Mnemonic::parse(&phrase)
        .map_err(|e| format!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");

    let child = bip32::XPrv::derive_from_path(
        &seed,
        &"m/44'/9999'/0'/0/0".parse().map_err(|e| format!("invalid path: {e}"))?,
    ).map_err(|e| format!("derivation failed: {e}"))?;

    let sk_bytes = child.to_bytes();
    let pk = child.public_key();
    let pk_compressed = pk.public_key().to_encoded_point(true);

    Ok((hex::encode(sk_bytes), hex::encode(pk_compressed.as_bytes())))
}

// ── Helpers ──

fn sign_and_encode(tx: &mut Transaction, private_key: &[u8], chain_id: u32) -> Result<TxResult, String> {
    let msg = tx.compute_signing_message_for_chain(chain_id)
        .map_err(|e| format!("signing message computation failed: {e}"))?;

    let sk32: [u8; 32] = private_key.try_into()
        .map_err(|_| "private key must be 32 bytes")?;
    let (_, pubkey) = noble_crypto::secp256k1::keypair_from_secret(&sk32)
        .map_err(|e| format!("public key derivation failed: {e}"))?;
    let sig = noble_crypto::secp256k1::sign(&sk32, &msg)
        .map_err(|e| format!("signing failed: {e}"))?;

    tx.issuer_sig = SignatureEnvelope {
        scheme_id: SCHEME_SECP256K1,
        public_key: pubkey,
        signature: sig,
    };

    let cbor_bytes = noble_codec::cbor_ser::to_cbor(tx)
        .map_err(|e| format!("CBOR encoding failed: {e}"))?;

    let tx_id = tx.compute_tx_id(chain_id)
        .map_err(|e| format!("tx_id computation failed: {e}"))?;

    Ok(TxResult {
        tx_hex: hex::encode(cbor_bytes),
        tx_id: hex::encode(tx_id.as_bytes()),
    })
}

fn parse_address(addr: &str) -> Result<NobleAddress, String> {
    if addr.starts_with("nbl1") {
        // Noble bech32m → NoblePublicKey → NobleAddress::Noble
        let pk = noble_crypto::noble_addr::decode(addr)
            .map_err(|e| format!("invalid Noble address: {e}"))?;
        Ok(NobleAddress::Noble(pk))
    } else if addr.starts_with("bc1") || addr.starts_with("BC1") || addr.starts_with('1') {
        // Bitcoin address (P2WPKH bc1q..., P2TR bc1p..., P2PKH 1...)
        let parsed = noble_crypto::bitcoin_addr::parse_bitcoin_address(addr)
            .map_err(|e| format!("invalid Bitcoin address: {e}"))?;
        match parsed.address_type {
            noble_crypto::bitcoin_addr::BitcoinAddressType::P2pkh
            | noble_crypto::bitcoin_addr::BitcoinAddressType::P2wpkh => {
                let hash: [u8; 20] = parsed.data.try_into()
                    .map_err(|_| "Bitcoin Hash160 must be 20 bytes")?;
                Ok(NobleAddress::BitcoinHash160(hash))
            }
            noble_crypto::bitcoin_addr::BitcoinAddressType::P2tr => {
                let xonly: [u8; 32] = parsed.data.try_into()
                    .map_err(|_| "Bitcoin Taproot must be 32 bytes")?;
                Ok(NobleAddress::BitcoinTaproot(xonly))
            }
        }
    } else {
        // Hex wire bytes fallback
        let bytes = hex::decode(addr).map_err(|e| format!("invalid address hex: {e}"))?;
        NobleAddress::from_wire_bytes(&bytes)
            .map_err(|e| format!("invalid address wire bytes: {e}"))
    }
}

fn build_inputs(utxos: &[Utxo]) -> Result<Vec<TxIn>, String> {
    utxos.iter().map(|u| {
        let txid_bytes = hex::decode(&u.txid)
            .map_err(|e| format!("invalid utxo txid hex: {e}"))?;
        let txid = Hash256::from_bytes(
            txid_bytes.try_into().map_err(|_| "txid must be 32 bytes".to_string())?
        );
        Ok(TxIn { prev_output: OutPoint { txid, vout: u.vout } })
    }).collect()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
