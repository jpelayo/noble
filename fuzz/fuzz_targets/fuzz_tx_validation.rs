#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;
use noble_core::{validate_transaction, Transaction, TxValidationContext};
use noble_crypto::Hash256;

/// Hardcoded chain ID for fuzz targets (ASCII "NOBL").
const FUZZ_CHAIN_ID: u32 = 0x4E4F424C;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::from_cbor(data) {
        // Compute the tx_id that would be claimed, then validate
        let claimed_tx_id = tx
            .compute_tx_id(FUZZ_CHAIN_ID)
            .unwrap_or(Hash256::ZERO);
        let ctx = TxValidationContext {
            chain_id: FUZZ_CHAIN_ID,
            current_time: 1_772_524_800 + 3600,
            chain_height: 0,
        };
        let _ = validate_transaction(&tx, &claimed_tx_id, &ctx);
    }
});
