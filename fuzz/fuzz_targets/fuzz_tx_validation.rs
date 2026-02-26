#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;
use noble_core::{validate_transaction, Transaction, TxValidationContext, MAINNET_CHAIN_ID};
use noble_crypto::Hash256;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::from_cbor(data) {
        // Compute the tx_id that would be claimed, then validate
        let claimed_tx_id = tx
            .compute_tx_id(MAINNET_CHAIN_ID)
            .unwrap_or(Hash256::ZERO);
        let ctx = TxValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_772_524_800 + 3600,
        };
        let _ = validate_transaction(&tx, &claimed_tx_id, &ctx);
    }
});
