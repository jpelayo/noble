#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;
use noble_core::{validate_transaction, Transaction, TxValidationContext, mainnet_chain_id};
use noble_crypto::Hash256;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::from_cbor(data) {
        // Compute the tx_id that would be claimed, then validate
        let claimed_tx_id = tx
            .compute_tx_id(mainnet_chain_id())
            .unwrap_or(Hash256::ZERO);
        let ctx = TxValidationContext {
            chain_id: mainnet_chain_id(),
            current_time: 1_772_524_800 + 3600,
            chain_height: 0,
        };
        let _ = validate_transaction(&tx, &claimed_tx_id, &ctx);
    }
});
