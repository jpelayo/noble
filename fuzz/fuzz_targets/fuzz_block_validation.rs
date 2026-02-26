#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;
use noble_core::{validate_block, Block, BlockValidationContext, MAINNET_CHAIN_ID};

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::from_cbor(data) {
        let ctx = BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_772_524_800 + 3600,
            parent: None,
            validator_list: &[],
        };
        let _ = validate_block(&block, &ctx);
    }
});
