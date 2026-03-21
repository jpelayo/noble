#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;
use noble_core::{validate_block, Block, BlockValidationContext};

/// Hardcoded chain ID for fuzz targets (ASCII "NOBL").
const FUZZ_CHAIN_ID: u32 = 0x4E4F424C;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::from_cbor(data) {
        let ctx = BlockValidationContext {
            chain_id: FUZZ_CHAIN_ID,
            current_time: 1_772_524_800 + 3600,
            parent: None,
            validator_list: &[],
            skip_timestamp_skew: false,
        };
        let _ = validate_block(&block, &ctx);
    }
});
