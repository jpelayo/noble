#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_consensus::config::ConsensusConfig;
use noble_consensus::validator::ValidatorList;
use noble_consensus::{ConsensusStateMachine, CycleEngine, CycleEvent};
use noble_crypto::Hash256;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    // Use first 8 bytes as base timestamp for tick events
    let ts = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    // Clamp to reasonable range
    let ts = ts % 1_000_000;

    let mut engine = CycleEngine::new(
        ConsensusConfig::default(),
        ValidatorList::new(),
        0,
        Hash256::ZERO,
        noble_core::mainnet_chain_id(),
        None,
        Some(0),
    );

    // Feed tick events at various timestamps derived from fuzz input
    let mut offset = 8;
    while offset + 8 <= data.len() {
        let delta = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) % 10_000;
        let _ = engine.step(CycleEvent::Tick { now: ts + delta });
        offset += 8;
    }
});
