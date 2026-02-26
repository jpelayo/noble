#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;

fuzz_target!(|data: &[u8]| {
    // Try decoding as Block
    let _ = noble_core::Block::from_cbor(data);
    // Try decoding as Transaction
    let _ = noble_core::Transaction::from_cbor(data);
    // Try decoding as BlockHeader
    let _ = noble_core::block::BlockHeader::from_cbor(data);
    // Try decoding as NodeAnnounce
    let _ = noble_core::NodeAnnounce::from_cbor(data);
    // Try decoding as PeerRecord
    let _ = noble_core::PeerRecord::from_cbor(data);
});
