#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_codec::NobleCbor;

fuzz_target!(|data: &[u8]| {
    // Try decoding as various P2P message types
    let _ = noble_network::messages::SyncRequest::from_cbor(data);
    let _ = noble_network::messages::SyncResponse::from_cbor(data);
    let _ = noble_network::messages::GossipMessage::from_cbor(data);
    let _ = noble_network::messages::TxRequest::from_cbor(data);
    let _ = noble_network::messages::TxResponse::from_cbor(data);
});
