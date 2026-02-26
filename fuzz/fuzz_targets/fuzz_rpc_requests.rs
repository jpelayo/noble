#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_crypto::{Hash256, NoblePublicKey};

fuzz_target!(|data: &[u8]| {
    // Exercise hex decoding -- common RPC parameter path
    if data.len() <= 256 {
        if let Ok(s) = std::str::from_utf8(data) {
            // Try parsing as a hex-encoded hash
            let _ = Hash256::from_hex(s);
        }
        // Try parsing as a public key from wire bytes
        let _ = NoblePublicKey::from_wire_bytes(data);
    }
});
