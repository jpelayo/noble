#![no_main]
use libfuzzer_sys::fuzz_target;
use noble_crypto::{ed25519, secp256k1};

fuzz_target!(|data: &[u8]| {
    // Need at least pubkey(32) + msg(1) + sig(64) = 97 bytes for ed25519
    if data.len() >= 97 {
        let pubkey = &data[..32];
        let msg = &data[32..data.len() - 64];
        let sig = &data[data.len() - 64..];
        let _ = ed25519::verify(pubkey, msg, sig);
    }
    // Try secp256k1 verify: pubkey(33) + msg(1) + sig(64) = 98 bytes
    if data.len() >= 98 {
        let pubkey = &data[..33];
        let msg = &data[33..data.len() - 64];
        let sig = &data[data.len() - 64..];
        let _ = secp256k1::verify(pubkey, msg, sig);
    }
});
