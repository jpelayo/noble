// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! SHA-256, Ed25519, secp256k1 and multi-scheme key management for the NOBLE protocol.
//!
//! This crate provides all cryptographic primitives used by NOBLE:
//!
//! - **Hashing**: SHA-256 and double-SHA-256 via the [`hash`] module
//! - **Ed25519**: Digital signatures via the [`ed25519`] module (Step 3)
//! - **secp256k1**: Digital signatures via the [`secp256k1`] module (Step 4)
//! - **Multi-scheme keys**: Unified key types via the [`keys`] module (Step 5)

pub mod bip137;
pub mod bitcoin_addr;
pub mod ecies;
pub mod ed25519;
pub mod error;
pub mod file_encrypt;
pub mod hash;
pub mod keys;
pub mod noble_addr;
pub mod schemes;
pub mod secp256k1;
pub mod signature;

pub use error::CryptoError;
pub use hash::{double_sha256, sha256, tagged_hash, Hash256};
pub use keys::{NoblePrivateKey, NoblePublicKey, NobleSigner, NobleVerifier, SignatureEnvelope};
pub use schemes::{
    is_recognized_scheme, is_signing_scheme, SCHEME_BIP137, SCHEME_ED25519,
    SCHEME_FAUCET_PASSPHRASE, SCHEME_P2P_IDENTITY, SCHEME_SECP256K1, SCHEME_TLS_KEY,
    SCHEME_TOTP_SECRET, SCHEME_VALIDATOR_ED25519, SCHEME_VALIDATOR_SECP256K1,
};
