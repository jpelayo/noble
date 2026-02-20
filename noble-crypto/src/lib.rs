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
pub mod ecies;
pub mod ed25519;
pub mod error;
pub mod hash;
pub mod keys;
pub mod schemes;
pub mod secp256k1;
pub mod signature;

pub use error::CryptoError;
pub use hash::{canonical_double_hash, canonical_hash, double_sha256, sha256, Hash256};
pub use keys::{NoblePrivateKey, NoblePublicKey, NobleSigner, NobleVerifier, SignatureEnvelope};
pub use schemes::{is_recognized_scheme, SCHEME_BIP137, SCHEME_ED25519, SCHEME_SECP256K1};
