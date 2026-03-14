// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Frozen wire format — thin re-export crate.
//!
//! The actual WireFormat trait, CBOR encoder, and V1 implementations live
//! in `noble-core::wire`. This crate re-exports them and adds the frozen
//! test vectors used by `noble-tool verify-wire` and brew post_install.
//!
//! This ensures the frozen vector verifier exercises the EXACT SAME code
//! path as production hashing (compute_tx_id, compute_block_hash).

pub use noble_core::wire::cbor;
pub use noble_core::wire::v1;
pub use noble_core::wire::WireFormat;
pub use noble_core::wire::WIRE_FORMAT_VERSION;

pub mod vectors;
