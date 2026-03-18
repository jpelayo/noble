// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared Rust library for Noble client apps.
//!
//! Provides transaction building, signing, coin selection, and key derivation
//! using the actual `noble-core` types and `noble-codec` serialization.
//! All 4 client apps (NobleApp, NobleMac, NobleWin, NobleDoc) call this
//! library — ensuring identical CBOR encoding with the node.

pub mod coin_selection;
pub mod transaction;
pub mod ffi;
