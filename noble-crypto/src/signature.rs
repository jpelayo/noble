// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Re-export of `SignatureEnvelope` from the keys module.
//!
//! The `SignatureEnvelope` type lives in [`crate::keys`] alongside the key
//! types it references. This module exists as a convenience re-export.

pub use crate::keys::SignatureEnvelope;
