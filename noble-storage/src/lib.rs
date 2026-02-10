// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! RocksDB storage engine with 8 column families for the NOBLE protocol.

pub mod error;
pub mod memory;
pub mod rocks;
pub mod traits;

pub use error::StorageError;
pub use memory::MemoryStorage;
pub use rocks::RocksDbStorage;
pub use traits::{ChainTip, StorageEngine};

/// Maximum number of tx_id registrations per checksum (GAP-M10).
/// Prevents unbounded growth in the checksum index.
pub const MAX_CHECKSUM_REGISTRATIONS: usize = 10_000;
