// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! RocksDB storage engine with 10 column families for the NOBLE protocol.

pub mod catalog;
pub mod commit_validation;
pub mod error;
pub mod integrity;
pub mod introspect;
pub mod memory;
pub mod pruning;
pub mod reconcile;
pub mod rocks;
pub mod traits;

pub use catalog::{
    bootstrap_path, catalog_path, ensure_bootstrap_marker, read_catalog, write_catalog,
    CatalogEntry, PathCatalog, BOOTSTRAP_FILE_NAME, CATALOG_FILE_NAME, CATALOG_MAGIC,
    CATALOG_VERSION,
};
pub use error::StorageError;
pub use integrity::{verify_chain_integrity, FindingKind, IntegrityFinding, IntegrityReport};
pub use introspect::{describe_sst, scan_directory, SstDescriptor};
pub use memory::MemoryStorage;
pub use pruning::{PruningConfig, PruningEngine, PruningMode, PruningResult};
pub use reconcile::{
    decide, discover_shards, DiscoveryReport, DuplicateSst, PathInventory, ReconcileDecision,
};
pub use rocks::{PathUsage, RocksDbConfig, RocksDbStorage, ALL_CF_NAMES};
pub use traits::{CfStats, ChainTip, KeyRotationRecord, StorageEngine, StorageStats};

/// Maximum number of tx_id registrations per checksum (GAP-M10).
/// Prevents unbounded growth in the checksum index.
pub const MAX_CHECKSUM_REGISTRATIONS: usize = 10_000;
