// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-path shard catalog (`.noble-shards.cbor`).
//!
//! Each directory listed as a Noble storage tier (`data_dir` + any
//! `extra_data_dirs`) carries one CBOR file at its root naming every SST
//! file the node *expects* to find there, together with the metadata
//! captured from RocksDB while the DB is open: column family name,
//! LSM level, key range, file number, size, num_entries, and the
//! creation time RocksDB recorded.
//!
//! The catalog is **advisory**: RocksDB never reads it. Noble's startup
//! reads it (Phase 2 discovery) to:
//!
//! - Detect missing files quickly without opening the DB.
//! - Detect drift (file is here but its size/hash diverged).
//! - Tell the operator what each directory contains.
//!
//! Writes are atomic via `write-to-tmp + rename`: a crash mid-write
//! never leaves a half-catalog.
//!
//! The catalog encodes through `noble_codec::NobleCbor`'s blanket impl
//! over `serde::{Serialize, DeserializeOwned}` — no derive macro is
//! needed beyond `#[derive(Serialize, Deserialize)]`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// Magic bytes identifying a Noble shard catalog: ASCII `NSHD`.
pub const CATALOG_MAGIC: [u8; 4] = *b"NSHD";

/// Catalog format version. Bumped when the wire layout changes in a
/// way readers cannot transparently absorb.
pub const CATALOG_VERSION: u32 = 1;

/// Catalog file basename (kept identical across every configured path).
pub const CATALOG_FILE_NAME: &str = ".noble-shards.cbor";

/// Bootstrap marker basename. Audit Fix #S7 (0.118): created
/// alongside the first successful catalog write at each tier. Its
/// presence on subsequent boots signals that the node has managed
/// this tier before, so a missing catalog now means a real fault
/// (deleted / lost), not a first-ever boot. Empty (0-byte) file —
/// only its presence matters.
pub const BOOTSTRAP_FILE_NAME: &str = ".noble-bootstrap";

/// Convenience: where the bootstrap marker lives within a given directory.
pub fn bootstrap_path(dir: &Path) -> PathBuf {
    dir.join(BOOTSTRAP_FILE_NAME)
}

/// Atomically materialise a bootstrap marker at `<dir>/.noble-bootstrap`.
/// No-op if the marker already exists. Used after the first successful
/// catalog write to indicate "this tier is now under steady-state
/// management."
pub fn ensure_bootstrap_marker(dir: &Path) -> Result<(), StorageError> {
    let p = bootstrap_path(dir);
    if p.exists() {
        return Ok(());
    }
    // Create + fsync to make the marker durable. The marker is
    // tiny and its presence (not contents) is what matters, so
    // truncate-on-conflict semantics are fine.
    let f = std::fs::File::create(&p).map_err(|e| {
        StorageError::Database(format!(
            "ensure_bootstrap_marker create {p:?}: {e}"
        ))
    })?;
    f.sync_all().map_err(|e| {
        StorageError::Database(format!(
            "ensure_bootstrap_marker fsync {p:?}: {e}"
        ))
    })?;
    Ok(())
}

/// One Noble shard catalog living at the root of a configured storage
/// directory. Catalogs are written on clean shutdown (via the
/// `Node::run` graceful-shutdown hook, audit Fix #2) and on demand via
/// the `noble_reconcileStorage` RPC. They are read on every startup
/// before the DB is opened so discovery can compare expected vs. disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathCatalog {
    /// Always [`CATALOG_MAGIC`]. Sanity guard.
    pub magic: [u8; 4],
    /// Format version. Must equal [`CATALOG_VERSION`] for the catalog
    /// to be trusted by readers in this Noble version.
    pub version: u32,
    /// Chain ID this catalog belongs to. Cross-chain mounting (e.g.
    /// pointing two different chains' data at the same disk) must not
    /// be reconciled together. `0` means "unknown / not yet recorded"
    /// — accepted by readers that pass `expected_chain_id = None`.
    pub chain_id: u32,
    /// Wall-clock at last update (Unix seconds).
    pub updated_at: u64,
    /// Hex of the node's identity public key that last wrote this
    /// catalog. Disaster-recovery hint: "this directory was last
    /// managed by this node." Empty string when unknown.
    pub node_pubkey_hex: String,
    /// One entry per SST file the node expects to find in this path.
    pub entries: Vec<CatalogEntry>,
}

impl PathCatalog {
    /// Construct a fresh catalog with no entries. Callers populate
    /// `entries` via [`crate::rocks::RocksDbStorage::build_catalog`].
    pub fn new(chain_id: u32, node_pubkey_hex: impl Into<String>) -> Self {
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            magic: CATALOG_MAGIC,
            version: CATALOG_VERSION,
            chain_id,
            updated_at,
            node_pubkey_hex: node_pubkey_hex.into(),
            entries: Vec::new(),
        }
    }
}

/// One row in a [`PathCatalog`]. Captures the RocksDB-side metadata
/// available via [`rocksdb::DB::live_files`] plus a content hash so
/// reconciliation can detect post-move drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogEntry {
    /// SST file basename, e.g. `"000123.sst"`.
    pub file_name: String,
    /// Column family the SST belongs to (`"blocks"`, `"utxo_set"`, …).
    pub column_family: String,
    /// LSM level the SST was at when the catalog was written.
    pub level: i32,
    /// Smallest user key (hex). Empty string when RocksDB reports
    /// `None` (e.g. for an empty file, which RocksDB doesn't produce
    /// but the API allows).
    pub smallest_key_hex: String,
    /// Largest user key (hex). Same null-empty convention.
    pub largest_key_hex: String,
    /// File size in bytes at last update.
    pub size_bytes: u64,
    /// Number of entries (`Put` + `Delete` + `Merge`).
    pub num_entries: u64,
    /// Number of deletions (tombstones) in the file.
    pub num_deletions: u64,
    /// Content SHA-256 (hex) at last update. Optional — computing
    /// hashes for thousands of SSTs at every flush would be expensive,
    /// so hashes are populated lazily on first reconciliation or when
    /// the operator explicitly requests `with_hash`.
    pub content_sha256: Option<String>,
}

/// Write a catalog **atomically and durably**.
///
/// Atomic: write to `<path>/.noble-shards.cbor.tmp`, then `rename`
/// into place — a crash anywhere in between leaves either the old
/// catalog or no `.tmp` file at all, never a torn write.
///
/// Durable (audit Fix #7): the tmp file is fsync'd (data + metadata)
/// before the rename, and the parent directory is fsync'd after the
/// rename. Without these, a successful `rename(2)` return can be
/// followed by a power-loss that leaves the catalog claim in place
/// while the underlying bytes never reached the platter — exactly
/// the failure mode this catalog is supposed to defend against.
pub fn write_catalog(dir: &Path, catalog: &PathCatalog) -> Result<(), StorageError> {
    use noble_codec::NobleCbor;
    use std::io::Write;

    let bytes = catalog.to_cbor().map_err(|e| {
        StorageError::Database(format!("write_catalog encode {:?}: {e}", dir))
    })?;
    let final_path = dir.join(CATALOG_FILE_NAME);
    let tmp_path = dir.join(format!("{CATALOG_FILE_NAME}.tmp"));

    // 1. Create + write + fsync the tmp file.
    {
        let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
            StorageError::Database(format!("write_catalog create {:?}: {e}", tmp_path))
        })?;
        f.write_all(&bytes).map_err(|e| {
            StorageError::Database(format!("write_catalog write {:?}: {e}", tmp_path))
        })?;
        // sync_all = data + metadata fsync (fdatasync would also work
        // but only-data; we want the size update durable too).
        f.sync_all().map_err(|e| {
            StorageError::Database(format!("write_catalog fsync {:?}: {e}", tmp_path))
        })?;
    }

    // 2. Atomic rename.
    std::fs::rename(&tmp_path, &final_path).map_err(|e| {
        StorageError::Database(format!(
            "write_catalog rename {:?} -> {:?}: {e}",
            tmp_path, final_path
        ))
    })?;

    // 3. fsync the parent directory so the rename itself is durable.
    //    POSIX requires this; on Linux without it a crash after the
    //    rename can leave the directory entry pointing nowhere.
    //    Unix-only — Windows uses MOVEFILE_WRITE_THROUGH inside the
    //    std::fs::rename path so the parent fsync is unnecessary.
    #[cfg(unix)]
    {
        let dir_handle = std::fs::File::open(dir).map_err(|e| {
            StorageError::Database(format!(
                "write_catalog open parent {:?}: {e}",
                dir
            ))
        })?;
        dir_handle.sync_all().map_err(|e| {
            StorageError::Database(format!(
                "write_catalog fsync parent {:?}: {e}",
                dir
            ))
        })?;
    }
    Ok(())
}

/// Read a catalog from `<dir>/.noble-shards.cbor`. Returns `Ok(None)`
/// when the file is absent (a fresh tier the node has never managed).
/// Returns `Err` when the file exists but is unparseable or carries
/// the wrong magic / version — reconciliation treats those as
/// "missing", falling back to a disk scan.
pub fn read_catalog(dir: &Path) -> Result<Option<PathCatalog>, StorageError> {
    use noble_codec::NobleCbor;

    let p = dir.join(CATALOG_FILE_NAME);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(StorageError::Database(format!(
                "read_catalog read {:?}: {e}",
                p
            )))
        }
    };
    let catalog: PathCatalog = PathCatalog::from_cbor(&bytes).map_err(|e| {
        StorageError::Database(format!("read_catalog decode {:?}: {e}", p))
    })?;
    if catalog.magic != CATALOG_MAGIC {
        return Err(StorageError::Database(format!(
            "read_catalog {:?}: bad magic {:?} (expected NSHD)",
            p, catalog.magic
        )));
    }
    if catalog.version != CATALOG_VERSION {
        return Err(StorageError::Database(format!(
            "read_catalog {:?}: version {} unsupported (expected {})",
            p, catalog.version, CATALOG_VERSION
        )));
    }
    Ok(Some(catalog))
}

/// Convenience: where the catalog lives within a given directory.
pub fn catalog_path(dir: &Path) -> PathBuf {
    dir.join(CATALOG_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_catalog() -> PathCatalog {
        let mut cat = PathCatalog::new(0x1234, "deadbeef");
        cat.entries.push(CatalogEntry {
            file_name: "000001.sst".to_string(),
            column_family: "blocks".to_string(),
            level: 0,
            smallest_key_hex: "00".to_string(),
            largest_key_hex: "ff".to_string(),
            size_bytes: 1024,
            num_entries: 100,
            num_deletions: 0,
            content_sha256: Some(
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
            ),
        });
        cat
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let original = sample_catalog();
        write_catalog(tmp.path(), &original).unwrap();
        let loaded = read_catalog(tmp.path()).unwrap().unwrap();
        assert_eq!(original, loaded);
    }

    #[test]
    fn missing_catalog_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let r = read_catalog(tmp.path()).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn bad_magic_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a catalog with wrong magic.
        let mut cat = sample_catalog();
        cat.magic = *b"BAD!";
        // Force-write directly to bypass the public writer's invariants.
        use noble_codec::NobleCbor;
        std::fs::write(tmp.path().join(CATALOG_FILE_NAME), cat.to_cbor().unwrap())
            .unwrap();
        let err = read_catalog(tmp.path()).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("bad magic"), "got {msg}");
    }

    #[test]
    fn version_mismatch_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cat = sample_catalog();
        cat.version = 9999;
        use noble_codec::NobleCbor;
        std::fs::write(tmp.path().join(CATALOG_FILE_NAME), cat.to_cbor().unwrap())
            .unwrap();
        let err = read_catalog(tmp.path()).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("unsupported"), "got {msg}");
    }

    #[test]
    fn atomic_write_no_tmp_leftover() {
        let tmp = tempfile::tempdir().unwrap();
        write_catalog(tmp.path(), &sample_catalog()).unwrap();
        // No .tmp file should linger after success.
        let entries: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap_or_default())
            .collect();
        assert!(entries.contains(&CATALOG_FILE_NAME.to_string()));
        assert!(!entries.iter().any(|n| n.ends_with(".tmp")));
    }
}
