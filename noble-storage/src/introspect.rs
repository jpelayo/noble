// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Filesystem-level SST introspection.
//!
//! Walks an arbitrary directory and returns one [`SstDescriptor`] per
//! `.sst` file found. Does **not** open a RocksDB instance — the
//! descriptors carry only what `std::fs` and (optionally) a content hash
//! reveal: file name, absolute path, byte size, and SHA-256.
//!
//! The richer per-file metadata (column family, LSM level, key range,
//! number of entries) lives inside RocksDB and is captured into the
//! per-path [`crate::catalog::PathCatalog`] via [`rocksdb::DB::live_files`]
//! while the DB is open. Reconciliation (Phase 2) cross-references the
//! disk-side descriptors against the catalog entries to detect moves,
//! duplicates, and strangers.
//!
//! Two operator surfaces consume this module:
//!
//! - `noble_listShards(path)` RPC — inspect any directory, configured or
//!   not, to answer "does this backup tape contain Noble data?".
//! - `noble_discoverShards` RPC — combines a scan of every configured path
//!   with the per-path catalog to produce the full [`DiscoveryReport`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::StorageError;

/// Describes a single SST file as observed on disk, without opening the
/// owning DB. Field `content_sha256` is only populated when the caller
/// passed `with_hash = true`; computing it requires a full file read so
/// it is opt-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SstDescriptor {
    /// File basename, e.g. `"000123.sst"`. Matches the RocksDB
    /// `LiveFile.name` reported by the open DB so the catalog and the
    /// disk descriptor can be joined by name.
    pub file_name: String,
    /// Absolute path on disk.
    pub absolute_path: PathBuf,
    /// File size in bytes.
    pub size_bytes: u64,
    /// SHA-256 hex of the full file contents. `None` unless the caller
    /// requested hashing. Used by the reconciliation logic to detect
    /// duplicates (same content in two paths) and verify that a file
    /// that "looks like" the moved one really is.
    pub content_sha256: Option<String>,
}

/// Reads a single `.sst` file's metadata. Errors only on filesystem
/// failures (missing file, permission denied, hash I/O errors). Does
/// not attempt to validate the SST internal structure — that would
/// require RocksDB internals not exposed through the Rust binding.
pub fn describe_sst(path: &Path, with_hash: bool) -> Result<SstDescriptor, StorageError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        StorageError::Database(format!("describe_sst stat {:?}: {e}", path))
    })?;
    if !metadata.is_file() {
        return Err(StorageError::Database(format!(
            "describe_sst {:?}: not a regular file",
            path
        )));
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            StorageError::Database(format!("describe_sst {:?}: bad file name", path))
        })?
        .to_string();
    let content_sha256 = if with_hash {
        Some(hash_file(path)?)
    } else {
        None
    };
    Ok(SstDescriptor {
        file_name,
        absolute_path: path.to_path_buf(),
        size_bytes: metadata.len(),
        content_sha256,
    })
}

/// Walks `dir` non-recursively and runs [`describe_sst`] on every entry
/// whose extension is `.sst`. The output is sorted by file name so
/// downstream comparisons are stable. Per-file errors are collected
/// separately rather than aborting the whole scan — a single corrupt
/// `*.sst` file should not hide the rest of the directory from the
/// operator.
pub fn scan_directory(
    dir: &Path,
    with_hash: bool,
) -> (Vec<SstDescriptor>, Vec<(PathBuf, StorageError)>) {
    let mut descriptors = Vec::new();
    let mut errors = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            errors.push((
                dir.to_path_buf(),
                StorageError::Database(format!("scan_directory read_dir {:?}: {e}", dir)),
            ));
            return (descriptors, errors);
        }
    };

    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("sst") {
            continue;
        }
        match describe_sst(&p, with_hash) {
            Ok(d) => descriptors.push(d),
            Err(e) => errors.push((p, e)),
        }
    }

    descriptors.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    (descriptors, errors)
}

/// Hex SHA-256 of the file at `path`. Streams in 64 KiB chunks so the
/// memory footprint is constant regardless of SST size.
fn hash_file(path: &Path) -> Result<String, StorageError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| {
        StorageError::Database(format!("hash_file open {:?}: {e}", path))
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            StorageError::Database(format!("hash_file read {:?}: {e}", path))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn scan_directory_picks_only_sst() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "000001.sst", b"hello");
        write_file(tmp.path(), "MANIFEST-000001", b"manifest");
        write_file(tmp.path(), "notes.txt", b"unrelated");
        write_file(tmp.path(), "LOG", b"log");
        let (descs, errs) = scan_directory(tmp.path(), false);
        assert!(errs.is_empty());
        assert_eq!(descs.len(), 1, "only the .sst file should be picked up");
        assert_eq!(descs[0].file_name, "000001.sst");
        assert_eq!(descs[0].size_bytes, 5);
        assert!(descs[0].content_sha256.is_none());
    }

    #[test]
    fn scan_directory_with_hash_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "000001.sst", b"hello world");
        let (descs1, _) = scan_directory(tmp.path(), true);
        let (descs2, _) = scan_directory(tmp.path(), true);
        assert_eq!(descs1.len(), 1);
        assert_eq!(descs2.len(), 1);
        let h1 = descs1[0].content_sha256.as_deref().unwrap();
        let h2 = descs2[0].content_sha256.as_deref().unwrap();
        assert_eq!(h1, h2);
        // sha256("hello world") = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert_eq!(
            h1,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn scan_directory_sorted_output() {
        let tmp = tempfile::tempdir().unwrap();
        write_file(tmp.path(), "000002.sst", b"a");
        write_file(tmp.path(), "000001.sst", b"b");
        write_file(tmp.path(), "000003.sst", b"c");
        let (descs, _) = scan_directory(tmp.path(), false);
        let names: Vec<&str> = descs.iter().map(|d| d.file_name.as_str()).collect();
        assert_eq!(names, vec!["000001.sst", "000002.sst", "000003.sst"]);
    }

    #[test]
    fn describe_sst_rejects_non_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("subdir.sst");
        std::fs::create_dir(&sub).unwrap();
        let err = describe_sst(&sub, false).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("not a regular file"), "got {msg}");
    }

    #[test]
    fn scan_directory_missing_dir_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("doesnotexist");
        let (descs, errs) = scan_directory(&missing, false);
        assert!(descs.is_empty());
        assert_eq!(errs.len(), 1);
    }
}
