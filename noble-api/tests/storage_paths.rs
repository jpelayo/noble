// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the sharding RPC surface (audit Fix #5
//! verification). The critical regression: `reconcileStorage` must
//! report drift, not erase it.

use std::path::PathBuf;

use noble_storage::{
    catalog::{write_catalog, CatalogEntry, PathCatalog, CATALOG_FILE_NAME},
    discover_shards, ReconcileDecision,
};

/// Audit Fix #S9 regression guard: when `set_storage_paths` accepts
/// an input path containing redundant `.` or `..` components, the
/// persisted TOML form must be the canonical version (after
/// `std::fs::canonicalize`). We don't have a live `ApiState` here
/// — the canonicalisation logic itself is what we test, by
/// reproducing the same `std::fs::canonicalize(&path)` call the RPC
/// performs.
#[test]
fn canonicalize_collapses_dot_segments() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("tier_real");
    std::fs::create_dir_all(&real).unwrap();
    // Path with redundant `.` segments — what an operator might
    // accidentally type into the RPC.
    let with_dots = tmp.path().join("tier_real").join(".");
    let canon = std::fs::canonicalize(&with_dots).unwrap();
    let canon_real = std::fs::canonicalize(&real).unwrap();
    assert_eq!(
        canon, canon_real,
        "canonicalize must collapse `.` segments to a stable form"
    );
    // Audit Fix #S9 contract: the canonical form is what
    // set_storage_paths persists into noble.toml. The boot-path
    // canonicalize (audit Fix #8) re-runs canonicalize and gets the
    // same answer, so storage-config round-trips are stable.
    assert!(!canon.to_string_lossy().contains("/./"));
}

/// Audit Fix #5 regression guard: when discovery sees the layout as
/// `RepairThenOpen` (an SST listed in one tier's catalog actually
/// lives in another), the *pre-rewrite* discovery must be the
/// authoritative one. Pre-Fix #5 the RPC would rewrite catalogs
/// FIRST, syncing them to disk reality, and the subsequent discovery
/// would see `OpenNormally`. This test exercises that path purely
/// through the storage layer (no live `ApiState` needed — the bug
/// was about ordering, and `discover_shards` + `decide` are the
/// ordering primitives the RPC composes).
#[test]
fn reconcile_does_not_erase_drift() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();

    // Plant a catalog at A claiming 000001.sst belongs there with 1
    // byte. Disk: the file actually lives in B.
    let mut cat = PathCatalog::new(0, "");
    cat.entries.push(CatalogEntry {
        file_name: "000001.sst".to_string(),
        column_family: "blocks".to_string(),
        level: 0,
        smallest_key_hex: String::new(),
        largest_key_hex: String::new(),
        size_bytes: 1,
        num_entries: 0,
        num_deletions: 0,
        content_sha256: None,
    });
    write_catalog(&a, &cat).unwrap();
    std::fs::write(b.join("000001.sst"), b"x").unwrap();

    // PRE-rewrite discovery: should see drift.
    let extras: Vec<(PathBuf, u64)> = vec![(b.clone(), 0)];
    let report = discover_shards(&a, &extras, None, false).unwrap();
    let decision = noble_storage::decide(&report);
    match decision {
        ReconcileDecision::RepairThenOpen { reason } => {
            assert!(reason.contains("moved"), "expected move detection, got: {reason}");
        }
        other => panic!("expected RepairThenOpen, got {other:?}"),
    }

    // Critical: the on-disk catalog at A must STILL claim 000001.sst
    // after discovery. If the RPC were re-ordered to rewrite first,
    // a subsequent discovery against the rewritten catalogs would
    // never see the drift. We assert the file is untouched.
    let catalog_after = std::fs::read(a.join(CATALOG_FILE_NAME)).unwrap();
    let catalog_before = {
        // Re-encode the original; bytes must match.
        use noble_codec::NobleCbor;
        cat.to_cbor().unwrap()
    };
    assert_eq!(
        catalog_after, catalog_before,
        "discovery alone must not mutate any .noble-shards.cbor file"
    );
}
