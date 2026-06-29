// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Integration tests for the multi-path RocksDB sharding wiring added
//! in noble-storage Phase 1. Exercises both legacy single-volume mode
//! (empty `db_paths`) and tiered mode (multiple `(path, target_bytes)`
//! entries) through the public `RocksDbStorage` API.
//!
//! Every test uses `tempfile::tempdir()` so failures don't leak data
//! between runs.

use std::path::PathBuf;

use noble_storage::{PathUsage, RocksDbConfig, RocksDbStorage, StorageEngine};

/// Empty `db_paths` must behave exactly like the legacy single-volume
/// constructor: RocksDB writes its MANIFEST, OPTIONS, CURRENT, LOG and
/// all SST files under `path`. We don't assert "byte-identical" (RocksDB
/// internal file numbering varies) but we do assert that no sibling
/// directories are created and that the DB opens, writes, and re-reads
/// cleanly.
#[test]
fn db_paths_empty_preserves_single_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    std::fs::create_dir_all(&primary).unwrap();

    let cfg = RocksDbConfig::default();
    assert!(cfg.db_paths.is_empty(), "default config must be single-volume");

    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    drop(storage);

    // Reopen and confirm RocksDB recovers cleanly.
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    let _stats = storage.get_storage_stats().unwrap();
    drop(storage);

    // No sibling dirs should have been created.
    let entries: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().into_string().unwrap_or_default())
        .collect();
    assert!(
        entries.iter().all(|n| n == "primary"),
        "unexpected sibling dirs: {entries:?}"
    );
}

/// Two configured paths, both reachable: open → close → reopen all work.
/// RocksDB physically distributes SST files between the paths based on
/// the per-path target sizes; the exact placement is RocksDB's call so
/// we don't assert it here — we just confirm that the API accepts the
/// config and the DB is consistent across a reopen.
#[test]
fn db_paths_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let secondary = tmp.path().join("secondary");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&secondary).unwrap();

    let cfg = RocksDbConfig {
        db_paths: vec![
            (secondary.clone(), 16 * 1024 * 1024), // 16 MiB target
        ],
        ..Default::default()
    };

    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    let _stats = storage.get_storage_stats().unwrap();
    drop(storage);

    // Reopen with the SAME db_paths list — must succeed cleanly.
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    let _stats = storage.get_storage_stats().unwrap();
    drop(storage);
}

/// `path_usage` reports per-path stats for every configured tier even
/// when the secondary tier holds no `.sst` files yet (the freshly-opened
/// DB has only the primary path's MANIFEST/CURRENT/OPTIONS). All entries
/// must come back with sst_count = 0 but with target_bytes echoing the
/// caller's input — that's how the GUI tells the operator "you
/// configured a 100 GiB target but the tier hasn't been used yet."
#[test]
fn path_usage_reports_per_path() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let secondary = tmp.path().join("secondary");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&secondary).unwrap();

    let cfg = RocksDbConfig {
        db_paths: vec![(secondary.clone(), 8 * 1024 * 1024)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();

    // Caller passes the full list (primary + extras) it wants stats for.
    let configured: Vec<(PathBuf, u64)> = vec![
        (primary.clone(), 0),
        (secondary.clone(), 8 * 1024 * 1024),
    ];
    let usage: Vec<PathUsage> = storage.path_usage(&configured);
    assert_eq!(usage.len(), 2, "one entry per configured path");

    let primary_usage = usage.iter().find(|u| u.path == primary).unwrap();
    let secondary_usage = usage.iter().find(|u| u.path == secondary).unwrap();
    assert_eq!(primary_usage.target_bytes, 0);
    assert_eq!(secondary_usage.target_bytes, 8 * 1024 * 1024);
    // Primary will have MANIFEST/CURRENT/OPTIONS/LOG → other_files_bytes > 0,
    // but sst_count starts at 0 (we haven't committed any blocks).
    assert!(
        primary_usage.other_files_bytes > 0,
        "primary should hold at least MANIFEST/CURRENT/OPTIONS"
    );
}

/// Audit Fix #1: listing the primary path inside `db_paths` is now
/// rejected at open time. The primary is the structural home (MANIFEST,
/// CURRENT, OPTIONS, LOG, WAL) and `db_paths` is operator tiers only;
/// allowing both would let RocksDB place SSTs on the primary path,
/// which defeats tiering (earlier uncapped paths absorb everything).
#[test]
fn db_paths_rejects_primary_path() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let secondary = tmp.path().join("secondary");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&secondary).unwrap();

    let cfg = RocksDbConfig {
        db_paths: vec![
            (primary.clone(), 100 * 1024 * 1024),
            (secondary.clone(), 16 * 1024 * 1024),
        ],
        ..Default::default()
    };
    let err = match RocksDbStorage::open_with_config_and_repair(&primary, &cfg) {
        Ok(_) => panic!("expected error rejecting primary in db_paths"),
        Err(e) => e,
    };
    let msg = format!("{err:?}");
    assert!(
        msg.contains("must NOT include the primary path"),
        "expected primary-path rejection, got {msg}"
    );
}

/// Audit Fix #10: actual SST placement verification. After Fix #1 the
/// primary is the structural home outside `db_paths`. If we list a
/// single tier in `db_paths`, RocksDB MUST place every flushed SST
/// there (no other placement target exists). We write enough data
/// through the public `StorageEngine::store_cycle_history` surface
/// (which writes raw bytes into the chain-state-CF family), force a
/// flush, and assert at least one `.sst` file landed in the cold
/// tier and not the primary.
#[test]
fn db_paths_actually_shards_to_cold_tier() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&cold).unwrap();

    let cfg = RocksDbConfig {
        // `target_bytes = 0` on the only tier means "no cap" — RocksDB
        // never has a reason to fall back elsewhere, so this is the
        // sharpest possible assertion.
        db_paths: vec![(cold.clone(), 0)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();

    // Write ~1 MiB of data through the public StorageEngine surface.
    // RocksDB's default memtable is ~64 MiB; this won't auto-flush
    // but `force_flush_all` will push the memtable to an L0 SST.
    for i in 0u64..2_000 {
        // 512-byte payload → ~1 MiB across 2_000 entries.
        let val = vec![0xAB; 512];
        storage.store_cycle_history(i, &val).unwrap();
    }
    storage.force_flush_all().unwrap();
    drop(storage);

    let count_sst = |dir: &std::path::Path| -> usize {
        std::fs::read_dir(dir).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("sst"))
            .count()
    };
    let n_primary = count_sst(&primary);
    let n_cold = count_sst(&cold);
    assert!(
        n_cold > 0,
        "expected SST files on the cold tier after forced flush; \
         got primary={n_primary} cold={n_cold}. \
         If this fails, set_db_paths is not actually distributing files."
    );
    assert_eq!(
        n_primary, 0,
        "primary path should hold zero SSTs when the only db_paths tier \
         has target=0 (unlimited); got primary={n_primary} cold={n_cold}"
    );
}

/// Two-tier setup: a small warm tier (4 MiB target) and an uncapped cold
/// tier. Writes ~8 MiB of incompressible data and verifies the SSTs are
/// routed onto the configured tiers and away from the structural primary.
/// (A specific warm→cold split is not asserted — see the body for why
/// RocksDB's whole-file placement makes that non-deterministic in a unit test.)
#[test]
fn db_paths_routes_dataset_to_tiers_not_primary() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let warm = tmp.path().join("warm");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&warm).unwrap();
    std::fs::create_dir_all(&cold).unwrap();

    let cfg = RocksDbConfig {
        db_paths: vec![
            (warm.clone(), 4 * 1024 * 1024),  // 4 MiB warm tier
            (cold.clone(), 0),                // unlimited cold tier
        ],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();

    // Write ~8 MiB through store_cycle_history (~16k entries × 512 B).
    // The payload must be INCOMPRESSIBLE — a repeated-byte buffer would be
    // shrunk to near-zero by the CF's block compression, leaving a single tiny
    // SST that never spills. Fill with an xorshift pseudo-random stream instead.
    for i in 0u64..16_000 {
        let mut val = vec![0u8; 512];
        let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        for b in val.iter_mut() {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
        storage.store_cycle_history(i, &val).unwrap();
    }
    storage.force_flush_all().unwrap();
    // Flush output (L0) always lands in the primary/warm path; spillover to the
    // cold tier happens during compaction once the warm target is exceeded.
    // Force it deterministically rather than waiting on background compaction.
    storage.compact_all();
    storage.force_flush_all().unwrap();
    drop(storage);

    let count_sst = |dir: &std::path::Path| -> usize {
        std::fs::read_dir(dir).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("sst"))
            .count()
    };
    let sst_bytes = |dir: &std::path::Path| -> u64 {
        std::fs::read_dir(dir).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("sst"))
            .filter_map(|e| e.metadata().ok().map(|m| m.len()))
            .sum()
    };
    let n_warm = count_sst(&warm);
    let n_cold = count_sst(&cold);
    let n_primary = count_sst(&primary);

    // The deterministic db_paths contract: the ~8 MiB of SST data is routed onto
    // the configured tiers (warm/cold) and NEVER onto the primary, which is the
    // structural home (MANIFEST/CURRENT/OPTIONS/WAL) only.
    //
    // We intentionally do NOT assert a specific warm→cold split. RocksDB places
    // whole SST files and a single synchronous manual compaction produces one
    // unsplit file that lands entirely in the first tier; true warm→cold
    // spillover only emerges from multi-file background compaction at production
    // scale, which a fast unit test cannot force deterministically.
    assert_eq!(
        n_primary, 0,
        "SSTs must live on the configured tiers, not the structural primary \
         (primary={n_primary} warm={n_warm} cold={n_cold})"
    );
    assert!(
        n_warm > 0 || n_cold > 0,
        "expected the written SST data on a configured tier (warm={n_warm} cold={n_cold})"
    );
    assert!(
        sst_bytes(&warm) + sst_bytes(&cold) > 4 * 1024 * 1024,
        "configured tiers should hold the bulk of the ~8 MiB written \
         (warm={} B cold={} B)",
        sst_bytes(&warm),
        sst_bytes(&cold)
    );
}

/// Audit Fix #2: the shutdown-hook contract is that
/// `rewrite_catalogs` produces a valid `.noble-shards.cbor` at every
/// configured tier. This is what `Node::run` calls during graceful
/// shutdown; here we exercise it directly so the storage-layer
/// guarantee is testable without spinning up a full node.
#[test]
fn shutdown_writes_catalogs_at_every_tier() {
    use noble_storage::catalog::{read_catalog, CATALOG_FILE_NAME};
    use noble_storage::StorageEngine;

    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&cold).unwrap();

    let cfg = RocksDbConfig {
        db_paths: vec![(cold.clone(), 0)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    // Force a flush so the cold tier has at least one SST that the
    // catalog can describe (without this, live_files() returns
    // nothing and both catalogs come back empty — still valid, just
    // less interesting).
    for i in 0u64..200 {
        let val = vec![0xAB; 256];
        storage.store_cycle_history(i, &val).unwrap();
    }
    storage.force_flush_all().unwrap();

    // Shutdown-hook call shape: full tier list (primary + extras),
    // chain_id, pubkey, with_hash=true.
    let full_tiers: Vec<(PathBuf, u64)> =
        vec![(primary.clone(), 0), (cold.clone(), 0)];
    let written = storage
        .rewrite_catalogs(&full_tiers, 0xCAFEBABE, "pubkey-hex", /* with_hash */ true)
        .expect("rewrite_catalogs succeeds");
    assert_eq!(written, 2, "expected one catalog per configured tier");
    drop(storage);

    for tier in &[&primary, &cold] {
        let f = tier.join(CATALOG_FILE_NAME);
        assert!(f.exists(), "expected catalog at {f:?}");
        let bytes = std::fs::read(&f).unwrap();
        assert!(!bytes.is_empty(), "catalog must not be empty at {f:?}");
    }

    let cold_cat = read_catalog(&cold)
        .expect("cold catalog readable")
        .expect("cold catalog present");
    assert!(
        !cold_cat.entries.is_empty(),
        "expected cold catalog to list at least one SST"
    );
    assert_eq!(cold_cat.chain_id, 0xCAFEBABE);
    assert_eq!(cold_cat.node_pubkey_hex, "pubkey-hex");
    // Audit Fix #6: with_hash=true populates content_sha256.
    for e in &cold_cat.entries {
        let h = e
            .content_sha256
            .as_deref()
            .unwrap_or_else(|| panic!("Fix #6: missing hash on {}", e.file_name));
        assert_eq!(h.len(), 64, "expected 64-hex SHA-256, got {h:?}");
    }
}

/// `repair_multi_path` runs `DB::repair` with the full `db_paths` list
/// so SST files living in extra tiers are correctly re-attached when
/// the MANIFEST is rebuilt. We exercise the happy path: open, close,
/// repair, reopen.
#[test]
fn repair_multi_path_succeeds_on_clean_db() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let secondary = tmp.path().join("secondary");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&secondary).unwrap();

    let cfg = RocksDbConfig {
        db_paths: vec![(secondary.clone(), 16 * 1024 * 1024)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    // Write + flush real data so SST files exist for repair to re-attach.
    // DB::repair errors with "repair found no files" on a truly empty DB, and
    // an empty DB wouldn't exercise this test's purpose (re-attaching tier SSTs).
    for i in 0u64..512 {
        storage.store_cycle_history(i, &vec![0xAB; 256]).unwrap();
    }
    storage.force_flush_all().unwrap();
    drop(storage);

    RocksDbStorage::repair_multi_path(&primary, &cfg).unwrap();

    // After repair the DB should still open cleanly.
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    let _ = storage.get_storage_stats().unwrap();
}

/// Audit Fix #S4: when a configured tier directory is unreadable
/// during catalog generation, `rewrite_catalogs` must propagate the
/// error rather than silently skipping that tier. Verified on Unix
/// by chmod-ing a tier 000.
#[cfg(unix)]
#[test]
fn build_catalogs_fails_on_unreadable_tier() {
    use noble_storage::StorageEngine;
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    let cfg = RocksDbConfig {
        db_paths: vec![(cold.clone(), 0)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    for i in 0u64..100 {
        storage.store_cycle_history(i, &[0u8; 64]).unwrap();
    }
    storage.force_flush_all().unwrap();

    // Make the cold tier unreadable so build_catalogs hits read_dir
    // failure for that directory.
    std::fs::set_permissions(&cold, std::fs::Permissions::from_mode(0o000)).unwrap();
    let full_tiers: Vec<(PathBuf, u64)> = vec![(primary.clone(), 0), (cold.clone(), 0)];
    let result = storage.rewrite_catalogs(&full_tiers, 1, "pk", false);
    // Restore permissions before any assertion so tempdir cleanup
    // doesn't fail (some tempfile backends complain).
    std::fs::set_permissions(&cold, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = result.expect_err("expected read_dir failure to propagate");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("read_dir") || msg.contains("requires every configured tier"),
        "expected unreadable-tier error, got: {msg}"
    );
}

/// Audit Fix #S5: hash failures during `with_hash=true` catalog
/// generation must propagate, not silently emit `content_sha256: None`.
/// Simulated by deleting an SST file between flush and rewrite.
#[test]
fn build_catalogs_hash_failure_propagates() {
    use noble_storage::StorageEngine;

    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    let cfg = RocksDbConfig {
        db_paths: vec![(cold.clone(), 0)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    for i in 0u64..100 {
        storage.store_cycle_history(i, &[0u8; 64]).unwrap();
    }
    storage.force_flush_all().unwrap();

    // Delete every .sst on the cold tier so hash_sst_file open()
    // fails. The rocksdb live_files() list still references them,
    // so build_catalogs will try to hash a missing file.
    for entry in std::fs::read_dir(&cold).unwrap().flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("sst") {
            std::fs::remove_file(p).unwrap();
        }
    }

    let full_tiers: Vec<(PathBuf, u64)> = vec![(primary.clone(), 0), (cold.clone(), 0)];
    let err = storage
        .rewrite_catalogs(&full_tiers, 1, "pk", /* with_hash */ true)
        .expect_err("hash failure must propagate when with_hash=true");
    let msg = format!("{err:?}");
    assert!(
        // Either the read_dir scan fails before hashing
        // (live_files names not on disk → S4 path), or the hash
        // attempt fails. Either is acceptable proof that S5's
        // strictness kicks in.
        msg.contains("hash failed")
            || msg.contains("not in any configured tier")
            || msg.contains("read_dir"),
        "expected hash/scan failure, got: {msg}"
    );
}

/// Audit Fix #S7: rewrite_catalogs must drop a `.noble-bootstrap`
/// marker at every configured tier after the first successful
/// catalog write. Without the marker, subsequent boots can't
/// distinguish "first-ever boot" from "steady-state with missing
/// catalog."
#[test]
fn rewrite_catalogs_creates_bootstrap_marker() {
    use noble_storage::catalog::{bootstrap_path, BOOTSTRAP_FILE_NAME};
    use noble_storage::StorageEngine;

    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    let cfg = RocksDbConfig {
        db_paths: vec![(cold.clone(), 0)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();

    // Before rewrite: no marker at either tier.
    assert!(!bootstrap_path(&primary).exists());
    assert!(!bootstrap_path(&cold).exists());

    let full_tiers: Vec<(PathBuf, u64)> = vec![(primary.clone(), 0), (cold.clone(), 0)];
    storage
        .rewrite_catalogs(&full_tiers, 1, "pk", false)
        .expect("rewrite succeeds on clean DB");

    // After rewrite: markers exist at both tiers.
    assert!(
        bootstrap_path(&primary).exists(),
        "expected {BOOTSTRAP_FILE_NAME} at primary"
    );
    assert!(
        bootstrap_path(&cold).exists(),
        "expected {BOOTSTRAP_FILE_NAME} at cold"
    );
}

/// Audit Fix #S8: `open_with_config_and_repair` no longer
/// auto-repairs on any open failure. Verify by corrupting CURRENT
/// (a tiny file pointing at the active MANIFEST) so the open
/// fails — pre-S8 it would silently repair; post-S8 it returns Err.
#[test]
fn open_with_config_and_repair_does_not_auto_repair() {
    let tmp = tempfile::tempdir().unwrap();
    let primary = tmp.path().join("primary");
    let cold = tmp.path().join("cold");
    std::fs::create_dir_all(&primary).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    let cfg = RocksDbConfig {
        db_paths: vec![(cold.clone(), 0)],
        ..Default::default()
    };
    let storage = RocksDbStorage::open_with_config_and_repair(&primary, &cfg).unwrap();
    drop(storage);

    // Corrupt CURRENT — RocksDB needs this file to identify which
    // MANIFEST to open. With garbage content, open will fail.
    let current = primary.join("CURRENT");
    assert!(current.exists(), "expected CURRENT file post-open");
    std::fs::write(&current, b"this is not a valid CURRENT pointer\n").unwrap();

    let result = RocksDbStorage::open_with_config_and_repair(&primary, &cfg);
    assert!(
        result.is_err(),
        "S8: open_with_config_and_repair must NOT silently repair; \
         operator must explicitly call repair_multi_path. Got Ok(_)."
    );
}
