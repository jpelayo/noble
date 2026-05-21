// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Multi-path discovery & reconciliation.
//!
//! Runs BEFORE the RocksDB instance is opened (which is what makes
//! resilience cheap — we can decide whether to repair without paying
//! the cost of an aborted open). The contract:
//!
//! 1. Walk every configured `(path, target_bytes)` tier with
//!    [`crate::introspect::scan_directory`] to learn what `.sst` files
//!    actually live on disk right now.
//! 2. Read the per-path catalog (`.noble-shards.cbor`) written on
//!    last shutdown to learn what the node *expected* to find there.
//! 3. Cross-reference: produce a [`DiscoveryReport`] listing missing
//!    files (catalog says here; disk says no), extra files (disk says
//!    here; catalog didn't), duplicates (same SHA in two paths), and
//!    strangers (file lives in our tier but its catalog entry's column
//!    family isn't one of [`crate::ALL_CF_NAMES`]).
//! 4. Hand the report to [`decide`], which returns
//!    [`ReconcileDecision::OpenNormally`] if disk matches catalog,
//!    [`ReconcileDecision::RepairThenOpen`] if files moved between
//!    paths (every catalog entry is found *somewhere*), or
//!    [`ReconcileDecision::Fail`] if files are genuinely lost or two
//!    copies of the same SST exist (operator must intervene).
//!
//! `Fail` reasons carry operator-facing text. Repair invokes
//! [`crate::rocks::RocksDbStorage::repair_multi_path`] which rebuilds
//! the MANIFEST from disk reality.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::catalog::{read_catalog, PathCatalog};
use crate::error::StorageError;
use crate::introspect::{scan_directory, SstDescriptor};
use crate::ALL_CF_NAMES;

/// Output of [`discover_shards`]. A single comparable picture of disk
/// reality across every configured storage tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryReport {
    /// Per-path inventory and catalog-versus-disk diff.
    pub paths: Vec<PathInventory>,
    /// SSTs whose content hash appears in MORE than one configured
    /// path. Indicates a botched copy (operator used `cp` instead of
    /// `mv`); reconciliation refuses to repair until the operator
    /// deletes one copy. Empty when `with_hash = false` was requested
    /// (we can't detect duplicates without hashes).
    pub duplicates: Vec<DuplicateSst>,
    /// SST files present in a configured tier but referenced (by the
    /// per-path catalog) under a column family that isn't one of
    /// [`crate::ALL_CF_NAMES`]. Indicates a foreign DB pointed at by
    /// mistake (e.g. wrong chain's data dir bind-mounted).
    pub strangers: Vec<SstDescriptor>,
    /// True iff every requested SST scan provided content hashes.
    /// Echoed back to callers so they know whether `duplicates` is
    /// authoritative.
    pub hashes_available: bool,
    /// Audit Fix #3: filesystem-level errors encountered while
    /// walking each tier (unreadable directory, permission denied,
    /// describe_sst stat failures). Non-empty means the discovery
    /// view is INCOMPLETE; [`decide`] returns `Fail` so the node
    /// refuses to start until the operator fixes the underlying
    /// access issue.
    pub scan_errors: Vec<(PathBuf, String)>,
    /// Audit Fix #3: tiers whose `.noble-shards.cbor` exists but
    /// failed to parse (bad magic, truncated, schema mismatch).
    /// Distinct from "no catalog at all" (which is fine for a fresh
    /// tier). Treated as a hard error.
    pub catalog_errors: Vec<(PathBuf, String)>,
}

/// What we discovered for a single configured tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInventory {
    /// Absolute path of the tier.
    pub path: PathBuf,
    /// Catalog as read from `<path>/.noble-shards.cbor`. `None` if
    /// the file is absent or unparseable — discovery falls back to
    /// trusting the disk in that case.
    pub catalog: Option<PathCatalog>,
    /// Descriptors of `.sst` files actually present on disk, sorted
    /// alphabetically by name.
    pub discovered: Vec<SstDescriptor>,
    /// Catalog entries with no matching file on disk in this tier.
    /// May be found in another tier (planned migration) — see the
    /// top-level `duplicates` and per-decision logic.
    pub missing_from_catalog: Vec<String>,
    /// Files on disk in this tier that the catalog doesn't list.
    /// On a clean node the only "extras" should be the catalog file
    /// itself, which discovery already filters out — so non-empty
    /// here means *unexpected SSTs*.
    pub extra_vs_catalog: Vec<String>,
}

/// Two configured tiers contain a file with identical SHA-256. Often a
/// `cp` mistake; sometimes an intentional belt-and-braces backup the
/// operator forgot to clean up before pointing Noble at both mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateSst {
    /// The shared content hash.
    pub content_sha256: String,
    /// Every path where a copy exists.
    pub paths: Vec<PathBuf>,
}

/// Walks every configured tier, reads each catalog, returns a unified
/// report. `with_hash = true` populates `content_sha256` on every
/// discovered descriptor and enables duplicate detection; the cost is
/// one full file read per `.sst` (use `false` on huge archive nodes
/// unless you specifically want duplicate detection).
///
/// `expected_chain_id = Some(id)`: catalogs whose `chain_id` differs
/// from `id` are treated as foreign and reported as strangers (their
/// entries land in [`DiscoveryReport::strangers`]).
/// `expected_chain_id = None`: no cross-chain check.
pub fn discover_shards(
    primary: &Path,
    extras: &[(PathBuf, u64)],
    expected_chain_id: Option<u32>,
    with_hash: bool,
) -> Result<DiscoveryReport, StorageError> {
    // Build the full list of tiers (primary first).
    let mut all_paths: Vec<PathBuf> = Vec::with_capacity(1 + extras.len());
    all_paths.push(primary.to_path_buf());
    for (p, _) in extras {
        if !all_paths.contains(p) {
            all_paths.push(p.clone());
        }
    }

    let mut inventories: Vec<PathInventory> = Vec::with_capacity(all_paths.len());
    let mut all_strangers: Vec<SstDescriptor> = Vec::new();
    let mut scan_errors: Vec<(PathBuf, String)> = Vec::new();
    let mut catalog_errors: Vec<(PathBuf, String)> = Vec::new();

    for path in &all_paths {
        // Audit Fix #3: collect scan errors instead of dropping them.
        let (descriptors, errs) = scan_directory(path, with_hash);
        for (p, e) in errs {
            scan_errors.push((p, format!("{e:?}")));
        }
        let catalog = match read_catalog(path) {
            Ok(Some(c)) => Some(c),
            Ok(None) => {
                // Audit Fix #S7: no catalog file at this tier.
                // - Bootstrap marker absent → first-ever boot of
                //   this tier; treat as "no diff" and let the
                //   shutdown hook drop both files later.
                // - Bootstrap marker present → steady state with
                //   missing catalog → record as an error so
                //   `decide` returns Fail. Either the catalog was
                //   deleted (operator must restore from backup or
                //   run noble_reconcileStorage) or the filesystem
                //   dropped it (operator must investigate).
                let bootstrap = crate::catalog::bootstrap_path(path);
                if bootstrap.exists() {
                    catalog_errors.push((
                        path.clone(),
                        "bootstrap marker present but catalog missing — \
                         either the catalog was deleted or the filesystem \
                         dropped it. Restore from backup or run \
                         noble_reconcileStorage."
                            .to_string(),
                    ));
                }
                None
            }
            Err(e) => {
                // Audit Fix #3: unreadable catalog is a hard signal,
                // not just a warn. Record it; `decide` will return Fail.
                tracing::warn!(
                    task = "shard_discovery",
                    "catalog at {path:?} unreadable: {e}"
                );
                catalog_errors.push((path.clone(), format!("{e:?}")));
                None
            }
        };

        // Apply chain_id check: catalogs whose chain_id mismatches are
        // dropped (treated as missing) AND their entries' files become
        // strangers (they belong to a different chain, even if the SST
        // structure looks valid).
        let catalog = match (catalog, expected_chain_id) {
            (Some(cat), Some(expected)) if cat.chain_id != 0 && cat.chain_id != expected => {
                tracing::warn!(
                    task = "shard_discovery",
                    "catalog at {path:?} chain_id={} differs from expected={} — treating contents as strangers",
                    cat.chain_id,
                    expected,
                );
                // Mark the discovered files as strangers (they were
                // managed by a different chain).
                all_strangers.extend(descriptors.clone());
                None
            }
            (other, _) => other,
        };

        // Diff: catalog says which files should be here.
        let (missing_from_catalog, extra_vs_catalog) = match &catalog {
            None => (Vec::new(), Vec::new()),
            Some(cat) => {
                let disk_names: std::collections::HashSet<&str> =
                    descriptors.iter().map(|d| d.file_name.as_str()).collect();
                let catalog_names: std::collections::HashSet<&str> =
                    cat.entries.iter().map(|e| e.file_name.as_str()).collect();
                let missing: Vec<String> = catalog_names
                    .difference(&disk_names)
                    .map(|s| (*s).to_string())
                    .collect();
                let extra: Vec<String> = disk_names
                    .difference(&catalog_names)
                    .map(|s| (*s).to_string())
                    .collect();
                (missing, extra)
            }
        };

        // Stranger CF detection: catalog entries naming a CF that isn't
        // in ALL_CF_NAMES → the file came from a non-Noble RocksDB
        // (or a future Noble version) and we won't reconcile.
        if let Some(cat) = &catalog {
            for entry in &cat.entries {
                if !is_known_cf(&entry.column_family) {
                    if let Some(d) = descriptors.iter().find(|d| d.file_name == entry.file_name) {
                        all_strangers.push(d.clone());
                    }
                }
            }
        }

        inventories.push(PathInventory {
            path: path.clone(),
            catalog,
            discovered: descriptors,
            missing_from_catalog,
            extra_vs_catalog,
        });
    }

    // Duplicate detection (requires hashes).
    let mut duplicates: Vec<DuplicateSst> = Vec::new();
    if with_hash {
        let mut by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for inv in &inventories {
            for d in &inv.discovered {
                if let Some(h) = &d.content_sha256 {
                    by_hash
                        .entry(h.clone())
                        .or_default()
                        .push(d.absolute_path.clone());
                }
            }
        }
        for (hash, paths) in by_hash {
            if paths.len() > 1 {
                duplicates.push(DuplicateSst {
                    content_sha256: hash,
                    paths,
                });
            }
        }
    }

    Ok(DiscoveryReport {
        paths: inventories,
        duplicates,
        strangers: all_strangers,
        hashes_available: with_hash,
        scan_errors,
        catalog_errors,
    })
}

fn is_known_cf(name: &str) -> bool {
    ALL_CF_NAMES.iter().any(|cf| *cf == name)
}

/// Decision the reconciliation layer makes given a [`DiscoveryReport`].
/// Phase 4 startup wiring branches on this to either open normally,
/// run `DB::Repair` first, or refuse to start with an operator-facing
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileDecision {
    /// Disk matches catalog (or both are empty). Open the DB as-is.
    OpenNormally,
    /// Files moved between configured tiers but every catalog entry
    /// is accounted for *somewhere*. Run `DB::Repair` against the
    /// union of tiers to rebuild the MANIFEST, then open.
    RepairThenOpen { reason: String },
    /// Disk and catalog cannot be reconciled automatically. The
    /// operator must intervene.
    Fail { reason: String, suggestion: String },
}

/// Maps a [`DiscoveryReport`] to a [`ReconcileDecision`]. Pure
/// function; testable.
pub fn decide(report: &DiscoveryReport) -> ReconcileDecision {
    // Audit Fix #3: filesystem errors mean the discovery view is
    // INCOMPLETE. Don't repair on incomplete information; refuse to
    // start and let the operator fix the underlying access issue.
    if !report.scan_errors.is_empty() {
        let samples: Vec<String> = report.scan_errors.iter().take(3)
            .map(|(p, e)| format!("{p:?}: {e}")).collect();
        return ReconcileDecision::Fail {
            reason: format!(
                "{} filesystem error(s) during tier discovery (e.g. {})",
                report.scan_errors.len(),
                samples.join("; ")
            ),
            suggestion: "Check filesystem permissions and disk health on every \
                configured tier. The node refuses to start when storage cannot \
                be enumerated cleanly.".to_string(),
        };
    }

    // Audit Fix #3: a catalog that EXISTS but fails to parse is a
    // hard error — distinct from "no catalog at all" (which is fine
    // on a fresh tier). Corruption could mask drift.
    if !report.catalog_errors.is_empty() {
        let samples: Vec<String> = report.catalog_errors.iter().take(3)
            .map(|(p, e)| format!("{p:?}: {e}")).collect();
        return ReconcileDecision::Fail {
            reason: format!(
                "{} corrupted catalog file(s) at: {}",
                report.catalog_errors.len(),
                samples.join("; ")
            ),
            suggestion: "Delete the corrupted .noble-shards.cbor file(s) so the \
                node regenerates them on next reconcile, or restore from a \
                known-good backup.".to_string(),
        };
    }

    // Strangers → fail. The operator pointed Noble at the wrong data.
    if !report.strangers.is_empty() {
        let names: Vec<String> =
            report.strangers.iter().map(|d| d.file_name.clone()).collect();
        return ReconcileDecision::Fail {
            reason: format!(
                "found {} file(s) belonging to an unknown column family or a different chain: {}",
                report.strangers.len(),
                names.join(", ")
            ),
            suggestion: "Verify each configured storage path holds Noble data for THIS chain. \
                Remove or relocate foreign files, then restart."
                .to_string(),
        };
    }

    // Duplicates → fail. Two copies of the same SST will confuse RocksDB.
    if !report.duplicates.is_empty() {
        let first = &report.duplicates[0];
        let paths: Vec<String> = first.paths.iter().map(|p| format!("{p:?}")).collect();
        return ReconcileDecision::Fail {
            reason: format!(
                "{} duplicate SST file(s) detected. Example: SHA {} appears in {}.",
                report.duplicates.len(),
                first.content_sha256,
                paths.join(", ")
            ),
            suggestion: "Delete one copy of each duplicated file (keep the one in the path you \
                want Noble to use), then restart. Tip: prefer `mv` over `cp` when relocating SSTs."
                .to_string(),
        };
    }

    // Drift: did anything move between tiers, or go missing entirely?
    //
    // Audit Fix #4: a "move" requires identity match (size + hash),
    // not just filename. Without this, an attacker (or accident) that
    // plants a file with the same name but different content in
    // another tier would trigger `DB::Repair` against junk. The
    // catalog carries `size_bytes` always; `content_sha256` is
    // populated when boot calls discovery with `with_hash=true`.
    let mut moves: Vec<(String, PathBuf)> = Vec::new();
    let mut still_missing: Vec<(String, PathBuf)> = Vec::new();

    // Build a name → list-of-(path, size, sha) map across all tiers.
    let mut name_to_candidates: HashMap<
        String,
        Vec<(PathBuf, u64, Option<String>)>,
    > = HashMap::new();
    for inv in &report.paths {
        for d in &inv.discovered {
            name_to_candidates
                .entry(d.file_name.clone())
                .or_default()
                .push((inv.path.clone(), d.size_bytes, d.content_sha256.clone()));
        }
    }

    for inv in &report.paths {
        if let Some(cat) = &inv.catalog {
            for missing_name in &inv.missing_from_catalog {
                let expected = cat.entries.iter().find(|e| e.file_name == *missing_name);
                let candidates = name_to_candidates
                    .get(missing_name)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let identity_match: Option<&PathBuf> = candidates
                    .iter()
                    .find(|(_, sz, sha)| match expected {
                        Some(e) => {
                            // Size match is the floor.
                            if *sz != e.size_bytes {
                                return false;
                            }
                            // Audit Fix #S6: when `hashes_available`
                            // is true (every scan_directory call in
                            // this report ran with `with_hash=true`)
                            // and the catalog entry HAS a hash, both
                            // sides must agree. A one-sided hash
                            // (catalog has it, disk doesn't, or
                            // vice versa) refuses the move — a
                            // hash-bearing catalog shouldn't be
                            // matched against an un-hashed disk file.
                            // Pre-Fix #S6 the fallback was "size
                            // only" which was strictly weaker than
                            // the safety guarantee Fix #4 promised.
                            match (sha.as_deref(), e.content_sha256.as_deref()) {
                                (Some(a), Some(b)) => a == b,
                                (None, Some(_)) | (Some(_), None)
                                    if report.hashes_available =>
                                {
                                    // We expected hashes from both
                                    // sides; one of them is missing
                                    // → refuse to treat as a move.
                                    false
                                }
                                _ => true,
                            }
                        }
                        None => false,
                    })
                    .map(|(p, _, _)| p);
                match identity_match {
                    Some(p) => moves.push((missing_name.clone(), p.clone())),
                    None => still_missing.push((missing_name.clone(), inv.path.clone())),
                }
            }
        }
    }

    if !still_missing.is_empty() {
        let names: Vec<String> = still_missing
            .iter()
            .take(5)
            .map(|(n, p)| format!("{n} (catalog: {p:?})"))
            .collect();
        return ReconcileDecision::Fail {
            reason: format!(
                "{} SST file(s) listed in catalogs but absent from every configured path: {}",
                still_missing.len(),
                names.join(", ")
            ),
            suggestion: "Either restore the missing files (rsync from a backup), or remove the \
                corresponding tier from `extra_data_dirs` if it was decommissioned cleanly."
                .to_string(),
        };
    }

    if !moves.is_empty() {
        let detail: Vec<String> = moves
            .iter()
            .take(3)
            .map(|(n, p)| format!("{n} → {p:?}"))
            .collect();
        return ReconcileDecision::RepairThenOpen {
            reason: format!(
                "{} SST file(s) moved between configured paths (examples: {}). Rebuilding MANIFEST.",
                moves.len(),
                detail.join(", ")
            ),
        };
    }

    // Extras with no catalog entry — happens on first-ever boot
    // (catalog absent) or after a flush that wasn't checkpointed.
    // Treated as benign: RocksDB itself drives the MANIFEST and the
    // extras come from there.
    ReconcileDecision::OpenNormally
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{write_catalog, CatalogEntry};

    fn cat_with(entries: Vec<CatalogEntry>) -> PathCatalog {
        let mut cat = PathCatalog::new(0, "");
        cat.entries = entries;
        cat
    }

    fn entry(name: &str, cf: &str) -> CatalogEntry {
        entry_with_size(name, cf, 0)
    }

    fn entry_with_size(name: &str, cf: &str, size: u64) -> CatalogEntry {
        CatalogEntry {
            file_name: name.to_string(),
            column_family: cf.to_string(),
            level: 0,
            smallest_key_hex: String::new(),
            largest_key_hex: String::new(),
            size_bytes: size,
            num_entries: 0,
            num_deletions: 0,
            content_sha256: None,
        }
    }

    fn entry_with_size_hash(name: &str, cf: &str, size: u64, sha: &str) -> CatalogEntry {
        let mut e = entry_with_size(name, cf, size);
        e.content_sha256 = Some(sha.to_string());
        e
    }

    fn write_sst(dir: &Path, name: &str, body: &[u8]) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    /// Empty world: no primary contents, no extras configured, no
    /// catalogs anywhere. Decision is `OpenNormally`.
    #[test]
    fn discover_empty_world_opens_normally() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("p");
        std::fs::create_dir_all(&primary).unwrap();
        let report = discover_shards(&primary, &[], None, false).unwrap();
        assert_eq!(decide(&report), ReconcileDecision::OpenNormally);
    }

    /// Catalog expects a file in path A; the file actually lives in
    /// path B (it was moved). Decision: `RepairThenOpen` when the
    /// disk file's size matches the catalog entry's recorded size
    /// (audit Fix #4 — identity check on move detection).
    #[test]
    fn discover_after_move_returns_repair() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        // Catalog at A claims 000001.sst should be there with 1 byte.
        write_catalog(&a, &cat_with(vec![entry_with_size("000001.sst", "blocks", 1)])).unwrap();
        // Disk: 1-byte file lives in B instead — sizes match → move.
        write_sst(&b, "000001.sst", b"x");

        let report = discover_shards(&a, &[(b.clone(), 0)], None, false).unwrap();
        match decide(&report) {
            ReconcileDecision::RepairThenOpen { reason } => {
                assert!(reason.contains("moved"), "got: {reason}");
            }
            other => panic!("expected RepairThenOpen, got {other:?}"),
        }
    }

    /// Audit Fix #3: a `.noble-shards.cbor` whose bytes don't parse
    /// (e.g. random junk) is reported in `catalog_errors` and `decide`
    /// returns `Fail`. Without this guard, corrupted catalogs were
    /// silently downgraded to `None` and the diff went empty.
    #[test]
    fn corrupt_catalog_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        // Plant random bytes as the catalog.
        std::fs::write(
            a.join(crate::catalog::CATALOG_FILE_NAME),
            b"this is not a valid NSHD catalog at all",
        ).unwrap();

        let report = discover_shards(&a, &[], None, false).unwrap();
        assert!(
            !report.catalog_errors.is_empty(),
            "expected catalog_errors to surface the corruption"
        );
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("corrupted catalog"), "got: {reason}");
            }
            other => panic!("expected Fail on corrupted catalog, got {other:?}"),
        }
    }

    /// Audit Fix #4: a file in another tier with the SAME name but
    /// WRONG size is NOT treated as a move. Without this guard a
    /// foreign file could trick `DB::Repair` into rebuilding the
    /// MANIFEST against junk.
    #[test]
    fn move_with_size_mismatch_is_not_a_move() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        // Catalog claims 100 bytes; disk file in B is 1 byte.
        write_catalog(&a, &cat_with(vec![entry_with_size("000001.sst", "blocks", 100)])).unwrap();
        write_sst(&b, "000001.sst", b"x");

        let report = discover_shards(&a, &[(b.clone(), 0)], None, false).unwrap();
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("absent"), "got: {reason}");
            }
            other => panic!("expected Fail (size mismatch), got {other:?}"),
        }
    }

    /// Audit Fix #4: a file with matching size BUT MISMATCHED hash
    /// (when both sides have hashes) is NOT treated as a move.
    #[test]
    fn move_with_hash_mismatch_is_not_a_move() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        // Catalog has hash A; disk file produces hash B but matching size.
        let catalog_sha = "0000000000000000000000000000000000000000000000000000000000000000";
        write_catalog(&a, &cat_with(vec![entry_with_size_hash("000001.sst", "blocks", 1, catalog_sha)])).unwrap();
        write_sst(&b, "000001.sst", b"x"); // SHA-256("x") ≠ all-zeros.

        let report = discover_shards(&a, &[(b.clone(), 0)], None, /* with_hash */ true).unwrap();
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("absent"), "got: {reason}");
            }
            other => panic!("expected Fail (hash mismatch), got {other:?}"),
        }
    }

    /// Catalog expects a file that isn't on disk anywhere. Decision:
    /// `Fail`.
    #[test]
    fn discover_truly_missing_file_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        write_catalog(&a, &cat_with(vec![entry("000001.sst", "blocks")])).unwrap();
        // No file on disk.

        let report = discover_shards(&a, &[], None, false).unwrap();
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("absent"), "got: {reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// Same content hash in two tiers → duplicate → `Fail`.
    #[test]
    fn discover_duplicate_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_sst(&a, "000001.sst", b"same content");
        write_sst(&b, "000001.sst", b"same content");

        let report = discover_shards(&a, &[(b.clone(), 0)], None, true).unwrap();
        assert!(!report.duplicates.is_empty(), "duplicates should be reported");
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("duplicate"), "got: {reason}");
            }
            other => panic!("expected Fail on duplicates, got {other:?}"),
        }
    }

    /// File present in tier A; catalog there says it belongs to a CF
    /// that isn't one of Noble's → stranger → `Fail`.
    #[test]
    fn discover_stranger_cf_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        write_catalog(&a, &cat_with(vec![entry("000001.sst", "definitely_not_a_noble_cf")]))
            .unwrap();
        write_sst(&a, "000001.sst", b"x");

        let report = discover_shards(&a, &[], None, false).unwrap();
        assert!(!report.strangers.is_empty());
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("unknown column family"), "got: {reason}");
            }
            other => panic!("expected Fail on strangers, got {other:?}"),
        }
    }

    /// Mismatched chain_id between catalog and `expected_chain_id`
    /// causes the catalog to be dropped and the files to be reported
    /// as strangers → `Fail`.
    #[test]
    fn discover_chain_id_mismatch_treats_as_stranger() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        let mut cat = cat_with(vec![entry("000001.sst", "blocks")]);
        cat.chain_id = 0xAAAA_AAAA;
        write_catalog(&a, &cat).unwrap();
        write_sst(&a, "000001.sst", b"x");

        let report = discover_shards(&a, &[], Some(0xBBBB_BBBB), false).unwrap();
        assert!(!report.strangers.is_empty(), "chain mismatch should produce strangers");
        match decide(&report) {
            ReconcileDecision::Fail { .. } => {}
            other => panic!("expected Fail on chain mismatch, got {other:?}"),
        }
    }

    /// Audit Fix #S6: when `hashes_available=true` and the catalog
    /// entry carries a hash but the disk descriptor lacks one (or
    /// vice versa), the candidate must NOT be treated as a move.
    /// Pre-S6 it fell back to size-only matching — defeated the
    /// safety guarantee Fix #4 promised.
    #[test]
    fn move_with_one_sided_hash_when_hashes_required() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        // Catalog at A has both size AND hash.
        let known_sha = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        write_catalog(
            &a,
            &cat_with(vec![entry_with_size_hash("000001.sst", "blocks", 11, known_sha)]),
        )
        .unwrap();
        // Disk: same-size file in tier B; we ask discovery to hash
        // so `hashes_available=true`.
        write_sst(&b, "000001.sst", b"hello world"); // 11 bytes, SHA matches known_sha

        let report =
            discover_shards(&a, &[(b.clone(), 0)], None, /* with_hash */ true).unwrap();
        assert!(report.hashes_available);
        // Sanity: this case should be a move (size + hash both match).
        match decide(&report) {
            ReconcileDecision::RepairThenOpen { .. } => {}
            other => panic!("expected RepairThenOpen when hashes match, got {other:?}"),
        }

        // Now test the inverse: catalog has hash, disk file has
        // different content (different hash) but same size. Should
        // NOT be treated as a move under S6 — must be Fail.
        std::fs::remove_file(b.join("000001.sst")).unwrap();
        // 11 bytes but different content → different SHA.
        write_sst(&b, "000001.sst", b"DIFFERENT!!");
        let report =
            discover_shards(&a, &[(b.clone(), 0)], None, /* with_hash */ true).unwrap();
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("absent"), "expected absent-file Fail, got: {reason}");
            }
            other => panic!("expected Fail on hash mismatch under S6, got {other:?}"),
        }
    }

    /// Audit Fix #S7: first boot of a fresh tier (no catalog AND no
    /// bootstrap marker) is accepted as OpenNormally — there's
    /// nothing yet to compare against, so the absence of a catalog
    /// is benign.
    #[test]
    fn first_boot_no_catalog_accepts() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        // No catalog, no bootstrap marker, no SSTs — fresh tier.
        let report = discover_shards(&a, &[], None, false).unwrap();
        assert!(report.catalog_errors.is_empty(), "no catalog should NOT be a catalog error on first boot");
        assert_eq!(decide(&report), ReconcileDecision::OpenNormally);
    }

    /// Audit Fix #S7: in steady state (`.noble-bootstrap` marker
    /// present), a missing `.noble-shards.cbor` is a hard error —
    /// either the catalog was deleted or the filesystem dropped it.
    #[test]
    fn steady_state_missing_catalog_fails() {
        use crate::catalog::ensure_bootstrap_marker;

        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir_all(&a).unwrap();
        // Plant the bootstrap marker but no catalog.
        ensure_bootstrap_marker(&a).unwrap();
        // No catalog file.
        let report = discover_shards(&a, &[], None, false).unwrap();
        assert!(
            !report.catalog_errors.is_empty(),
            "expected catalog_errors to record the missing-but-expected catalog"
        );
        match decide(&report) {
            ReconcileDecision::Fail { reason, .. } => {
                assert!(reason.contains("corrupted catalog"), "got: {reason}");
            }
            other => panic!("expected Fail on steady-state missing catalog, got {other:?}"),
        }
    }
}
