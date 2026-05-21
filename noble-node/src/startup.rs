// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Multi-path storage startup helpers.
//!
//! Lives between `[storage] extra_data_dirs` in `noble.toml` and
//! `noble_storage::RocksDbConfig::db_paths`. Three responsibilities:
//!
//! 1. **Materialize tier directories.** Each operator-listed path is
//!    `create_dir_all`'d and (on Unix) chmod'd to `0700` so a misconfigured
//!    bind-mount can't accidentally expose blockchain data.
//! 2. **Resolve per-tier targets.** Shape A entries get
//!    `auto_target_bytes` = 90 % of free space rounded down to GiB.
//!    Shape B entries pass `target_gb` straight through (with `0` →
//!    unlimited).
//! 3. **Emit structured boot log.** Operators see the resolved tier list
//!    with target sizes, so a wrong-mount mistake surfaces immediately
//!    rather than waiting for RocksDB to overflow a small disk.

use std::path::{Path, PathBuf};

use noble_storage::{DiscoveryReport, ReconcileDecision};

use crate::config::StorageConfig;
#[cfg(test)]
use crate::config::ExtraDataDir;

/// Compute the `(path, target_bytes)` list to feed into
/// `noble_storage::RocksDbConfig::db_paths`. Empty config →
/// empty result (legacy single-volume mode).
pub fn compute_db_paths(cfg: &StorageConfig) -> Result<Vec<(PathBuf, u64)>, String> {
    if cfg.extra_data_dirs.is_empty() {
        return Ok(Vec::new());
    }
    // Audit Fix #8: canonicalize the primary so duplicate detection
    // against extras compares like-for-like. The data_dir must
    // already exist (created in main.rs before this is called).
    let primary_canon = std::fs::canonicalize(&cfg.data_dir)
        .map_err(|e| format!("storage.data_dir: canonicalize {:?}: {e}", cfg.data_dir))?;

    let mut out: Vec<(PathBuf, u64)> = Vec::with_capacity(cfg.extra_data_dirs.len());
    for extra in &cfg.extra_data_dirs {
        let raw = extra.path().to_path_buf();
        std::fs::create_dir_all(&raw).map_err(|e| {
            format!(
                "storage.extra_data_dirs: create {:?} failed: {e}. \
                 Make sure the path's parent is writable by the node process.",
                raw
            )
        })?;
        // Audit Fix #8: canonicalize AFTER create_dir_all (so the
        // path exists) to collapse `..`, `.`, and symlink aliases.
        // Two configured paths that share a canonical form would
        // make RocksDB see one physical tier as two `DBPath` entries
        // — undefined behaviour.
        let path = std::fs::canonicalize(&raw)
            .map_err(|e| format!("storage.extra_data_dirs: canonicalize {raw:?}: {e}"))?;
        if path == primary_canon {
            return Err(format!(
                "storage.extra_data_dirs: {raw:?} resolves to the primary data_dir \
                 after symlink/`..` resolution. Extra tiers must be distinct \
                 physical directories from `data_dir`."
            ));
        }
        if out.iter().any(|(p, _)| p == &path) {
            return Err(format!(
                "storage.extra_data_dirs: {raw:?} resolves to the same physical \
                 directory as a previously-configured tier (via symlink or `..` \
                 alias). Each tier must be a distinct physical directory."
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            {
                tracing::warn!(
                    task = "storage_startup",
                    "could not chmod 0700 on {path:?}: {e} (continuing; bind-mounted tiers may not allow chmod)"
                );
            }
        }
        let target = match extra.explicit_target_gb() {
            Some(0) => 0u64,
            Some(gb) => gb.saturating_mul(1024 * 1024 * 1024),
            None => auto_target_bytes(&path)
                .map_err(|e| format!("auto target for {:?}: {e}", path))?,
        };
        out.push((path, target));
    }

    // Audit Fix #S1: every long-running node must have at least one
    // unlimited spillover tier (target_bytes == 0) at the end of its
    // db_paths list. Without it, all tiers eventually fill and RocksDB
    // exits its "best-effort target" guarantee — newer SSTs cram into
    // whichever tier RocksDB picks last. The escape hatch
    // `NOBLE_ALLOW_BOUNDED_FINAL_TIER=1` accepts the risk for
    // operators who genuinely want a hard cap (rare).
    match out.last() {
        Some((_, 0)) => { /* OK: explicit unlimited spillover */ }
        Some((last_path, target_bytes)) => {
            let allow_override = std::env::var("NOBLE_ALLOW_BOUNDED_FINAL_TIER")
                .ok()
                .as_deref()
                == Some("1");
            if allow_override {
                tracing::warn!(
                    task = "storage_startup",
                    "final tier {last_path:?} is bounded ({} GiB); \
                     NOBLE_ALLOW_BOUNDED_FINAL_TIER=1 override active — RocksDB \
                     will overflow this tier when full",
                    target_bytes / (1u64 << 30)
                );
            } else {
                return Err(format!(
                    "storage.extra_data_dirs: final tier {last_path:?} has \
                     target_gb={} (finite). Every long-running node must have an \
                     unlimited spillover tier — set the LAST entry's \
                     `target_gb = 0` (or omit the size for auto), or accept the \
                     overflow risk by setting NOBLE_ALLOW_BOUNDED_FINAL_TIER=1.",
                    target_bytes / (1u64 << 30)
                ));
            }
        }
        None => unreachable!("compute_db_paths returns early when extras empty"),
    }

    Ok(out)
}

/// 90 % of free bytes on the filesystem hosting `p`, rounded down to
/// the nearest GiB. The 10 % headroom buffers against the
/// best-effort nature of RocksDB's per-path overflow rule: a tier
/// near its target can still grow briefly during compaction.
fn auto_target_bytes(p: &Path) -> std::io::Result<u64> {
    let free = noble_core::paths::filesystem_free_bytes(p)?;
    let raw = free.saturating_mul(9) / 10;
    let gib = 1u64 << 30;
    Ok(raw & !(gib - 1))
}

/// One-line-per-tier startup log. Pattern matches the existing
/// `[storage]` log prefix used elsewhere in `noble-node`.
pub fn log_storage_paths(primary: &Path, extras: &[(PathBuf, u64)]) {
    if extras.is_empty() {
        tracing::info!(
            task = "storage_startup",
            "open path={primary:?} mode=single-volume"
        );
        return;
    }
    let total_target = extras
        .iter()
        .map(|(_, t)| *t)
        .filter(|t| *t > 0)
        .fold(0u64, |a, b| a.saturating_add(b));
    let unlimited_count = extras.iter().filter(|(_, t)| *t == 0).count();
    tracing::info!(
        task = "storage_startup",
        "open path={primary:?} extra={} total_target={} unlimited_tiers={}",
        extras.len(),
        format_bytes(total_target),
        unlimited_count
    );
    tracing::info!(task = "storage_startup", "  path[0] {primary:?} (primary; structural)");
    for (i, (p, t)) in extras.iter().enumerate() {
        let target_str = if *t == 0 {
            "unlimited".to_string()
        } else {
            format_bytes(*t)
        };
        tracing::info!(task = "storage_startup", "  path[{}] {p:?} target={target_str}", i + 1);
    }
}

/// Discovery-summary log. Emits one line for the headline plus one
/// per tier. Caller is responsible for invoking
/// `noble_storage::decide` and acting on the result.
pub fn log_discovery_summary(report: &DiscoveryReport) {
    let total_sst: usize = report.paths.iter().map(|p| p.discovered.len()).sum();
    tracing::info!(
        task = "shard_discovery",
        "{} paths scanned, {} SST(s) total, duplicates={} strangers={} hashes_available={}",
        report.paths.len(),
        total_sst,
        report.duplicates.len(),
        report.strangers.len(),
        report.hashes_available
    );
    for inv in &report.paths {
        let cat_state = if inv.catalog.is_some() { "present" } else { "MISSING" };
        tracing::info!(
            task = "shard_discovery",
            "  {:?} catalog={cat_state} discovered={} missing_from_catalog={} extra_vs_catalog={}",
            inv.path,
            inv.discovered.len(),
            inv.missing_from_catalog.len(),
            inv.extra_vs_catalog.len()
        );
    }
}

/// Log a [`ReconcileDecision`]. The Phase 4 boot flow branches on
/// the decision; this helper just renders it for the operator.
pub fn log_decision(decision: &ReconcileDecision) {
    match decision {
        ReconcileDecision::OpenNormally => {
            tracing::info!(task = "shard_discovery", "decision: OpenNormally");
        }
        ReconcileDecision::RepairThenOpen { reason } => {
            tracing::warn!(
                task = "shard_discovery",
                "decision: RepairThenOpen — {reason}"
            );
        }
        ReconcileDecision::Fail { reason, suggestion } => {
            tracing::error!(task = "shard_discovery", "decision: Fail — {reason}");
            tracing::error!(task = "shard_discovery", "suggestion: {suggestion}");
        }
    }
}

fn format_bytes(b: u64) -> String {
    const GIB: u64 = 1u64 << 30;
    const TIB: u64 = 1u64 << 40;
    if b >= TIB {
        format!("{:.1} TiB", b as f64 / TIB as f64)
    } else if b >= GIB {
        format!("{:.1} GiB", b as f64 / GIB as f64)
    } else if b == 0 {
        "0".to_string()
    } else {
        format!("{} bytes", b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_db_paths_empty() {
        let cfg = StorageConfig::default();
        let r = compute_db_paths(&cfg).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn compute_db_paths_creates_dirs_for_shape_a() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        std::fs::create_dir_all(&primary).unwrap();
        let a = tmp.path().join("tier_a");
        let b = tmp.path().join("tier_b");
        // Audit Fix #S1: last tier must have target_gb=0 (unlimited)
        // or the call returns Err. We supply a Shape-A warm tier
        // followed by an unlimited Shape-B cold tier.
        let cfg = StorageConfig {
            data_dir: primary,
            extra_data_dirs: vec![
                ExtraDataDir::JustPath(a.clone()),
                ExtraDataDir::WithSize {
                    path: b.clone(),
                    target_gb: 0,
                },
            ],
            ..Default::default()
        };
        let r = compute_db_paths(&cfg).unwrap();
        assert_eq!(r.len(), 2);
        assert!(a.exists());
        assert!(b.exists());
        // Shape B target_gb=0 → unlimited (0 bytes sentinel).
        assert_eq!(r[1].1, 0);
        // Shape A target auto-detected → some positive amount of bytes,
        // or zero if statvfs reports the rounded value as exactly zero
        // (only on extremely small/full mounts). Just assert it's a
        // multiple of GiB (rounding contract).
        let gib = 1u64 << 30;
        assert_eq!(r[0].1 % gib, 0, "auto target should be a multiple of GiB");
    }

    /// Audit Fix #S1: a single Shape-A tier (with auto-target,
    /// hence a finite quota derived from free bytes) violates the
    /// "last tier must be unlimited" rule. Should return Err.
    #[test]
    fn compute_db_paths_rejects_bounded_final_tier() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        std::fs::create_dir_all(&primary).unwrap();
        let cold = tmp.path().join("cold");
        let cfg = StorageConfig {
            data_dir: primary,
            extra_data_dirs: vec![ExtraDataDir::JustPath(cold)],
            ..Default::default()
        };
        let err = compute_db_paths(&cfg).unwrap_err();
        assert!(
            err.contains("final tier") && err.contains("unlimited"),
            "expected final-tier error, got: {err}"
        );
    }

    /// Audit Fix #S1: same setup but with the env override → warns
    /// (we can't easily assert log output here without a tracing
    /// subscriber) but does NOT return Err.
    #[test]
    fn compute_db_paths_allows_bounded_final_tier_with_override() {
        // SAFETY: integration tests share a process; using
        // env::set_var here is safe because no other test in this
        // module reads NOBLE_ALLOW_BOUNDED_FINAL_TIER at the same
        // time. Cargo test parallelism within the same binary is
        // handled by Rust's test framework via separate threads
        // reading the same OS env; this could in principle race if
        // another test set+unset the same var. None do.
        // SAFETY: see audit comment above. The env var is read by
        // compute_db_paths inside this test and immediately removed.
        unsafe { std::env::set_var("NOBLE_ALLOW_BOUNDED_FINAL_TIER", "1") };
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        std::fs::create_dir_all(&primary).unwrap();
        let cold = tmp.path().join("cold");
        let cfg = StorageConfig {
            data_dir: primary,
            extra_data_dirs: vec![ExtraDataDir::JustPath(cold)],
            ..Default::default()
        };
        let r = compute_db_paths(&cfg);
        unsafe { std::env::remove_var("NOBLE_ALLOW_BOUNDED_FINAL_TIER") };
        let v = r.expect("override accepts bounded final tier");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn compute_db_paths_shape_b_zero_means_unlimited() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        std::fs::create_dir_all(&primary).unwrap();
        let a = tmp.path().join("tier_unl");
        let cfg = StorageConfig {
            data_dir: primary,
            extra_data_dirs: vec![ExtraDataDir::WithSize {
                path: a.clone(),
                target_gb: 0,
            }],
            ..Default::default()
        };
        let r = compute_db_paths(&cfg).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].1, 0, "Shape B target_gb=0 → 0 bytes (unlimited)");
    }

    /// Audit Fix #8: two tier paths that differ in spelling but
    /// canonicalize to the same physical directory must be rejected.
    /// `/tier_a` and `/tier_a/.` should not both pass duplicate
    /// detection.
    #[test]
    fn compute_db_paths_rejects_alias_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        let real = tmp.path().join("tier_real");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        // Two "different" paths that canonicalize to the same dir.
        let alias = tmp.path().join("tier_real").join(".");
        let cfg = StorageConfig {
            data_dir: primary,
            extra_data_dirs: vec![
                ExtraDataDir::JustPath(real.clone()),
                ExtraDataDir::JustPath(alias),
            ],
            ..Default::default()
        };
        let err = compute_db_paths(&cfg).unwrap_err();
        assert!(
            err.contains("same physical directory"),
            "expected duplicate-alias rejection, got: {err}"
        );
    }

    /// Audit Fix #8: extra tier resolving to the same physical dir
    /// as `data_dir` must be rejected (a symlink, a `..` path, or
    /// just literal equality after canonicalization).
    #[test]
    fn compute_db_paths_rejects_primary_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        std::fs::create_dir_all(&primary).unwrap();
        // `/primary/.` canonicalizes to `/primary`.
        let alias = primary.join(".");
        let cfg = StorageConfig {
            data_dir: primary,
            extra_data_dirs: vec![ExtraDataDir::JustPath(alias)],
            ..Default::default()
        };
        let err = compute_db_paths(&cfg).unwrap_err();
        assert!(
            err.contains("resolves to the primary data_dir"),
            "expected primary-alias rejection, got: {err}"
        );
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0");
        assert_eq!(format_bytes(1024), "1024 bytes");
        assert_eq!(format_bytes(1u64 << 30), "1.0 GiB");
        assert_eq!(format_bytes(2u64 << 40), "2.0 TiB");
    }
}
