// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Storage-related RPC methods: getStorageInfo, setStorageMode, getPruningStatus.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

/// Minimal TOML string escaping for the dynamic `extra_data_dirs`
/// array we hand to `set_config_value`. Only handles the characters
/// that arise in real filesystem paths.
fn escape_toml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Translate a `noble_storage::DiscoveryReport` (Rust types) into the
/// wire-friendly DTO used by the GUI / external clients.
fn discovery_to_dto(report: &noble_storage::DiscoveryReport) -> DiscoveryReportDto {
    let decision = noble_storage::decide(report);
    let (decision_str, decision_reason) = match &decision {
        noble_storage::ReconcileDecision::OpenNormally => ("OpenNormally".to_string(), None),
        noble_storage::ReconcileDecision::RepairThenOpen { reason } => {
            ("RepairThenOpen".to_string(), Some(reason.clone()))
        }
        noble_storage::ReconcileDecision::Fail { reason, .. } => {
            ("Fail".to_string(), Some(reason.clone()))
        }
    };
    DiscoveryReportDto {
        paths: report
            .paths
            .iter()
            .map(|inv| PathInventoryDto {
                path: inv.path.display().to_string(),
                catalog_present: inv.catalog.is_some(),
                catalog_chain_id: inv.catalog.as_ref().map(|c| c.chain_id),
                catalog_updated_at: inv.catalog.as_ref().map(|c| c.updated_at),
                discovered: inv
                    .discovered
                    .iter()
                    .map(|d| ShardDescriptorDto {
                        file_name: d.file_name.clone(),
                        absolute_path: d.absolute_path.display().to_string(),
                        size_bytes: d.size_bytes,
                        content_sha256: d.content_sha256.clone(),
                    })
                    .collect(),
                missing_from_catalog: inv.missing_from_catalog.clone(),
                extra_vs_catalog: inv.extra_vs_catalog.clone(),
            })
            .collect(),
        duplicates: report
            .duplicates
            .iter()
            .map(|d| DuplicateSstDto {
                content_sha256: d.content_sha256.clone(),
                paths: d.paths.iter().map(|p| p.display().to_string()).collect(),
            })
            .collect(),
        strangers: report
            .strangers
            .iter()
            .map(|d| ShardDescriptorDto {
                file_name: d.file_name.clone(),
                absolute_path: d.absolute_path.display().to_string(),
                size_bytes: d.size_bytes,
                content_sha256: d.content_sha256.clone(),
            })
            .collect(),
        hashes_available: report.hashes_available,
        decision: decision_str,
        decision_reason,
        scan_errors: report
            .scan_errors
            .iter()
            .map(|(p, e)| (p.display().to_string(), e.clone()))
            .collect(),
        catalog_errors: report
            .catalog_errors
            .iter()
            .map(|(p, e)| (p.display().to_string(), e.clone()))
            .collect(),
    }
}

#[rpc(server, namespace = "noble")]
pub trait StorageApi {
    /// Get storage information including chain height and pruning status.
    #[method(name = "getStorageInfo")]
    async fn get_storage_info(&self) -> Result<StorageInfoResponse, ErrorObjectOwned>;

    /// Get the current pruning status and last run result.
    #[method(name = "getPruningStatus")]
    async fn get_pruning_status(&self) -> Result<PruningStatusResponse, ErrorObjectOwned>;

    /// Get detailed storage statistics: disk usage, column family breakdown, config.
    #[method(name = "getStorageStats")]
    async fn get_storage_stats(&self) -> Result<StorageStatsResponse, ErrorObjectOwned>;

    /// Get the current storage configuration values.
    #[method(name = "getStorageConfig")]
    async fn get_storage_config(&self) -> Result<StorageConfigResponse, ErrorObjectOwned>;

    /// Update storage configuration (writes to noble.toml, restart required).
    #[method(name = "setStorageConfig")]
    async fn set_storage_config(
        &self,
        data_dir: String,
        cache_size_mb: u32,
        compression: bool,
        pruning_mode: String,
        keep_blocks: u64,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned>;

    /// Run a chain integrity check over a range of blocks.
    /// Verifies block hashes, merkle roots, prev_hash linkage, and height continuity.
    /// Defaults to the full chain if no range is specified. Capped at 10,000 blocks per call.
    #[method(name = "checkChainIntegrity")]
    async fn check_chain_integrity(
        &self,
        from_height: Option<u64>,
        to_height: Option<u64>,
    ) -> Result<ChainIntegrityResponse, ErrorObjectOwned>;

    // ─── Multi-path storage sharding (Phase 5) ─────────────────────────

    /// Return every configured storage tier with live usage.
    /// Read-only; mirrors what `noble-node` passed to
    /// `RocksDbConfig::db_paths` at boot.
    #[method(name = "getStoragePaths")]
    async fn get_storage_paths(&self) -> Result<GetStoragePathsResponse, ErrorObjectOwned>;

    /// Persist a new `extra_data_dirs` list to `noble.toml`. Validates
    /// each input path (absolute, no duplicates, no clash with
    /// `data_dir`, writable via `noble_checkDataDir`-style probe) and
    /// returns the diff of `accepted` / `rejected`. Takes effect on
    /// next restart (RocksDB cannot reconfigure `db_paths` live).
    #[method(name = "setStoragePaths")]
    async fn set_storage_paths(
        &self,
        extras: Vec<StoragePathInput>,
    ) -> Result<SetStoragePathsResponse, ErrorObjectOwned>;

    /// Run the same discovery the node runs at boot, against the
    /// currently-configured tiers. Read-only; returns the full
    /// disk-vs-catalog diff plus the [`noble_storage::decide`]
    /// outcome as a string. Used by the GUI Recovery page.
    #[method(name = "discoverShards")]
    async fn discover_shards(&self) -> Result<DiscoveryReportDto, ErrorObjectOwned>;

    /// Inspect any directory (configured tier or not) for `.sst`
    /// files. Powers the GUI Recovery → Inspect tool ("does this
    /// backup tape contain Noble data?").
    #[method(name = "listShards")]
    async fn list_shards(
        &self,
        path: String,
        with_hash: bool,
    ) -> Result<ListShardsResponse, ErrorObjectOwned>;

    /// Re-run discovery AND rewrite the per-path catalog at every
    /// configured tier using the live `DB::live_files()` view. Does
    /// not run `DB::Repair` — that requires a restart. TOTP-gated.
    #[method(name = "reconcileStorage")]
    async fn reconcile_storage(&self) -> Result<ReconcileResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> StorageApiServer for Arc<ApiState<S>> {
    async fn get_storage_info(&self) -> Result<StorageInfoResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let chain_height = storage
            .get_chain_tip()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map(|t| t.height)
            .unwrap_or(0);
        let pruned_up_to = storage.get_pruning_marker().unwrap_or(0);
        let lowest_full = if pruned_up_to > 0 {
            pruned_up_to + 1
        } else {
            0
        };

        Ok(StorageInfoResponse {
            chain_height,
            pruning_mode: self.pruning_mode.clone(),
            keep_blocks: self.keep_blocks,
            pruned_up_to,
            lowest_full_height: lowest_full,
        })
    }

    async fn get_pruning_status(&self) -> Result<PruningStatusResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let pruned_up_to = storage.get_pruning_marker().unwrap_or(0);
        let lowest_full = if pruned_up_to > 0 {
            pruned_up_to + 1
        } else {
            0
        };

        Ok(PruningStatusResponse {
            mode: self.pruning_mode.clone(),
            blocks_pruned: 0,
            transactions_removed: 0,
            lowest_full_height: lowest_full,
            more_remaining: false,
        })
    }

    async fn get_storage_stats(&self) -> Result<StorageStatsResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let stats = storage
            .get_storage_stats()
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let column_families: Vec<CfStatsEntry> = stats
            .column_families
            .into_iter()
            .map(|cf| CfStatsEntry {
                name: cf.name,
                estimated_bytes: cf.estimated_bytes,
                estimated_keys: cf.estimated_keys,
            })
            .collect();

        let total_db_bytes: u64 = column_families.iter().map(|cf| cf.estimated_bytes).sum();

        let (data_dir_str, available_bytes, total_volume_bytes) =
            if let Some(ref dd) = self.data_dir {
                let dir_str = dd.display().to_string();
                let avail = super::node::disk_available(dd);
                let cap = super::node::disk_capacity(dd);
                (Some(dir_str), avail, cap)
            } else {
                (None, 0, 0)
            };

        Ok(StorageStatsResponse {
            data_dir: data_dir_str,
            total_db_bytes,
            available_bytes,
            total_volume_bytes,
            cache_size_bytes: u64::from(self.cache_size_mb) * 1024 * 1024,
            compression_enabled: self.compression_enabled,
            column_families,
        })
    }

    async fn get_storage_config(&self) -> Result<StorageConfigResponse, ErrorObjectOwned> {
        let data_dir = self
            .data_dir
            .as_ref()
            .map(|d| d.display().to_string())
            .unwrap_or_default();

        Ok(StorageConfigResponse {
            data_dir,
            cache_size_mb: self.cache_size_mb,
            compression: self.compression_enabled,
            pruning_mode: self.pruning_mode.clone(),
            keep_blocks: self.keep_blocks,
        })
    }

    async fn set_storage_config(
        &self,
        data_dir: String,
        cache_size_mb: u32,
        compression: bool,
        pruning_mode: String,
        keep_blocks: u64,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned> {
        let set_fn = self
            .set_config_value
            .as_ref()
            .ok_or_else(|| ApiError::Internal("config updates not available".into()))?;

        let fields: &[(&str, String)] = &[
            ("data_dir", data_dir),
            ("cache_size_mb", cache_size_mb.to_string()),
            ("compression", compression.to_string()),
            ("pruning_mode", pruning_mode),
            ("keep_blocks", keep_blocks.to_string()),
        ];

        for (key, value) in fields {
            set_fn("storage", key, value)
                .map_err(|e| ApiError::Internal(format!("failed to set storage.{key}: {e}")))?;
        }

        Ok(SetConfigValueResponse {
            success: true,
            restart_required: true,
        })
    }

    async fn get_storage_paths(&self) -> Result<GetStoragePathsResponse, ErrorObjectOwned> {
        // Build the full tier list: primary (`data_dir`) first, then
        // extras in the same order they were resolved at boot.
        let mut tiers: Vec<(PathBuf, u64)> = Vec::with_capacity(1 + self.extra_data_dirs.len());
        if let Some(dd) = self.data_dir.as_ref() {
            tiers.push((dd.clone(), 0));
        }
        for (p, t) in &self.extra_data_dirs {
            tiers.push((p.clone(), *t));
        }

        // Heavy lifting delegates to `StorageEngine::path_usage` (the
        // trait method with a default impl shared by every backend).
        let usage_by_path: std::collections::HashMap<PathBuf, noble_storage::PathUsage> = {
            let storage = self.storage.read();
            storage
                .path_usage(&tiers)
                .into_iter()
                .map(|u| (u.path.clone(), u))
                .collect()
        };

        let mut paths: Vec<StoragePathInfo> = Vec::new();
        for (i, (p, _)) in tiers.iter().enumerate() {
            let usage = usage_by_path
                .get(p)
                .cloned()
                .unwrap_or(noble_storage::PathUsage {
                    path: p.clone(),
                    target_bytes: 0,
                    used_bytes: 0,
                    sst_count: 0,
                    other_files_bytes: 0,
                });
            let free_bytes = noble_core::paths::filesystem_free_bytes(p).unwrap_or(0);
            let (catalog_present, catalog_updated_at) =
                match noble_storage::read_catalog(p) {
                    Ok(Some(c)) => (true, Some(c.updated_at)),
                    _ => (false, None),
                };
            paths.push(StoragePathInfo {
                path: p.display().to_string(),
                target_bytes: usage.target_bytes,
                used_bytes: usage.used_bytes,
                free_bytes,
                sst_count: usage.sst_count,
                other_files_bytes: usage.other_files_bytes,
                catalog_present,
                catalog_updated_at,
                is_primary: i == 0,
            });
        }
        Ok(GetStoragePathsResponse {
            paths,
            reconcile_mode: self.reconcile_mode.clone(),
        })
    }

    async fn set_storage_paths(
        &self,
        extras: Vec<StoragePathInput>,
    ) -> Result<SetStoragePathsResponse, ErrorObjectOwned> {
        let set_fn = self
            .set_config_value
            .as_ref()
            .ok_or_else(|| ApiError::Internal("config updates not available".into()))?;

        // Audit Fix #S9: track (canonical_path, target_gb) per
        // accepted entry. Canonical paths drive both the response
        // and the on-disk noble.toml persistence; target_gb travels
        // alongside so we can emit Shape B entries verbatim.
        let mut accepted: Vec<(String, Option<u64>)> = Vec::new();
        let mut rejected: Vec<StoragePathRejection> = Vec::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        let data_dir_pb = self.data_dir.clone();
        for input in &extras {
            let path = PathBuf::from(&input.path);
            // Validation mirrors NodeConfig::validate_storage_paths.
            if !path.is_absolute() {
                rejected.push(StoragePathRejection {
                    path: input.path.clone(),
                    reason: "not an absolute path".into(),
                });
                continue;
            }
            if let Some(dd) = data_dir_pb.as_ref() {
                if path == *dd {
                    rejected.push(StoragePathRejection {
                        path: input.path.clone(),
                        reason: "duplicates the primary data_dir".into(),
                    });
                    continue;
                }
            }
            if seen.contains(&path) {
                rejected.push(StoragePathRejection {
                    path: input.path.clone(),
                    reason: "duplicate entry".into(),
                });
                continue;
            }
            // Probe writability: try to create the dir + drop a test
            // file. Mirrors the contract of `noble_checkDataDir`.
            if let Err(e) = std::fs::create_dir_all(&path) {
                rejected.push(StoragePathRejection {
                    path: input.path.clone(),
                    reason: format!("create failed: {e}"),
                });
                continue;
            }
            // Audit Fix #8: canonicalize so symlinks / `..` aliases
            // collapse to one canonical form. Without this an
            // operator could submit two "different" paths via the
            // RPC that resolve to the same physical directory, and
            // the duplicate check above (using raw `path`) would
            // accept both.
            let canon = match std::fs::canonicalize(&path) {
                Ok(c) => c,
                Err(e) => {
                    rejected.push(StoragePathRejection {
                        path: input.path.clone(),
                        reason: format!("canonicalize failed: {e}"),
                    });
                    continue;
                }
            };
            if seen.iter().any(|p| p == &canon) {
                rejected.push(StoragePathRejection {
                    path: input.path.clone(),
                    reason: "resolves to the same physical directory as a \
                             previously-listed tier (symlink or `..` alias)"
                        .into(),
                });
                continue;
            }
            if let Some(dd) = data_dir_pb.as_ref() {
                if let Ok(dd_canon) = std::fs::canonicalize(dd) {
                    if canon == dd_canon {
                        rejected.push(StoragePathRejection {
                            path: input.path.clone(),
                            reason: "resolves to the primary data_dir after \
                                     symlink/`..` resolution"
                                .into(),
                        });
                        continue;
                    }
                }
            }
            let probe = canon.join(".noble_write_test");
            match std::fs::write(&probe, b"ok") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                }
                Err(e) => {
                    rejected.push(StoragePathRejection {
                        path: input.path.clone(),
                        reason: format!("not writable: {e}"),
                    });
                    continue;
                }
            }
            // Audit Fix #S9 (0.118): persist the CANONICAL form, not
            // the operator's raw input. Without this the on-disk
            // noble.toml drifts every time symlinks / CWD change
            // — the boot path canonicalises anyway, but the
            // stored config becomes a moving target. Persist what
            // RocksDB will actually use.
            //
            // Each "accepted" entry carries (raw_input, canonical,
            // optional target_gb) so:
            // - response.accepted echoes the canonical path (more
            //   truthful than the input the operator typed),
            // - persistence emits canonical paths,
            // - duplicate detection uses canonical (already in
            //   `seen`).
            let canon_str = canon.display().to_string();
            seen.push(canon);
            accepted.push((canon_str, input.target_gb));
        }

        // Persist accepted list as a TOML inline array. Shape B
        // entries are emitted as `{ path = "...", target_gb = N }`,
        // Shape A as `"path"`. All paths are CANONICAL (audit Fix
        // #S9).
        let mut parts: Vec<String> = Vec::with_capacity(accepted.len());
        for (canon_path, target_gb) in &accepted {
            match target_gb {
                None => parts.push(format!("\"{}\"", escape_toml(canon_path))),
                Some(gb) => parts.push(format!(
                    "{{ path = \"{}\", target_gb = {} }}",
                    escape_toml(canon_path),
                    gb
                )),
            }
        }
        let toml_array = format!("[{}]", parts.join(", "));
        set_fn("storage", "extra_data_dirs", &toml_array)
            .map_err(|e| ApiError::Internal(format!("failed to persist extra_data_dirs: {e}")))?;

        // Response carries the canonical paths (more truthful than
        // echoing raw input; operator sees the form RocksDB will use).
        Ok(SetStoragePathsResponse {
            accepted: accepted.into_iter().map(|(p, _)| p).collect(),
            rejected,
            requires_restart: true,
        })
    }

    async fn discover_shards(&self) -> Result<DiscoveryReportDto, ErrorObjectOwned> {
        let primary = self
            .data_dir
            .as_ref()
            .ok_or_else(|| ApiError::Internal("data_dir unknown".into()))?;
        let chain_id = self.chain_id.load(Ordering::Relaxed);
        let report = noble_storage::discover_shards(
            primary,
            &self.extra_data_dirs,
            if chain_id == 0 { None } else { Some(chain_id) },
            false,
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(discovery_to_dto(&report))
    }

    async fn list_shards(
        &self,
        path: String,
        with_hash: bool,
    ) -> Result<ListShardsResponse, ErrorObjectOwned> {
        let p = Path::new(&path);
        let (descriptors, errors) = noble_storage::scan_directory(p, with_hash);
        Ok(ListShardsResponse {
            path,
            descriptors: descriptors
                .into_iter()
                .map(|d| ShardDescriptorDto {
                    file_name: d.file_name,
                    absolute_path: d.absolute_path.display().to_string(),
                    size_bytes: d.size_bytes,
                    content_sha256: d.content_sha256,
                })
                .collect(),
            errors: errors
                .into_iter()
                .map(|(p, e)| format!("{}: {e}", p.display()))
                .collect(),
        })
    }

    async fn reconcile_storage(&self) -> Result<ReconcileResponse, ErrorObjectOwned> {
        // Audit Fix #5: discovery must run BEFORE any catalog rewrite,
        // otherwise the rewrite synchronises catalogs to disk reality
        // and we erase the very drift this RPC is supposed to surface.
        // We only rewrite catalogs when discovery sees the layout as
        // healthy (decision == OpenNormally); RepairThenOpen and Fail
        // states report the diff and ask the operator to restart.
        let primary = self
            .data_dir
            .as_ref()
            .ok_or_else(|| ApiError::Internal("data_dir unknown".into()))?;
        let chain_id = self.chain_id.load(Ordering::Relaxed);

        // 1) DISCOVER FIRST against on-disk catalogs as they are.
        //    Pass `with_hash = true` so move detection can verify
        //    identity by content (audit Fix #4).
        let report = noble_storage::discover_shards(
            primary,
            &self.extra_data_dirs,
            if chain_id == 0 { None } else { Some(chain_id) },
            /* with_hash */ true,
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;
        let decision = noble_storage::decide(&report);

        // 2) REWRITE catalogs only when the layout is healthy. If
        //    discovery shows drift, rewriting would silently erase it.
        let written = if matches!(decision, noble_storage::ReconcileDecision::OpenNormally) {
            let mut full_tiers: Vec<(PathBuf, u64)> =
                Vec::with_capacity(1 + self.extra_data_dirs.len());
            full_tiers.push((primary.clone(), 0));
            for (p, t) in &self.extra_data_dirs {
                full_tiers.push((p.clone(), *t));
            }
            let node_pubkey = self.validator_pubkey.read().clone().unwrap_or_default();
            let storage = self.storage.read();
            storage
                .rewrite_catalogs(&full_tiers, chain_id, &node_pubkey, /* with_hash */ true)
                .map_err(|e| ApiError::Internal(format!("rewrite_catalogs: {e}")))?
        } else {
            0
        };

        let requires_restart =
            !matches!(decision, noble_storage::ReconcileDecision::OpenNormally);
        Ok(ReconcileResponse {
            report: discovery_to_dto(&report),
            catalogs_rewritten: written,
            requires_restart,
        })
    }

    async fn check_chain_integrity(
        &self,
        from_height: Option<u64>,
        to_height: Option<u64>,
    ) -> Result<ChainIntegrityResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let tip = storage
            .get_chain_tip()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map(|t| t.height)
            .unwrap_or(0);

        let pruned_up_to = storage.get_pruning_marker().unwrap_or(0);
        let lowest_full = if pruned_up_to > 0 { pruned_up_to + 1 } else { 0 };
        let start = from_height.unwrap_or(lowest_full).max(lowest_full);
        let end = to_height.unwrap_or(tip);

        if end < start {
            return Err(ApiError::InvalidParam("to_height must be >= from_height".into()).into());
        }
        let range = end.saturating_sub(start) + 1;
        if range > 10_000 {
            return Err(ApiError::InvalidParam(
                format!("range too large ({range} blocks, max 10,000). Use from_height/to_height to paginate."),
            ).into());
        }

        let chain_id = self.chain_id.load(std::sync::atomic::Ordering::Relaxed);
        let report = noble_storage::verify_chain_integrity(&*storage, chain_id, start, end);

        Ok(ChainIntegrityResponse {
            heights_checked: report.heights_checked,
            is_clean: report.is_clean(),
            findings_count: report.findings.len(),
            first_corrupt_height: report.first_corrupt_height,
            findings: report.findings.iter().map(|f| ChainIntegrityFinding {
                height: f.height,
                kind: format!("{:?}", f.kind),
                detail: f.detail.clone(),
            }).collect(),
        })
    }
}
