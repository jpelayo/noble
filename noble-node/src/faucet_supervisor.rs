// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Faucet child-process supervisor.
//!
//! The node runs `noble-faucet` as a child process. Before this module the
//! child was spawned exactly once at startup and never watched — if it died
//! (or a `brew reinstall` replaced the Cellar under a running node) the port
//! went dark while every status surface kept smiling. The supervisor makes
//! that impossible:
//!
//! - **Respawn with backoff** when the child exits (1 s → ×2 → 60 s cap,
//!   reset after 5 min of stable run), with a CRITICAL `faucet_down` event on
//!   the Protocol-Activity WS channel and a `faucet_restarted` event on
//!   recovery.
//! - **Live toggle**: the dashboard's Enable/Disable flips the shared
//!   `faucet_enabled` atomic (via `setConfigValue`); the supervisor kills or
//!   spawns the child within ~2 s — no node restart.
//! - **Real liveness**: `faucet_listening` is set ONLY after a successful
//!   probe of `https://127.0.0.1:{port}/api/faucet/status` (and re-verified
//!   every 30 s). `getNodeInfo` exposes it so the GUI badge reflects the
//!   port, not the config.
//! - **Binary discovery per attempt** (next to `noble-node`), so a replaced
//!   install path is picked up on the next spawn instead of failing forever.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::broadcast;
use tokio::time::Instant;

/// How often the supervisor wakes to check the enable flag / run probes.
const FLAG_POLL: Duration = Duration::from_secs(2);
/// Steady-state liveness probe cadence, in FLAG_POLL ticks (15 × 2 s = 30 s).
const PROBE_EVERY_TICKS: u32 = 15;
/// Startup grace: if the child never answers within this many ticks
/// (15 × 2 s = 30 s), it is presumed wedged and gets restarted.
const STARTUP_PROBE_MAX_TICKS: u32 = 15;
/// Respawn backoff bounds.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// A child that survives this long earns a backoff reset.
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(300);

/// Everything needed to (re)build the faucet spawn command. Owned copies so
/// the supervisor task is `'static`.
pub struct FaucetSpawnConfig {
    pub server_port: u16,
    pub rpc_url: String,
    pub db_path: String,
    pub keystore_dir: String,
    pub node_data_dir: PathBuf,
    /// The node's RESOLVED wallet keystore file (`NodeConfig::
    /// resolved_keystore_file()`). Passed as --node-keystore so the faucet
    /// never guesses `{data_dir}/keystore.noble` — a wrong guess on layouts
    /// with an absolute keystore_path crash-loops the child.
    pub node_keystore: PathBuf,
    pub log_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
}

/// Why the per-child supervision loop ended.
enum ChildEnd {
    /// The process exited on its own (exit code if available).
    Died(Option<i32>),
    /// The operator disabled the faucet — kill without respawn.
    Disabled,
    /// Spawned but never answered its HTTP port within the grace window.
    Wedged,
}

/// Exponential backoff step: double, capped.
fn next_backoff(prev: Duration) -> Duration {
    (prev * 2).min(BACKOFF_CAP)
}

/// Locate `noble-faucet` next to the running `noble-node` executable.
/// Re-evaluated on every spawn attempt so a replaced install (brew upgrade)
/// is picked up without a node restart.
fn locate_binary() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| {
        let dir = p.parent()?;
        let candidate = dir.join("noble-faucet");
        candidate.exists().then_some(candidate)
    })
}

/// Build the spawn command — argument set identical to the pre-supervisor
/// inline spawn (--listen/--rpc-url/--db-path/--keystore-dir/--node-data-dir
/// plus --tls-cert/--tls-key when both files exist). stdout/stderr are
/// APPENDED to faucet.log so respawns never erase death evidence.
fn build_command(bin: &PathBuf, cfg: &FaucetSpawnConfig) -> tokio::process::Command {
    let open_log = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.log_path)
    };
    let (log_out, log_err) = match open_log() {
        Ok(f) => {
            let err = f.try_clone().ok();
            (
                std::process::Stdio::from(f),
                err.map(std::process::Stdio::from)
                    .unwrap_or_else(std::process::Stdio::null),
            )
        }
        Err(e) => {
            tracing::warn!(
                task = "faucet",
                "Cannot open faucet log at {}: {e}",
                cfg.log_path.display()
            );
            (std::process::Stdio::null(), std::process::Stdio::null())
        }
    };

    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("--listen")
        .arg(format!("0.0.0.0:{}", cfg.server_port))
        .arg("--rpc-url")
        .arg(&cfg.rpc_url)
        .arg("--db-path")
        .arg(&cfg.db_path)
        .arg("--keystore-dir")
        .arg(&cfg.keystore_dir)
        .arg("--node-data-dir")
        .arg(&cfg.node_data_dir)
        .arg("--node-keystore")
        .arg(&cfg.node_keystore);
    if cfg.tls_cert_path.exists() && cfg.tls_key_path.exists() {
        cmd.arg("--tls-cert")
            .arg(&cfg.tls_cert_path)
            .arg("--tls-key")
            .arg(&cfg.tls_key_path);
    }
    cmd.stdout(log_out).stderr(log_err).kill_on_drop(true);
    cmd
}

/// Emit an event onto the Protocol-Activity WS channel (same channel the
/// sync-stall backstop uses). Send failure means no live subscriber beyond
/// the keepalive — an operational signal, logged at debug.
fn emit(tx: &broadcast::Sender<serde_json::Value>, event: serde_json::Value) {
    if let Err(e) = tx.send(event) {
        tracing::debug!(task = "faucet", "activity event send failed: {e}");
    }
}

/// Spawn the supervisor task. Lives for the node's lifetime; owns the child.
pub fn spawn_supervisor(
    enabled: Arc<AtomicBool>,
    listening: Arc<AtomicBool>,
    cfg: FaucetSpawnConfig,
    tx: broadcast::Sender<serde_json::Value>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut backoff = BACKOFF_INITIAL;
        let mut restarts: u64 = 0;
        let mut binary_missing_reported = false;

        loop {
            // Parked while disabled — the dashboard toggle flips the shared
            // atomic and we react within one FLAG_POLL.
            if !enabled.load(Ordering::Relaxed) {
                listening.store(false, Ordering::Relaxed);
                tokio::time::sleep(FLAG_POLL).await;
                continue;
            }

            let Some(bin) = locate_binary() else {
                listening.store(false, Ordering::Relaxed);
                if !binary_missing_reported {
                    tracing::warn!(
                        task = "faucet",
                        "noble-faucet binary not found next to noble-node — faucet cannot start"
                    );
                    emit(
                        &tx,
                        json!({
                            "event": "faucet_down",
                            "severity": "critical",
                            "reason": "binary not found",
                        }),
                    );
                    binary_missing_reported = true;
                }
                tokio::time::sleep(FLAG_POLL).await;
                continue;
            };
            binary_missing_reported = false;

            let mut child = match build_command(&bin, &cfg).spawn() {
                Ok(c) => {
                    tracing::info!(
                        task = "faucet",
                        "Faucet server started on port {} (PID {}, attempt {})",
                        cfg.server_port,
                        c.id().unwrap_or(0),
                        restarts + 1
                    );
                    c
                }
                Err(e) => {
                    tracing::error!(task = "faucet", "Failed to start faucet: {e}");
                    emit(
                        &tx,
                        json!({
                            "event": "faucet_down",
                            "severity": "critical",
                            "reason": format!("spawn failed: {e}"),
                            "restarts": restarts,
                        }),
                    );
                    listening.store(false, Ordering::Relaxed);
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff);
                    restarts += 1;
                    continue;
                }
            };

            if restarts > 0 {
                emit(
                    &tx,
                    json!({
                        "event": "faucet_restarted",
                        "severity": "info",
                        "restarts": restarts,
                    }),
                );
            }

            let spawned_at = Instant::now();
            let mut ticks: u32 = 0;
            let mut interval = tokio::time::interval(FLAG_POLL);
            interval.tick().await; // consume the immediate first tick

            // Per-child supervision: watch for exit, disable, wedge.
            let end = loop {
                tokio::select! {
                    status = child.wait() => {
                        break ChildEnd::Died(status.ok().and_then(|s| s.code()));
                    }
                    _ = interval.tick() => {
                        if !enabled.load(Ordering::Relaxed) {
                            break ChildEnd::Disabled;
                        }
                        ticks += 1;
                        let was_listening = listening.load(Ordering::Relaxed);
                        // Probe every tick until the first success (startup
                        // grace), then every PROBE_EVERY_TICKS (30 s).
                        if !was_listening || ticks % PROBE_EVERY_TICKS == 0 {
                            let port = cfg.server_port;
                            let ok = tokio::task::spawn_blocking(move || {
                                crate::faucet_probe::probe_faucet("127.0.0.1", port).is_some()
                            })
                            .await
                            .unwrap_or(false);
                            if ok && !was_listening {
                                tracing::info!(task = "faucet", "faucet listening on port {port}");
                            }
                            if !ok && was_listening {
                                tracing::warn!(
                                    task = "faucet",
                                    "faucet stopped answering on port {port}"
                                );
                            }
                            listening.store(ok, Ordering::Relaxed);
                            if !ok && !was_listening && ticks >= STARTUP_PROBE_MAX_TICKS {
                                break ChildEnd::Wedged;
                            }
                        }
                    }
                }
            };

            listening.store(false, Ordering::Relaxed);
            match end {
                ChildEnd::Disabled => {
                    if let Err(e) = child.kill().await {
                        tracing::warn!(task = "faucet", "kill on disable failed: {e}");
                    }
                    let _ = child.wait().await;
                    tracing::info!(task = "faucet", "Faucet stopped (disabled via settings)");
                    // No backoff/restart bookkeeping — this is deliberate.
                }
                ChildEnd::Wedged => {
                    if let Err(e) = child.kill().await {
                        tracing::warn!(task = "faucet", "kill of wedged faucet failed: {e}");
                    }
                    let _ = child.wait().await;
                    tracing::error!(
                        task = "faucet",
                        restarts,
                        "faucet never answered on port {} within {}s — restarting",
                        cfg.server_port,
                        (STARTUP_PROBE_MAX_TICKS as u64) * FLAG_POLL.as_secs()
                    );
                    emit(
                        &tx,
                        json!({
                            "event": "faucet_down",
                            "severity": "critical",
                            "reason": "not listening after startup grace — restarting",
                            "restarts": restarts,
                        }),
                    );
                    restarts += 1;
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff);
                }
                ChildEnd::Died(code) => {
                    if spawned_at.elapsed() >= BACKOFF_RESET_AFTER {
                        backoff = BACKOFF_INITIAL;
                    }
                    tracing::error!(
                        task = "faucet",
                        exit_code = ?code,
                        restarts,
                        "faucet process exited — restarting with backoff"
                    );
                    emit(
                        &tx,
                        json!({
                            "event": "faucet_down",
                            "severity": "critical",
                            "exit_code": code,
                            "restarts": restarts,
                        }),
                    );
                    restarts += 1;
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = BACKOFF_INITIAL;
        assert_eq!(b, Duration::from_secs(1));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(2));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(4));
        for _ in 0..10 {
            b = next_backoff(b);
        }
        assert_eq!(b, BACKOFF_CAP, "backoff must cap at {BACKOFF_CAP:?}");
        assert_eq!(next_backoff(BACKOFF_CAP), BACKOFF_CAP, "cap is a fixpoint");
    }

    #[test]
    fn spawn_command_preserves_the_exact_argument_set() {
        let dir = std::env::temp_dir().join("noble-faucet-supervisor-test");
        let _ = std::fs::create_dir_all(&dir);
        let cfg = FaucetSpawnConfig {
            server_port: 8786,
            rpc_url: "https://127.0.0.1:8783".into(),
            db_path: "/tmp/faucet.db".into(),
            keystore_dir: "/tmp/faucet-keystore".into(),
            node_data_dir: PathBuf::from("/tmp/noble-data"),
            // Deliberately OUTSIDE node_data_dir — the regression this
            // argument exists to fix (absolute wallet.keystore_path).
            node_keystore: PathBuf::from("/tmp/elsewhere/keystore.noble"),
            log_path: dir.join("faucet.log"),
            // Non-existent on purpose: TLS args must be omitted.
            tls_cert_path: dir.join("no-cert.pem"),
            tls_key_path: dir.join("no-key.pem"),
        };
        let bin = PathBuf::from("/usr/bin/true");
        let cmd = build_command(&bin, &cfg);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            vec![
                "--listen", "0.0.0.0:8786",
                "--rpc-url", "https://127.0.0.1:8783",
                "--db-path", "/tmp/faucet.db",
                "--keystore-dir", "/tmp/faucet-keystore",
                "--node-data-dir", "/tmp/noble-data",
                "--node-keystore", "/tmp/elsewhere/keystore.noble",
            ]
        );

        // With both TLS files present, the TLS args must be appended.
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, "x").unwrap();
        std::fs::write(&key, "x").unwrap();
        let cfg_tls = FaucetSpawnConfig {
            tls_cert_path: cert.clone(),
            tls_key_path: key.clone(),
            ..cfg
        };
        let cmd = build_command(&bin, &cfg_tls);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args[args.len() - 4], "--tls-cert");
        assert_eq!(args[args.len() - 2], "--tls-key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
