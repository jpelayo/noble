// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Platform-aware default path resolution for NOBLE configuration and data files.

use std::path::PathBuf;

/// Determine the platform-aware default configuration file path.
///
/// Search order — returns the **first path that exists**:
/// 1. `/opt/homebrew/etc/noble/noble.toml` (macOS ARM Homebrew)
/// 2. `/usr/local/etc/noble/noble.toml` (macOS Intel / Linux Homebrew)
/// 3. `~/.noble/noble.toml` (user-local)
/// 4. `/etc/noble/noble.toml` (system-wide Linux root install)
/// 5. `noble.toml` (CWD fallback)
///
/// If none exist, returns the best *creation* path for the current platform.
pub fn platform_config_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        PathBuf::from("/opt/homebrew/etc/noble/noble.toml"),
        PathBuf::from("/usr/local/etc/noble/noble.toml"),
        home.join(".noble").join("noble.toml"),
        PathBuf::from("/etc/noble/noble.toml"),
        PathBuf::from("noble.toml"),
    ];

    for p in &candidates {
        if p.exists() {
            return p.clone();
        }
    }

    // None found — return the best creation path.
    creation_config_path()
}

/// Best path to *create* a new config file on this platform.
fn creation_config_path() -> PathBuf {
    let is_root = std::env::var("USER").map(|u| u == "root").unwrap_or(false);
    if is_root && cfg!(target_os = "linux") {
        PathBuf::from("/etc/noble/noble.toml")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".noble")
            .join("noble.toml")
    }
}

/// Determine the platform-aware default data directory.
///
/// - macOS: `~/Library/Application Support/NOBLE/data`
/// - Linux: `~/.noble/data` (non-root) or `/var/lib/noble/data` (root)
/// - Windows: `{AppData}/NOBLE/data`
/// - Other: `./data`
pub fn platform_data_dir() -> PathBuf {
    match std::env::consts::OS {
        "macos" => dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("NOBLE")
            .join("data"),
        "linux" => {
            let is_root = std::env::var("USER").map(|u| u == "root").unwrap_or(false);
            if is_root {
                PathBuf::from("/var/lib/noble/data")
            } else {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".noble")
                    .join("data")
            }
        }
        "windows" => dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("NOBLE")
            .join("data"),
        _ => PathBuf::from("data"),
    }
}

/// Default genesis block path: `<platform_data_dir>/genesis.cbor`.
pub fn platform_genesis_path() -> PathBuf {
    platform_data_dir().join("genesis.cbor")
}
