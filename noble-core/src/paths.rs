// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Platform-aware default path resolution for NOBLE configuration and data files.
//!
//! Config discovery is exhaustive: it tries 12 strategies to find `noble.toml`
//! so that `noble-tool`, `noble-node`, and any other binary in the workspace
//! locate the same file regardless of how they were installed or invoked.

use std::path::{Path, PathBuf};

const TOML_RELATIVE: &str = "etc/noble/noble.toml";

/// Determine the platform-aware default configuration file path.
///
/// Exhaustive search — returns the **first path that exists**:
///
///  1.  `NOBLE_CONFIG` env var (explicit override, any install)
///  2.  Cellar extraction: if resolved exe path contains `/Cellar/`,
///      split on it to derive the Homebrew prefix directly.
///      `…/.linuxbrew/Cellar/noble/HEAD/bin/noble-tool` → `…/.linuxbrew/`
///  3.  Walk every ancestor of the resolved binary path, checking
///      `<ancestor>/etc/noble/noble.toml`.  Catches non-Cellar prefix
///      installs (e.g. `/usr/local/bin/noble-tool` → `/usr/local/`).
///  4.  `argv[0]` resolved through `$PATH` (preserves symlink, not
///      resolved by the OS).  Check `<symlink_dir>/../etc/noble/noble.toml`.
///  5.  `argv[0]` resolved through `$PATH`, then `read_link` one level.
///      If the link target contains `/Cellar/`, extract prefix from that.
///  6.  `HOMEBREW_PREFIX` env var.
///  7.  `HOMEBREW_CELLAR` env var — parent is the prefix.
///  8.  `HOMEBREW_REPOSITORY` env var — equals the prefix on standard installs.
///  9.  Well-known Homebrew prefixes:
///      `/opt/homebrew`, `/usr/local`, `/home/linuxbrew/.linuxbrew`
/// 10.  `XDG_CONFIG_HOME/noble/noble.toml` (freedesktop)
/// 11.  `~/.noble/noble.toml` (user-local)
/// 12.  `/etc/noble/noble.toml` (system-wide)
/// 13.  `noble.toml` (CWD fallback — cargo run / dev)
///
/// If none exist, returns the best *creation* path for the current platform.
pub fn platform_config_path() -> PathBuf {
    // 1. Explicit override — any install, any platform.
    if let Some(p) = env_existing("NOBLE_CONFIG") {
        return p;
    }

    // 2. Cellar extraction from resolved exe path.
    //    current_exe() follows all symlinks.  On Homebrew the resolved path
    //    lives under <prefix>/Cellar/<formula>/<version>/bin/<binary>.
    //    Splitting on "/Cellar/" yields the prefix in one step.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(prefix) = extract_cellar_prefix(&exe) {
            let c = prefix.join(TOML_RELATIVE);
            if c.exists() {
                return c;
            }
        }
    }

    // 3. Walk every ancestor of the resolved binary path.
    //    Catches non-Cellar layouts: /usr/local/bin/noble-tool → /usr/local/
    //    Also catches custom prefix installs without Cellar indirection.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(c) = walk_ancestors_for_config(&exe) {
            return c;
        }
    }

    // 4. argv[0] + PATH resolution — preserves symlink.
    //    Shell invocation: user types `noble-tool`, PATH finds the symlink
    //    at <prefix>/bin/noble-tool.  Parent of parent = prefix.
    if let Some(symlink) = resolve_argv0_via_path() {
        if let Some(c) = check_prefix_from_bin(&symlink) {
            return c;
        }

        // 5. Follow the symlink one level.  If the link target is inside a
        //    Cellar, extract the prefix from that target path.
        if let Ok(target) = std::fs::read_link(&symlink) {
            // read_link may return relative; resolve against the symlink dir.
            let abs_target = if target.is_relative() {
                symlink.parent().unwrap_or(Path::new(".")).join(&target)
            } else {
                target
            };
            if let Some(prefix) = extract_cellar_prefix(&abs_target) {
                let c = prefix.join(TOML_RELATIVE);
                if c.exists() {
                    return c;
                }
            }
            // Also walk ancestors of the link target.
            if let Some(c) = walk_ancestors_for_config(&abs_target) {
                return c;
            }
        }
    }

    // 6–8. Homebrew env vars.
    for var in &["HOMEBREW_PREFIX", "HOMEBREW_REPOSITORY"] {
        if let Some(c) = env_prefix_config(var) {
            return c;
        }
    }
    if let Ok(cellar) = std::env::var("HOMEBREW_CELLAR") {
        if let Some(prefix) = Path::new(&cellar).parent() {
            let c = prefix.join(TOML_RELATIVE);
            if c.exists() {
                return c;
            }
        }
    }

    // 9. Well-known Homebrew prefixes.
    for prefix in &[
        "/opt/homebrew",
        "/usr/local",
        "/home/linuxbrew/.linuxbrew",
    ] {
        let c = Path::new(prefix).join(TOML_RELATIVE);
        if c.exists() {
            return c;
        }
    }

    // 10. XDG_CONFIG_HOME (freedesktop).
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let c = Path::new(&xdg).join("noble/noble.toml");
        if c.exists() {
            return c;
        }
    }

    // 11–13. User-local, system-wide, CWD.
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    for p in &[
        home.join(".noble").join("noble.toml"),
        PathBuf::from("/etc/noble/noble.toml"),
        PathBuf::from("noble.toml"),
    ] {
        if p.exists() {
            return p.clone();
        }
    }

    creation_config_path()
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// If `path` contains `/Cellar/`, return everything before it as the prefix.
/// e.g. `/home/linuxbrew/.linuxbrew/Cellar/noble/HEAD/bin/x` → `/home/linuxbrew/.linuxbrew`
fn extract_cellar_prefix(path: &Path) -> Option<PathBuf> {
    let s = path.to_str()?;
    let idx = s.find("/Cellar/")?;
    Some(PathBuf::from(&s[..idx]))
}

/// Walk every ancestor of `path`, return the first `<ancestor>/etc/noble/noble.toml` that exists.
fn walk_ancestors_for_config(path: &Path) -> Option<PathBuf> {
    let mut dir = path;
    while let Some(parent) = dir.parent() {
        let c = parent.join(TOML_RELATIVE);
        if c.exists() {
            return Some(c);
        }
        dir = parent;
    }
    None
}

/// Given a path like `<prefix>/bin/noble-tool`, check `<prefix>/etc/noble/noble.toml`.
fn check_prefix_from_bin(bin_path: &Path) -> Option<PathBuf> {
    let prefix = bin_path.parent()?.parent()?;
    let c = prefix.join(TOML_RELATIVE);
    c.exists().then_some(c)
}

/// Resolve `argv[0]` through `$PATH` WITHOUT following symlinks.
fn resolve_argv0_via_path() -> Option<PathBuf> {
    let arg0 = std::env::args().next()?;
    let p = Path::new(&arg0);

    // Absolute path — use directly (don't follow symlinks).
    if p.is_absolute() {
        return p.exists().then(|| p.to_path_buf());
    }

    // Relative with directory component (e.g. `./noble-tool`) — resolve against CWD.
    if arg0.contains('/') {
        let abs = std::env::current_dir().ok()?.join(p);
        return abs.exists().then_some(abs);
    }

    // Bare name — search PATH.
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(&arg0);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Read an env var as a path; return it only if the file exists.
fn env_existing(var: &str) -> Option<PathBuf> {
    std::env::var(var).ok().map(PathBuf::from).filter(|p| p.exists())
}

/// Read an env var as a Homebrew-style prefix; return config path if it exists.
fn env_prefix_config(var: &str) -> Option<PathBuf> {
    let prefix = std::env::var(var).ok()?;
    let c = Path::new(&prefix).join(TOML_RELATIVE);
    c.exists().then_some(c)
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
/// - `NOBLE_DATA_DIR` env var (when set and non-empty) — the container
///   contract: docker/entrypoint.sh and docker-compose.yml declare the
///   bind-mounted data path this way (`/var/lib/noble`), so honoring it
///   here makes the setup wizard, `resolve_data_dir()`, and every default
///   recommend the durable path inside our image.
/// - macOS: `~/Library/Application Support/NOBLE/data`
/// - Linux: `~/.noble/data` (non-root) or `/var/lib/noble/data` (root)
/// - Windows: `{AppData}/NOBLE/data`
/// - Other: `./data`
pub fn platform_data_dir() -> PathBuf {
    if let Ok(env_dir) = std::env::var("NOBLE_DATA_DIR") {
        let trimmed = env_dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
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

/// Resolve the effective data directory.
///
/// Priority: `noble.toml [storage] data_dir` → `cli_fallback` → `platform_data_dir()`.
///
/// `noble.toml` is always consulted first because the platform default compiled
/// into the binary may differ from the Homebrew-configured data directory
/// (e.g. Linuxbrew uses `/home/linuxbrew/.linuxbrew/var/noble/data`).
///
/// This is the **canonical directory resolver** for every Noble binary.
pub fn resolve_data_dir(cli_fallback: &Path) -> PathBuf {
    let config_path = platform_config_path();
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(table) = content.parse::<toml::Table>() {
                if let Some(dir) = table
                    .get("storage")
                    .and_then(|s| s.as_table())
                    .and_then(|s| s.get("data_dir"))
                    .and_then(|d| d.as_str())
                {
                    return PathBuf::from(dir);
                }
            }
        }
    }
    if cli_fallback.as_os_str().is_empty() {
        platform_data_dir()
    } else {
        cli_fallback.to_path_buf()
    }
}

/// Bytes currently available on the filesystem hosting `path`. Used by
/// the sharding startup helper to auto-detect a per-tier `target_bytes`
/// when the operator left it implicit (Shape A `JustPath` config).
///
/// On Unix (Linux, macOS) this calls `statvfs(2)`. The result is the
/// number of bytes a non-privileged user could write — equivalent to
/// `df`'s "Avail" column. On unsupported platforms (Windows) it
/// returns `Err(ErrorKind::Unsupported)`.
#[cfg(unix)]
pub fn filesystem_free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::ffi::CString;
    let raw_path = path.as_os_str().to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "filesystem_free_bytes: path is not valid UTF-8",
        )
    })?;
    let cpath = CString::new(raw_path).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
    })?;
    // SAFETY: `statvfs` writes into the zeroed buffer; we pass a valid
    // C string pointer. The returned code is checked before we use any
    // of the populated fields.
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bavail = buf.f_bavail as u64;
    let frsize = buf.f_frsize as u64;
    Ok(bavail.saturating_mul(frsize))
}

#[cfg(not(unix))]
pub fn filesystem_free_bytes(_path: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "filesystem_free_bytes: only implemented for Unix",
    ))
}

// ── Environment recognition (container / mount awareness) ──────────────
//
// Used by the setup wizard (CLI + noble_checkDataDir RPC) to recognize a
// container environment and to warn when a chosen data directory lives on
// the container's ephemeral overlay filesystem instead of a bind-mount.

/// True when this process runs inside a container (Docker, Podman, LXC,
/// Kubernetes). Non-Linux hosts always return false — macOS/Windows Docker
/// runs Linux VMs, so the Linux branch is the one that matters.
pub fn running_in_container() -> bool {
    if std::env::consts::OS != "linux" {
        return false;
    }
    if Path::new("/.dockerenv").exists() {
        return true;
    }
    // Podman/systemd-nspawn set `container=<runtime>`.
    if std::env::var("container").map(|v| !v.is_empty()).unwrap_or(false) {
        return true;
    }
    std::fs::read_to_string("/proc/1/cgroup")
        .map(|c| cgroup_indicates_container(&c))
        .unwrap_or(false)
}

/// Pure classifier for `/proc/1/cgroup` content (separated for tests).
pub fn cgroup_indicates_container(cgroup: &str) -> bool {
    ["docker", "containerd", "kubepods", "lxc", "podman"]
        .iter()
        .any(|marker| cgroup.contains(marker))
}

/// The mount entry governing a path (Linux only — None elsewhere).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub mount_point: PathBuf,
    pub fstype: String,
}

/// Find the mount entry whose mount point is the longest prefix of `path`.
/// The path need not exist — we walk up to the first existing ancestor
/// first (same as the wizard's writability probe). Linux only.
pub fn mount_for_path(path: &Path) -> Option<MountInfo> {
    if std::env::consts::OS != "linux" {
        return None;
    }
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        probe = probe.parent()?.to_path_buf();
    }
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    parse_mountinfo(&content, &probe)
}

/// Pure `/proc/self/mountinfo` parser (separated for tests). Format per
/// proc(5): `ID PARENT MAJ:MIN ROOT MOUNT_POINT OPTS [OPTIONAL...] - FSTYPE
/// SOURCE SUPER_OPTS`; the fstype is the first field after the `-`
/// separator. Returns the entry with the longest mount-point prefix of
/// `path`.
pub fn parse_mountinfo(content: &str, path: &Path) -> Option<MountInfo> {
    let mut best: Option<MountInfo> = None;
    for line in content.lines() {
        let mut halves = line.splitn(2, " - ");
        let pre = halves.next()?;
        let post = halves.next();
        let mount_point = match pre.split(' ').nth(4) {
            Some(mp) => PathBuf::from(mp),
            None => continue,
        };
        if !path.starts_with(&mount_point) {
            continue;
        }
        let fstype = post
            .and_then(|p| p.split(' ').next())
            .unwrap_or("")
            .to_string();
        let better = match &best {
            Some(b) => mount_point.as_os_str().len() > b.mount_point.as_os_str().len(),
            None => true,
        };
        if better {
            best = Some(MountInfo { mount_point, fstype });
        }
    }
    best
}

/// True when `path` (or its first existing ancestor) is writable by this
/// process. Uses `access(2)` W_OK — no test-file litter. Single source of
/// truth; noble-api's checkDataDir delegates here.
#[cfg(unix)]
pub fn path_appears_writable(path: &Path) -> bool {
    use std::ffi::CString;
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(p) => probe = p.to_path_buf(),
            None => return false,
        }
    }
    let Some(s) = probe.as_os_str().to_str() else {
        return false;
    };
    let Ok(cpath) = CString::new(s) else {
        return false;
    };
    // SAFETY: valid NUL-terminated C string; access() only reads it.
    unsafe { libc::access(cpath.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
pub fn path_appears_writable(path: &Path) -> bool {
    // Windows: fall back to a metadata readonly probe on the first
    // existing ancestor.
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(p) => probe = p.to_path_buf(),
            None => return false,
        }
    }
    std::fs::metadata(&probe)
        .map(|m| !m.permissions().readonly())
        .unwrap_or(false)
}

#[cfg(all(test, unix))]
mod free_bytes_tests {
    use super::*;

    #[test]
    fn free_bytes_on_tempdir_is_positive() {
        let tmp = std::env::temp_dir();
        let n = filesystem_free_bytes(&tmp).expect("statvfs ok");
        // Anything > 0 is enough to confirm the call wired up. A
        // filesystem that genuinely has zero bytes free would fail
        // every subsequent test anyway.
        assert!(n > 0, "expected non-zero free bytes on {:?}, got {n}", tmp);
    }

    #[test]
    fn free_bytes_missing_path_errors() {
        let p = std::path::PathBuf::from("/this/path/does/not/exist/noble-test");
        let err = filesystem_free_bytes(&p).unwrap_err();
        // statvfs returns ENOENT here.
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn cgroup_classifier() {
        // Real-world docker cgroup v1 line.
        assert!(cgroup_indicates_container(
            "12:pids:/docker/8c1a3b\n11:memory:/docker/8c1a3b\n"
        ));
        // containerd / kubernetes.
        assert!(cgroup_indicates_container("0::/kubepods/besteffort/pod1/abc\n"));
        assert!(cgroup_indicates_container("0::/system.slice/containerd.service\n"));
        // Bare host (cgroup v2 unified).
        assert!(!cgroup_indicates_container("0::/init.scope\n"));
        assert!(!cgroup_indicates_container(
            "12:pids:/user.slice/user-1000.slice/session-2.scope\n"
        ));
    }

    #[test]
    fn mountinfo_longest_prefix_wins() {
        // Container-shaped mountinfo: overlay root + a bind-mounted data dir.
        let mi = "\
676 675 0:139 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b\n\
677 676 8:1 /opt/noble /var/lib/noble rw,relatime - ext4 /dev/sda1 rw\n\
678 676 0:140 / /proc rw,nosuid - proc proc rw\n";

        // Path under the bind mount → ext4 entry (longest prefix).
        let m = parse_mountinfo(mi, Path::new("/var/lib/noble/data")).unwrap();
        assert_eq!(m.mount_point, PathBuf::from("/var/lib/noble"));
        assert_eq!(m.fstype, "ext4");

        // Path elsewhere → the root overlay governs it (EPHEMERAL in a container).
        let m = parse_mountinfo(mi, Path::new("/home/user/noble")).unwrap();
        assert_eq!(m.mount_point, PathBuf::from("/"));
        assert_eq!(m.fstype, "overlay");

        // Empty content → None.
        assert!(parse_mountinfo("", Path::new("/anything")).is_none());
    }

    #[test]
    fn writable_probe_walks_to_existing_ancestor() {
        let tmp = std::env::temp_dir();
        // Nonexistent child of a writable dir → still writable (ancestor probe).
        assert!(path_appears_writable(&tmp.join("noble-does-not-exist/sub/dir")));
        // Root-owned location should not be writable for a normal user; if the
        // test runs as root it legitimately is — accept both, but the call
        // must not panic.
        let _ = path_appears_writable(Path::new("/etc/noble-test-probe"));
    }

    #[test]
    fn env_var_overrides_platform_data_dir() {
        // NOBLE_DATA_DIR (the container contract) must win over OS defaults.
        // Serialized via a lock-free single test: set → check → restore.
        let prev = std::env::var("NOBLE_DATA_DIR").ok();
        std::env::set_var("NOBLE_DATA_DIR", "/var/lib/noble");
        assert_eq!(platform_data_dir(), PathBuf::from("/var/lib/noble"));
        std::env::set_var("NOBLE_DATA_DIR", "   ");
        assert_ne!(
            platform_data_dir(),
            PathBuf::from("   "),
            "blank env var must fall through to the OS default"
        );
        match prev {
            Some(v) => std::env::set_var("NOBLE_DATA_DIR", v),
            None => std::env::remove_var("NOBLE_DATA_DIR"),
        }
    }
}
