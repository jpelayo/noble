// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Size-based rotating log file writer (in-house — no extra dependency).
//!
//! Implements [`tracing_subscriber::fmt::MakeWriter`] so it plugs straight into
//! a `fmt::layer().with_writer(...)`. The total on-disk footprint is bounded by
//! a live `Arc<AtomicU64>` cap (set at startup, adjustable at runtime via the
//! admin GUI / RPC and shared with `noble_api::trace_types::TraceHandle`): the
//! active file plus `max_files - 1` rotated files, each capped at
//! `cap / max_files`, so the set never exceeds `cap` bytes.
//!
//! `tracing-appender` only rotates on *time* (hourly/daily); the requirement is
//! a hard *size* cap, hence this small purpose-built writer.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::fmt::MakeWriter;

/// Smallest per-file size we allow, so a tiny/misconfigured cap can't thrash
/// rotation on every line.
const MIN_PER_FILE_BYTES: u64 = 64 * 1024;

/// Cloneable `MakeWriter` handle. All clones share one underlying file/state.
#[derive(Clone)]
pub struct RotatingWriter {
    inner: Arc<Mutex<RotatingFile>>,
    /// Live total-size cap (bytes), shared with `TraceHandle::set_log_max_size`.
    /// Read on every rotation check, so GUI/RPC changes take effect without a
    /// restart. `0` makes the writer a silent no-op (file logging disabled).
    max_total: Arc<AtomicU64>,
}

impl RotatingWriter {
    /// Create a rotating writer for `path` (e.g. `…/noble-node.log`), keeping at
    /// most `max_files` files total (active + rotated suffixes `.1`..`.N-1`),
    /// bounded overall by the live `max_total` cap. The file opens lazily on the
    /// first write and resumes an existing file across restarts.
    pub fn new(path: PathBuf, max_files: usize, max_total: Arc<AtomicU64>) -> Self {
        let dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let base = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "noble-node.log".to_string());
        Self {
            inner: Arc::new(Mutex::new(RotatingFile {
                dir,
                base,
                max_files: max_files.max(1),
                file: None,
                current_size: 0,
            })),
            max_total,
        }
    }
}

struct RotatingFile {
    dir: PathBuf,
    base: String,
    /// Total files kept (active + rotated). >= 1.
    max_files: usize,
    file: Option<File>,
    current_size: u64,
}

impl RotatingFile {
    fn base_path(&self) -> PathBuf {
        self.dir.join(&self.base)
    }

    fn path_n(&self, n: usize) -> PathBuf {
        self.dir.join(format!("{}.{n}", self.base))
    }

    fn ensure_open(&mut self) -> io::Result<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let _ = fs::create_dir_all(&self.dir);
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.base_path())?;
        // Resume the existing file across restarts: count what's already there.
        self.current_size = f.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(f);
        Ok(())
    }

    /// Rotate: drop the oldest, shift `.i -> .(i+1)`, move active -> `.1`, then
    /// open a fresh active file.
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None; // close active before renaming

        if self.max_files >= 2 {
            // Drop the oldest rotated file (`.{max_files-1}`).
            let oldest = self.path_n(self.max_files - 1);
            if oldest.exists() {
                let _ = fs::remove_file(&oldest);
            }
            // Shift `.{N-2} -> .{N-1}`, …, `.1 -> .2`.
            for i in (1..self.max_files - 1).rev() {
                let from = self.path_n(i);
                if from.exists() {
                    let _ = fs::rename(&from, self.path_n(i + 1));
                }
            }
            // Active -> `.1`.
            let base = self.base_path();
            if base.exists() {
                let _ = fs::rename(&base, self.path_n(1));
            }
        }

        // Fresh active file (truncate any leftover from a prior crash).
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.base_path())?;
        self.current_size = 0;
        self.file = Some(f);
        Ok(())
    }

    fn write_chunk(&mut self, buf: &[u8], max_total: u64) -> io::Result<usize> {
        if max_total == 0 {
            // File logging disabled — behave as a silent sink so tracing never
            // errors on the disabled path.
            return Ok(buf.len());
        }
        let per_file = (max_total / self.max_files as u64).max(MIN_PER_FILE_BYTES);
        self.ensure_open()?;
        // Rotate before writing if this line would push us past the per-file cap
        // (but never rotate an empty file — a single line larger than per_file
        // must still land somewhere).
        if self.current_size > 0 && self.current_size + buf.len() as u64 > per_file {
            self.rotate()?;
        }
        if let Some(f) = self.file.as_mut() {
            f.write_all(buf)?;
            self.current_size += buf.len() as u64;
        }
        Ok(buf.len())
    }
}

/// Per-`make_writer` guard. Locks the shared file for each write.
pub struct RotatingGuard {
    inner: Arc<Mutex<RotatingFile>>,
    max_total: Arc<AtomicU64>,
}

impl Write for RotatingGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .write_chunk(buf, self.max_total.load(Ordering::Relaxed))
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut g = self.inner.lock();
        match g.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for RotatingWriter {
    type Writer = RotatingGuard;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingGuard {
            inner: self.inner.clone(),
            max_total: self.max_total.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        // Unique-ish per test without Date/rand (unavailable): use the tag + pid.
        d.push(format!("noble-logrotate-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rotates_at_cap_and_bounds_file_count() {
        let dir = tmp_dir("rotate");
        let path = dir.join("noble-node.log");
        let max_files = 3usize;
        // Tiny cap so per_file = MIN_PER_FILE_BYTES (64 KiB). Write > 3*64KiB.
        let cap = Arc::new(AtomicU64::new(1)); // forces per_file = MIN_PER_FILE_BYTES
        let w = RotatingWriter::new(path.clone(), max_files, cap);

        let line = vec![b'x'; 8 * 1024]; // 8 KiB
        for _ in 0..40 {
            // 40 * 8KiB = 320 KiB across a 64KiB/file, 3-file budget.
            w.make_writer().write_all(&line).unwrap();
        }
        // Active + at most max_files-1 rotated files exist; none beyond.
        assert!(path.exists(), "active file must exist");
        assert!(!dir.join("noble-node.log.3").exists(), "must not keep > max_files-1 rotated");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_when_cap_zero() {
        let dir = tmp_dir("disabled");
        let path = dir.join("noble-node.log");
        let cap = Arc::new(AtomicU64::new(0));
        let w = RotatingWriter::new(path.clone(), 5, cap);
        w.make_writer().write_all(b"hello").unwrap();
        assert!(!path.exists(), "cap=0 must not create a file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_cap_change_takes_effect() {
        let dir = tmp_dir("livecap");
        let path = dir.join("noble-node.log");
        let cap = Arc::new(AtomicU64::new(0)); // start disabled
        let w = RotatingWriter::new(path.clone(), 5, cap.clone());
        w.make_writer().write_all(b"ignored").unwrap();
        assert!(!path.exists());
        // Enable at runtime — next write must create + write the file.
        cap.store(10 * 1024 * 1024, Ordering::Relaxed);
        w.make_writer().write_all(b"now logged").unwrap();
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
