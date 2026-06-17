// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared trace types used by the RPC trace methods.
//!
//! The actual tracing infrastructure lives in `noble-node::trace`.
//! This module defines the interface that the API layer uses.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;

use serde::{Deserialize, Serialize};

/// A single captured trace event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceRecord {
    pub timestamp: u64,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
    pub span_stack: Vec<String>,
}

/// Thread-safe ring buffer for trace records.
#[derive(Clone)]
pub struct TraceBuffer {
    inner: Arc<RwLock<BufferInner>>,
}

struct BufferInner {
    records: VecDeque<TraceRecord>,
    capacity: usize,
}

impl TraceBuffer {
    /// Create a new ring buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(BufferInner {
                records: VecDeque::with_capacity(capacity.min(1024)),
                capacity,
            })),
        }
    }

    /// Push a trace record, evicting the oldest if at capacity.
    pub fn push(&self, record: TraceRecord) {
        let mut inner = self.inner.write();
        if inner.records.len() >= inner.capacity {
            inner.records.pop_front();
        }
        inner.records.push_back(record);
    }

    /// Query the buffer.
    pub fn query(
        &self,
        last_n: Option<usize>,
        task_filter: Option<&str>,
        level_filter: Option<&str>,
    ) -> Vec<TraceRecord> {
        let inner = self.inner.read();

        let filtered: Vec<_> = inner
            .records
            .iter()
            .filter(|r| {
                if let Some(task) = task_filter {
                    if !r.fields.get("task").is_some_and(|t| t == task) {
                        return false;
                    }
                }
                if let Some(level) = level_filter {
                    if !r.level.eq_ignore_ascii_case(level) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        match last_n {
            Some(n) if n < filtered.len() => filtered[filtered.len() - n..].to_vec(),
            _ => filtered,
        }
    }

    /// Clear all records.
    pub fn clear(&self) {
        self.inner.write().records.clear();
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of records currently in the buffer.
    pub fn len(&self) -> usize {
        self.inner.read().records.len()
    }

    /// Maximum capacity.
    pub fn capacity(&self) -> usize {
        self.inner.read().capacity
    }
}

/// Type alias for the filter-swap callback.
type SetFilterFn = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Shared mutable state for trace session management (AUD4-F2).
struct TraceSessionState {
    /// Epoch seconds when the current trace session expires (0 = no session).
    expiry: std::sync::atomic::AtomicU64,
    /// Currently active filter string.
    current_filter: parking_lot::RwLock<String>,
}

/// Handle for runtime trace control — filter swapping and buffer access.
pub struct TraceHandle {
    /// The shared ring buffer.
    pub buffer: TraceBuffer,
    /// Callback to set a new filter at runtime.
    set_filter_fn: Arc<SetFilterFn>,
    /// Cancel token for the timer task.
    cancel_tx: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Default filter to revert to on expiry.
    default_filter: String,
    /// Shared session state (expiry + current filter) accessible from timer tasks.
    session: Arc<TraceSessionState>,
    /// Live maximum total size (bytes) for the rotating log file set. Shared
    /// with the rotating writer in `noble-node` so the GUI/RPC can change the
    /// cap without a restart (the writer reads it on each rotation check).
    /// `0` = file logging disabled / not configured.
    log_max_size: Arc<std::sync::atomic::AtomicU64>,
}

impl TraceHandle {
    /// Create a new trace handle with a filter-reload callback and a shared
    /// live log-size cap (the same `Arc` the rotating writer reads).
    pub fn new(
        buffer: TraceBuffer,
        default_filter: String,
        set_filter_fn: SetFilterFn,
        log_max_size: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        let current = default_filter.clone();
        Self {
            buffer,
            set_filter_fn: Arc::new(set_filter_fn),
            cancel_tx: parking_lot::Mutex::new(None),
            default_filter,
            session: Arc::new(TraceSessionState {
                expiry: std::sync::atomic::AtomicU64::new(0),
                current_filter: parking_lot::RwLock::new(current),
            }),
            log_max_size,
        }
    }

    /// Current maximum total log size in bytes (0 = file logging disabled).
    pub fn log_max_size(&self) -> u64 {
        self.log_max_size.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Update the maximum total log size (bytes) at runtime. Takes effect on the
    /// next rotation check; `0` is rejected to avoid silently disabling logging.
    /// Returns the value that was stored.
    pub fn set_log_max_size(&self, bytes: u64) -> u64 {
        self.log_max_size
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
        bytes
    }

    /// Change the tracing filter at runtime.
    pub fn set_filter(
        &self,
        filter_str: &str,
        duration: Option<std::time::Duration>,
    ) -> Result<(), String> {
        (self.set_filter_fn)(filter_str)?;

        // Track the currently active filter (AUD4-F2).
        *self.session.current_filter.write() = filter_str.to_string();

        // Cancel any existing timer
        {
            let mut cancel = self.cancel_tx.lock();
            if let Some(tx) = cancel.take() {
                let _ = tx.send(());
            }
        }

        if let Some(dur) = duration {
            let expiry_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + dur.as_secs();
            self.session
                .expiry
                .store(expiry_secs, std::sync::atomic::Ordering::Relaxed);

            let (tx, rx) = tokio::sync::oneshot::channel();
            {
                let mut cancel = self.cancel_tx.lock();
                *cancel = Some(tx);
            }

            // AUD4-F2: Auto-revert filter to default when session expires.
            let revert_fn = self.set_filter_fn.clone();
            let revert_filter = self.default_filter.clone();
            let session = self.session.clone();
            tokio::spawn(async move {
                let cancelled = tokio::select! {
                    _ = tokio::time::sleep(dur) => false,
                    _ = rx => true,
                };
                if !cancelled {
                    // Timer expired naturally — revert to default filter.
                    session
                        .expiry
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    if let Err(e) = (revert_fn)(&revert_filter) {
                        tracing::warn!(task = "trace_session", "failed to revert filter: {e}");
                    }
                    *session.current_filter.write() = revert_filter;
                    tracing::info!(
                        task = "trace_session",
                        "timed session expired — filter reverted to default"
                    );
                }
            });
        } else {
            self.session
                .expiry
                .store(0, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }

    /// Remaining seconds until expiry, or None if no session.
    pub fn remaining_seconds(&self) -> Option<u64> {
        let expiry = self
            .session
            .expiry
            .load(std::sync::atomic::Ordering::Relaxed);
        if expiry == 0 {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(expiry.saturating_sub(now))
    }

    /// Whether a timed session is active.
    pub fn is_session_active(&self) -> bool {
        self.remaining_seconds().is_some_and(|s| s > 0)
    }

    /// Current default filter string.
    pub fn default_filter(&self) -> &str {
        &self.default_filter
    }

    /// Currently active filter string (AUD4-F2).
    pub fn current_filter(&self) -> String {
        self.session.current_filter.read().clone()
    }
}
