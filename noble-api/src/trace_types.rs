// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared trace types used by the RPC trace methods.
//!
//! The actual tracing infrastructure lives in `noble-node::trace`.
//! This module defines the interface that the API layer uses.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};

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
        if let Ok(mut inner) = self.inner.write() {
            if inner.records.len() >= inner.capacity {
                inner.records.pop_front();
            }
            inner.records.push_back(record);
        }
    }

    /// Query the buffer.
    pub fn query(
        &self,
        last_n: Option<usize>,
        task_filter: Option<&str>,
        level_filter: Option<&str>,
    ) -> Vec<TraceRecord> {
        let inner = match self.inner.read() {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };

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
        if let Ok(mut inner) = self.inner.write() {
            inner.records.clear();
        }
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of records currently in the buffer.
    pub fn len(&self) -> usize {
        self.inner.read().map(|i| i.records.len()).unwrap_or(0)
    }

    /// Maximum capacity.
    pub fn capacity(&self) -> usize {
        self.inner.read().map(|i| i.capacity).unwrap_or(0)
    }
}

/// Type alias for the filter-swap callback.
type SetFilterFn = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Handle for runtime trace control — filter swapping and buffer access.
pub struct TraceHandle {
    /// The shared ring buffer.
    pub buffer: TraceBuffer,
    /// Callback to set a new filter at runtime.
    set_filter_fn: SetFilterFn,
    /// Epoch seconds when the current trace session expires (0 = no session).
    expiry: std::sync::atomic::AtomicU64,
    /// Cancel token for the timer task.
    cancel_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Default filter to revert to on expiry.
    default_filter: String,
}

impl TraceHandle {
    /// Create a new trace handle with a filter-reload callback.
    pub fn new(buffer: TraceBuffer, default_filter: String, set_filter_fn: SetFilterFn) -> Self {
        Self {
            buffer,
            set_filter_fn,
            expiry: std::sync::atomic::AtomicU64::new(0),
            cancel_tx: std::sync::Mutex::new(None),
            default_filter,
        }
    }

    /// Change the tracing filter at runtime.
    pub fn set_filter(
        &self,
        filter_str: &str,
        duration: Option<std::time::Duration>,
    ) -> Result<(), String> {
        (self.set_filter_fn)(filter_str)?;

        // Cancel any existing timer
        if let Ok(mut cancel) = self.cancel_tx.lock() {
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
            self.expiry
                .store(expiry_secs, std::sync::atomic::Ordering::Relaxed);

            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Ok(mut cancel) = self.cancel_tx.lock() {
                *cancel = Some(tx);
            }

            // Spawn a timer that zeros the expiry on completion.
            // The filter is not automatically reverted — callers should check
            // is_session_active() and call set_filter() to revert if needed.
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(dur) => {}
                    _ = rx => {}
                }
            });
        } else {
            self.expiry.store(0, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }

    /// Remaining seconds until expiry, or None if no session.
    pub fn remaining_seconds(&self) -> Option<u64> {
        let expiry = self.expiry.load(std::sync::atomic::Ordering::Relaxed);
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
}
