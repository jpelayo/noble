// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Runtime tracing system — `tracing_subscriber::Layer` that captures events
//! into a `noble_api::trace_types::TraceBuffer` ring buffer.
//!
//! The buffer and handle types live in `noble_api::trace_types` so that both
//! `noble-node` (subscriber setup) and `noble-api` (RPC methods) can access them.

use std::collections::BTreeMap;
use std::sync::Arc;

use noble_api::trace_types::{TraceBuffer, TraceHandle, TraceRecord};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// A `tracing_subscriber::Layer` that captures events into a `TraceBuffer`.
pub struct RamBufferLayer {
    buffer: TraceBuffer,
}

impl RamBufferLayer {
    /// Create a new layer backed by the given buffer.
    pub fn new(buffer: TraceBuffer) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for RamBufferLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = event.metadata();
        let level = metadata.level().to_string();
        let target = metadata.target().to_string();

        // Extract fields
        let mut fields = BTreeMap::new();
        let mut visitor = FieldVisitor {
            fields: &mut fields,
        };
        event.record(&mut visitor);

        // Extract message from the "message" field
        let message = fields.remove("message").unwrap_or_default();

        // Build span stack
        let mut span_stack = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                span_stack.push(span.name().to_string());
                // Extract span fields
                let extensions = span.extensions();
                if let Some(span_fields) = extensions.get::<SpanFields>() {
                    for (k, v) in &span_fields.0 {
                        fields.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
        }
        span_stack.reverse();

        self.buffer.push(TraceRecord {
            timestamp: now,
            level,
            target,
            message,
            fields,
            span_stack,
        });
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let span = ctx.span(id).expect("span not found");
        let mut fields = BTreeMap::new();
        let mut visitor = FieldVisitor {
            fields: &mut fields,
        };
        attrs.record(&mut visitor);
        span.extensions_mut().insert(SpanFields(fields));
    }
}

/// Storage for span fields attached via extensions.
struct SpanFields(BTreeMap<String, String>);

/// Visitor that collects event/span fields into a BTreeMap.
struct FieldVisitor<'a> {
    fields: &'a mut BTreeMap<String, String>,
}

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
}

/// Configuration for the tracing system.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Maximum number of records in the ring buffer.
    pub buffer_capacity: usize,
    /// Initial filter directive string.
    pub initial_filter: String,
    /// Whether to also output to stderr.
    pub stderr_enabled: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 50_000,
            initial_filter: "info".to_string(),
            stderr_enabled: false,
        }
    }
}

/// Initialize the tracing system and return a `TraceHandle` for runtime control.
///
/// This should be called once at startup, before any other tracing calls.
pub fn init_tracing(config: &TraceConfig) -> Arc<TraceHandle> {
    use tracing_subscriber::prelude::*;

    let buffer = TraceBuffer::new(config.buffer_capacity);
    let buffer_layer = RamBufferLayer::new(buffer.clone());

    let initial_filter = tracing_subscriber::filter::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::filter::EnvFilter::new(&config.initial_filter));

    let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(initial_filter);

    // Create the set_filter closure
    #[allow(clippy::type_complexity)]
    let set_filter_fn: Box<dyn Fn(&str) -> Result<(), String> + Send + Sync> =
        Box::new(move |filter_str: &str| {
            let filter = tracing_subscriber::filter::EnvFilter::try_new(filter_str)
                .map_err(|e| format!("invalid filter '{filter_str}': {e}"))?;
            reload_handle
                .reload(filter)
                .map_err(|e| format!("reload filter: {e}"))
        });

    if config.stderr_enabled {
        let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(buffer_layer)
            .with(fmt_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(buffer_layer)
            .init();
    }

    Arc::new(TraceHandle::new(
        buffer,
        config.initial_filter.clone(),
        set_filter_fn,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_capacity_eviction() {
        let buf = TraceBuffer::new(3);
        for i in 0..5 {
            buf.push(TraceRecord {
                timestamp: i,
                level: "INFO".into(),
                target: "test".into(),
                message: format!("msg-{i}"),
                fields: BTreeMap::new(),
                span_stack: vec![],
            });
        }
        assert_eq!(buf.len(), 3);
        let records = buf.query(None, None, None);
        assert_eq!(records[0].message, "msg-2");
        assert_eq!(records[2].message, "msg-4");
    }

    #[test]
    fn query_with_task_filter() {
        let buf = TraceBuffer::new(100);
        for i in 0..10u64 {
            let mut fields = BTreeMap::new();
            if i % 2 == 0 {
                fields.insert("task".into(), "consensus".into());
            }
            buf.push(TraceRecord {
                timestamp: i,
                level: "DEBUG".into(),
                target: "test".into(),
                message: format!("msg-{i}"),
                fields,
                span_stack: vec![],
            });
        }
        let all = buf.query(None, None, None);
        assert_eq!(all.len(), 10);
        let consensus_only = buf.query(None, Some("consensus"), None);
        assert_eq!(consensus_only.len(), 5);
    }

    #[test]
    fn query_last_n() {
        let buf = TraceBuffer::new(100);
        for i in 0..20u64 {
            buf.push(TraceRecord {
                timestamp: i,
                level: "TRACE".into(),
                target: "test".into(),
                message: format!("msg-{i}"),
                fields: BTreeMap::new(),
                span_stack: vec![],
            });
        }
        let last5 = buf.query(Some(5), None, None);
        assert_eq!(last5.len(), 5);
        assert_eq!(last5[0].message, "msg-15");
        assert_eq!(last5[4].message, "msg-19");
    }

    #[test]
    fn clear_empties_buffer() {
        let buf = TraceBuffer::new(100);
        buf.push(TraceRecord {
            timestamp: 1,
            level: "INFO".into(),
            target: "test".into(),
            message: "hello".into(),
            fields: BTreeMap::new(),
            span_stack: vec![],
        });
        assert_eq!(buf.len(), 1);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.query(None, None, None).is_empty());
    }

    #[test]
    fn concurrent_push_and_query() {
        use std::thread;

        let buf = TraceBuffer::new(1000);
        let buf_clone = buf.clone();

        let writer = thread::spawn(move || {
            for i in 0..500u64 {
                buf_clone.push(TraceRecord {
                    timestamp: i,
                    level: "TRACE".into(),
                    target: "test".into(),
                    message: format!("msg-{i}"),
                    fields: BTreeMap::new(),
                    span_stack: vec![],
                });
            }
        });

        // Concurrent reads should not panic
        for _ in 0..50 {
            let _ = buf.query(Some(10), None, None);
            let _ = buf.len();
        }

        writer.join().unwrap();
        assert!(buf.len() <= 1000);
        assert!(!buf.is_empty());
    }

    #[test]
    fn query_with_level_filter() {
        let buf = TraceBuffer::new(100);
        for (i, level) in ["INFO", "DEBUG", "WARN", "ERROR", "TRACE"]
            .iter()
            .enumerate()
        {
            buf.push(TraceRecord {
                timestamp: i as u64,
                level: level.to_string(),
                target: "test".into(),
                message: format!("msg-{level}"),
                fields: BTreeMap::new(),
                span_stack: vec![],
            });
        }
        let warns = buf.query(None, None, Some("WARN"));
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0].message, "msg-WARN");
    }
}
