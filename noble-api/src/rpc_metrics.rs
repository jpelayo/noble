// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-method RPC latency middleware using jsonrpsee's [`RpcServiceT`].
//!
//! Records `noble_rpc_request_duration_seconds{method="..."}` for every
//! JSON-RPC call handled by the server. Integrates with the Prometheus
//! [`HistogramVec`] created in `noble-node::metrics::NobleMetrics`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use jsonrpsee::core::server::MethodResponse;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::Request;
use prometheus::HistogramVec;

/// A jsonrpsee RPC middleware that records per-method latency.
///
/// When `histogram` is `None`, the middleware is a zero-cost pass-through.
#[derive(Clone)]
pub struct MetricsMiddleware<S> {
    inner: S,
    histogram: Option<Arc<HistogramVec>>,
}

impl<S> MetricsMiddleware<S> {
    /// Create a new metrics middleware wrapping `inner`.
    ///
    /// Pass `None` to disable instrumentation (pass-through mode).
    pub fn new(inner: S, histogram: Option<Arc<HistogramVec>>) -> Self {
        Self { inner, histogram }
    }
}

impl<'a, S> RpcServiceT<'a> for MetricsMiddleware<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>;

    fn call(&self, request: Request<'a>) -> Self::Future {
        let histogram = self.histogram.clone();
        let inner = self.inner.clone();

        if histogram.is_none() {
            // Fast path: no metrics configured, just forward.
            return Box::pin(async move { inner.call(request).await });
        }

        // M13: bucket unrecognised method names.
        //
        // The raw name went straight into a Prometheus label, so every
        // misspelled or invented method minted a NEW, PERMANENT time series —
        // unbounded cardinality driven by whatever a caller types, and the
        // metrics endpoint is reachable before auth. Known methods keep their
        // own series; everything else collapses to one bucket.
        let raw = request.method_name();
        let method: String = if crate::middleware::is_known_method(raw) {
            raw.to_owned()
        } else {
            "other".to_string()
        };
        Box::pin(async move {
            let start = std::time::Instant::now();
            let response = inner.call(request).await;
            if let Some(ref h) = histogram {
                h.with_label_values(&[&method])
                    .observe(start.elapsed().as_secs_f64());
            }
            response
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{HistogramOpts, HistogramVec};

    fn make_histogram() -> Arc<HistogramVec> {
        Arc::new(
            HistogramVec::new(HistogramOpts::new("test_rpc_duration", "test"), &["method"])
                .unwrap(),
        )
    }

    /// Dummy RPC service for testing.
    #[derive(Clone)]
    struct DummyRpcService;

    impl<'a> RpcServiceT<'a> for DummyRpcService {
        type Future = Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>;

        fn call(&self, _request: Request<'a>) -> Self::Future {
            Box::pin(async {
                MethodResponse::response(
                    jsonrpsee::types::Id::Null,
                    jsonrpsee::types::ResponsePayload::success("ok").into(),
                    128,
                )
            })
        }
    }

    /// Create a test JSON-RPC request from a method name.
    fn make_request(json_str: &str) -> Request<'_> {
        serde_json::from_str(json_str).unwrap()
    }

    #[tokio::test]
    async fn metrics_middleware_records_duration() {
        let histogram = make_histogram();
        let mw = MetricsMiddleware::new(DummyRpcService, Some(histogram.clone()));

        let json = r#"{"jsonrpc":"2.0","method":"noble_getBlockCount","id":1}"#;
        let req = make_request(json);
        let _resp = mw.call(req).await;

        let metric = histogram.with_label_values(&["noble_getBlockCount"]);
        let count = metric.get_sample_count();
        assert_eq!(count, 1, "should have recorded exactly one observation");
        assert!(metric.get_sample_sum() > 0.0, "sum should be positive");
    }

    #[tokio::test]
    async fn metrics_middleware_records_multiple_methods() {
        let histogram = make_histogram();
        let mw = MetricsMiddleware::new(DummyRpcService, Some(histogram.clone()));

        let jsons = [
            r#"{"jsonrpc":"2.0","method":"noble_getBlockCount","id":1}"#,
            r#"{"jsonrpc":"2.0","method":"noble_submitTransaction","id":2}"#,
            r#"{"jsonrpc":"2.0","method":"noble_getBlockCount","id":3}"#,
        ];
        for json in &jsons {
            let req = make_request(json);
            let _resp = mw.call(req).await;
        }

        assert_eq!(
            histogram
                .with_label_values(&["noble_getBlockCount"])
                .get_sample_count(),
            2
        );
        assert_eq!(
            histogram
                .with_label_values(&["noble_submitTransaction"])
                .get_sample_count(),
            1
        );
    }

    #[tokio::test]
    async fn metrics_middleware_none_is_passthrough() {
        let mw = MetricsMiddleware::new(DummyRpcService, None);

        let json = r#"{"jsonrpc":"2.0","method":"noble_getBlockCount","id":1}"#;
        let req = make_request(json);
        let resp = mw.call(req).await;
        // Should still produce a valid response even without metrics.
        assert!(resp.is_success());
    }
}
