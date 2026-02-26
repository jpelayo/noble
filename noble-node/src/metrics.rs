// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for the NOBLE node.
//!
//! Defines [`NobleMetrics`] with 10 gauges/histograms that expose chain state,
//! peer counts, mempool size, consensus phase, RPC latency, and storage stats.
//! A lightweight HTTP server on the configured `prometheus_addr` serves the
//! standard Prometheus text exposition format at `/metrics`.

use prometheus::{
    Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};

/// Prometheus metrics collector for a NOBLE node.
///
/// All metrics are registered in a dedicated [`Registry`] (not the global one)
/// so tests and multiple instances do not collide.
#[derive(Clone)]
pub struct NobleMetrics {
    pub registry: Registry,
    /// Current chain tip height.
    pub chain_height: Gauge,
    /// Number of connected P2P peers.
    pub connected_peers: Gauge,
    /// Number of transactions in the mempool.
    pub mempool_size: Gauge,
    /// Total byte size of mempool transactions (approximate).
    pub mempool_bytes: Gauge,
    /// Current consensus cycle phase (0 = Idle, 1 = Proposal, 2 = Voting).
    pub cycle_phase: Gauge,
    /// Seconds elapsed in the current consensus cycle.
    pub cycle_elapsed_secs: Gauge,
    /// Duration histogram for block validation (seconds).
    pub block_validation_duration: Histogram,
    /// Duration histogram for RPC request handling, keyed by method name.
    pub rpc_request_duration: HistogramVec,
    /// Estimated on-disk storage size in bytes (per column family).
    pub storage_size_bytes: GaugeVec,
    /// Total circulating supply in atomic units.
    pub total_supply_atomic: Gauge,
}

impl Default for NobleMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl NobleMetrics {
    /// Create and register all metrics in a new registry.
    pub fn new() -> Self {
        let registry = Registry::new();

        let chain_height =
            Gauge::with_opts(Opts::new("noble_chain_height", "Current chain tip height"))
                .expect("metric");
        let connected_peers = Gauge::with_opts(Opts::new(
            "noble_connected_peers",
            "Number of connected P2P peers",
        ))
        .expect("metric");
        let mempool_size = Gauge::with_opts(Opts::new(
            "noble_mempool_size",
            "Number of transactions in the mempool",
        ))
        .expect("metric");
        let mempool_bytes = Gauge::with_opts(Opts::new(
            "noble_mempool_bytes",
            "Approximate mempool byte size",
        ))
        .expect("metric");
        let cycle_phase = Gauge::with_opts(Opts::new(
            "noble_cycle_phase",
            "Current consensus cycle phase (0=Idle, 1=Proposal, 2=Voting)",
        ))
        .expect("metric");
        let cycle_elapsed_secs = Gauge::with_opts(Opts::new(
            "noble_cycle_elapsed_secs",
            "Seconds elapsed in the current consensus cycle",
        ))
        .expect("metric");

        let block_validation_duration = Histogram::with_opts(
            HistogramOpts::new(
                "noble_block_validation_duration_seconds",
                "Block validation duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
        )
        .expect("metric");

        let rpc_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "noble_rpc_request_duration_seconds",
                "RPC request duration in seconds",
            )
            .buckets(vec![
                0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
            ]),
            &["method"],
        )
        .expect("metric");

        let storage_size_bytes = GaugeVec::new(
            Opts::new(
                "noble_storage_size_bytes",
                "On-disk storage size by column family",
            ),
            &["cf"],
        )
        .expect("metric");

        let total_supply_atomic = Gauge::with_opts(Opts::new(
            "noble_total_supply_atomic",
            "Total circulating supply in atomic units",
        ))
        .expect("metric");

        // Register all metrics.
        registry
            .register(Box::new(chain_height.clone()))
            .expect("register");
        registry
            .register(Box::new(connected_peers.clone()))
            .expect("register");
        registry
            .register(Box::new(mempool_size.clone()))
            .expect("register");
        registry
            .register(Box::new(mempool_bytes.clone()))
            .expect("register");
        registry
            .register(Box::new(cycle_phase.clone()))
            .expect("register");
        registry
            .register(Box::new(cycle_elapsed_secs.clone()))
            .expect("register");
        registry
            .register(Box::new(block_validation_duration.clone()))
            .expect("register");
        registry
            .register(Box::new(rpc_request_duration.clone()))
            .expect("register");
        registry
            .register(Box::new(storage_size_bytes.clone()))
            .expect("register");
        registry
            .register(Box::new(total_supply_atomic.clone()))
            .expect("register");

        Self {
            registry,
            chain_height,
            connected_peers,
            mempool_size,
            mempool_bytes,
            cycle_phase,
            cycle_elapsed_secs,
            block_validation_duration,
            rpc_request_duration,
            storage_size_bytes,
            total_supply_atomic,
        }
    }

    /// Encode all registered metrics to Prometheus text format.
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("encode");
        String::from_utf8(buffer).expect("utf8")
    }
}

/// Start a lightweight HTTP server that serves `/metrics` in Prometheus text format.
///
/// Binds to `addr` (e.g. `"127.0.0.1:8786"`) and serves `GET /metrics`.
/// Returns a `JoinHandle` so the caller can manage the task.
pub async fn start_metrics_server(
    addr: &str,
    metrics: NobleMetrics,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let socket_addr: std::net::SocketAddr = addr.parse()?;
    let metrics = std::sync::Arc::new(metrics);

    let metrics_clone = metrics.clone();
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let m = metrics_clone.clone();
            async move {
                let body = m.encode();
                (
                    axum::http::StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    body,
                )
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind(socket_addr).await?;
    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Metrics server error: {e}");
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_creation_registers_all() {
        let m = NobleMetrics::new();

        // Touch labeled metrics so they appear in gather().
        m.rpc_request_duration
            .with_label_values(&["init"])
            .observe(0.0);
        m.storage_size_bytes.with_label_values(&["init"]).set(0.0);

        let families = m.registry.gather();
        let names: Vec<&str> = families.iter().map(|f| f.get_name()).collect();

        assert!(
            names.contains(&"noble_chain_height"),
            "missing chain_height"
        );
        assert!(
            names.contains(&"noble_connected_peers"),
            "missing connected_peers"
        );
        assert!(
            names.contains(&"noble_mempool_size"),
            "missing mempool_size"
        );
        assert!(
            names.contains(&"noble_mempool_bytes"),
            "missing mempool_bytes"
        );
        assert!(names.contains(&"noble_cycle_phase"), "missing cycle_phase");
        assert!(
            names.contains(&"noble_cycle_elapsed_secs"),
            "missing cycle_elapsed_secs"
        );
        assert!(
            names.contains(&"noble_block_validation_duration_seconds"),
            "missing block_validation"
        );
        assert!(
            names.contains(&"noble_rpc_request_duration_seconds"),
            "missing rpc_duration"
        );
        assert!(
            names.contains(&"noble_storage_size_bytes"),
            "missing storage_size"
        );
        assert!(
            names.contains(&"noble_total_supply_atomic"),
            "missing total_supply"
        );
    }

    #[test]
    fn metrics_encode_produces_text() {
        let m = NobleMetrics::new();
        m.chain_height.set(42.0);
        m.connected_peers.set(5.0);
        m.mempool_size.set(100.0);

        let text = m.encode();
        assert!(text.contains("noble_chain_height 42"));
        assert!(text.contains("noble_connected_peers 5"));
        assert!(text.contains("noble_mempool_size 100"));
    }

    #[test]
    fn metrics_histogram_records() {
        let m = NobleMetrics::new();
        m.block_validation_duration.observe(0.015);
        m.block_validation_duration.observe(0.042);

        let text = m.encode();
        assert!(text.contains("noble_block_validation_duration_seconds_count 2"));
    }

    #[test]
    fn metrics_rpc_duration_by_method() {
        let m = NobleMetrics::new();
        m.rpc_request_duration
            .with_label_values(&["getBlockCount"])
            .observe(0.002);
        m.rpc_request_duration
            .with_label_values(&["submitTransaction"])
            .observe(0.05);

        let text = m.encode();
        assert!(text.contains("method=\"getBlockCount\""));
        assert!(text.contains("method=\"submitTransaction\""));
    }

    #[test]
    fn metrics_storage_size_by_cf() {
        let m = NobleMetrics::new();
        m.storage_size_bytes
            .with_label_values(&["blocks"])
            .set(1024.0);
        m.storage_size_bytes
            .with_label_values(&["transactions"])
            .set(2048.0);

        let text = m.encode();
        assert!(text.contains("cf=\"blocks\""));
        assert!(text.contains("cf=\"transactions\""));
    }

    #[test]
    fn metrics_clone_shares_state() {
        let m1 = NobleMetrics::new();
        let m2 = m1.clone();

        m1.chain_height.set(99.0);
        // Both clones share the same underlying counter.
        assert_eq!(m2.chain_height.get(), 99.0);
    }

    #[tokio::test]
    async fn metrics_server_serves_text() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let m = NobleMetrics::new();
        m.chain_height.set(123.0);

        // Bind to a random port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = std::sync::Arc::new(m.clone());
        let metrics_clone = metrics.clone();
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let m = metrics_clone.clone();
                async move { m.encode() }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Fetch metrics via raw TCP.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET /metrics HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("noble_chain_height 123"), "body: {text}");
    }
}
