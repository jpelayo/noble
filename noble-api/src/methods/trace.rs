// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Trace RPC methods: setTraceFilter, getTraceBuffer, clearTraceBuffer, getTraceStatus.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::trace_types::TraceRecord;

/// Valid duration options in minutes.
const VALID_DURATIONS: &[u64] = &[1, 5, 15, 30, 60, 120, 360, 720, 1440];

#[derive(Debug, Deserialize)]
pub struct SetTraceParams {
    /// Filter directive string (e.g. "trace", "noble_core=debug,info").
    pub filter: String,
    /// Optional duration in minutes. Session auto-reverts when expired.
    pub duration_minutes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetTraceResponse {
    pub active: bool,
    pub filter: String,
    pub expires_at: Option<u64>,
    pub remaining_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TraceQueryParams {
    /// Return only the last N entries.
    pub last_n: Option<usize>,
    /// Filter by task field value.
    pub task: Option<String>,
    /// Filter by log level.
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceBufferResponse {
    pub entries: Vec<TraceRecord>,
    pub total_in_buffer: usize,
    pub capacity: usize,
    pub current_filter: String,
    pub session_active: bool,
    pub remaining_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceStatusResponse {
    pub session_active: bool,
    pub remaining_seconds: Option<u64>,
    pub buffer_size: usize,
    pub buffer_capacity: usize,
    pub default_filter: String,
}

#[rpc(server, namespace = "noble")]
pub trait TraceApi {
    /// Set the tracing filter. Requires admin auth.
    #[method(name = "setTraceFilter")]
    async fn set_trace_filter(
        &self,
        params: SetTraceParams,
    ) -> Result<SetTraceResponse, ErrorObjectOwned>;

    /// Query the trace buffer. Requires admin auth.
    #[method(name = "getTraceBuffer")]
    async fn get_trace_buffer(
        &self,
        params: TraceQueryParams,
    ) -> Result<TraceBufferResponse, ErrorObjectOwned>;

    /// Clear the trace buffer. Requires admin auth.
    #[method(name = "clearTraceBuffer")]
    async fn clear_trace_buffer(&self) -> Result<bool, ErrorObjectOwned>;

    /// Get trace session status. Requires admin auth.
    #[method(name = "getTraceStatus")]
    async fn get_trace_status(&self) -> Result<TraceStatusResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> TraceApiServer for Arc<ApiState<S>> {
    async fn set_trace_filter(
        &self,
        params: SetTraceParams,
    ) -> Result<SetTraceResponse, ErrorObjectOwned> {
        let handle = self.trace_handle.as_ref().ok_or_else(|| {
            ErrorObjectOwned::from(ApiError::Internal("tracing not initialized".to_string()))
        })?;

        // Validate duration if provided
        let duration = if let Some(mins) = params.duration_minutes {
            if !VALID_DURATIONS.contains(&mins) {
                return Err(ApiError::InvalidParam(format!(
                    "invalid duration_minutes: {mins}. Valid: {VALID_DURATIONS:?}"
                ))
                .into());
            }
            Some(std::time::Duration::from_secs(mins * 60))
        } else {
            None
        };

        handle
            .set_filter(&params.filter, duration)
            .map_err(|e| ErrorObjectOwned::from(ApiError::InvalidParam(e)))?;

        Ok(SetTraceResponse {
            active: handle.is_session_active(),
            filter: params.filter,
            expires_at: handle.remaining_seconds().map(|r| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + r
            }),
            remaining_seconds: handle.remaining_seconds(),
        })
    }

    async fn get_trace_buffer(
        &self,
        params: TraceQueryParams,
    ) -> Result<TraceBufferResponse, ErrorObjectOwned> {
        let handle = self.trace_handle.as_ref().ok_or_else(|| {
            ErrorObjectOwned::from(ApiError::Internal("tracing not initialized".to_string()))
        })?;

        let entries = handle.buffer.query(
            params.last_n,
            params.task.as_deref(),
            params.level.as_deref(),
        );

        Ok(TraceBufferResponse {
            entries,
            total_in_buffer: handle.buffer.len(),
            capacity: handle.buffer.capacity(),
            current_filter: handle.default_filter().to_string(),
            session_active: handle.is_session_active(),
            remaining_seconds: handle.remaining_seconds(),
        })
    }

    async fn clear_trace_buffer(&self) -> Result<bool, ErrorObjectOwned> {
        let handle = self.trace_handle.as_ref().ok_or_else(|| {
            ErrorObjectOwned::from(ApiError::Internal("tracing not initialized".to_string()))
        })?;

        handle.buffer.clear();
        Ok(true)
    }

    async fn get_trace_status(&self) -> Result<TraceStatusResponse, ErrorObjectOwned> {
        let handle = self.trace_handle.as_ref().ok_or_else(|| {
            ErrorObjectOwned::from(ApiError::Internal("tracing not initialized".to_string()))
        })?;

        Ok(TraceStatusResponse {
            session_active: handle.is_session_active(),
            remaining_seconds: handle.remaining_seconds(),
            buffer_size: handle.buffer.len(),
            buffer_capacity: handle.buffer.capacity(),
            default_filter: handle.default_filter().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_durations_sorted() {
        for pair in VALID_DURATIONS.windows(2) {
            assert!(pair[0] < pair[1], "VALID_DURATIONS should be sorted");
        }
    }

    #[test]
    fn set_trace_params_deserializes() {
        let json = r#"{"filter":"trace","duration_minutes":5}"#;
        let params: SetTraceParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.filter, "trace");
        assert_eq!(params.duration_minutes, Some(5));
    }

    #[test]
    fn trace_query_params_optional_fields() {
        let json = r#"{"last_n":10}"#;
        let params: TraceQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.last_n, Some(10));
        assert!(params.task.is_none());
        assert!(params.level.is_none());
    }
}
