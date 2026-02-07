// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared test utilities, fixture builders and helpers for NOBLE protocol integration tests.
//!
//! This crate provides:
//! - Test fixture builders for transactions, blocks, and headers
//! - Temporary directory helpers for storage tests
//! - Common test assertions for validation results

pub mod fixtures;
pub mod tmpdir;

/// Re-export tempfile for convenience in integration tests.
pub use tempfile;
