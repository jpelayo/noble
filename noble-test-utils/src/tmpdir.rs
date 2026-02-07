// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Temporary directory helpers for storage and file-based tests.
//!
//! Wraps `tempfile::TempDir` with NOBLE-specific convenience methods.
//! Stubs — will be extended when noble-storage is implemented in Sprint 2.

use tempfile::TempDir;

/// Create a temporary directory for a storage test.
/// The directory is automatically cleaned up when the returned `TempDir` is dropped.
pub fn test_data_dir() -> TempDir {
    tempfile::tempdir().expect("failed to create temporary test directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_dir_is_created_and_writable() {
        let dir = test_data_dir();
        assert!(dir.path().exists());
        assert!(dir.path().is_dir());
    }
}
