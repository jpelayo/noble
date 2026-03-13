// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Embeds the shared WebUI at compile time and serves assets by path.

use include_dir::{include_dir, Dir};

/// The entire WebUI directory embedded at compile time.
static WEBUI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../noble-client-libraries/WebUI");

/// Serve an embedded WebUI asset by relative path.
///
/// Returns `(file_bytes, mime_type)` or `None` if the file doesn't exist.
pub fn serve_asset(path: &str) -> Option<(Vec<u8>, String)> {
    // Strip leading slash if present
    let clean_path = path.strip_prefix('/').unwrap_or(path);

    // Default to index.html for empty path
    let file_path = if clean_path.is_empty() {
        "index.html"
    } else {
        clean_path
    };

    let file = WEBUI_DIR.get_file(file_path)?;
    let bytes = file.contents().to_vec();
    let mime = mime_for_extension(file_path);

    Some((bytes, mime))
}

/// Determine MIME type from file extension.
fn mime_for_extension(path: &str) -> String {
    let ext = path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "xml" => "application/xml",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}
