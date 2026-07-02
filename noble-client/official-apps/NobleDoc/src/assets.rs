// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Embeds the shared WebUI at compile time and serves assets by path.
//!
//! Files are served individually through the `noble://` custom protocol
//! registered in `main.rs`, so the WebView resolves the WebUI's real
//! ES-module import graph — the same architecture as the Mac app's
//! `noble-app://` scheme handler. (The previous approach inlined a
//! hand-maintained list of JS files into one `<script>` block, which silently
//! broke whenever the shared WebUI gained a module.)

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_entry_modules_with_js_mime() {
        // The two module entry points index.html loads — if these disappear
        // from the embedded tree, the app cannot boot.
        for path in ["js/bridge.js", "js/app.js"] {
            let (bytes, mime) = serve_asset(path).unwrap_or_else(|| panic!("{path} missing"));
            assert!(!bytes.is_empty(), "{path} is empty");
            assert_eq!(mime, "application/javascript", "{path}");
        }
    }

    #[test]
    fn empty_and_slash_paths_fall_back_to_index() {
        for path in ["", "/"] {
            let (bytes, mime) = serve_asset(path).expect("index fallback");
            assert_eq!(mime, "text/html");
            let html = String::from_utf8_lossy(&bytes);
            assert!(html.contains("type=\"module\""), "index must load ES modules");
        }
    }

    #[test]
    fn unknown_path_returns_none() {
        assert!(serve_asset("js/does-not-exist.js").is_none());
    }

    #[test]
    fn every_module_imported_by_the_webui_is_embedded() {
        // Drift guard (replaces the old hardcoded bundle list failure mode):
        // every relative `import ... from './x.js'` inside the embedded JS must
        // resolve to an embedded file. Catches a stale snapshot at test time
        // instead of a runtime ReferenceError.
        fn collect<'a>(dir: &'a Dir<'a>, out: &mut Vec<&'a include_dir::File<'a>>) {
            for f in dir.files() {
                out.push(f);
            }
            for d in dir.dirs() {
                collect(d, out);
            }
        }
        let mut files = Vec::new();
        collect(&WEBUI_DIR, &mut files);

        let mut missing = Vec::new();
        for file in &files {
            let path = file.path().to_string_lossy().to_string();
            if !path.ends_with(".js") {
                continue;
            }
            let src = match std::str::from_utf8(file.contents()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let base_dir = std::path::Path::new(&path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new(""));
            for line in src.lines() {
                let t = line.trim_start();
                if !t.starts_with("import ") {
                    continue;
                }
                // Extract the module specifier between quotes.
                let spec = t
                    .split(&['\'', '"'][..])
                    .nth(1)
                    .unwrap_or("");
                if !spec.starts_with('.') {
                    continue; // bare/external specifier — not ours
                }
                // Resolve ./ and ../ against the importing file's directory.
                let mut resolved = base_dir.to_path_buf();
                for comp in std::path::Path::new(spec).components() {
                    match comp {
                        std::path::Component::ParentDir => {
                            resolved.pop();
                        }
                        std::path::Component::CurDir => {}
                        std::path::Component::Normal(c) => resolved.push(c),
                        _ => {}
                    }
                }
                let resolved = resolved.to_string_lossy().to_string();
                if WEBUI_DIR.get_file(&resolved).is_none() {
                    missing.push(format!("{path} imports {spec} → {resolved}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "embedded WebUI has unresolved imports:\n{}",
            missing.join("\n")
        );
    }
}
