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

/// Serve index.html with init scripts injected into `<head>`.
///
/// WRY's `with_initialization_script` only works with custom protocol URLs,
/// not plain `http://` URLs.  We inject the scripts directly into the HTML
/// so they execute regardless of how the page is loaded.
/// Build a fully self-contained HTML page with ALL assets inlined.
///
/// CSS is inlined as a `<style>` block, all JS modules are concatenated
/// into a single `<script>` block (with `export`/`import` statements stripped),
/// and the init script (webkit shim + NativeConfig) is prepended.
///
/// This avoids all cross-origin/ATS/CSP issues: WRY's `with_html` loads
/// everything from `about:blank` with no external resource fetches.
pub fn build_self_contained_html(init_script: &str) -> String {
    // 1. Read CSS
    let css = WEBUI_DIR
        .get_file("css/noble.css")
        .and_then(|f| std::str::from_utf8(f.contents()).ok())
        .unwrap_or("");

    // 2. Collect all JS files in dependency order.
    //    Components and utils first, then pages, then bridge, then app (entry).
    let js_order = [
        "js/utils.js",
        "js/components/empty-state.js",
        "js/components/noble-card.js",
        "js/components/hash-text.js",
        "js/components/amount-text.js",
        "js/components/status-badge.js",
        "js/components/modal.js",
        "js/components/qr-code.js",
        "js/components/contact-card.js",
        "js/pages/home.js",
        "js/pages/documents.js",
        "js/pages/drafts.js",
        "js/pages/verify.js",
        "js/pages/payments.js",
        "js/pages/contacts.js",
        "js/pages/settings.js",
        "js/pages/faucet.js",
        "js/bridge.js",
        "js/app.js",
    ];

    let mut js_bundle = String::new();
    for path in &js_order {
        if let Some(file) = WEBUI_DIR.get_file(path) {
            if let Ok(src) = std::str::from_utf8(file.contents()) {
                js_bundle.push_str(&format!("\n// --- {path} ---\n"));

                // Derive a unique prefix from the file name for disambiguation.
                // e.g. "js/pages/home.js" → "Home", "js/components/empty-state.js" → "EmptyState"
                let stem = path.rsplit('/').next().unwrap_or(path)
                    .strip_suffix(".js").unwrap_or(path);
                let prefix: String = stem.split('-').map(|part| {
                    let mut c = part.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                    }
                }).collect();

                let is_page = path.contains("/pages/");
                let is_bridge = *path == "js/bridge.js";
                let is_app = *path == "js/app.js";

                // Wrap each module in an IIFE for scope isolation (avoids duplicate
                // const/let declarations across modules).  Page init functions and
                // key globals (Bridge, NativeBridge, App) are hoisted to window.
                let mut body = String::new();
                for line in src.lines() {
                    let trimmed = line.trim_start();

                    // Skip import/re-export lines.
                    if trimmed.starts_with("import ")
                        || trimmed.starts_with("export {")
                        || trimmed.starts_with("export default")
                    {
                        continue;
                    }

                    // Page files: rename "export function init(" to unique name.
                    if is_page && trimmed.starts_with("export function init(") {
                        body.push_str(&line.replacen(
                            "export function init(",
                            &format!("window.init{prefix} = function("),
                            1,
                        ));
                        body.push('\n');
                        continue;
                    }

                    // Strip "export " keyword.
                    if trimmed.starts_with("export ") {
                        body.push_str(&line.replacen("export ", "", 1));
                    } else {
                        body.push_str(line);
                    }
                    body.push('\n');
                }

                // Collect names of exported functions/consts/classes to hoist to window.
                let mut exports: Vec<String> = Vec::new();
                for line in body.lines() {
                    let t = line.trim_start();
                    // "function foo(" or "class Foo" or "const foo ="
                    // These came from "export function foo(" etc. after stripping "export ".
                    // Page init functions are already "window.initFoo = function(..." so skip those.
                    if t.starts_with("window.init") { continue; }
                    if let Some(rest) = t.strip_prefix("function ") {
                        if let Some(name) = rest.split('(').next() {
                            let name = name.trim();
                            if !name.is_empty() { exports.push(name.to_string()); }
                        }
                    } else if let Some(rest) = t.strip_prefix("class ") {
                        if let Some(name) = rest.split_whitespace().next() {
                            exports.push(name.to_string());
                        }
                    } else if let Some(rest) = t.strip_prefix("const ") {
                        if let Some(name) = rest.split('=').next() {
                            let name = name.trim();
                            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                exports.push(name.to_string());
                            }
                        }
                    }
                }

                if is_app {
                    // app.js is the entry point — runs last, accesses globals directly.
                    // Don't wrap in IIFE so it can reference window.initHome etc. as bare names.
                    // Pull needed names from window first.
                    js_bundle.push_str("// --- app.js entry (no IIFE) ---\n");
                    js_bundle.push_str("var Bridge = window.Bridge;\n");
                    js_bundle.push_str("var emptyState = window.emptyState;\n");
                    js_bundle.push_str("var initHome = window.initHome;\n");
                    js_bundle.push_str("var initDocuments = window.initDocuments;\n");
                    js_bundle.push_str("var initDrafts = window.initDrafts;\n");
                    js_bundle.push_str("var initVerify = window.initVerify;\n");
                    js_bundle.push_str("var initPayments = window.initPayments;\n");
                    js_bundle.push_str("var initContacts = window.initContacts;\n");
                    js_bundle.push_str("var initSettings = window.initSettings;\n");
                    js_bundle.push_str("var initFaucet = window.initFaucet;\n");
                    js_bundle.push_str(&body);
                } else {
                    // Wrap in IIFE for scope isolation + hoist exports to window.
                    js_bundle.push_str("(function(){\n");
                    // Pages and bridge need access to globals from other modules.
                    // Only inject preamble for files that CONSUME these globals (pages),
                    // not for files that DEFINE them (utils, components, bridge).
                    if is_page {
                        js_bundle.push_str("var W=window,Bridge=W.Bridge,esc=W.esc,escAttr=W.escAttr,timeAgo=W.timeAgo,truncate=W.truncate,initials=W.initials,formatBytes=W.formatBytes,formatTimestamp=W.formatTimestamp,showCopyFeedback=W.showCopyFeedback,emptyState=W.emptyState,nobleCard=W.nobleCard,hashText=W.hashText,amountText=W.amountText,formatAmount=W.formatAmount,statusBadge=W.statusBadge,openModal=W.openModal,openWizardModal=W.openWizardModal,closeModal=W.closeModal,renderQR=W.renderQR,contactCard=W.contactCard,NativeBridge=W.NativeBridge,MockBridge=W.MockBridge;\n");
                    }
                    js_bundle.push_str(&body);
                    for name in &exports {
                        js_bundle.push_str(&format!(
                            "if(typeof {name}!=='undefined')window.{name}={name};\n"
                        ));
                    }
                    js_bundle.push_str("})();\n");
                }
            }
        }
    }

    // Fix app.js references: the import aliases like `initHome` map to `initHome` (from home.js).
    // Our renaming produces `initHome` from "js/pages/home.js" (stem "home" → prefix "Home").
    // Verify: the pages dict in app.js uses `initHome`, `initDocuments`, etc.
    // Our bundler renames `export function init(` in pages/home.js to `function initHome(`.
    // This matches because the import in app.js was `import { init as initHome }`.
    // ✓ All page init functions are now uniquely named.

    // 3. Assemble HTML
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, interactive-widget=resizes-content">
    <meta name="color-scheme" content="light dark">
    <title>NobleDoc</title>
    <style>{css}</style>
</head>
<body>
    <div id="chain-bar" class="chain-bar" hidden></div>
    <main id="app-content"></main>
    <script>
    // Init script (webkit shim + NativeConfig)
    {init_script}
    // Error display
    window._errs=[];
    window.onerror=function(m,f,l){{ document.body.innerHTML='<pre style="color:red;padding:20px;z-index:99999;position:fixed;top:0;left:0;right:0;background:#000">'+m+' @'+f+':'+l+'</pre>'+document.body.innerHTML; }};
    try {{
    // Bundled WebUI
    {js_bundle}
    }} catch(e) {{ document.body.innerHTML='<pre style="color:red;padding:20px;z-index:99999;position:fixed;top:0;left:0;right:0;background:#000">BUNDLE ERROR: '+e.message+'\\n'+e.stack+'</pre>'+document.body.innerHTML; }}
    </script>
</body>
</html>"#
    )
}

/// Get the embedded CSS content as a string.
pub fn get_css() -> &'static str {
    WEBUI_DIR
        .get_file("css/noble.css")
        .and_then(|f| std::str::from_utf8(f.contents()).ok())
        .unwrap_or("")
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
