// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UniformTypeIdentifiers
import WebKit

// MARK: - Custom URL Scheme Handler

/// Serves bundled WebUI files under the `noble-app://` scheme.
///
/// This avoids `file://` restrictions that break ES module imports
/// in a sandboxed WKWebView.
final class WebUISchemeHandler: NSObject, WKURLSchemeHandler {
    private let baseDirectory: URL

    init(baseDirectory: URL) {
        self.baseDirectory = baseDirectory
        super.init()
    }

    func webView(_ webView: WKWebView, start urlSchemeTask: any WKURLSchemeTask) {
        guard let requestURL = urlSchemeTask.request.url else {
            urlSchemeTask.didFailWithError(URLError(.badURL))
            return
        }

        // Map noble-app://webui/path → base/path in the bundle
        let relativePath = requestURL.path.hasPrefix("/")
            ? String(requestURL.path.dropFirst())
            : requestURL.path
        let fileURL = baseDirectory.appendingPathComponent(relativePath)

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))
            return
        }

        guard let data = try? Data(contentsOf: fileURL) else {
            urlSchemeTask.didFailWithError(URLError(.cannotOpenFile))
            return
        }

        let mimeType = Self.mimeType(for: fileURL.pathExtension)
        let headers: [String: String] = [
            "Content-Type": mimeType + (mimeType.hasPrefix("text/") || mimeType.contains("javascript") ? "; charset=utf-8" : ""),
            "Content-Length": "\(data.count)",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        ]
        let response = HTTPURLResponse(
            url: requestURL,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        )!
        urlSchemeTask.didReceive(response)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: any WKURLSchemeTask) {
        // Nothing to cancel for synchronous file reads
    }

    private static func mimeType(for ext: String) -> String {
        switch ext.lowercased() {
        case "html": "text/html"
        case "css": "text/css"
        case "js", "mjs": "application/javascript"
        case "json": "application/json"
        case "svg": "image/svg+xml"
        case "png": "image/png"
        case "jpg", "jpeg": "image/jpeg"
        case "woff2": "font/woff2"
        case "woff": "font/woff"
        default:
            if let utType = UTType(filenameExtension: ext), let mime = utType.preferredMIMEType {
                mime
            } else {
                "application/octet-stream"
            }
        }
    }
}

// MARK: - WebContentView

/// UIViewRepresentable wrapping a WKWebView that hosts the portable web UI.
struct WebContentView: UIViewRepresentable {
    let appState: AppState

    /// Base URL for the custom scheme — matches what the scheme handler expects.
    private static let baseURLString = "noble-app://webui/"

    func makeCoordinator() -> Coordinator {
        Coordinator(appState: appState)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()

        // Non-persistent data store: never caches to disk.
        // Ensures updated JS/CSS from new builds are always loaded fresh.
        config.websiteDataStore = .nonPersistent()

        // Register the custom URL scheme handler for bundled WebUI files.
        // iOS bundles individual folder references (js/, css/, index.html) at the bundle root,
        // so we fall back to resourceURL if no WebUI directory exists.
        let webUIDir = Bundle.main.url(forResource: "WebUI", withExtension: nil)
            ?? Bundle.main.resourceURL!
        let schemeHandler = WebUISchemeHandler(baseDirectory: webUIDir)
        config.setURLSchemeHandler(schemeHandler, forURLScheme: "noble-app")

        // Register bridge message handlers
        let handlers = ["noble_api", "noble_crypto", "noble_security", "noble_app", "noble_storage"]
        for handler in handlers {
            config.userContentController.add(context.coordinator, name: handler)
        }

        // Inject NativeConfig at document start so it's available before app.js runs
        let nativeConfigScript = buildNativeConfigScript()
        let userScript = WKUserScript(
            source: nativeConfigScript,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        config.userContentController.addUserScript(userScript)

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.isOpaque = false
        webView.backgroundColor = .clear
        webView.scrollView.backgroundColor = .clear
        webView.scrollView.contentInsetAdjustmentBehavior = .automatic
        webView.scrollView.bounces = false

        #if DEBUG
        if #available(iOS 16.4, *) {
            webView.isInspectable = true
        }
        #endif

        // Set navigation delegate to catch loading errors
        webView.navigationDelegate = context.coordinator

        context.coordinator.webView = webView
        appState.webViewCoordinator = context.coordinator

        // Load index.html via the custom scheme
        if let url = URL(string: "\(Self.baseURLString)index.html") {
            webView.load(URLRequest(url: url))
        }

        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // State changes are pushed via evaluateJavaScript from MainView's onChange
    }

    private func buildNativeConfigScript() -> String {
        let address = appState.walletAddress ?? ""
        let connected = appState.isConnected
        let hasWallet = appState.hasWallet
        let chainId = appState.chainId
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1"
        let section = appState.selectedSection?.webRoute ?? "home"

        let config: [String: Any] = [
            "platform": "ios",
            "version": version,
            "isConnected": connected,
            "hasWallet": hasWallet,
            "walletAddress": address,
            "chainId": chainId,
            "initialRoute": section,
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: config),
              let json = String(data: data, encoding: .utf8)
        else {
            return "window.NativeConfig = {};"
        }
        return "window.NativeConfig = \(json);"
    }

    // MARK: - Coordinator

    final class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
        let appState: AppState
        weak var webView: WKWebView?
        private let bridgeHandler: WebBridgeHandler

        init(appState: AppState) {
            self.appState = appState
            self.bridgeHandler = WebBridgeHandler(appState: appState)
            super.init()
        }

        /// Evaluate JavaScript in the web view.
        func evaluateJS(_ script: String) {
            webView?.evaluateJavaScript(script) { _, error in
                if let error {
                    print("[WebContentView] JS error: \(error.localizedDescription)")
                }
            }
        }

        // MARK: - WKNavigationDelegate

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: any Error) {
            print("[WebContentView] Navigation failed: \(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: any Error) {
            print("[WebContentView] Provisional navigation failed: \(error.localizedDescription)")
        }

        // MARK: - WKScriptMessageHandler

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            guard let body = message.body as? [String: Any],
                  let callbackId = body["callbackId"] as? String,
                  let action = body["action"] as? String
            else {
                return
            }

            let params = body["params"] as? [String: Any] ?? [:]

            Task { @MainActor in
                await self.bridgeHandler.handle(
                    handler: message.name,
                    action: action,
                    params: params,
                    callbackId: callbackId,
                    coordinator: self
                )
            }
        }
    }
}
