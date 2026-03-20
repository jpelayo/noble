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

        // Map noble-app://webui/path → WebUI/path in the bundle
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

// MARK: - DroppableWebView

/// WKWebView subclass that accepts file drops from Finder and forwards paths to JavaScript.
final class DroppableWebView: WKWebView {
    override init(frame: CGRect, configuration: WKWebViewConfiguration) {
        super.init(frame: frame, configuration: configuration)
        registerForDraggedTypes([.fileURL])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    override func draggingEntered(_ sender: any NSDraggingInfo) -> NSDragOperation {
        if sender.draggingPasteboard.canReadObject(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) {
            return .copy
        }
        return super.draggingEntered(sender)
    }

    override func draggingUpdated(_ sender: any NSDraggingInfo) -> NSDragOperation {
        if sender.draggingPasteboard.canReadObject(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) {
            return .copy
        }
        return super.draggingUpdated(sender)
    }

    override func draggingExited(_ sender: (any NSDraggingInfo)?) {
        super.draggingExited(sender)
    }

    override func performDragOperation(_ sender: any NSDraggingInfo) -> Bool {
        guard let urls = sender.draggingPasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [URL] else {
            return super.performDragOperation(sender)
        }
        let fileURLs = urls.filter { $0.isFileURL }
        guard !fileURLs.isEmpty else { return super.performDragOperation(sender) }

        // Build JS array of {name, path, size}
        var entries: [[String: Any]] = []
        for url in fileURLs {
            let name = url.lastPathComponent
            let path = url.path
            let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
            entries.append(["name": name, "path": path, "size": size])
        }

        guard let data = try? JSONSerialization.data(withJSONObject: entries),
              let json = String(data: data, encoding: .utf8) else { return false }

        let script = "if(window._nobleHandleFileDrop) window._nobleHandleFileDrop(\(json));"
        evaluateJavaScript(script, completionHandler: nil)
        return true
    }
}

// MARK: - WebContentView

/// NSViewRepresentable wrapping a WKWebView that hosts the portable web UI.
struct WebContentView: NSViewRepresentable {
    let appState: AppState

    /// Base URL for the custom scheme — matches what the scheme handler expects.
    private static let baseURLString = "noble-app://webui/"

    func makeCoordinator() -> Coordinator {
        Coordinator(appState: appState)
    }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()

        // Register the custom URL scheme handler for bundled WebUI files
        if let webUIDir = Bundle.main.url(forResource: "WebUI", withExtension: nil)
            ?? Bundle.main.resourceURL?.appendingPathComponent("WebUI")
        {
            let schemeHandler = WebUISchemeHandler(baseDirectory: webUIDir)
            config.setURLSchemeHandler(schemeHandler, forURLScheme: "noble-app")
        }

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

        let webView = DroppableWebView(frame: .zero, configuration: config)
        webView.setValue(false, forKey: "drawsBackground") // Transparent background

        #if DEBUG
        if #available(macOS 13.3, *) {
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

    func updateNSView(_ nsView: WKWebView, context: Context) {
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
            "platform": "macos",
            "version": version,
            "isConnected": true,     // Always start optimistic — heartbeat/poll corrects if offline
            "hasWallet": hasWallet,
            "walletAddress": address,
            "chainId": chainId,
            "initialRoute": section
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: config),
              let json = String(data: data, encoding: .utf8) else {
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
