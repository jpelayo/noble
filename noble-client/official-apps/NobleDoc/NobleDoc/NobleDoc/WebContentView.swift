// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import WebKit

/// NSViewRepresentable wrapping a WKWebView that hosts the portable web UI.
struct WebContentView: NSViewRepresentable {
    let appState: AppState

    func makeCoordinator() -> Coordinator {
        Coordinator(appState: appState)
    }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()

        // Register bridge message handlers
        let handlers = ["noble_api", "noble_crypto", "noble_security", "noble_app"]
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
        webView.setValue(false, forKey: "drawsBackground") // Transparent background

        #if DEBUG
        if #available(macOS 13.3, *) {
            webView.isInspectable = true
        }
        #endif

        context.coordinator.webView = webView
        appState.webViewCoordinator = context.coordinator

        // Load index.html from the bundle
        if let htmlURL = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "WebUI") {
            let webUIDir = htmlURL.deletingLastPathComponent()
            webView.loadFileURL(htmlURL, allowingReadAccessTo: webUIDir)
        }

        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {
        // State changes are pushed via evaluateJavaScript from MainView's onChange
    }

    private func buildNativeConfigScript() -> String {
        let address = appState.walletAddress ?? ""
        let connected = appState.isConnected ? "true" : "false"
        let hasWallet = appState.hasWallet ? "true" : "false"
        let network = appState.networkLabel
        let section = appState.selectedSection?.webRoute ?? "home"

        return """
        window.NativeConfig = {
            platform: 'macos',
            version: '0.23.0',
            isConnected: \(connected),
            hasWallet: \(hasWallet),
            walletAddress: '\(address)',
            network: '\(network)',
            initialRoute: '\(section)'
        };
        """
    }

    // MARK: - Coordinator

    final class Coordinator: NSObject, WKScriptMessageHandler {
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
