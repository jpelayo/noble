// NOBLE Document Client — Native Bridge
// Provides NativeBridge (WKWebView) and MockBridge (Safari/dev) with identical APIs.

let _callbackId = 0;
const _callbacks = {};
const _progressHandlers = new Map();
let _requestId = 0;
const DEFAULT_TIMEOUT_MS = 10000;
const TX_TIMEOUT_MS = 30000;
const DOWNLOAD_TIMEOUT_MS = 10 * 60 * 1000;
const TX_ACTIONS = new Set(['submitTransaction', 'signNotarization', 'signTransfer']);
const LONG_ACTIONS = new Set(['downloadAndHash']);

/** Real bridge for native hosts — WKWebView (Swift) or WRY (Rust).
 *
 * Detection order:
 * 1. WRY (window.ipc) — single IPC channel, handler name embedded in payload.
 * 2. WKWebView (window.webkit.messageHandlers) — named message handlers.
 */
class NativeBridge {
    static get isNative() {
        return !!(window.ipc || (window.webkit && window.webkit.messageHandlers));
    }

    static call(handler, action, params = {}) {
        const timeoutMs = LONG_ACTIONS.has(action) ? DOWNLOAD_TIMEOUT_MS
            : TX_ACTIONS.has(action) ? TX_TIMEOUT_MS
            : DEFAULT_TIMEOUT_MS;
        return new Promise((resolve, reject) => {
            const id = 'cb_' + (++_callbackId);
            const timer = setTimeout(() => {
                delete _callbacks[id];
                const err = new Error(`Bridge timeout: ${handler}.${action} exceeded ${timeoutMs}ms`);
                // Notify App of bridge failure — triggers connectivity check
                if (window.App && window.App.onBridgeError) {
                    window.App.onBridgeError(handler, action, err);
                }
                reject(err);
            }, timeoutMs);
            _callbacks[id] = {
                resolve: v => { clearTimeout(timer); resolve(v); },
                reject: e => { clearTimeout(timer); reject(e); }
            };
            const msg = { callbackId: id, action, params };
            if (window.ipc) {
                // WRY: single IPC channel — embed handler name in payload.
                window.ipc.postMessage(JSON.stringify(Object.assign({}, msg, { handler })));
            } else {
                // WKWebView (Swift): named message handlers.
                window.webkit.messageHandlers[handler].postMessage(msg);
            }
        });
    }

    /** Call a bridge action that reports streaming progress via
     *  `window.NobleBridge._onDownloadProgress`. The onProgress callback
     *  receives `{ bytesDownloaded, totalBytes }`. Returns the final
     *  `{ ok, hash, ... }` payload from the native handler.
     */
    static callWithProgress(handler, action, params = {}, onProgress) {
        const requestId = 'req_' + (++_requestId);
        if (typeof onProgress === 'function') {
            _progressHandlers.set(requestId, onProgress);
        }
        const finalParams = Object.assign({}, params, { requestId });
        return NativeBridge.call(handler, action, finalParams)
            .finally(() => { _progressHandlers.delete(requestId); });
    }

    /** Called from Swift to resolve a pending callback. */
    static _handleCallback(id, error, result) {
        const cb = _callbacks[id];
        if (!cb) return;
        delete _callbacks[id];
        if (error) {
            cb.reject(new Error(typeof result === 'string' ? result : error));
        } else {
            let parsed;
            try {
                parsed = typeof result === 'string' ? JSON.parse(result) : result;
            } catch (e) {
                cb.reject(new Error('Invalid bridge response: ' + e.message));
                return;
            }
            cb.resolve(parsed);
        }
    }
}

/** Mock bridge for development in Safari / non-WKWebView contexts. */
class MockBridge {
    static get isNative() { return false; }

    static call(handler, action, params = {}) {
        return new Promise(resolve => {
            setTimeout(() => resolve(MockBridge._mock(handler, action, params)), 200);
        });
    }

    static callWithProgress(handler, action, params = {}, _onProgress) {
        // In mock mode the native download path doesn't exist; callers should
        // detect this via Bridge.isNative and use the fetch fallback.
        return MockBridge.call(handler, action, params);
    }

    static _mock(handler, action, params) {
        const addr = '02ab3f4c8e9d1a2b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b';

        if (handler === 'noble_app') {
            if (action === 'getState') return {
                isConnected: true,
                hasWallet: true,
                walletAddress: addr,
                chainId: '4E4F424C',
                blockHeight: 1234,
                selectedSection: 'home',
                // 'desktop' is in the WRY platform set, so browser dev renders
                // the WRY-only UI (persistent nav, reveal phrase, p12 password
                // modal). Override via localStorage 'noble.mockPlatform' to
                // preview the Mac/iOS chrome-less layout.
                platform: localStorage.getItem('noble.mockPlatform') || 'desktop'
            };
            if (action === 'navigateTo') return { ok: true };
            if (action === 'copyToClipboard') return { ok: true };
            if (action === 'openFileDialog') return {
                files: [
                    { path: '/tmp/contract.pdf', name: 'contract.pdf', size: 245760 },
                    { path: '/tmp/invoice.pdf', name: 'invoice.pdf', size: 102400 }
                ]
            };
            if (action === 'shareText') return { ok: true };
            if (action === 'getSettings') return {
                nodeURL: 'https://localhost:8783',
                authMode: 'none',
                tlsFingerprint: 'AB:CD:EF:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A',
                appVersion: '1.0.0',
                autoConnect: true
            };
            if (action === 'getSecuritySettings') return {
                appLockEnabled: false,
                lockTimeout: 300,
                reAuthForSends: true
            };
            if (action === 'saveSettings') return { ok: true };
            if (action === 'saveSecuritySettings') return { ok: true };
            if (action === 'testConnection') return { ok: true };
            if (action === 'disconnectNode') return { ok: true };
            // Wallet provisioning (WRY first-run flow; browser-dev mocks)
            if (action === 'createWallet') return {
                ok: true,
                address: addr,
                mnemonic: ['abandon', 'ability', 'able', 'about', 'above', 'absent',
                           'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident'],
            };
            if (action === 'importWallet') return { ok: true, address: addr };
            if (action === 'exportWallet') return { ok: true, mnemonic: 'abandon ability able about above absent absorb abstract absurd abuse access accident' };
        }

        if (handler === 'noble_api') {
            if (action === 'getBalance') return {
                balance: 1250000000,
                available: 1200000000,
                pending: 50000000,
                txCount: 42
            };
            if (action === 'getSyncStatus') return {
                synced: true, currentHeight: 1234, highestKnown: 1234
            };
            if (action === 'getCycleStatus') return {
                cycleNumber: 42, phase: 'Proposal', phaseRemainingSecs: 180, cycleRemainingSecs: 780
            };
            if (action === 'getWalletTransactions' || action === 'getTransactionHistory') return {
                transactions: [
                    { txId: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890', blockHeight: 1230, type: 'notarization', direction: '', total_output: 0, inputs: [], outputs: [], signer: '020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01', recipient: '', timestamp: Date.now() / 1000 - 7200, confirmations: 4 },
                    { txId: 'b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1', blockHeight: 1228, type: 'transfer', direction: 'incoming', total_output: 50000000, inputs: [{txid: '0000000000000000000000000000000000000000000000000000000000000000', vout: 0}], outputs: [{value: 50000000, address: '020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01'}], signer: '03ff1122334455667788990011223344556677889900112233445566778899001122', recipient: '03ff1122334455667788990011223344556677889900112233445566778899001122', timestamp: Date.now() / 1000 - 14400, confirmations: 6 },
                    { txId: 'c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2', blockHeight: 1225, type: 'transfer', direction: 'outgoing', total_output: 25000000, inputs: [{txid: '0000000000000000000000000000000000000000000000000000000000000000', vout: 0}], outputs: [{value: 25000000, address: '03aabb0011223344556677889900112233445566778899001122334455667788990011'}], signer: '020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01', recipient: '03aabb0011223344556677889900112233445566778899001122334455667788990011', timestamp: Date.now() / 1000 - 28800, confirmations: 9 },
                    { txId: 'd4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3', blockHeight: 1220, type: 'notarization', direction: '', total_output: 0, inputs: [], outputs: [], signer: '020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01', recipient: '', timestamp: Date.now() / 1000 - 43200, confirmations: 14 },
                    { txId: 'e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4', blockHeight: 1215, type: 'transfer', direction: 'incoming', total_output: 100000000, inputs: [{txid: '0000000000000000000000000000000000000000000000000000000000000000', vout: 0}], outputs: [{value: 100000000, address: '020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01'}], signer: '03dd1122334455667788990011223344556677889900112233445566778899001122', recipient: '03dd1122334455667788990011223344556677889900112233445566778899001122', timestamp: Date.now() / 1000 - 86400, confirmations: 19 }
                ],
                total: 42, page: 0, limit: 20
            };
            if (action === 'estimateFee') return {
                lowFeeRate: 1, recommendedFeeRate: 2, highPriorityFeeRate: 5,
                networkMinFeeRate: 1, networkMedianFeeRate: 2, localMinFeeRate: 1
            };
            if (action === 'verifyDocument') {
                const checksum = params.checksum || '';
                if (checksum.startsWith('dead')) {
                    return { checksum, registered: false, registrations: [], firstSeen: null };
                }
                return {
                    checksum,
                    registered: true,
                    registrations: [
                        { blockHeight: 1230, txId: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890', timestamp: Date.now() / 1000 - 7200 }
                    ],
                    firstSeen: Date.now() / 1000 - 7200
                };
            }
            if (action === 'getDocumentVersions') return {
                checksum: params.checksum, versions: [
                    { checksum: params.checksum, blockHeight: 1230, timestamp: Date.now() / 1000 - 7200, txId: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890' }
                ]
            };
            if (action === 'submitTransaction') return {
                txId: 'f6789012345678901234567890123456789012345678901234567890abcdef01', accepted: true
            };
            if (action === 'getNodeInfo') return {
                chainId: '0x4E4F424C', version: '0.30.0', blockHeight: 1234
            };
            if (action === 'getBlockCount') return { height: 1234, block_hash: '00ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab' };
            if (action === 'getNetworkInfo') return { peer_count: 8, inbound: 5, outbound: 3, clock_offset_ms: 0 };
            if (action === 'getPeers') return { total: 8, inbound: 5, outbound: 3 };
            if (action === 'getTransaction') return {
                txId: params.txId, blockHeight: 1230, confirmations: 4, status: 'confirmed'
            };
            if (action === 'getTransactionStatus') return {
                txId: params.txId, status: 'confirmed', blockHeight: 1230, confirmations: 4
            };
            if (action === 'lookupChecksum') return {
                found: true, records: [{ blockHeight: 1230, txId: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890', timestamp: Date.now() / 1000 - 7200 }]
            };
            if (action === 'validateAddress') return {
                valid: true, scheme: 'secp256k1', publicKey: params.address
            };
        }

        if (handler === 'noble_crypto') {
            if (action === 'signNotarization') return {
                txHex: 'a76776657273696f6e01677478_type00' + Math.random().toString(16).slice(2, 18)
            };
            if (action === 'signTransfer') return {
                txHex: 'a76776657273696f6e01677478_type01' + Math.random().toString(16).slice(2, 18)
            };
        }

        if (handler === 'noble_security') {
            if (action === 'hashFile') return {
                hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            };
            if (action === 'loadPrivateKey') return { available: true };
            if (action === 'importPKCS12') return {
                id: 'mock-p12-' + Math.random().toString(16).slice(2, 10),
                label: 'Mock Certificate',
                algorithm: 'p256',
                publicKeyHex: addr,
                hasPrivateKey: true,
                certificateSubject: 'CN=Mock Signer,O=Noble',
                subjectKeyIdentifier: 'ab'.repeat(20),
                importedAt: Date.now() / 1000
            };
            if (action === 'generateSigningKey') return {
                id: 'mock-gen-' + Math.random().toString(16).slice(2, 10),
                label: 'Noble Key',
                algorithm: 'secp256k1',
                publicKeyHex: addr,
                hasPrivateKey: true,
                subjectKeyIdentifier: 'cd'.repeat(20),
                importedAt: Date.now() / 1000
            };
        }

        if (handler === 'noble_storage') {
            if (action === 'getContacts') return { contacts: MockBridge._contacts() };
            if (action === 'saveContact') return { ok: true, id: params.contact?.id || 'new-uuid' };
            if (action === 'deleteContact') return { ok: true };
            if (action === 'exportContactsVCF') return { vcf: 'BEGIN:VCARD\nVERSION:3.0\nN:Nakamoto;Satoshi;;;\nFN:Satoshi Nakamoto\nX-NOBLE-PUBKEY:0201abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678\nEND:VCARD' };
            if (action === 'importContactsVCF') return { contacts: [], count: 0 };
        }

        if (handler === 'noble_app' && action === 'saveFileDialog') return { ok: true };
        if (handler === 'noble_app' && action === 'readFileText') return { text: '' };

        return {};
    }

    static _contacts() {
        return [
            {
                id: '11111111-1111-1111-1111-111111111111',
                firstName: 'Satoshi', lastName: 'Nakamoto', company: '',
                email: 'satoshi@bitcoin.org',
                noblePubkey: 'nbl1pqyqs0ydkfxrq8z9q0a5k0j3fzph36c7z4ywmkv',
                nobleHex: '0201abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
                bitcoinP2pkh: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                bitcoinP2wpkh: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                bitcoinP2tr: '',
                notes: 'Creator of Bitcoin', isFavorite: true,
                displayName: 'Satoshi Nakamoto',
                createdAt: Date.now() / 1000 - 86400 * 30,
                updatedAt: Date.now() / 1000 - 86400
            },
            {
                id: '22222222-2222-2222-2222-222222222222',
                firstName: 'Alice', lastName: 'Validator', company: 'Noble Labs',
                email: 'alice@noblelabs.io',
                noblePubkey: 'nbl1pvlse3zga2sj80p8e6nnfvzxkn5qe59c0uqclj',
                nobleHex: '0301ff2233445566778899aabbccddeeff00112233445566778899aabbccddeeff00',
                bitcoinP2pkh: '', bitcoinP2wpkh: '', bitcoinP2tr: '',
                notes: 'Testnet validator', isFavorite: false,
                displayName: 'Alice Validator',
                createdAt: Date.now() / 1000 - 86400 * 14,
                updatedAt: Date.now() / 1000 - 86400 * 7
            },
            {
                id: '33333333-3333-3333-3333-333333333333',
                firstName: 'Bob', lastName: 'Miner', company: 'Block Factory',
                email: 'bob@blockfactory.net',
                noblePubkey: 'nbl1p4tvd6qqg3rjcnp9q9zrvqxk54npst6e7xqy7j',
                nobleHex: '02aabb0011223344556677889900112233445566778899001122334455667788990011',
                bitcoinP2pkh: '', bitcoinP2wpkh: '',
                bitcoinP2tr: 'bc1p5cyxnuxmeuwuvkwfem96lqzszee2456h0vwcdh',
                notes: '', isFavorite: true,
                displayName: 'Bob Miner',
                createdAt: Date.now() / 1000 - 86400 * 7,
                updatedAt: Date.now() / 1000 - 3600
            },
            {
                id: '44444444-4444-4444-4444-444444444444',
                firstName: 'Carol', lastName: '', company: 'Noble Foundation',
                email: 'carol@noblefoundation.org',
                noblePubkey: '', nobleHex: '', bitcoinP2pkh: '', bitcoinP2wpkh: '', bitcoinP2tr: '',
                notes: 'No crypto keys on file', isFavorite: false,
                displayName: 'Carol',
                createdAt: Date.now() / 1000 - 86400 * 2,
                updatedAt: Date.now() / 1000 - 86400 * 2
            }
        ];
    }

    static _handleCallback() {} // no-op for compatibility
}

const Bridge = NativeBridge.isNative ? NativeBridge : MockBridge;
window.NativeBridge = NativeBridge;

// Global dispatcher for streaming progress events from native hosts.
// Native side calls `window.NobleBridge._onDownloadProgress({ requestId, ... })`.
window.NobleBridge = window.NobleBridge || {};
window.NobleBridge._onDownloadProgress = function(evt) {
    if (!evt || !evt.requestId) return;
    const cb = _progressHandlers.get(evt.requestId);
    if (cb) {
        try { cb(evt); } catch (e) { console.warn('[bridge] progress callback threw:', e); }
    }
};

// ── Persistent preferences ──────────────────────────────────────────────
// The Apple shells run the WebUI on a non-persistent website data store
// (fresh-JS guarantee), so localStorage dies with the process. Prefs mirrors
// preference keys into the native store (UserDefaults on macOS/iOS, a JSON
// file on WRY) through the app bridge: hydrate() restores them into
// localStorage at boot, set() writes through to both. In a plain browser
// (no native bridge) localStorage is durable by itself and the bridge half
// is a no-op.
const Prefs = {
    /** Restore natively-stored preferences into localStorage. Time-bounded
     *  so a bridge failure can never block boot. Call before first render. */
    async hydrate() {
        if (!NativeBridge.isNative) return;
        try {
            const timeout = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('getPreferences timed out')), 800));
            const prefs = await Promise.race([
                NativeBridge.call('noble_app', 'getPreferences'),
                timeout,
            ]);
            for (const [key, value] of Object.entries(prefs || {})) {
                if (typeof value === 'string') localStorage.setItem(key, value);
            }
        } catch (e) {
            console.warn('[prefs] hydrate failed — session uses defaults:', e);
        }
    },

    /** Write-through setter: localStorage for this session, native store for
     *  the next launch. value === null deletes the key from both. */
    set(key, value) {
        if (value === null) localStorage.removeItem(key);
        else localStorage.setItem(key, String(value));
        if (NativeBridge.isNative) {
            NativeBridge.call('noble_app', 'setPreference', { key, value })
                .catch(e => console.warn('[prefs] native persist failed:', e));
        }
    },
};

export { Bridge, NativeBridge, MockBridge, Prefs };
