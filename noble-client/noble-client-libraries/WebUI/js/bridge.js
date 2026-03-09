// NOBLE Document Client — Native Bridge
// Provides NativeBridge (WKWebView) and MockBridge (Safari/dev) with identical APIs.

let _callbackId = 0;
const _callbacks = {};

/** Real bridge for WKWebView — calls Swift via webkit.messageHandlers. */
class NativeBridge {
    static get isNative() {
        return !!(window.webkit && window.webkit.messageHandlers);
    }

    static call(handler, action, params = {}) {
        return new Promise((resolve, reject) => {
            const id = 'cb_' + (++_callbackId);
            _callbacks[id] = { resolve, reject };
            window.webkit.messageHandlers[handler].postMessage({
                callbackId: id,
                action,
                params
            });
        });
    }

    /** Called from Swift to resolve a pending callback. */
    static _handleCallback(id, error, result) {
        const cb = _callbacks[id];
        if (!cb) return;
        delete _callbacks[id];
        if (error) {
            cb.reject(new Error(typeof result === 'string' ? result : error));
        } else {
            const parsed = typeof result === 'string' ? JSON.parse(result) : result;
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

    static _mock(handler, action, params) {
        const addr = '02ab3f4c8e9d1a2b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b';

        if (handler === 'noble_app') {
            if (action === 'getState') return {
                isConnected: true,
                hasWallet: true,
                walletAddress: addr,
                chain_id: '4E4F424C',
                blockHeight: 1234,
                selectedSection: 'home'
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
                cycle: 42, phase: 'Proposal', phaseProgress: 0.6, timeRemaining: 120
            };
            if (action === 'getTransactionHistory') return {
                transactions: [
                    { txId: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890', blockHeight: 1230, type: 'notarization', direction: '', amount: 0, fee: 2000, counterparty: '', timestamp: Date.now() / 1000 - 7200, confirmations: 4 },
                    { txId: 'b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1', blockHeight: 1228, type: 'transfer_in', direction: 'incoming', amount: 50000000, fee: 2000, counterparty: '03ff1122334455667788990011223344556677889900112233445566778899001122', timestamp: Date.now() / 1000 - 14400, confirmations: 6 },
                    { txId: 'c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2', blockHeight: 1225, type: 'transfer_out', direction: 'outgoing', amount: 25000000, fee: 2000, counterparty: '03aabb0011223344556677889900112233445566778899001122334455667788990011', timestamp: Date.now() / 1000 - 28800, confirmations: 9 },
                    { txId: 'd4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3', blockHeight: 1220, type: 'notarization', direction: '', amount: 0, fee: 1500, counterparty: '', timestamp: Date.now() / 1000 - 43200, confirmations: 14 },
                    { txId: 'e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4', blockHeight: 1215, type: 'transfer_in', direction: 'incoming', amount: 100000000, fee: 5000, counterparty: '03dd1122334455667788990011223344556677889900112233445566778899001122', timestamp: Date.now() / 1000 - 86400, confirmations: 19 }
                ],
                total: 42, page: 0, limit: 20
            };
            if (action === 'estimateFee') return {
                minFee: 1000, recommendedFee: 2000, highPriorityFee: 5000
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
                chain_id: '4E4F424C', version: '0.28.0', blockHeight: 1234
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
                valid: true, scheme: 'ed25519', publicKey: params.address
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
                noblePubkey: '0201abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
                bitcoinKey: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                notes: 'Creator of Bitcoin', isFavorite: true,
                displayName: 'Satoshi Nakamoto',
                createdAt: Date.now() / 1000 - 86400 * 30,
                updatedAt: Date.now() / 1000 - 86400
            },
            {
                id: '22222222-2222-2222-2222-222222222222',
                firstName: 'Alice', lastName: 'Validator', company: 'Noble Labs',
                email: 'alice@noblelabs.io',
                noblePubkey: '0301ff2233445566778899aabbccddeeff00112233445566778899aabbccddeeff00',
                bitcoinKey: '', notes: 'Testnet validator', isFavorite: false,
                displayName: 'Alice Validator',
                createdAt: Date.now() / 1000 - 86400 * 14,
                updatedAt: Date.now() / 1000 - 86400 * 7
            },
            {
                id: '33333333-3333-3333-3333-333333333333',
                firstName: 'Bob', lastName: 'Miner', company: 'Block Factory',
                email: 'bob@blockfactory.net',
                noblePubkey: '02aabb0011223344556677889900112233445566778899001122334455667788990011',
                bitcoinKey: 'bc1p5cyxnuxmeuwuvkwfem96lqzszee2456h0vwcdh',
                notes: '', isFavorite: true,
                displayName: 'Bob Miner',
                createdAt: Date.now() / 1000 - 86400 * 7,
                updatedAt: Date.now() / 1000 - 3600
            },
            {
                id: '44444444-4444-4444-4444-444444444444',
                firstName: 'Carol', lastName: '', company: 'Noble Foundation',
                email: 'carol@noblefoundation.org',
                noblePubkey: '', bitcoinKey: '',
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

export { Bridge, NativeBridge, MockBridge };
