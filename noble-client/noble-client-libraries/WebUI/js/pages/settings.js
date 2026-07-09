// NOBLE Document Client — Settings
import { Bridge, Prefs } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { statusBadge } from '../components/status-badge.js';
import { renderQR } from '../components/qr-code.js';
import { openModal } from '../components/modal.js';
import { promptP12Password } from '../components/p12-password.js';
import { esc, escAttr, isWryPlatform, groupThousands, setThousandsSeparator, getThousandsSeparatorId, THEME_KEY } from '../utils.js';

/** Human label for where private keys live, per platform. */
function walletStorageLabel(platform) {
    switch (platform) {
        case 'macos':   return 'macOS Keychain';
        case 'ios':     return 'iOS Keychain';
        case 'linux':   return 'Secret Service keyring';
        case 'windows': return 'Windows Credential Manager';
        default:        return 'OS keyring';
    }
}

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let settings = {};
    let securitySettings = {};
    let nodeInfo = {};
    let syncStatus = {};
    let cycleStatus = {};
    let networkInfo = {};
    // Wallet fields as of the last render — lets refresh() detect late-arriving
    // wallet state (see refresh()).
    let lastRenderedWalletKey = null;

    loadSettings();

    async function loadSettings() {
        try {
            const [appSettings, secSettings, info, sync, cycle, net] = await Promise.all([
                Bridge.call('noble_app', 'getSettings').catch(() => ({})),
                Bridge.call('noble_app', 'getSecuritySettings').catch(() => ({})),
                Bridge.call('noble_api', 'getNodeInfo').catch(() => ({})),
                Bridge.call('noble_api', 'getSyncStatus').catch(() => ({})),
                Bridge.call('noble_api', 'getCycleStatus').catch(() => ({})),
                Bridge.call('noble_api', 'getNetworkInfo').catch(() => ({})),
            ]);
            if (!alive) return;
            settings = appSettings;
            securitySettings = secSettings;
            nodeInfo = info;
            syncStatus = sync;
            cycleStatus = cycle;
            networkInfo = net;
            render();
        } catch {
            if (!alive) return;
            render();
        }
    }

    function render() {
        if (!alive) return;
        lastRenderedWalletKey = renderedWalletKey();
        root.innerHTML = '';
        root.classList.add('page-content');

        // Page header
        const header = document.createElement('div');
        header.className = 'page-header';
        header.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
                <div><h1>Settings</h1><p>Node, wallet, and app configuration</p></div>
                <button id="settings-close" class="btn btn-secondary" style="padding:6px 14px;font-size:var(--font-size-sm);flex-shrink:0">Done</button>
            </div>`;
        header.querySelector('#settings-close').addEventListener('click', () => {
            // The router keeps no browser history stack, so history.back() is a
            // no-op that strands the user (fatal on WRY, which has no native
            // chrome to escape with). Use the app router's own back instead.
            window.App.navigateBack();
        });
        root.appendChild(header);

        renderAppearanceSection();
        renderNodeSection();
        renderWalletSection();
        renderIdentitySection();
        renderBlockchainSection();
        renderSecuritySection();
        renderBackupSection();
        // Developer API (embedded RPC/MCP servers) exists only in the Mac shell.
        // WRY (linux/windows/desktop) and iOS have no server, so the panel would
        // be a dead toggle there — show it only on macOS.
        if (state.platform === 'macos') renderDeveloperApiSection();
        renderAboutSection();
    }

    // ── Appearance ──

    function renderAppearanceSection() {
        const currentTheme = localStorage.getItem(THEME_KEY) || 'system';
        const currentSep = getThousandsSeparatorId();
        // Sample labels rendered literally (the select can't call the live
        // formatter per option) — keep in sync with THOUSANDS_SEPS in utils.js.
        const sepOptions = [
            ['space', 'Space — 205 120.00'],
            ['narrow', 'Narrow space — 205 120.00'],
            ['apostrophe', "Apostrophe — 205'120.00"],
            ['comma', 'Comma — 205,120.00'],
            ['dot', 'Dot — 205.120.00'],
            ['none', 'None — 205120.00'],
        ];
        const card = document.createElement('div');
        card.className = 'panel';
        card.innerHTML = `
            <div class="panel-header">Appearance</div>
            <div class="panel-body">
                <div style="display:flex;align-items:center;justify-content:space-between">
                    <div>
                        <div style="font-size:var(--font-size-sm);font-weight:500">Theme</div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted)">Choose light, dark, or follow system appearance</div>
                    </div>
                    <div class="segmented-control segmented-control-sm" id="theme-toggle">
                        <button data-theme="system" class="${currentTheme === 'system' ? 'active' : ''}">System</button>
                        <button data-theme="light" class="${currentTheme === 'light' ? 'active' : ''}">Light</button>
                        <button data-theme="dark" class="${currentTheme === 'dark' ? 'active' : ''}">Dark</button>
                    </div>
                </div>
                <div style="display:flex;align-items:center;justify-content:space-between;margin-top:var(--gap)">
                    <div>
                        <div style="font-size:var(--font-size-sm);font-weight:500">Thousands separator</div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted)">How large numbers are grouped (decimal point is always ".")</div>
                    </div>
                    <select class="input input-sm" id="thousands-sep" aria-label="Thousands separator" style="max-width:230px">
                        ${sepOptions.map(([id, label]) =>
                            `<option value="${id}" ${id === currentSep ? 'selected' : ''}>${esc(label)}</option>`
                        ).join('')}
                    </select>
                </div>
            </div>
        `;
        root.appendChild(card);

        card.querySelectorAll('#theme-toggle button').forEach(btn => {
            btn.addEventListener('click', () => {
                const theme = btn.dataset.theme;
                Prefs.set(THEME_KEY, theme); // write-through: localStorage + native store
                window.applyTheme(theme);
                card.querySelectorAll('#theme-toggle button').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            });
        });

        card.querySelector('#thousands-sep').addEventListener('change', (e) => {
            setThousandsSeparator(e.target.value);
            // Re-render so this page's own numbers (sync heights, block info)
            // reflect the choice immediately; other pages pick it up on their
            // next poll tick or remount.
            render();
        });
    }

    // ── Node Connection ──

    function renderNodeSection() {
        const card = document.createElement('div');
        card.className = 'panel';

        const isConn = state.isConnected;
        const dot = isConn ? '\u{1F7E2}' : '\u{1F534}';
        const statusText = isConn ? 'Connected' : 'Disconnected';
        const nodeURL = settings.nodeURL || state.nodeURL || 'https://localhost:8783';
        const connChainId = nodeInfo.chainId || state.chainId || '';
        const authMode = settings.authMode || 'none';
        const fingerprint = settings.tlsFingerprint || 'Not available';

        card.innerHTML = `
            <div class="panel-header">Node Connection</div>
            <div class="panel-body">
                <div class="settings-row">
                    <span class="settings-label">Status</span>
                    <span>${dot} ${esc(statusText)}${isConn && connChainId ? ` &mdash; <span class="mono" style="font-weight:600">${esc(connChainId)}</span>` : ''}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Node URL</span>
                    <span class="mono" style="font-size: var(--font-size-sm)">${esc(nodeURL)}</span>
                </div>
                <div class="settings-row settings-edit-row">
                    <input type="text" class="input" id="settings-node-url" value="${escAttr(nodeURL)}" placeholder="https://host:8783" aria-label="Node URL" enterkeyhint="done" />
                    <button class="btn btn-secondary" id="settings-test-btn">Test Connection</button>
                </div>
                <div id="settings-conn-result" style="margin-top: var(--gap-xs)"></div>
                <div class="settings-row">
                    <span class="settings-label">Auth Mode</span>
                    <span>${esc(authMode)}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">TLS Fingerprint</span>
                    <span class="mono" style="font-size: var(--font-size-xs); word-break: break-all">${esc(fingerprint)}</span>
                </div>
                <div class="settings-actions">
                    ${isConn
                        ? '<button class="btn btn-secondary" id="settings-disconnect-btn">Disconnect</button>'
                        : '<button class="btn btn-primary" id="settings-connect-btn">Connect</button>'
                    }
                </div>
            </div>
        `;
        root.appendChild(card);

        // Wire event handlers
        const testBtn = card.querySelector('#settings-test-btn');
        const urlInput = card.querySelector('#settings-node-url');
        const resultDiv = card.querySelector('#settings-conn-result');

        if (testBtn) {
            testBtn.addEventListener('click', async () => {
                const url = urlInput.value.trim();
                if (!url) return;
                testBtn.disabled = true;
                testBtn.textContent = 'Testing\u2026';
                resultDiv.innerHTML = '';
                try {
                    const info = await Bridge.call('noble_app', 'testConnection', { url });
                    resultDiv.setAttribute('role', 'status');
                    const chainId = info.chainId || '';
                    const height = info.blockHeight ? ` \u00B7 Block ${groupThousands(Number(info.blockHeight))}` : '';
                    // A probe result, not a connection state \u2014 say what it means.
                    resultDiv.innerHTML = `<span style="color: var(--success)">\u2713 Node reachable</span>`
                        + (chainId ? `<div style="margin-top:var(--gap-xs);font-size:var(--font-size-sm)"><span style="color:var(--text-muted)">Chain:</span> <span class="mono" style="font-weight:600">${esc(chainId)}</span>${height}</div>` : '');
                } catch (e) {
                    resultDiv.setAttribute('role', 'alert');
                    resultDiv.innerHTML = `<span style="color: var(--error)">Failed: ${esc(e.message || 'Unknown error')}</span>`;
                } finally {
                    testBtn.disabled = false;
                    testBtn.textContent = 'Test Connection';
                }
            });
        }

        const disconnBtn = card.querySelector('#settings-disconnect-btn');
        if (disconnBtn) {
            disconnBtn.addEventListener('click', async () => {
                await Bridge.call('noble_app', 'disconnectNode');
                // Route through updateState (not direct mutation) so the chain
                // bar, nav, and page cache all react; _userDisconnected keeps
                // the "Reconnecting…" banner honest — a deliberate disconnect
                // is not an outage.
                if (window.App) {
                    window.App.updateState({ isConnected: false, _userDisconnected: true });
                }
            });
        }

        const connBtn = card.querySelector('#settings-connect-btn');
        if (connBtn) {
            connBtn.addEventListener('click', async () => {
                const url = urlInput.value.trim();
                if (!url) return;
                connBtn.disabled = true;
                connBtn.textContent = 'Connecting\u2026';
                // Clear the deliberate-disconnect flag: connecting is an
                // explicit act, so automatic reconnection is welcome again.
                if (window.App) window.App.updateState({ _userDisconnected: false });
                try {
                    await Bridge.call('noble_app', 'saveSettings', { nodeURL: url });
                    // The REAL connect: rebuilds the native client and starts
                    // polling (testConnection is only a probe and must never be
                    // used here). Mac returns {connected:bool} and schedules its
                    // own 10s retries on failure; WRY rejects the promise and
                    // its reconnect loop keeps dialing. On success the native
                    // layer pushes isConnected:true, which clears the banner
                    // and re-renders this page through updateState.
                    const res = await Bridge.call('noble_app', 'connectToNode', { url });
                    if (res && res.connected === false) {
                        throw new Error('Could not connect \u2014 automatic retries are running.');
                    }
                    await loadSettings();
                } catch (e) {
                    const res = card.querySelector('#settings-conn-result');
                    if (res) res.innerHTML = `<span style="color: var(--error)">${esc(e.message || 'Connection failed')}</span>`;
                    connBtn.disabled = false;
                    connBtn.textContent = 'Connect';
                }
            });
        }
    }

    // ── Wallet ──

    function renderWalletSection() {
        const card = document.createElement('div');
        card.className = 'panel';

        const addr = state.walletAddress || '';
        const hasWallet = state.hasWallet;

        let body = '';
        if (!hasWallet) {
            body = `<div class="empty-inline">No wallet configured. Set up a wallet during onboarding.</div>`;
        } else {
            body = `
                <div class="settings-row">
                    <span class="settings-label">Scheme</span>
                    <span>secp256k1</span>
                </div>
                <div class="settings-row" style="flex-wrap:wrap">
                    <span class="settings-label">Noble Address</span>
                    <span class="mono" style="font-size:var(--font-size-xs);word-break:break-all;flex:1;text-align:right" id="settings-noble-addr"></span>
                    <button class="btn-icon" id="settings-copy-noble" title="Copy Noble address" style="margin-left:4px;cursor:pointer;background:none;border:none;color:var(--text-muted);font-size:1rem">\u{1F4CB}</button>
                </div>
                <div class="settings-row" style="flex-wrap:wrap" id="settings-btc-row" style="display:none">
                    <span class="settings-label">Bitcoin Address</span>
                    <span class="mono" style="font-size:var(--font-size-xs);word-break:break-all;flex:1;text-align:right" id="settings-btc-addr"></span>
                    <button class="btn-icon" id="settings-copy-btc" title="Copy Bitcoin address" style="margin-left:4px;cursor:pointer;background:none;border:none;color:var(--text-muted);font-size:1rem">\u{1F4CB}</button>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Storage</span>
                    <span>\u{1F512} ${esc(walletStorageLabel(state.platform))}</span>
                </div>
                ${isWryPlatform(state.platform) ? `<div class="settings-row" style="margin-top:var(--gap-sm)">
                    <button id="settings-reveal-phrase" class="btn btn-sm btn-secondary" style="width:100%">Reveal recovery phrase</button>
                </div>` : ''}
                <div id="settings-wallet-qr" style="text-align: center; margin-top: var(--gap-sm)"></div>
            `;
        }

        card.innerHTML = `
            <div class="panel-header">Wallet</div>
            <div class="panel-body">
                ${body}
                ${hasWallet ? `<div class="settings-row" style="margin-top:var(--gap-sm)">
                    <button id="settings-utxo-manage" class="btn btn-sm" style="width:100%">UTXO Management</button>
                </div>` : ''}
            </div>
        `;
        root.appendChild(card);

        // UTXO Management link
        card.querySelector('#settings-utxo-manage')?.addEventListener('click', () => {
            if (window.App) App.navigateTo('utxo-maintenance');
        });

        // Reveal recovery phrase (WRY only — uses the native exportWallet handler).
        card.querySelector('#settings-reveal-phrase')?.addEventListener('click', () => {
            revealRecoveryPhrase();
        });

        if (hasWallet && addr) {
            // Noble address — full, no trimming
            const nobleSlot = card.querySelector('#settings-noble-addr');
            if (nobleSlot) nobleSlot.textContent = addr;

            // Copy Noble address
            const copyNoble = card.querySelector('#settings-copy-noble');
            if (copyNoble) {
                copyNoble.addEventListener('click', () => {
                    Bridge.call('noble_app', 'copyToClipboard', { text: addr });
                    copyNoble.textContent = '\u2713';
                    setTimeout(() => { copyNoble.textContent = '\u{1F4CB}'; }, 1200);
                });
            }

            // Bitcoin address (if available in state)
            const btcAddr = state.bitcoinAddress || '';
            const btcRow = card.querySelector('#settings-btc-row');
            if (btcAddr && btcRow) {
                btcRow.style.display = '';
                const btcSlot = card.querySelector('#settings-btc-addr');
                if (btcSlot) btcSlot.textContent = btcAddr;
                const copyBtc = card.querySelector('#settings-copy-btc');
                if (copyBtc) {
                    copyBtc.addEventListener('click', () => {
                        Bridge.call('noble_app', 'copyToClipboard', { text: btcAddr });
                        copyBtc.textContent = '\u2713';
                        setTimeout(() => { copyBtc.textContent = '\u{1F4CB}'; }, 1200);
                    });
                }
            } else if (btcRow) {
                btcRow.style.display = 'none';
            }

            // QR code
            const qrSlot = card.querySelector('#settings-wallet-qr');
            if (qrSlot) renderQR(qrSlot, addr, 180);
        }
    }

    /** WRY-only: reveal the wallet recovery phrase via the native exportWallet
     *  handler, behind a "someone could be watching" confirmation. */
    async function revealRecoveryPhrase() {
        const { el, close } = openModal({ title: 'Recovery phrase' });
        el.innerHTML = `
            <p style="color:var(--error,#e5484d);font-weight:600;margin:0 0 0.75rem">
                Anyone who sees these words can steal your funds.
            </p>
            <p style="color:var(--text-muted);margin:0 0 1.25rem">
                Make sure no one is watching your screen before continuing.
            </p>
            <div style="display:flex;gap:0.5rem">
                <button id="rp-cancel" class="btn" style="flex:1">Cancel</button>
                <button id="rp-reveal" class="btn btn-primary" style="flex:1">Reveal phrase</button>
            </div>`;
        el.querySelector('#rp-cancel').addEventListener('click', close);
        el.querySelector('#rp-reveal').addEventListener('click', async () => {
            el.innerHTML = `<p style="color:var(--text-muted);text-align:center;padding:1rem">Loading…</p>`;
            let words = [];
            try {
                const res = await Bridge.call('noble_app', 'exportWallet');
                const m = res && res.mnemonic;
                words = Array.isArray(m) ? m : String(m || '').trim().split(/\s+/).filter(Boolean);
            } catch (e) {
                el.innerHTML = `<p style="color:var(--error,#e5484d)">Could not load recovery phrase: ${esc(e.message || String(e))}</p>`;
                return;
            }
            if (!words.length) {
                el.innerHTML = `<p style="color:var(--error,#e5484d)">No recovery phrase is available for this wallet.</p>`;
                return;
            }
            const grid = words.map((w, i) =>
                `<div style="display:flex;gap:0.4rem;align-items:baseline;padding:0.35rem 0.5rem;background:var(--bg-secondary,rgba(128,128,128,0.08));border-radius:6px">
                    <span style="color:var(--text-muted);font-size:0.75rem;min-width:1.2em;text-align:right">${i + 1}</span>
                    <span style="font-family:var(--font-mono,monospace);font-weight:600">${esc(w)}</span>
                </div>`
            ).join('');
            el.innerHTML = `
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:0.4rem;text-align:left;margin-bottom:1rem">${grid}</div>
                <div style="display:flex;gap:0.5rem">
                    <button id="rp-copy" class="btn" style="flex:1">Copy phrase</button>
                    <button id="rp-done" class="btn btn-primary" style="flex:1">Done</button>
                </div>`;
            el.querySelector('#rp-copy').addEventListener('click', () => {
                Bridge.call('noble_app', 'copyToClipboard', { text: words.join(' ') }).catch(() => {});
            });
            el.querySelector('#rp-done').addEventListener('click', close);
        });
    }

    // ── Identity & Signing ──

    function renderIdentitySection() {
        const card = nobleCard('Identity & Signing', '');
        const body = card.querySelector('.panel-body');

        const desc = document.createElement('p');
        desc.style.cssText = 'color:var(--text-secondary);font-size:var(--font-size-sm);margin:0 0 var(--gap)';
        desc.textContent = 'Manage your signing certificates for document authentication. Import PKCS#12 (.p12) corporate certificates or generate Noble-native signing keys.';
        body.appendChild(desc);

        const keyList = document.createElement('div');
        keyList.id = 'identity-key-list';
        body.appendChild(keyList);

        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:var(--gap-sm);flex-wrap:wrap;margin-top:var(--gap)';

        const importBtn = document.createElement('button');
        importBtn.className = 'btn btn-primary';
        importBtn.textContent = 'Import .p12 Certificate';
        importBtn.addEventListener('click', async () => {
            // On WRY, collect the password in-WebUI first; on Mac/iOS the native
            // handler prompts (password stays undefined → no params passed).
            const password = await promptP12Password(state.platform);
            if (password === null) return; // cancelled on WRY
            importBtn.disabled = true;
            importBtn.textContent = 'Importing...';
            try {
                const params = password === undefined ? undefined : { password };
                const result = await Bridge.call('noble_security', 'importPKCS12', params);
                if (result && result.id) loadIdentityKeys();
            } catch (e) {
                // "cancelled" = user closed the file picker; anything else is a
                // real failure whose message carries actionable guidance (wrong
                // password, legacy encryption re-export command, RSA rejection).
                const msg = (e && e.message) || String(e);
                console.error('PKCS#12 import failed:', msg);
                if (msg !== 'cancelled') alert('PKCS#12 import failed:\n' + msg);
            }
            importBtn.disabled = false;
            importBtn.textContent = 'Import .p12 Certificate';
        });
        actions.appendChild(importBtn);

        const genBtn = document.createElement('button');
        genBtn.className = 'btn btn-secondary';
        genBtn.textContent = 'Generate Signing Key';
        genBtn.addEventListener('click', async () => {
            genBtn.disabled = true;
            genBtn.textContent = 'Generating...';
            try {
                const result = await Bridge.call('noble_security', 'generateSigningKey');
                if (result && result.id) loadIdentityKeys();
            } catch (e) {
                console.error('Key generation failed:', e);
            }
            genBtn.disabled = false;
            genBtn.textContent = 'Generate Signing Key';
        });
        actions.appendChild(genBtn);

        body.appendChild(actions);
        root.appendChild(card);

        loadIdentityKeys();

        async function loadIdentityKeys() {
            try {
                const myCard = await Bridge.call('noble_security', 'getMyCard');
                const keys = myCard?.signingKeys || [];
                renderKeyList(keys);
            } catch {
                keyList.innerHTML = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">Could not load signing keys.</p>';
            }
        }

        function renderKeyList(keys) {
            keyList.innerHTML = '';
            if (keys.length === 0) {
                keyList.innerHTML = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">No signing keys configured. Import a .p12 certificate or generate a Noble-native key to sign document metadata.</p>';
                return;
            }
            for (const sk of keys) {
                const row = document.createElement('div');
                row.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm);padding:var(--gap-sm);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:var(--gap-xs)';

                const info = document.createElement('div');
                info.style.flex = '1';
                const algo = sk.algorithm === 'p256' ? 'P-256 (Corporate)' : 'secp256k1 (Noble)';
                const algoBadge = sk.algorithm === 'p256'
                    ? '<span style="font-size:0.6rem;padding:1px 5px;border-radius:var(--radius-sm);background:color-mix(in srgb, var(--accent) 15%, transparent);color:var(--accent)">P-256</span>'
                    : '<span style="font-size:0.6rem;padding:1px 5px;border-radius:var(--radius-sm);background:color-mix(in srgb, var(--success) 15%, transparent);color:var(--success)">secp256k1</span>';
                const subject = sk.certificateSubject ? `<div style="font-size:var(--font-size-xs);color:var(--text-secondary)">${esc(sk.certificateSubject)}</div>` : '';
                const pkHex = sk.publicKeyHex ? sk.publicKeyHex.slice(0, 12) + '...' : '';
                info.innerHTML = `
                    <div style="display:flex;align-items:center;gap:var(--gap-xs)">
                        <strong style="font-size:var(--font-size-sm)">${esc(sk.label || 'Signing Key')}</strong>
                        ${algoBadge}
                    </div>
                    ${subject}
                    <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${esc(pkHex)}</div>
                `;
                row.appendChild(info);

                const removeBtn = document.createElement('button');
                removeBtn.className = 'btn btn-sm';
                removeBtn.textContent = 'Remove';
                removeBtn.style.cssText = 'color:var(--error);border-color:var(--error)';
                removeBtn.addEventListener('click', async () => {
                    if (!confirm('Remove this signing key? The private key will be permanently deleted from secure storage.')) return;
                    try {
                        await Bridge.call('noble_security', 'removeSigningKey', { keyId: sk.id });
                        loadIdentityKeys();
                    } catch (e) {
                        console.error('Remove key failed:', e);
                    }
                });
                row.appendChild(removeBtn);

                keyList.appendChild(row);
            }
        }
    }

    // ── Blockchain Info ──

    function renderBlockchainSection() {
        const card = document.createElement('div');
        card.className = 'panel';

        const height = syncStatus.currentHeight || nodeInfo.blockHeight || state.blockHeight || 0;
        const synced = syncStatus.synced !== undefined ? syncStatus.synced : true;
        const highestKnown = syncStatus.highestKnown || height;
        const phase = cycleStatus.phase || 'Unknown';
        const cycleNum = cycleStatus.cycle || cycleStatus.cycleNumber || 0;
        const timeRemaining = cycleStatus.timeRemaining || cycleStatus.phaseRemainingSecs || 0;
        const peers = networkInfo.peer_count || networkInfo.total || 0;
        const inbound = networkInfo.inbound || 0;
        const outbound = networkInfo.outbound || 0;

        const chainIdStr = nodeInfo.chainId || state.chainId || '';
        card.innerHTML = `
            <div class="panel-header">Blockchain Info</div>
            <div class="panel-body">
                ${chainIdStr ? `<div class="settings-row">
                    <span class="settings-label">Chain ID</span>
                    <span class="mono" style="font-weight:600">${esc(chainIdStr)}</span>
                </div>` : ''}
                <div class="settings-row">
                    <span class="settings-label">Block Height</span>
                    <span class="mono">${groupThousands(Number(height))}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Sync Status</span>
                    <span id="settings-sync-badge"></span>
                </div>
                ${!synced ? `<div class="settings-row">
                    <span class="settings-label">Highest Known</span>
                    <span class="mono">${groupThousands(Number(highestKnown))}</span>
                </div>` : ''}
                <div class="settings-row">
                    <span class="settings-label">Cycle</span>
                    <span>#${cycleNum} &mdash; ${esc(phase)}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Phase Remaining</span>
                    <span>${formatSeconds(timeRemaining)}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Peers</span>
                    <span>${peers} (${inbound} in / ${outbound} out)</span>
                </div>
                <div class="settings-actions">
                    <button class="btn btn-secondary" id="settings-refresh-chain">Refresh</button>
                </div>
                <div class="settings-row" style="color: var(--text-muted); font-size: var(--font-size-sm)"
                    Last updated: <span id="settings-last-updated">${new Date().toLocaleTimeString()}</span>
                </div>
            </div>
        `;
        root.appendChild(card);

        // Sync badge
        const badgeSlot = card.querySelector('#settings-sync-badge');
        if (badgeSlot) badgeSlot.appendChild(statusBadge(synced ? 'Synced' : 'Syncing'));

        // Refresh button
        const refreshBtn = card.querySelector('#settings-refresh-chain');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', async () => {
                refreshBtn.disabled = true;
                refreshBtn.textContent = 'Refreshing\u2026';
                await loadSettings();
                refreshBtn.disabled = false;
                refreshBtn.textContent = 'Refresh';
            });
        }
    }

    // ── Security ──

    function renderSecuritySection() {
        const card = document.createElement('div');
        card.className = 'panel';

        const lockEnabled = securitySettings.appLockEnabled || false;
        const timeout = securitySettings.lockTimeout || 300;
        const reAuth = securitySettings.reAuthForSends !== undefined ? securitySettings.reAuthForSends : true;

        const timeoutOptions = [
            { value: 60, label: '1 minute' },
            { value: 300, label: '5 minutes' },
            { value: 900, label: '15 minutes' },
            { value: 0, label: 'Never' },
        ];
        const optionsHTML = timeoutOptions.map(o =>
            `<option value="${o.value}" ${o.value === timeout ? 'selected' : ''}>${o.label}</option>`
        ).join('');

        card.innerHTML = `
            <div class="panel-header">Security</div>
            <div class="panel-body">
                <div class="settings-row">
                    <span class="settings-label">App Lock (Biometric/PIN)</span>
                    <label class="toggle">
                        <input type="checkbox" id="settings-applock" ${lockEnabled ? 'checked' : ''} />
                        <span class="toggle-label">${lockEnabled ? 'Enabled' : 'Disabled'}</span>
                    </label>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Lock Timeout</span>
                    <select class="input input-sm" id="settings-lock-timeout">${optionsHTML}</select>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Re-auth for Sends</span>
                    <label class="toggle">
                        <input type="checkbox" id="settings-reauth" ${reAuth ? 'checked' : ''} />
                        <span class="toggle-label">${reAuth ? 'Required' : 'Not required'}</span>
                    </label>
                </div>
                <div class="settings-actions">
                    <button class="btn btn-secondary" id="settings-save-security">Save Security Settings</button>
                </div>
            </div>
        `;
        root.appendChild(card);

        // Toggle label updates
        const lockCheck = card.querySelector('#settings-applock');
        if (lockCheck) {
            lockCheck.addEventListener('change', () => {
                lockCheck.nextElementSibling.textContent = lockCheck.checked ? 'Enabled' : 'Disabled';
            });
        }
        const reAuthCheck = card.querySelector('#settings-reauth');
        if (reAuthCheck) {
            reAuthCheck.addEventListener('change', () => {
                reAuthCheck.nextElementSibling.textContent = reAuthCheck.checked ? 'Required' : 'Not required';
            });
        }

        // Save
        const saveBtn = card.querySelector('#settings-save-security');
        if (saveBtn) {
            saveBtn.addEventListener('click', async () => {
                const appLockEnabled = card.querySelector('#settings-applock')?.checked || false;
                const lockTimeout = parseInt(card.querySelector('#settings-lock-timeout')?.value || '300');
                const reAuthForSends = card.querySelector('#settings-reauth')?.checked || false;
                saveBtn.disabled = true;
                saveBtn.textContent = 'Saving\u2026';
                try {
                    await Bridge.call('noble_app', 'saveSecuritySettings', {
                        appLockEnabled, lockTimeout, reAuthForSends
                    });
                    saveBtn.textContent = 'Saved!';
                    setTimeout(() => { saveBtn.textContent = 'Save Security Settings'; saveBtn.disabled = false; }, 1200);
                } catch {
                    saveBtn.textContent = 'Save Security Settings';
                    saveBtn.disabled = false;
                }
            });
        }
    }

    // ── Backup & Restore ──

    function renderBackupSection() {
        const card = document.createElement('div');
        card.className = 'panel';
        card.innerHTML = `
            <div class="panel-header">Backup & Restore</div>
            <div class="panel-body">
                <div class="settings-row">
                    <span class="settings-label">Contacts</span>
                    <span id="settings-contact-count">Loading\u2026</span>
                </div>
                <div class="settings-actions">
                    <button class="btn btn-secondary" id="settings-export-vcf">Export Contacts (VCF)</button>
                    <button class="btn btn-secondary" id="settings-import-vcf">Import Contacts (VCF)</button>
                </div>
            </div>
        `;
        root.appendChild(card);

        // Load contact count
        Bridge.call('noble_storage', 'getContacts').then(data => {
            const countEl = card.querySelector('#settings-contact-count');
            if (countEl) countEl.textContent = `${(data.contacts || []).length} contacts`;
        }).catch(() => {
            const countEl = card.querySelector('#settings-contact-count');
            if (countEl) countEl.textContent = '0 contacts';
        });

        // Export VCF
        const exportBtn = card.querySelector('#settings-export-vcf');
        if (exportBtn) {
            exportBtn.addEventListener('click', async () => {
                try {
                    const result = await Bridge.call('noble_storage', 'exportContactsVCF');
                    if (result.vcf) {
                        await Bridge.call('noble_app', 'saveFileDialog', {
                            data: result.vcf,
                            filename: 'noble-contacts.vcf',
                            type: 'text/vcard'
                        });
                    }
                } catch { /* handled by bridge */ }
            });
        }

        // Import VCF
        const importBtn = card.querySelector('#settings-import-vcf');
        if (importBtn) {
            importBtn.addEventListener('click', async () => {
                try {
                    const file = await Bridge.call('noble_app', 'openFileDialog', { types: ['vcf'] });
                    if (file && file.files && file.files.length) {
                        const text = await Bridge.call('noble_app', 'readFileText', { path: file.files[0].path });
                        await Bridge.call('noble_storage', 'importContactsVCF', { vcf: text.text });
                        await loadSettings(); // refresh count
                    }
                } catch { /* handled by bridge */ }
            });
        }
    }

    // ── Developer API ──

    function renderDeveloperApiSection() {
        const rpcEnabled = settings.rpcApiEnabled || false;
        const rpcPort = settings.rpcApiPort || 8788;
        const mcpEnabled = settings.mcpServerEnabled || false;
        const mcpPort = settings.mcpServerPort || 8789;

        const card = document.createElement('div');
        card.className = 'panel';
        card.innerHTML = `
            <div class="panel-header">Developer API</div>
            <div class="panel-body">
                <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
                    Enable local servers so external software can control this application.
                    Both bind to 127.0.0.1 (localhost only).
                </p>

                <div style="display:flex;flex-direction:column;gap:var(--gap)">
                    <div class="panel" style="padding:var(--gap-sm) var(--gap)">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--gap-xs)">
                            <strong style="font-size:var(--font-size-sm)">RPC API Server</strong>
                            <label class="toggle-switch">
                                <input type="checkbox" id="settings-rpc-enabled" ${rpcEnabled ? 'checked' : ''}>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap-xs)">
                            Plain JSON-RPC for scripts and automation.
                        </div>
                        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
                            <label style="font-size:var(--font-size-xs)">Port</label>
                            <input type="number" class="form-input" id="settings-rpc-port" value="${rpcPort}" min="1024" max="65535" style="width:100%;max-width:120px;font-size:var(--font-size-xs);padding:2px 6px">
                        </div>
                        <div style="margin-top:var(--gap-xs)">
                            <code style="font-size:var(--font-size-xs);color:var(--text-muted)">curl -X POST http://127.0.0.1:${rpcPort} -d '{"method":"noble.getBalance",...}'</code>
                        </div>
                    </div>

                    <div class="panel" style="padding:var(--gap-sm) var(--gap)">
                        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--gap-xs)">
                            <strong style="font-size:var(--font-size-sm)">MCP Server</strong>
                            <label class="toggle-switch">
                                <input type="checkbox" id="settings-mcp-enabled" ${mcpEnabled ? 'checked' : ''}>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap-xs)">
                            Model Context Protocol for AI agents (Claude Code, Cursor).
                            Provides tool discovery, resources, prompts, and notifications.
                        </div>
                        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
                            <label style="font-size:var(--font-size-xs)">Port</label>
                            <input type="number" class="form-input" id="settings-mcp-port" value="${mcpPort}" min="1024" max="65535" style="width:100%;max-width:120px;font-size:var(--font-size-xs);padding:2px 6px">
                        </div>
                    </div>
                </div>

                <button class="btn btn-primary" id="settings-save-api" style="margin-top:var(--gap);width:100%">Save API Settings</button>
            </div>
        `;
        root.appendChild(card);

        card.querySelector('#settings-save-api').addEventListener('click', async () => {
            const btn = card.querySelector('#settings-save-api');
            btn.disabled = true;
            btn.textContent = 'Saving...';
            try {
                await Bridge.call('noble_app', 'saveSettings', {
                    rpcApiEnabled: card.querySelector('#settings-rpc-enabled').checked,
                    rpcApiPort: parseInt(card.querySelector('#settings-rpc-port').value, 10) || 8788,
                    mcpServerEnabled: card.querySelector('#settings-mcp-enabled').checked,
                    mcpServerPort: parseInt(card.querySelector('#settings-mcp-port').value, 10) || 8789,
                });
                btn.textContent = 'Saved \u2713';
                setTimeout(() => { btn.textContent = 'Save API Settings'; btn.disabled = false; }, 1200);
            } catch (e) {
                btn.textContent = 'Save API Settings';
                btn.disabled = false;
            }
        });
    }

    // ── About ──

    function renderAboutSection() {
        const card = document.createElement('div');
        card.className = 'panel';

        const appVersion = settings.appVersion || '1.0.0';
        const nodeVersion = nodeInfo.version || 'N/A';

        card.innerHTML = `
            <div class="panel-header">About</div>
            <div class="panel-body">
                <div class="settings-row">
                    <span class="settings-label">App Version</span>
                    <span>${esc(appVersion)}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Node Version</span>
                    <span>${esc(nodeVersion)}</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Project</span>
                    <span>NOBLE Blockchain</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Copyright</span>
                    <span>&copy; 2026 InfiniteContext.com</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">License</span>
                    <span>Apache-2.0</span>
                </div>
                <div class="settings-row">
                    <span class="settings-label">Source</span>
                    <span>This software is open source (available at https://github.com/jpelayo/noble)</span>
                </div>
            </div>
        `;
        root.appendChild(card);
    }

    // ── Helpers ──

    function formatSeconds(s) {
        if (!s || s <= 0) return '--';
        const m = Math.floor(s / 60);
        const sec = s % 60;
        return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
    }

    function refresh(newState) {
        Object.assign(state, newState);
        // `state` and the incoming patch are the same shared appState object,
        // so field comparison can't detect changes — compare against what was
        // last RENDERED instead. Without this, a wallet address arriving after
        // mount (poll/heartbeat) leaves a stale "No wallet configured" panel
        // forever, because this page instance stays cached across navigation.
        if (alive && renderedWalletKey() !== lastRenderedWalletKey) render();
    }

    function renderedWalletKey() {
        return `${state.hasWallet}|${state.walletAddress || ''}|${state.isConnected}`;
    }

    return {
        destroy() { alive = false; },
        refresh
    };
}

