// NOBLE Document Client — Home Dashboard
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { amountText, formatAmount, formatSignedAmount } from '../components/amount-text.js';
import { statusBadge } from '../components/status-badge.js';
import { emptyState } from '../components/empty-state.js';
import { esc, timeAgo, showCopyFeedback } from '../utils.js';
import { txDisplayAmount, formatTxType, txStatusBadge } from '../tx-display.js';

export function init(root, ctx) {
    let alive = true;
    let loadRetries = 0;
    const state = ctx.state;

    if (!state.isConnected && state._confirmedDisconnected) {
        // Only show welcome screen when we have CONFIRMED the node is offline
        // (set by heartbeat after 2+ failures, never at boot)
        root.classList.add('page-content');
        const defaultSeed = 'https://node.infinitecontext.com:8783';
        const welcome = document.createElement('div');
        welcome.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:40vh;text-align:center;padding:var(--gap)';
        welcome.innerHTML = `
            <div style="font-size:64px;margin-bottom:var(--gap)">&#x2B22;</div>
            <h1 style="margin:0 0 8px">Welcome to Noble</h1>
            <p style="color:var(--text-secondary);margin:0 0 var(--gap-lg);max-width:400px">
                Document notarization on the blockchain. Connect to a node to get started, or configure your settings.
            </p>
            <div id="welcome-buttons" style="display:flex;flex-direction:column;gap:var(--gap-sm);align-items:center;width:100%;max-width:340px">
                <button id="welcome-connect" class="btn btn-primary" style="width:100%;padding:12px 24px;font-weight:600">
                    Connect to node.infinitecontext.com
                </button>
                <button id="welcome-settings" class="btn btn-secondary" style="width:100%;padding:10px 24px;font-size:var(--font-size-sm)">
                    Settings
                </button>
            </div>
            <p style="color:var(--text-muted);font-size:var(--font-size-xs);margin-top:var(--gap)">
                Run your own node or use the public seed at <strong>node.infinitecontext.com</strong>
            </p>
        `;
        root.appendChild(welcome);


        // Connect to default seed.
        welcome.querySelector('#welcome-connect').addEventListener('click', async () => {
            const btn = welcome.querySelector('#welcome-connect');
            btn.disabled = true;
            btn.textContent = 'Connecting...';
            try { await Bridge.call('noble_app', 'connectToNode', { url: defaultSeed }); }
            catch {
                btn.textContent = 'Connection failed';
                setTimeout(() => { btn.textContent = 'Connect to node.infinitecontext.com'; btn.disabled = false; }, 2000);
            }
        });

        // Settings.
        welcome.querySelector('#welcome-settings').addEventListener('click', () => {
            if (window.App) window.App.navigateTo('settings');
        });

        // Async: fetch saved settings to show reconnect button for previously configured node.
        Bridge.call('noble_app', 'getSettings').then(appSettings => {
            if (!alive || state.isConnected) return;
            const url = appSettings && appSettings.nodeURL;
            if (url && url !== defaultSeed) {
                const label = url.replace(/^https?:\/\//, '').replace(/:8783$/, '');
                const btns = welcome.querySelector('#welcome-buttons');
                const reconnectBtn = document.createElement('button');
                reconnectBtn.className = 'btn btn-primary';
                reconnectBtn.style.cssText = 'width:100%;padding:12px 24px;font-weight:600';
                reconnectBtn.textContent = 'Reconnect to ' + label;
                reconnectBtn.addEventListener('click', async () => {
                    reconnectBtn.disabled = true;
                    reconnectBtn.textContent = 'Connecting...';
                    try { await Bridge.call('noble_app', 'connectToNode', { url }); }
                    catch {
                        reconnectBtn.textContent = 'Connection failed';
                        setTimeout(() => { reconnectBtn.textContent = 'Reconnect to ' + label; reconnectBtn.disabled = false; }, 2000);
                    }
                });
                btns.insertBefore(reconnectBtn, btns.firstChild);
                // Demote default seed button to secondary.
                const seedBtn = welcome.querySelector('#welcome-connect');
                if (seedBtn) { seedBtn.className = 'btn'; seedBtn.style.cssText = 'width:100%;padding:12px 24px'; }
            }
        }).catch(() => {});

        return { destroy() { alive = false; }, refresh() {} };
    }

    root.classList.add('page-content');

    // Node alignment status card
    let lastBannerState = '';
    const alignmentBanner = document.createElement('div');
    alignmentBanner.id = 'home-alignment-banner';
    alignmentBanner.style.marginBottom = 'var(--gap)';
    root.appendChild(alignmentBanner);
    renderAlignmentBanner(alignmentBanner, state);

    // Hero balance card placeholder
    const balanceContainer = document.createElement('div');
    balanceContainer.setAttribute('aria-live', 'polite');
    root.appendChild(balanceContainer);

    // Two-column grid: Recent Activity (left, wide) + Quick Actions (right, narrow)
    const grid = document.createElement('div');
    grid.className = 'home-grid';
    const activityContainer = document.createElement('div');
    const actionsContainer = document.createElement('div');
    grid.appendChild(activityContainer);
    grid.appendChild(actionsContainer);
    root.appendChild(grid);

    // Skeletons
    balanceContainer.innerHTML = '<div class="skeleton skeleton-balance"></div>';
    activityContainer.innerHTML = '<div class="skeleton skeleton-section"></div>';
    actionsContainer.innerHTML = '<div class="skeleton skeleton-section"></div>';

    let loadInFlight = false;

    loadDashboard();

    async function loadDashboard() {
        if (!alive || loadInFlight) return;
        loadInFlight = true;
        const address = state.walletAddress;
        if (!address) {
            loadInFlight = false;
            balanceContainer.innerHTML = '';
            balanceContainer.appendChild(emptyState({
                icon: '\u{1F4B0}',
                title: 'No Wallet',
                subtitle: 'Set up a wallet to see your balance.'
            }));
            activityContainer.innerHTML = '';
            actionsContainer.innerHTML = '';
            return;
        }

        try {
            // Use atomic snapshot when available — single chain_height for consistency.
            let snapshot;
            try {
                snapshot = await Bridge.call('noble_api', 'getWalletSnapshot');
            } catch {
                const [balance, history] = await Promise.all([
                    Bridge.call('noble_api', 'getBalance', { address }),
                    Bridge.call('noble_api', 'getWalletTransactions')
                ]);
                snapshot = { ...balance, transactions: (history.transactions || []) };
            }
            if (!alive) return;

            const balance = snapshot;
            const txs = snapshot.transactions || [];
            renderHeroBalance(balanceContainer, balance, address);
            renderRecentActivity(activityContainer, txs);
            renderQuickActions(actionsContainer);
        } catch (err) {
            if (!alive) return;
            const msg = err.message.toLowerCase();
            const isOffline = msg.includes('timeout') || msg.includes('not connected') || msg.includes('ne-404');
            if (isOffline && loadRetries < 5) {
                // Node not ready yet — auto-retry silently (keep loading skeletons)
                loadRetries++;
                setTimeout(() => { if (alive) loadDashboard(); }, 3000);
                return;
            }
            // Genuine error or retries exhausted — show error card
            loadRetries = 0;
            balanceContainer.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = 'error-card';
            errDiv.setAttribute('role', 'alert');
            errDiv.innerHTML = isOffline
                ? `<p>Node offline. Check that your Noble node is running and reachable.</p><button type="button">Retry</button>`
                : `<p>${err.message}</p><button type="button">Retry</button>`;
            errDiv.querySelector('button').addEventListener('click', () => {
                loadRetries = 0;
                balanceContainer.innerHTML = '<div class="skeleton" style="height:200px;border-radius:var(--radius)"></div>';
                activityContainer.innerHTML = '<div class="skeleton" style="height:300px;border-radius:var(--radius)"></div>';
                actionsContainer.innerHTML = '';
                loadDashboard();
            });
            balanceContainer.appendChild(errDiv);
            activityContainer.innerHTML = '';
            actionsContainer.innerHTML = '';
        } finally {
            loadInFlight = false;
        }
    }

    // ── Stitch-inspired render functions ──

    function renderHeroBalance(container, balance, address) {
        container.innerHTML = '';
        const chainId = state.chainId || '';
        const el = document.createElement('div');
        el.className = 'home-hero-grid';

        // Hero balance card
        const heroHtml = `
            <div class="panel" style="padding:12px;min-height:0;display:flex;flex-direction:column;justify-content:space-between;position:relative;overflow:hidden">
                <div>
                    <div style="display:inline-block;padding:4px 12px;background:var(--accent-subtle);color:var(--accent);font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;border-radius:999px;margin-bottom:var(--gap-sm)">Total Balance</div>
                    <div style="display:flex;align-items:baseline;gap:8px;margin-top:4px">
                        <span style="color:var(--accent);font-size:var(--font-size-2xl);">\u25C6</span>
                        <span id="bal-total" class="mono" style="font-size:clamp(2rem, 4vw, 3rem);font-weight:800;letter-spacing:-0.02em">${formatAmount(balance.balance)}</span>
                        <span style="font-size:var(--font-size-lg);color:var(--text-muted);font-weight:600">NOBLE</span>
                    </div>
                </div>
                <div class="balance-breakdown">
                    <div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Available</div>
                        <div id="bal-available" class="mono" style="font-size:clamp(0.8rem, 3vw, 1.1rem);font-weight:600">${formatAmount(balance.available)}</div>
                    </div>
                    <div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Pending</div>
                        <div id="bal-pending" class="mono" style="font-size:clamp(0.8rem, 3vw, 1.1rem);font-weight:600;${balance.pending > 0 ? 'color:var(--warning)' : ''}">${balance.pending > 0 ? '\u2212' : ''}${formatAmount(balance.pending)}</div>
                    </div>
                    ${balance.immature_value > 0 ? `<div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Maturing</div>
                        <div id="bal-maturing" class="mono" style="font-size:clamp(0.8rem, 3vw, 1.1rem);font-weight:600;color:var(--warning)">${formatAmount(balance.immature_value)}</div>
                    </div>` : ''}
                </div>
                ${chainId ? `<div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-sm)">Chain: ${esc(chainId)}</div>` : ''}
            </div>`;

        // Right column: Address card
        const rightHtml = `
            <div style="display:flex;flex-direction:column;gap:var(--gap-lg)">
                <div class="panel" style="padding:var(--gap-lg);flex:1;display:flex;flex-direction:column;justify-content:center;cursor:pointer" id="home-address-card" title="Click to copy address">
                    <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);font-weight:700;margin-bottom:4px">Your Address</div>
                    <div class="mono" style="font-size:var(--font-size-sm);word-break:break-all">${address.slice(0, 12)}\u2026${address.slice(-8)}</div>
                </div>
            </div>`;

        el.innerHTML = heroHtml + rightHtml;
        container.appendChild(el);

        // Copy address
        const addrCard = container.querySelector('#home-address-card');
        if (addrCard) {
            addrCard.addEventListener('click', () => {
                Bridge.call('noble_app', 'copyToClipboard', { text: address });
                const label = addrCard.querySelector('div:last-child');
                if (label) showCopyFeedback(label, label.textContent);
            });
        }
    }

    function renderRecentActivity(container, txs) {
        container.innerHTML = '';
        const recent = txs.slice(0, 6);

        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.style.padding = '10px';

        // Header
        let html = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <h3 style="font-size:var(--font-size-lg);font-weight:700;margin:0">Recent Activity</h3>
            <a href="#" id="home-view-all" style="font-size:var(--font-size-sm);font-weight:600;color:var(--accent);text-decoration:none">View all</a>
        </div>`;

        if (recent.length === 0) {
            html += `<div style="text-align:center;padding:var(--gap-xl);color:var(--text-muted)">
                <div style="font-size:2rem;margin-bottom:var(--gap-sm)">\u{1F4CB}</div>
                <div>No activity yet</div>
            </div>`;
        } else {
            html += '<div style="display:flex;flex-direction:column;gap:4px">';
            for (const tx of recent) {
                const disp = txDisplayAmount(tx);
                const typeName = formatTxType(tx.tx_type ?? 0);
                const signedAmt = formatSignedAmount(disp.amount, disp.direction);
                const amtColor = disp.direction === 'outgoing' ? 'var(--warning)'
                               : disp.direction === 'incoming' ? 'var(--success)' : 'var(--text-primary)';
                const ago = timeAgo(tx.timestamp);
                const badge = txStatusBadge(tx.confirmations, tx.status);

                // Icon + background color per type
                let iconBg, iconColor, iconName;
                if (disp.direction === 'incoming') {
                    iconBg = 'color-mix(in srgb, var(--success) 12%, transparent)';
                    iconColor = 'var(--success)';
                    iconName = '\u2193'; // ↓
                } else if (tx.tx_type === 0x00 || tx.tx_type === 0x06 || tx.tx_type === 0x07) {
                    iconBg = 'color-mix(in srgb, var(--accent) 12%, transparent)';
                    iconColor = 'var(--accent)';
                    iconName = '\u{1F4C4}'; // doc
                } else {
                    iconBg = 'color-mix(in srgb, var(--warning) 12%, transparent)';
                    iconColor = 'var(--warning)';
                    iconName = '\u2191'; // ↑
                }

                const counterparty = tx.recipient ? esc(tx.recipient).slice(0, 20) : '';

                html += `<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 8px;border-radius:var(--radius);cursor:pointer;transition:background 0.15s" class="activity-row" data-txid="${esc(tx.txId || '')}">
                    <div style="display:flex;align-items:center;gap:8px">
                        <div style="width:28px;height:28px;border-radius:var(--radius-sm);background:${iconBg};display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:${iconColor};flex-shrink:0">${iconName}</div>
                        <div>
                            <div style="font-weight:600;font-size:var(--font-size-sm)">${typeName}</div>
                            <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${counterparty ? counterparty + ' \u00B7 ' : ''}${ago}</div>
                        </div>
                    </div>
                    <div style="text-align:right;flex-shrink:0;white-space:nowrap">
                        <div class="mono" style="font-weight:700;font-size:0.8rem;color:${amtColor}">${disp.amount > 0 ? '\u25C6 ' + signedAmt : ''}</div>
                        <div data-role="status" style="font-size:0.6rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.03em">${badge.html.replace(/<[^>]+>/g, '')}</div>
                    </div>
                </div>`;
            }
            html += '</div>';
        }

        panel.innerHTML = html;
        container.appendChild(panel);

        // Wire view-all
        const viewAll = panel.querySelector('#home-view-all');
        if (viewAll) viewAll.addEventListener('click', e => {
            e.preventDefault();
            if (window.App) window.App.navigateTo('payments');
        });

        // Wire activity rows → tx-detail
        panel.querySelectorAll('.activity-row').forEach(row => {
            row.addEventListener('mouseenter', () => { row.style.background = 'var(--accent-subtle)'; });
            row.addEventListener('mouseleave', () => { row.style.background = ''; });
            row.addEventListener('click', () => {
                const txid = row.dataset.txid;
                if (txid && window.App) window.App.navigateTo('tx-detail', { txid });
            });
        });
    }

    function renderQuickActions(container) {
        container.innerHTML = '';
        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.style.padding = '10px';

        const actions = [
            { label: 'Send', icon: '\u{1F680}', page: 'payments', color: 'var(--accent)' },
            { label: 'Register Document', icon: '\u{1F4DD}', page: 'documents', color: 'var(--text-primary)' },
            { label: 'Receive Noble', icon: '\u{1F4E5}', page: 'payments', color: 'var(--info)' },
            { label: 'Verify', icon: '\u2705', page: 'verify', color: 'var(--success)' },
        ];

        let html = '<h3 style="font-size:var(--font-size-lg);font-weight:700;margin:0 0 var(--gap-lg) 0">Quick Actions</h3>';
        html += '<div style="display:flex;flex-direction:column;gap:var(--gap-sm)">';
        for (const a of actions) {
            html += `<button class="quick-action-btn" data-page="${a.page}" style="width:100%;display:flex;align-items:center;justify-content:space-between;padding:var(--gap) var(--gap);background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:var(--radius);cursor:pointer;transition:all 0.15s;text-align:left;font:inherit;color:inherit">
                <div style="display:flex;align-items:center;gap:var(--gap)">
                    <div style="width:36px;height:36px;border-radius:50%;background:color-mix(in srgb, ${a.color} 12%, transparent);display:flex;align-items:center;justify-content:center;font-size:1rem">${a.icon}</div>
                    <span style="font-weight:600;font-size:var(--font-size-sm)">${a.label}</span>
                </div>
                <span style="color:var(--text-muted);font-size:1.2rem">\u203A</span>
            </button>`;
        }
        html += '</div>';

        panel.innerHTML = html;
        container.appendChild(panel);

        // Wire buttons
        panel.querySelectorAll('.quick-action-btn').forEach(btn => {
            btn.addEventListener('mouseenter', () => { btn.style.transform = 'translateX(2px)'; btn.style.borderColor = 'var(--accent)'; });
            btn.addEventListener('mouseleave', () => { btn.style.transform = ''; btn.style.borderColor = 'var(--glass-border)'; });
            btn.addEventListener('click', () => {
                if (window.App) window.App.navigateTo(btn.dataset.page);
            });
        });
    }


    return {
        destroy() { alive = false; },
        async refresh(newState) {
            Object.assign(state, newState);
            // Banner: only re-render if nodeState changed (avoids innerHTML wipe)
            const ns = state.nodeState || '';
            if (ns !== lastBannerState) { lastBannerState = ns; renderAlignmentBanner(alignmentBanner, state); }
            // Balance leaf-node updates — zero DOM mutation
            const fmt = formatAmount;
            const total = root.querySelector('#bal-total');
            if (total && newState.walletBalance != null) total.textContent = fmt(newState.walletBalance);
            const avail = root.querySelector('#bal-available');
            if (avail && newState.walletAvailable != null) avail.textContent = fmt(newState.walletAvailable);
            const pend = root.querySelector('#bal-pending');
            if (pend && newState.walletPending != null) {
                const v = newState.walletPending;
                pend.textContent = (v > 0 ? '\u2212' : '') + fmt(v);
            }
            const mat = root.querySelector('#bal-maturing');
            if (mat && newState.walletImmature != null) mat.textContent = fmt(newState.walletImmature);
            // Status badge updates — zero DOM mutation (leaf textContent only)
            try {
                const snap = await Bridge.call('noble_api', 'getWalletSnapshot');
                if (!alive) return;
                const txMap = new Map((snap.transactions || []).map(t => [t.txId || t.tx_id, t]));
                root.querySelectorAll('.activity-row').forEach(row => {
                    const tx = txMap.get(row.dataset.txid);
                    if (!tx) return;
                    const el = row.querySelector('[data-role="status"]');
                    if (el) {
                        const b = txStatusBadge(tx.confirmations, tx.status);
                        el.textContent = b.html.replace(/<[^>]+>/g, '');
                    }
                });
            } catch { /* silent — balance already updated */ }
        }
    };
}

/** Render a contextual status card based on node alignment state.
 *  Shown when connected but node is NOT fully aligned. */
function renderAlignmentBanner(container, state) {
    if (!state.isConnected) {
        container.innerHTML = '';
        return;
    }
    const ns = state.nodeState;
    if (!ns || ns === 'Aligned' || ns === 'Connected' || ns === 'Unknown' || ns === 'Isolated' || ns === 'Offline') {
        container.innerHTML = '';
        return;
    }
    const messages = {
        'Syncing': { text: 'Node is syncing with the network...', cls: 'warning' },
        'Catching Up': { text: 'Node is catching up with peers...', cls: 'warning' },
        'Diverged': { text: 'Node is on a minority fork. Healing in progress.', cls: 'warning' },
        'Bootstrapping': { text: 'Node is bootstrapping — waiting for peers.', cls: 'info' },
        'Creating': { text: 'Node is forming the initial chain.', cls: 'info' },
    };
    const info = messages[ns] || { text: `Node status: ${ns}`, cls: 'info' };
    container.innerHTML = `<div class="alignment-card alignment-${info.cls}">${info.text}</div>`;
}
