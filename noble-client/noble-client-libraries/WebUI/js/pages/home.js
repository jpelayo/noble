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
        welcome.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:60vh;text-align:center;padding:var(--gap)';
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

    // Page header
    const header = document.createElement('div');
    header.className = 'page-header';
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start';
    header.innerHTML = '<div><h1>Home</h1><p>Dashboard overview</p></div><button id="home-refresh" title="Refresh" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1">&#x21BB;</button>';
    root.appendChild(header);
    root.querySelector('#home-refresh').addEventListener('click', () => loadDashboard());

    // Node alignment status card (shown when node is not fully aligned)
    const alignmentBanner = document.createElement('div');
    alignmentBanner.id = 'home-alignment-banner';
    alignmentBanner.style.marginBottom = 'var(--gap)';
    root.appendChild(alignmentBanner);
    renderAlignmentBanner(alignmentBanner, state);

    // Balance card placeholder
    const balanceContainer = document.createElement('div');
    balanceContainer.style.marginBottom = 'var(--gap)';
    balanceContainer.setAttribute('aria-live', 'polite');
    root.appendChild(balanceContainer);

    // Quick actions
    const actionsCard = buildQuickActions();
    root.appendChild(actionsCard);

    // Split layout for recent docs + recent txs
    const split = document.createElement('div');
    split.className = 'split-layout';
    split.style.marginTop = 'var(--gap)';

    const docsContainer = document.createElement('div');
    const txsContainer = document.createElement('div');
    split.appendChild(docsContainer);
    split.appendChild(txsContainer);
    root.appendChild(split);

    // Show skeleton while loading
    balanceContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
    docsContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
    txsContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';

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
            docsContainer.innerHTML = '';
            txsContainer.innerHTML = '';
            return;
        }

        try {
            const [balance, history] = await Promise.all([
                Bridge.call('noble_api', 'getBalance', { address }),
                Bridge.call('noble_api', 'getWalletTransactions')
            ]);
            if (!alive) return;

            renderBalance(balanceContainer, balance, address);
            renderRecentDocs(docsContainer, history.transactions);
            renderRecentTxs(txsContainer, history.transactions);
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
                balanceContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                docsContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                txsContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                loadDashboard();
            });
            balanceContainer.appendChild(errDiv);
            docsContainer.innerHTML = '';
            txsContainer.innerHTML = '';
        } finally {
            loadInFlight = false;
        }
    }

    function renderBalance(container, balance, address) {
        container.innerHTML = '';
        const chainId = state.chainId || '';
        const html = `
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Total Balance</div>
                    <div class="kpi-value">\u25C6 ${formatAmount(balance.balance)}</div>
                    ${chainId ? `<div class="kpi-sub mono">Chain: ${esc(chainId)}</div>` : ''}
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Available</div>
                    <div class="kpi-value">${formatAmount(balance.available)}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Pending</div>
                    <div class="kpi-value"${balance.pending > 0 ? ' style="color:var(--warning)"' : ''}>${balance.pending > 0 ? '\u2212' : ''}${formatAmount(balance.pending)}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Address</div>
                    <button class="kpi-value" id="home-address" style="background:none;border:none;cursor:pointer;font:inherit;color:inherit;padding:0;font-size:var(--font-size-sm);" title="${address}">${address.slice(0, 8)}\u2026${address.slice(-8)}</button>
                </div>
            </div>
            <div class="chain-note">\u26A0\uFE0F Make sure you always work within the same chain your balance resides in. If you connect to a different chain, you cannot access your balance.</div>
        `;
        const card = nobleCard('Balance Summary', html);
        container.appendChild(card);

        // Copy address on click
        const addrEl = container.querySelector('#home-address');
        if (addrEl) {
            addrEl.addEventListener('click', () => {
                Bridge.call('noble_app', 'copyToClipboard', { text: address });
                const orig = addrEl.textContent;
                showCopyFeedback(addrEl, orig);
            });
        }
    }

    function renderRecentDocs(container, txs) {
        container.innerHTML = '';
        const docs = txs.filter(t => (t.tx_type === 0x00) || (t.type || '').toLowerCase() === 'notarization').slice(0, 5);

        if (docs.length === 0) {
            const card = nobleCard('Recent Documents', '');
            card.querySelector('.panel-body').appendChild(emptyState({
                icon: '\u{1F4C4}',
                title: 'No Documents',
                subtitle: 'Register your first document.'
            }));
            container.appendChild(card);
            return;
        }

        let html = '<div class="table-scroll-wrapper"><table class="data-table"><thead><tr><th>TX ID</th><th>Status</th><th>Time</th></tr></thead><tbody>';
        for (const tx of docs) {
            const ago = timeAgo(tx.timestamp);
            const status = tx.confirmations >= 6 ? 'confirmed' : 'pending';
            html += `<tr>
                <td class="mono" style="font-size:var(--font-size-xs)">${tx.txId.slice(0, 8)}\u2026${tx.txId.slice(-8)}</td>
                <td><span class="badge badge-${status}">${status}</span></td>
                <td style="font-size:var(--font-size-xs);color:var(--text-muted)">${ago}</td>
            </tr>`;
        }
        html += '</tbody></table></div>';

        const card = nobleCard('Recent Documents', html);

        // View all link
        const viewAll = document.createElement('div');
        viewAll.style.cssText = 'padding: var(--gap-sm) var(--gap); text-align: right;';
        viewAll.innerHTML = '<a href="#" style="font-size:var(--font-size-sm); color:var(--accent); text-decoration:none;">View All \u2192</a>';
        viewAll.querySelector('a').addEventListener('click', e => {
            e.preventDefault();
            Bridge.call('noble_app', 'navigateTo', { section: 'documents' });
        });
        card.appendChild(viewAll);
        container.appendChild(card);
    }

    function renderRecentTxs(container, txs) {
        container.innerHTML = '';
        // Show ALL transaction types — no filtering.
        const recent = txs.slice(0, 5);

        if (recent.length === 0) {
            const card = nobleCard('Recent Transactions', '');
            card.querySelector('.panel-body').appendChild(emptyState({
                icon: '\u{1F4B8}',
                title: 'No Transactions',
                subtitle: 'Send or receive NOBLE tokens.'
            }));
            container.appendChild(card);
            return;
        }

        let html = '<div class="table-scroll-wrapper"><table class="data-table"><thead><tr><th>Type</th><th>Amount</th><th>Status</th><th>Time</th></tr></thead><tbody>';
        for (const tx of recent) {
            const typeName = formatTxType(tx.tx_type);
            const disp = txDisplayAmount(tx);
            const signedAmt = formatSignedAmount(disp.amount, disp.direction);
            const amtColor = disp.direction === 'outgoing' ? 'color:var(--warning)'
                           : disp.direction === 'incoming' ? 'color:var(--success)' : '';
            const badge = txStatusBadge(tx.confirmations, tx.status);
            const ago = timeAgo(tx.timestamp);
            html += `<tr>
                <td style="font-size:var(--font-size-xs);font-weight:600">${typeName}</td>
                <td class="mono" style="${amtColor}">\u25C6 ${signedAmt}</td>
                <td><span class="badge ${badge.cls}" style="font-size:0.7em">${badge.html}</span></td>
                <td style="font-size:var(--font-size-xs);color:var(--text-muted)">${ago}</td>
            </tr>`;
        }
        html += '</tbody></table></div>';

        const card = nobleCard('Recent Transactions', html);

        const viewAll = document.createElement('div');
        viewAll.style.cssText = 'padding: var(--gap-sm) var(--gap); text-align: right;';
        viewAll.innerHTML = '<a href="#" style="font-size:var(--font-size-sm); color:var(--accent); text-decoration:none;">View All \u2192</a>';
        viewAll.querySelector('a').addEventListener('click', e => {
            e.preventDefault();
            Bridge.call('noble_app', 'navigateTo', { section: 'payments' });
        });
        card.appendChild(viewAll);
        container.appendChild(card);
    }

    function buildQuickActions() {
        const card = nobleCard('Quick Actions', '');
        const body = card.querySelector('.panel-body');
        const wrap = document.createElement('div');
        wrap.className = 'quick-actions';

        const actions = [
            { label: 'Register', section: 'documents', icon: '\u{1F4DD}' },
            { label: 'Verify', section: 'verify', icon: '\u2705' },
            { label: 'Send', section: 'payments', icon: '\u{1F4E4}' },
            { label: 'Receive', section: 'payments', icon: '\u{1F4E5}' },
        ];

        for (const a of actions) {
            const btn = document.createElement('button');
            btn.className = 'btn';
            btn.textContent = `${a.icon} ${a.label}`;
            btn.setAttribute('aria-label', a.label);
            btn.addEventListener('click', () => {
                Bridge.call('noble_app', 'navigateTo', { section: a.section });
            });
            wrap.appendChild(btn);
        }

        body.appendChild(wrap);
        return card;
    }

    // Auto-refresh every 30s
    const autoRefreshId = setInterval(() => { if (alive) loadDashboard(); }, 30_000);

    return {
        destroy() { alive = false; clearInterval(autoRefreshId); },
        refresh(newState) {
            Object.assign(state, newState);
            renderAlignmentBanner(alignmentBanner, state);
            loadDashboard();
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
