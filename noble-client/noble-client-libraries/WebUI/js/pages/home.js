// NOBLE Document Client — Home Dashboard
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { amountText, formatAmount } from '../components/amount-text.js';
import { statusBadge } from '../components/status-badge.js';
import { emptyState } from '../components/empty-state.js';
import { esc, timeAgo, showCopyFeedback } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    if (!state.isConnected) {
        root.appendChild(emptyState({
            icon: '\u{1F517}',
            title: 'Not Connected',
            subtitle: 'Connect to a NOBLE node to view your dashboard.'
        }));
        return { destroy() { alive = false; }, refresh() {} };
    }

    root.classList.add('page-content');

    // Page header
    const header = document.createElement('div');
    header.className = 'page-header';
    header.innerHTML = '<h1>Home</h1><p>Dashboard overview</p>';
    root.appendChild(header);

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

    loadDashboard();

    async function loadDashboard() {
        if (!alive) return;
        const address = state.walletAddress;
        if (!address) {
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
                Bridge.call('noble_api', 'getTransactionHistory', { address, page: 0, limit: 20 })
            ]);
            if (!alive) return;

            renderBalance(balanceContainer, balance, address);
            renderRecentDocs(docsContainer, history.transactions);
            renderRecentTxs(txsContainer, history.transactions);
        } catch (err) {
            if (!alive) return;
            balanceContainer.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = 'error-card';
            errDiv.setAttribute('role', 'alert');
            errDiv.innerHTML = `<p>${err.message}</p><button type="button">Retry</button>`;
            errDiv.querySelector('button').addEventListener('click', () => {
                balanceContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                docsContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                txsContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                loadDashboard();
            });
            balanceContainer.appendChild(errDiv);
            docsContainer.innerHTML = '';
            txsContainer.innerHTML = '';
        }
    }

    function renderBalance(container, balance, address) {
        container.innerHTML = '';
        const html = `
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Total Balance</div>
                    <div class="kpi-value">\u25C6 ${formatAmount(balance.balance)}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Available</div>
                    <div class="kpi-value">${formatAmount(balance.available)}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Pending</div>
                    <div class="kpi-value">${formatAmount(balance.pending)}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Address</div>
                    <button class="kpi-value" id="home-address" style="background:none;border:none;cursor:pointer;font:inherit;color:inherit;padding:0;font-size:var(--font-size-sm);" title="${address}">${address.slice(0, 8)}\u2026${address.slice(-8)}</button>
                </div>
            </div>
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
        const docs = txs.filter(t => t.type === 'notarization').slice(0, 5);

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
        const transfers = txs.filter(t => t.type !== 'notarization').slice(0, 5);

        if (transfers.length === 0) {
            const card = nobleCard('Recent Transactions', '');
            card.querySelector('.panel-body').appendChild(emptyState({
                icon: '\u{1F4B8}',
                title: 'No Transactions',
                subtitle: 'Send or receive NOBLE tokens.'
            }));
            container.appendChild(card);
            return;
        }

        let html = '<div class="table-scroll-wrapper"><table class="data-table"><thead><tr><th>Type</th><th>Amount</th><th>Time</th></tr></thead><tbody>';
        for (const tx of transfers) {
            const dir = tx.direction === 'incoming' ? '\u2199' : '\u2197';
            const typeLabel = tx.type.replace('_', ' ');
            const ago = timeAgo(tx.timestamp);
            html += `<tr>
                <td>${dir} ${typeLabel}</td>
                <td class="mono">\u25C6 ${formatAmount(tx.amount || 0)}</td>
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

    return {
        destroy() { alive = false; },
        refresh(newState) {
            Object.assign(state, newState);
        }
    };
}
