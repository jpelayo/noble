// NOBLE Document Client — Faucet Page
// Request coins from the NOBLE faucet.
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { emptyState } from '../components/empty-state.js';
import { formatAmount } from '../components/amount-text.js';
import { esc } from '../utils.js';

const COOLDOWN_KEY = 'noble.faucet.lastRequest';
const COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    if (!state.isConnected) {
        root.appendChild(emptyState({
            icon: '\u{1F517}',
            title: 'Not Connected',
            subtitle: 'Connect to a NOBLE node to use the faucet.'
        }));
        return { destroy() { alive = false; }, refresh() {} };
    }

    if (!state.walletAddress) {
        root.appendChild(emptyState({
            icon: '\u{1F4B0}',
            title: 'No Wallet',
            subtitle: 'Set up a wallet to request coins from the faucet.'
        }));
        return { destroy() { alive = false; }, refresh() {} };
    }

    root.classList.add('page-content');

    // Header
    const header = document.createElement('div');
    header.className = 'page-header';
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start';
    header.innerHTML = '<div><h1>Faucet</h1><p>Request coins for your wallet</p></div><button id="faucet-refresh" title="Refresh" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1">&#x21BB;</button>';
    root.appendChild(header);
    root.querySelector('#faucet-refresh').addEventListener('click', () => loadFaucetStatus());

    const container = document.createElement('div');
    root.appendChild(container);

    let requesting = false;
    let faucetInfo = null;
    let resultMsg = null;
    let errorMsg = null;
    let peerFaucets = [];

    render();
    loadFaucetStatus();
    loadPeerFaucets();

    function getCooldownRemaining() {
        const last = localStorage.getItem(COOLDOWN_KEY);
        if (!last) return 0;
        const elapsed = Date.now() - parseInt(last, 10);
        return Math.max(0, COOLDOWN_MS - elapsed);
    }

    function formatCooldown(ms) {
        const hours = Math.floor(ms / 3600000);
        const mins = Math.floor((ms % 3600000) / 60000);
        if (hours > 0) return `${hours}h ${mins}m`;
        return `${mins}m`;
    }

    async function loadFaucetStatus() {
        try {
            faucetInfo = await Bridge.call('noble_api', 'faucetStatus');
            if (alive) render();
        } catch {
            // Faucet may not be running — show request UI anyway
            if (alive) render();
        }
    }

    async function requestTokens() {
        if (requesting) return;
        const cooldown = getCooldownRemaining();
        if (cooldown > 0) {
            errorMsg = `Please wait ${formatCooldown(cooldown)} before requesting again.`;
            render();
            return;
        }

        requesting = true;
        resultMsg = null;
        errorMsg = null;
        localStorage.setItem(COOLDOWN_KEY, Date.now().toString());
        resultMsg = 'Request sent — verifying...';
        render();

        try {
            const res = await Bridge.call('noble_api', 'faucetRequest', {
                address: state.walletAddress
            });
            const txId = res.tx_id || res.txId || '';
            const amt = res.amount ? formatAmount(res.amount) : '';

            if (!txId) {
                resultMsg = res.message || 'Request accepted';
                requesting = false;
                if (alive) render();
                return;
            }

            const short = txId.length > 16 ? txId.slice(0, 8) + '\u2026' + txId.slice(-8) : txId;
            resultMsg = 'Coins sent! Checking mempool...';
            requesting = false;
            render();

            const pollId = setInterval(async () => {
                if (!alive) { clearInterval(pollId); return; }
                try {
                    const st = await Bridge.call('noble_api', 'getTransactionStatus', { txId });
                    if (st.status === 'pending' || st.status === 'confirmed') {
                        clearInterval(pollId);
                        resultMsg = `${amt} NOBLE on the way! (tx ${short})`;
                        if (alive) render();
                    }
                } catch { /* keep polling */ }
            }, 2000);
        } catch (e) {
            requesting = false;
            resultMsg = null;
            errorMsg = e.message || 'Faucet request failed.';
            localStorage.removeItem(COOLDOWN_KEY);
            if (alive) render();
        }
    }

    function render() {
        if (!alive) return;
        container.innerHTML = '';

        // Faucet request card
        const cooldown = getCooldownRemaining();
        const onCooldown = cooldown > 0;

        let cardHtml = '<div class="faucet-content">';

        // Info section
        cardHtml += '<div class="faucet-info">';
        cardHtml += '<div class="faucet-icon">\u{1F4A7}</div>';
        cardHtml += '<p class="faucet-desc">Request a small amount of NOBLE coins. Limited to <strong>one request per day</strong>.</p>';
        cardHtml += '</div>';

        // Faucet availability indicator
        if (faucetInfo) {
            const bal = faucetInfo.faucet_balance ?? faucetInfo.faucetBalance ?? 0;
            const drip = faucetInfo.drip_amount ?? faucetInfo.dripAmount ?? 0;
            const isDry = bal < drip;
            if (isDry) {
                cardHtml += `<div class="faucet-dry">
                    <span>\u{1F3DC}\uFE0F</span>
                    <span>The faucet is currently <strong>dry</strong>. Please try again later.</span>
                </div>`;
            } else {
                cardHtml += `<div class="faucet-available">
                    <span>\u2705</span>
                    <span>Faucet has coins available to distribute</span>
                </div>`;
            }

            // Drip amount
            const dripFmt = formatAmount(drip);
            cardHtml += `<div class="faucet-drip">
                <span class="faucet-drip-label">Amount per request</span>
                <span class="faucet-drip-value">\u25C6 ${dripFmt} NOBLE</span>
            </div>`;
        }

        // Address
        const addr = state.walletAddress;
        cardHtml += `<div class="faucet-field">
            <label>Receiving address</label>
            <div class="faucet-address mono">${addr.slice(0, 12)}\u2026${addr.slice(-12)}</div>
        </div>`;

        // Cooldown notice
        if (onCooldown) {
            cardHtml += `<div class="faucet-cooldown">
                <span class="faucet-cooldown-icon">\u23F3</span>
                <span>Next request available in <strong>${formatCooldown(cooldown)}</strong></span>
            </div>`;
        }

        // Check if faucet is dry
        const isDry = faucetInfo && (faucetInfo.faucet_balance ?? faucetInfo.faucetBalance ?? 0) < (faucetInfo.drip_amount ?? faucetInfo.dripAmount ?? 1);

        // Result message
        if (resultMsg) {
            cardHtml += `<div class="faucet-result faucet-result-success" role="status">
                <span>\u2705</span> <span>${esc(resultMsg)}</span>
            </div>`;
        }
        if (errorMsg) {
            cardHtml += `<div class="faucet-result faucet-result-error" role="alert">
                <span>\u274C</span> <span>${esc(errorMsg)}</span>
            </div>`;
        }

        // Request button
        const btnDisabled = onCooldown || requesting || isDry;
        const btnLabel = requesting ? 'Requesting\u2026'
            : isDry ? 'Faucet Dry'
            : onCooldown ? 'On Cooldown'
            : 'Request Coins';
        cardHtml += `<button class="btn btn-primary faucet-btn"
            ${btnDisabled ? 'disabled' : ''}>
            ${btnLabel}
        </button>`;

        cardHtml += '</div>';

        const card = nobleCard('Request Coins', cardHtml);
        const btn = card.querySelector('.faucet-btn');
        if (btn && !btnDisabled) {
            btn.addEventListener('click', requestTokens);
        }
        container.appendChild(card);

        // Faucet stats card (always shown)
        const statsHtml = faucetInfo
            ? buildStatsHtml(faucetInfo)
            : '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">Faucet service not detected. Start the faucet on this node or check Settings.</p>';
        const statsCard = nobleCard('Faucet Info', statsHtml);
        statsCard.style.marginTop = 'var(--gap)';
        container.appendChild(statsCard);

        // Peer faucets table (collapsible)
        renderPeerFaucets();
    }

    // ── Peer Faucets ──

    async function loadPeerFaucets() {
        try {
            const res = await Bridge.call('noble_api', 'getAvailableFaucets');
            peerFaucets = (res.faucets || [])
                .sort((a, b) => (b.faucet_balance || 0) - (a.faucet_balance || 0));
        } catch {
            peerFaucets = [];
        }
        if (alive) renderPeerFaucets();
    }

    function renderPeerFaucets() {
        let panel = container.querySelector('#faucet-peers-panel');
        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'faucet-peers-panel';
            panel.style.marginTop = 'var(--gap)';
            container.appendChild(panel);
        }

        const count = peerFaucets.length;
        const now = Date.now() / 1000;
        const STALE_THRESHOLD = 48 * 3600; // 48 hours

        let html = `<details class="panel" style="border:1px solid var(--border);border-radius:var(--radius)">
            <summary style="padding:var(--gap-sm) var(--gap);cursor:pointer;font-weight:600;font-size:var(--font-size-sm);user-select:none;list-style:none;display:flex;justify-content:space-between;align-items:center">
                <span>\u25B6 Faucets on This Chain (${count})</span>
            </summary>
            <div style="padding:0 var(--gap) var(--gap)">`;

        if (count === 0) {
            html += '<p style="color:var(--text-muted);font-size:var(--font-size-sm);margin:var(--gap-sm) 0 0">No peer faucets discovered yet. Faucets are discovered automatically from network peers.</p>';
        } else {
            html += `<div class="table-scroll-wrapper"><table class="data-table" style="font-size:var(--font-size-xs)">
                <thead><tr>
                    <th>Status</th><th>Balance</th><th>Drip</th><th>Address</th><th>Last Seen</th><th></th>
                </tr></thead><tbody>`;

            for (let i = 0; i < count; i++) {
                const f = peerFaucets[i];
                const bal = f.faucet_balance || 0;
                const drip = f.drip_amount || 0;
                const isOnline = f.last_probed && (now - f.last_probed) < STALE_THRESHOLD;
                const isDry = bal < drip;
                const statusBadge = isOnline
                    ? '<span class="badge" style="background:var(--success);color:#fff;font-size:0.7em">Online</span>'
                    : '<span class="badge" style="background:var(--text-muted);color:#fff;font-size:0.7em">Stale</span>';
                const balColor = isDry ? 'var(--error)' : 'var(--success)';
                const addr = f.faucet_address || '';
                const addrShort = addr.length > 20 ? addr.slice(0, 10) + '\u2026' + addr.slice(-8) : addr;
                const lastSeen = f.last_probed ? timeAgo(f.last_probed) : '--';
                const hopDisabled = isDry || !isOnline;
                const hopBtn = hopDisabled
                    ? '<span style="color:var(--text-muted)">\u2014</span>'
                    : `<button class="btn btn-sm faucet-hop-btn" data-idx="${i}" style="padding:2px 10px;font-size:var(--font-size-xs)">Hop</button>`;

                html += `<tr>
                    <td>${statusBadge}</td>
                    <td class="mono" style="color:${balColor}">${formatAmount(bal)} NOBLE</td>
                    <td class="mono">${formatAmount(drip)}</td>
                    <td class="mono" title="${esc(addr)}">${esc(addrShort)}</td>
                    <td>${lastSeen}</td>
                    <td id="faucet-hop-cell-${i}">${hopBtn}</td>
                </tr>`;
            }
            html += '</tbody></table></div>';
        }

        html += `<div style="margin-top:var(--gap-sm);text-align:center">
            <a href="#" id="faucet-back-local" style="font-size:var(--font-size-xs);color:var(--accent);text-decoration:none">\u2191 Back to local faucet</a>
        </div></div></details>`;

        panel.innerHTML = html;

        // Wire hop buttons
        panel.querySelectorAll('.faucet-hop-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const idx = parseInt(btn.dataset.idx, 10);
                const f = peerFaucets[idx];
                const cell = panel.querySelector(`#faucet-hop-cell-${idx}`);
                cell.innerHTML = '<span style="color:var(--text-muted)">Requesting\u2026</span>';
                try {
                    const res = await Bridge.call('noble_api', 'faucetHopRequest', {
                        url: f.url,
                        address: state.walletAddress,
                    });
                    const msg = res.message || `Received ${formatAmount(res.amount || 0)} NOBLE`;
                    cell.innerHTML = `<span style="color:var(--success);font-size:var(--font-size-xs)">\u2705 ${esc(msg)}</span>`;
                } catch (err) {
                    cell.innerHTML = `<span style="color:var(--error);font-size:var(--font-size-xs)">\u274C ${esc(err.message || 'Failed')}</span>`;
                }
            });
        });

        // Wire back-to-local link
        const backLink = panel.querySelector('#faucet-back-local');
        if (backLink) {
            backLink.addEventListener('click', e => {
                e.preventDefault();
                root.scrollTo({ top: 0, behavior: 'smooth' });
            });
        }
    }

    function timeAgo(unix) {
        const diff = Math.floor(Date.now() / 1000 - unix);
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }

    function buildStatsHtml(info) {
        const rows = [];

        if (info.distribution_count != null || info.distributionCount != null) {
            const count = info.distribution_count ?? info.distributionCount;
            rows.push(['Distributions', Number(count).toLocaleString()]);
        }
        if (info.daily_cap != null || info.dailyCap != null) {
            const cap = formatAmount(info.daily_cap ?? info.dailyCap);
            rows.push(['Daily Cap', `\u25C6 ${cap} NOBLE`]);
        }
        if (info.ip_cooldown_hours != null || info.ipCooldownHours != null) {
            const h = info.ip_cooldown_hours ?? info.ipCooldownHours;
            rows.push(['IP Cooldown', `${h} hours`]);
        }
        if (info.address_cooldown_hours != null || info.addressCooldownHours != null) {
            const h = info.address_cooldown_hours ?? info.addressCooldownHours;
            rows.push(['Address Cooldown', `${h / 24} days`]);
        }
        if (info.network) {
            rows.push(['Network', info.network]);
        }

        if (rows.length === 0) return '<p style="color:var(--text-muted)">No stats available</p>';

        let html = '<div class="faucet-stats">';
        for (const [label, value] of rows) {
            html += `<div class="faucet-stat-row">
                <span class="faucet-stat-label">${esc(label)}</span>
                <span class="faucet-stat-value">${value}</span>
            </div>`;
        }
        html += '</div>';
        return html;
    }

    // Auto-refresh every 30s
    const autoRefreshId = setInterval(() => { if (alive) { loadFaucetStatus(); loadPeerFaucets(); } }, 30_000);

    return {
        destroy() { alive = false; clearInterval(autoRefreshId); },
        refresh(newState) { Object.assign(state, newState); }
    };
}
