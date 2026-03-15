// NOBLE Document Client — Faucet Page
// Request test tokens from the NOBLE faucet (0.1 NOBLE per day limit).
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
            subtitle: 'Set up a wallet to request tokens.'
        }));
        return { destroy() { alive = false; }, refresh() {} };
    }

    root.classList.add('page-content');

    // Header
    const header = document.createElement('div');
    header.className = 'page-header';
    header.innerHTML = '<h1>Faucet</h1><p>Request test tokens for your wallet</p>';
    root.appendChild(header);

    const container = document.createElement('div');
    container.style.maxWidth = '520px';
    root.appendChild(container);

    let requesting = false;
    let faucetInfo = null;
    let resultMsg = null;
    let errorMsg = null;

    render();
    loadFaucetStatus();

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
        render();

        try {
            const res = await Bridge.call('noble_api', 'faucetRequest', {
                address: state.walletAddress
            });
            localStorage.setItem(COOLDOWN_KEY, Date.now().toString());
            resultMsg = res.message || `Received ${formatAmount(res.amount)} NOBLE`;
            requesting = false;
            if (alive) render();
        } catch (err) {
            errorMsg = err.message || 'Faucet request failed';
            requesting = false;
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
        cardHtml += '<p class="faucet-desc">Request a small amount of NOBLE tokens for testing. Limited to <strong>one request per day</strong>.</p>';
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
                    <span>Faucet has tokens available</span>
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
            : 'Request Tokens';
        cardHtml += `<button class="btn btn-primary faucet-btn"
            ${btnDisabled ? 'disabled' : ''}>
            ${btnLabel}
        </button>`;

        cardHtml += '</div>';

        const card = nobleCard('Request Tokens', cardHtml);
        const btn = card.querySelector('.faucet-btn');
        if (btn && !btnDisabled) {
            btn.addEventListener('click', requestTokens);
        }
        container.appendChild(card);

        // Faucet stats card (if available)
        if (faucetInfo) {
            const statsHtml = buildStatsHtml(faucetInfo);
            const statsCard = nobleCard('Faucet Info', statsHtml);
            statsCard.style.marginTop = 'var(--gap)';
            container.appendChild(statsCard);
        }
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

    return {
        destroy() { alive = false; },
        refresh(newState) { Object.assign(state, newState); }
    };
}
