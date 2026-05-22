// Shared fee-picker component used by every wallet flow that builds a
// transaction (transfer, notarization, locked doc, UTXO split/join).
//
// Three operator-honest choices replace the legacy Min/Recommended/High
// tiers (which were misleading — in Noble, fee does not determine
// proposal priority, only relay eligibility per validator):
//
//   1. Network rate     — median across peers' gossiped min_fee_rate
//                         plus a small visible buffer. Default.
//   2. Connected node   — this node's local min_fee_rate.
//   3. Custom           — numeric input, floor-enforced at MIN_RELAY_FEE_RATE.
//
// Public API:
//   buildFeeData(estimateResponse, txSize)         → feeData
//   renderFeePicker(container, feeData, choice, customRate, onChange)
//   getSelectedRate(choice, feeData, customRate)   → u64 g/B
//   getSelectedTotal(choice, feeData, customRate)  → u64 groats
//   validateCustomRate(rateInput, feeData)         → { valid, value, error, warning }
//
// State (choice, customRate) lives in the caller — this component is
// pure render. The onChange callback fires whenever the user picks a
// different tile or types a new value in the custom input.
//
// Worked examples (no JS test runner in this project; these double as
// the unit-test contract):
//
//   buildFeeData({ network_median_fee_rate: 3, local_min_fee_rate: 1 }, 200)
//     →  { networkRate: 4, networkMedian: 3, nodeRate: 1,
//          networkSource: 'peers', effectiveSize: 204,
//          networkFee: 816, nodeFee: 204, ... }
//
//   buildFeeData({}, 200)         // no peer data
//     →  networkSource: 'fallback', networkRate: 2 (local_min 1 + 1)
//
//   getSelectedRate('network', fd)        → 4
//   getSelectedRate('node',    fd)        → 1
//   getSelectedRate('custom',  fd, 7)     → 7
//   getSelectedRate('custom',  fd, 0)     → 1 (floor; selection invalid)
//
//   validateCustomRate(0, fd)
//     →  { valid: false, error: "Protocol minimum is 1 groat/byte..." }
//   validateCustomRate(2, fd)             // below median (3)
//     →  { valid: true, value: 2, warning: "Below network median (3 g/B)..." }
//   validateCustomRate(150, fd)
//     →  { valid: true, value: 150, warning: "That is a high rate..." }

import { formatAmount } from './amount-text.js';

export const MIN_RELAY_FEE_RATE = 1;

export function buildFeeData(estimateResponse, txSize) {
    const f = estimateResponse || {};
    const networkMedian = Number(f.networkMedianFeeRate ?? f.network_median_fee_rate ?? 0);
    const networkMin    = Number(f.networkMinFeeRate    ?? f.network_min_fee_rate    ?? 0);
    const localMin      = Number(f.localMinFeeRate      ?? f.local_min_fee_rate      ?? MIN_RELAY_FEE_RATE);

    // +2 % size safety margin (matches the previous calc).
    const margin = Math.ceil(txSize * 0.02);
    const effectiveSize = txSize + margin;

    // Network rate: median + 10 % (min +1). If no peer data, local floor + 1.
    let networkRate;
    let networkSource;
    if (networkMedian > 0) {
        const buffer = Math.max(1, Math.ceil(networkMedian * 0.10));
        networkRate = networkMedian + buffer;
        networkSource = 'peers';
    } else {
        networkRate = Math.max(localMin, MIN_RELAY_FEE_RATE) + 1;
        networkSource = 'fallback';
    }

    const nodeRate = Math.max(localMin, MIN_RELAY_FEE_RATE);

    return {
        networkRate,
        networkMedian,
        networkMin,
        networkSource,
        nodeRate,
        localMin,
        txSize,
        effectiveSize,
        networkFee: networkRate * effectiveSize,
        nodeFee:    nodeRate    * effectiveSize,
        minRelayFeeRate: MIN_RELAY_FEE_RATE,
    };
}

export function getSelectedRate(choice, feeData, customRate) {
    if (!feeData) return MIN_RELAY_FEE_RATE;
    if (choice === 'node')   return feeData.nodeRate;
    if (choice === 'custom') {
        const n = Number(customRate);
        return Number.isFinite(n) && n >= MIN_RELAY_FEE_RATE ? Math.floor(n) : MIN_RELAY_FEE_RATE;
    }
    return feeData.networkRate;
}

export function getSelectedTotal(choice, feeData, customRate) {
    if (!feeData) return 0;
    return getSelectedRate(choice, feeData, customRate) * feeData.effectiveSize;
}

export function validateCustomRate(rateInput, feeData) {
    const trimmed = String(rateInput ?? '').trim();
    if (trimmed === '') {
        return { valid: false, value: 0, error: 'Enter a fee rate in groats/byte.', warning: null };
    }
    const n = Number(trimmed);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
        return { valid: false, value: 0, error: 'Fee rate must be a positive whole number.', warning: null };
    }
    if (n < MIN_RELAY_FEE_RATE) {
        return {
            valid: false,
            value: n,
            error: `Protocol minimum is ${MIN_RELAY_FEE_RATE} groat/byte. Lower rates are dropped by the relay layer.`,
            warning: null,
        };
    }
    let warning = null;
    if (feeData && feeData.networkMedian > 0 && n < feeData.networkMedian) {
        warning = `Below network median (${feeData.networkMedian} g/B) — may propagate slowly.`;
    } else if (n > 100) {
        warning = `That is a high rate. Confirm before submitting.`;
    }
    return { valid: true, value: n, error: null, warning };
}

export function renderFeePicker(container, feeData, currentChoice, customRate, onChange) {
    container.innerHTML = '';

    if (!feeData) {
        const loading = document.createElement('p');
        loading.textContent = 'Loading fee estimates...';
        loading.style.color = 'var(--text-muted)';
        container.appendChild(loading);
        return;
    }

    const options = document.createElement('div');
    options.className = 'fee-options';

    // ── Network rate ───────────────────────────────────────────────
    const networkTile = document.createElement('div');
    networkTile.className = 'fee-option' + (currentChoice === 'network' ? ' selected' : '');
    const netBreakdown = feeData.networkSource === 'peers'
        ? `Network median ${feeData.networkMedian} g/B + buffer ${feeData.networkRate - feeData.networkMedian}`
        : `No peer data yet — using local floor + 1`;
    networkTile.innerHTML = `
        <div class="fee-label">Network rate</div>
        <div class="fee-amount">${feeData.networkRate} g/B · ◆ ${formatAmount(feeData.networkFee)}</div>
        <div class="fee-breakdown">${netBreakdown}</div>
    `;
    networkTile.addEventListener('click', () => {
        if (currentChoice !== 'network') onChange('network', customRate);
    });
    options.appendChild(networkTile);

    // ── Connected node rate ────────────────────────────────────────
    const nodeTile = document.createElement('div');
    nodeTile.className = 'fee-option' + (currentChoice === 'node' ? ' selected' : '');
    let nodeNote = '';
    if (feeData.networkMedian > 0) {
        if (feeData.nodeRate < feeData.networkMedian) {
            nodeNote = `<div class="fee-note fee-note--warn">⚠ Your node accepts ${feeData.nodeRate} g/B but most peers want ≥ ${feeData.networkMedian}. Tx may propagate slowly.</div>`;
        } else if (feeData.nodeRate > feeData.networkMedian * 2) {
            nodeNote = `<div class="fee-note">ℹ Your node's minimum is well above the network typical (${feeData.networkMedian} g/B). You're paying more than needed.</div>`;
        }
    }
    nodeTile.innerHTML = `
        <div class="fee-label">Connected node</div>
        <div class="fee-amount">${feeData.nodeRate} g/B · ◆ ${formatAmount(feeData.nodeFee)}</div>
        <div class="fee-breakdown">This node's min_fee_rate</div>
        ${nodeNote}
    `;
    nodeTile.addEventListener('click', () => {
        if (currentChoice !== 'node') onChange('node', customRate);
    });
    options.appendChild(nodeTile);

    // ── Custom ─────────────────────────────────────────────────────
    const customTile = document.createElement('div');
    customTile.className = 'fee-option' + (currentChoice === 'custom' ? ' selected' : '');
    let customBody;
    if (currentChoice === 'custom') {
        const v = validateCustomRate(customRate, feeData);
        const total = v.valid ? v.value * feeData.effectiveSize : 0;
        const totalDisplay = v.valid ? `◆ ${formatAmount(total)}` : '—';
        const noteHtml = v.error
            ? `<div class="fee-note fee-note--warn">${v.error}</div>`
            : v.warning
                ? `<div class="fee-note">${v.warning}</div>`
                : '';
        customBody = `
            <div class="fee-label">Custom</div>
            <div class="fee-amount">
                <input type="number" min="${MIN_RELAY_FEE_RATE}" step="1"
                       class="fee-custom-input"
                       value="${customRate ?? ''}"
                       placeholder="g/B" />
            </div>
            <div class="fee-breakdown">Total: ${totalDisplay}</div>
            ${noteHtml}
        `;
    } else {
        customBody = `
            <div class="fee-label">Custom</div>
            <div class="fee-amount">Enter a rate</div>
            <div class="fee-breakdown">Set groats/byte directly</div>
        `;
    }
    customTile.innerHTML = customBody;
    customTile.addEventListener('click', (e) => {
        if (e.target.classList.contains('fee-custom-input')) return;
        if (currentChoice !== 'custom') {
            onChange('custom', customRate ?? (feeData.networkRate || MIN_RELAY_FEE_RATE));
        }
    });
    const input = customTile.querySelector('.fee-custom-input');
    if (input) {
        input.addEventListener('click', e => e.stopPropagation());
        input.addEventListener('input', e => {
            const next = e.target.value;
            onChange('custom', next === '' ? null : Number(next));
        });
        // Re-focus the input after parent re-renders so typing doesn't break.
        // Caller is expected to re-render synchronously; we restore focus on next tick.
        if (currentChoice === 'custom' && document.activeElement !== input) {
            setTimeout(() => input.focus(), 0);
        }
    }
    options.appendChild(customTile);

    container.appendChild(options);
}
