// NOBLE Client — UTXO Maintenance
// Checkbox-selectable UTXO list with split, join, and auto-maintenance.
// All DOM built with createElement — no innerHTML on root. Event listeners
// are attached directly to stable element references, never lost.

import { Bridge } from '../bridge.js';
import { formatAmount } from '../components/amount-text.js';
import { openModal, openWizardModal, closeModal, createSlideConfirm } from '../components/modal.js';
import { esc } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let utxos = [];
    let selected = new Set();
    let feeRate = 1;
    let minimumReady = 5;
    let targetReady = 10;
    let autoMaintainEnabled = false;
    const TYPICAL_SIZE = 200;

    // Load persisted auto-split config
    try {
        const saved = localStorage.getItem('noble.autoSplit');
        if (saved) {
            const cfg = JSON.parse(saved);
            minimumReady = Math.max(2, Math.min(63, parseInt(cfg.minimumReady, 10) || 5));
            targetReady = Math.max(2, Math.min(63, parseInt(cfg.targetReady, 10) || 10));
            autoMaintainEnabled = !!cfg.enabled;
        }
    } catch {}

    root.classList.add('page-content');
    root.style.padding = '8px';
    loadData();

    async function loadData() {
        if (!alive) return;
        if (!state.walletAddress) {
            root.textContent = '';
            const msg = document.createElement('div');
            msg.style.cssText = 'text-align:center;padding:var(--gap-xl);color:var(--text-muted)';
            msg.textContent = 'No wallet. Connect to a node first.';
            root.appendChild(msg);
            return;
        }
        try {
            const [utxoResp, feeResp] = await Promise.all([
                Bridge.call('noble_api', 'getAddressUtxos', { address: state.walletAddress }),
                Bridge.call('noble_api', 'estimateFee').catch(() => ({ recommended: 1 }))
            ]);
            utxos = utxoResp.utxos || [];
            feeRate = feeResp.networkMinFeeRate || feeResp.network_min_fee_rate || feeResp.recommendedFeeRate || feeResp.recommended || 1;
        } catch (e) { console.error('[UTXO] loadData failed:', e); utxos = []; }
        selected.clear();
        render();
    }

    function utxoKey(u) { return u.txid + ':' + u.vout; }
    function minUtxoValue() { return Math.max(1_000_000, feeRate * TYPICAL_SIZE * 5); }

    function el(tag, style, text) {
        const e = document.createElement(tag);
        if (style) e.style.cssText = style;
        if (text) e.textContent = text;
        return e;
    }

    function render() {
        if (!alive) return;
        while (root.firstChild) root.removeChild(root.firstChild);

        const available = utxos.filter(u => u.status === 'available' || u.status === 'unconfirmed');
        const immatureCount = utxos.filter(u => u.status === 'immature').length;
        const pendingCount = utxos.filter(u => u.status === 'pending_spend').length;
        const selAvailable = [...selected].filter(k => available.some(u => utxoKey(u) === k));
        const minVal = minUtxoValue();

        // ── Header ──
        const header = el('div', 'display:flex;align-items:center;gap:8px;margin-bottom:8px');
        const backBtn = el('button', 'font-size:0.8rem;padding:4px 8px');
        backBtn.className = 'btn btn-sm';
        backBtn.textContent = '\u2190 Wallet';
        backBtn.addEventListener('click', () => { if (window.App) window.App.navigateTo('wallet'); });
        const title = el('h2', 'margin:0;font-size:var(--font-size-lg);flex:1', 'UTXO Management');
        const refreshBtn = el('button', 'font-size:0.75rem');
        refreshBtn.className = 'btn btn-sm';
        refreshBtn.textContent = 'Refresh';
        refreshBtn.addEventListener('click', loadData);
        header.appendChild(backBtn);
        header.appendChild(title);
        header.appendChild(refreshBtn);
        root.appendChild(header);

        // ── Summary row ──
        const summary = el('div', 'display:flex;gap:8px;margin-bottom:8px;font-size:var(--font-size-xs);flex-wrap:wrap');
        const addStat = (text, color) => {
            const s = el('span', 'color:' + color, text);
            summary.appendChild(s);
        };
        addStat(available.length + ' available', 'var(--success)');
        addStat(immatureCount + ' maturing', 'var(--warning)');
        addStat(pendingCount + ' pending', 'var(--text-muted)');
        const spacer = el('span', 'margin-left:auto', 'Fee: ' + feeRate + ' g/b');
        summary.appendChild(spacer);
        summary.appendChild(el('span', '', 'Min: ' + formatAmount(minVal)));
        root.appendChild(summary);

        // ── UTXO list ──
        const listPanel = el('div', 'padding:8px;margin-bottom:8px');
        listPanel.className = 'panel';
        const listTitle = el('div', 'font-weight:600;font-size:var(--font-size-sm);margin-bottom:6px',
            'All UTXOs (' + utxos.length + ')');
        listPanel.appendChild(listTitle);

        if (utxos.length === 0) {
            listPanel.appendChild(el('div', 'color:var(--text-muted);text-align:center;padding:var(--gap)', 'No UTXOs'));
        } else {
            for (const u of utxos) {
                const key = utxoKey(u);
                const isAvail = u.status === 'available' || u.status === 'unconfirmed';
                const statusColor = u.status === 'available' ? 'var(--success)'
                    : u.status === 'unconfirmed' ? 'var(--accent)'
                    : u.status === 'immature' ? 'var(--warning)' : 'var(--text-muted)';
                const statusText = u.status === 'pending_spend' ? 'pending' : u.status;

                const label = el('label',
                    'display:flex;align-items:center;gap:8px;padding:5px 6px;border-radius:var(--radius-sm);'
                    + 'cursor:' + (isAvail ? 'pointer' : 'default') + ';'
                    + 'opacity:' + (isAvail ? '1' : '0.5') + ';'
                    + 'background:' + (selected.has(key) ? 'var(--accent-subtle)' : 'transparent'));

                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.checked = selected.has(key);
                cb.disabled = !isAvail;
                cb.style.accentColor = 'var(--accent)';
                cb.addEventListener('change', () => {
                    if (cb.checked) selected.add(key); else selected.delete(key);
                    render();
                });

                const txidSpan = el('span', 'font-size:0.7rem;flex:1;word-break:break-all');
                txidSpan.className = 'mono';
                txidSpan.textContent = u.txid.slice(0, 16) + '\u2026:' + u.vout;

                const statusSpan = el('span',
                    'color:' + statusColor + ';font-size:0.65rem;font-weight:600;min-width:55px;text-align:center',
                    statusText);

                const valueSpan = el('span', 'font-size:0.75rem;font-weight:600;white-space:nowrap;min-width:80px;text-align:right');
                valueSpan.className = 'mono';
                valueSpan.textContent = formatAmount(u.value);

                label.appendChild(cb);
                label.appendChild(txidSpan);
                label.appendChild(statusSpan);
                label.appendChild(valueSpan);
                listPanel.appendChild(label);
            }
        }
        root.appendChild(listPanel);

        // ── Action bar ──
        const actionBar = el('div', 'display:flex;gap:8px;align-items:center;flex-wrap:wrap');

        const joinBtn = el('button', 'flex:0 0 auto', 'Join Selected (' + selAvailable.length + ')');
        joinBtn.className = 'btn btn-sm';
        joinBtn.disabled = selAvailable.length < 2;
        joinBtn.addEventListener('click', joinSelected);

        const splitBtn = el('button', 'flex:0 0 auto', 'Split Selected');
        splitBtn.className = 'btn btn-primary btn-sm';
        splitBtn.disabled = selAvailable.length !== 1;
        splitBtn.addEventListener('click', splitSelected);

        const splitLabel = el('label', 'font-size:var(--font-size-xs);color:var(--text-muted);display:flex;align-items:center;gap:4px');
        splitLabel.append('for ');
        const splitInput = document.createElement('input');
        splitInput.type = 'number';
        splitInput.min = '2';
        splitInput.max = '63';
        splitInput.value = targetReady;
        splitInput.style.cssText = 'width:45px;padding:3px;font-size:var(--font-size-xs);border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--glass-bg);color:inherit;text-align:center';
        splitInput.addEventListener('change', () => {
            targetReady = Math.max(2, Math.min(63, parseInt(splitInput.value) || 10));
            render();
        });
        splitLabel.appendChild(splitInput);
        splitLabel.append(' smaller UTXOs of ' + formatAmount(minVal));

        const autoBtn = el('button', 'font-size:0.7rem;margin-left:auto', 'Configure Auto-Split');
        autoBtn.className = 'btn btn-sm';
        autoBtn.addEventListener('click', openAutoConfig);

        actionBar.appendChild(joinBtn);
        actionBar.appendChild(splitBtn);
        actionBar.appendChild(splitLabel);
        actionBar.appendChild(autoBtn);
        root.appendChild(actionBar);
    }

    // ── Split selected UTXO ──
    function splitSelected() {
        const selKeys = [...selected];
        if (selKeys.length !== 1) return;
        const u = utxos.find(x => utxoKey(x) === selKeys[0]);
        if (!u) return;
        const minVal = minUtxoValue();
        const maxN = Math.min(targetReady, 63, Math.floor(u.value / minVal) - 1);
        if (maxN < 1) { alert('UTXO too small to split.'); return; }
        openSplitWizard(u, maxN);
    }

    // ── Split modal (single screen: summary + fee + slider → inline result) ──
    function openSplitWizard(sourceUtxo, splitCount) {
        let feeLevel = 'recommended';
        let feeData = null;
        const n = splitCount;
        const perOutput = minUtxoValue();
        const totalOut = n * perOutput;

        function getSelectedFee() {
            if (!feeData) return 0;
            if (feeLevel === 'min') return feeData.minFee;
            if (feeLevel === 'high') return feeData.highPriorityFee;
            return feeData.recommendedFee;
        }
        function getSelectedFeeRate() {
            if (!feeData) return 2;
            if (feeLevel === 'min') return feeData.minFeeRate;
            if (feeLevel === 'high') return feeData.highPriorityFeeRate;
            return feeData.recommendedFeeRate;
        }

        const body = document.createElement('div');

        // ── Summary ──
        const summaryDiv = document.createElement('div');
        summaryDiv.innerHTML = '<div class="detail-grid" style="margin-bottom:var(--gap)">'
            + '<dt>Source</dt><dd class="mono" style="font-size:var(--font-size-xs)">\u25c6 ' + formatAmount(sourceUtxo.value) + '</dd>'
            + '<dt>Outputs</dt><dd>' + n + ' \u00d7 \u25c6 ' + formatAmount(perOutput) + '</dd>'
            + '</div>';
        body.appendChild(summaryDiv);

        // ── Fee options (loading placeholder) ──
        const feeContainer = document.createElement('div');
        feeContainer.innerHTML = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">Loading fees\u2026</p>';
        body.appendChild(feeContainer);

        // ── Output preview ──
        const outputDiv = el('div', 'text-align:center;margin:var(--gap) 0');
        body.appendChild(outputDiv);

        // ── Action area (slider → replaced by result) ──
        const actionDiv = document.createElement('div');
        actionDiv.style.cssText = 'margin-top:var(--gap)';
        const sliderPlaceholder = el('div', 'text-align:center;color:var(--text-muted);font-size:var(--font-size-sm)', 'Loading\u2026');
        actionDiv.appendChild(sliderPlaceholder);
        body.appendChild(actionDiv);

        function updateOutput() {
            const fee = getSelectedFee();
            const change = sourceUtxo.value - totalOut - fee;
            outputDiv.innerHTML = '<div style="font-size:var(--font-size-sm);color:var(--text-muted)">Change After Split</div>'
                + '<div class="mono" style="font-size:var(--font-size-lg);font-weight:600">\u25c6 ' + formatAmount(Math.max(0, change)) + '</div>'
                + '<div style="font-size:var(--font-size-xs);color:var(--text-muted)">Fee: \u25c6 ' + formatAmount(fee) + '</div>';
        }

        function renderFeeOptions() {
            feeContainer.innerHTML = '';
            const options = document.createElement('div');
            options.className = 'fee-options';
            for (const l of [
                { key: 'min', label: 'Minimum', value: feeData.minFee },
                { key: 'recommended', label: 'Recommended', value: feeData.recommendedFee },
                { key: 'high', label: 'High Priority', value: feeData.highPriorityFee },
            ]) {
                const opt = document.createElement('div');
                opt.className = 'fee-option' + (feeLevel === l.key ? ' selected' : '');
                opt.innerHTML = '<div class="fee-label">' + l.label + '</div><div class="fee-amount">\u25c6 ' + formatAmount(l.value) + '</div>';
                opt.addEventListener('click', () => { feeLevel = l.key; renderFeeOptions(); updateOutput(); });
                options.appendChild(opt);
            }
            feeContainer.appendChild(options);
            updateOutput();
            if (!actionDiv.querySelector('.slide-confirm')) {
                actionDiv.innerHTML = '';
                actionDiv.appendChild(createSlideConfirm('Slide to Split', doSplit));
            }
        }

        // Fetch fees
        Bridge.call('noble_api', 'estimateFee').then(f => {
            const netMin = f.networkMinFeeRate || f.network_min_fee_rate || 1;
            const netMedian = f.networkMedianFeeRate || f.network_median_fee_rate || 1;
            const localMin = f.localMinFeeRate || f.local_min_fee_rate || 1;
            const localLow = f.lowFeeRate || f.low_fee_rate || 1;
            const localRec = f.recommendedFeeRate || f.recommended_fee_rate || 2;
            const localHigh = f.highPriorityFeeRate || f.high_priority_fee_rate || 5;
            const minRate = Math.max(localLow, netMin, localMin);
            const recRate = Math.max(localRec, netMedian, netMin, localMin);
            const highRate = Math.max(localHigh, netMedian * 2, netMin, localMin);
            const txSize = 150 + (n * 40) + 60;
            const eff = txSize + Math.ceil(txSize * 0.02);
            feeData = {
                minFee: minRate * eff, recommendedFee: recRate * eff, highPriorityFee: highRate * eff,
                minFeeRate: minRate, recommendedFeeRate: recRate, highPriorityFeeRate: highRate,
            };
            renderFeeOptions();
        }).catch(err => {
            feeContainer.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">Fee error: ' + esc(err?.message || 'unknown') + '</div>';
        });

        // Submit handler (called by slider)
        async function doSplit() {
            const label = actionDiv.querySelector('.slide-confirm-label');
            if (label) label.textContent = 'Submitting\u2026';
            try {
                const result = await Bridge.call('noble_crypto', 'buildTransaction', {
                    mode: 'split', split_count: n, fee_rate: getSelectedFeeRate(),
                    selected_utxos: [{ txid: sourceUtxo.txid, vout: sourceUtxo.vout, value: sourceUtxo.value }],
                    utxos: [{ txid: sourceUtxo.txid, vout: sourceUtxo.vout, value: sourceUtxo.value, status: 'available' }]
                });
                if (!result.txHex) throw new Error('No txHex returned');
                const sub = await Bridge.call('noble_api', 'submitTransaction', { txHex: result.txHex });
                if (sub.accepted) {
                    actionDiv.innerHTML = '<div class="receipt-card receipt-success" style="margin:0">'
                        + '<div class="receipt-title">\u2713 Split Submitted</div>'
                        + '<div style="font-size:var(--font-size-xs)">' + n + ' UTXOs of \u25c6 ' + formatAmount(perOutput) + '</div></div>';
                    setTimeout(loadData, 1500);
                } else {
                    actionDiv.innerHTML = '<div class="receipt-card receipt-error" style="margin:0">'
                        + '<div class="receipt-title">\u2717 Rejected</div>'
                        + '<div style="font-size:var(--font-size-sm);color:var(--error)">' + esc(sub.error || 'unknown') + '</div></div>';
                }
            } catch (err) {
                actionDiv.innerHTML = '<div class="receipt-card receipt-error" style="margin:0">'
                    + '<div class="receipt-title">\u2717 Failed</div>'
                    + '<div style="font-size:var(--font-size-sm);color:var(--error)">' + esc(err.message || String(err)) + '</div></div>';
            }
        }

        openModal({ title: 'Split into ' + n + ' UTXOs', body });
    }

    // ── Join selected UTXOs ──
    function joinSelected() {
        const selUtxos = utxos.filter(u => selected.has(utxoKey(u)) && (u.status === 'available' || u.status === 'unconfirmed'));
        if (selUtxos.length < 2) return;
        openJoinWizard(selUtxos);
    }

    // ── Join modal (single screen: summary + fee + confirm → inline result) ──
    function openJoinWizard(sourceUtxos) {
        let feeLevel = 'recommended';
        let feeData = null;
        const count = sourceUtxos.length;
        const totalIn = sourceUtxos.reduce((s, u) => s + u.value, 0);

        function getSelectedFee() {
            if (!feeData) return 0;
            if (feeLevel === 'min') return feeData.minFee;
            if (feeLevel === 'high') return feeData.highPriorityFee;
            return feeData.recommendedFee;
        }
        function getSelectedFeeRate() {
            if (!feeData) return 2;
            if (feeLevel === 'min') return feeData.minFeeRate;
            if (feeLevel === 'high') return feeData.highPriorityFeeRate;
            return feeData.recommendedFeeRate;
        }

        const body = document.createElement('div');

        // ── Summary ──
        let summaryHtml = '<div class="detail-grid" style="margin-bottom:var(--gap)">'
            + '<dt>Inputs</dt><dd>' + count + ' UTXOs</dd>'
            + '<dt>Total Value</dt><dd class="mono">\u25c6 ' + formatAmount(totalIn) + '</dd>'
            + '</div>';
        const summaryDiv = document.createElement('div');
        summaryDiv.innerHTML = summaryHtml;
        body.appendChild(summaryDiv);

        // ── Fee options (loading placeholder) ──
        const feeContainer = document.createElement('div');
        feeContainer.innerHTML = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">Loading fees\u2026</p>';
        body.appendChild(feeContainer);

        // ── Output preview ──
        const outputDiv = el('div', 'text-align:center;margin:var(--gap) 0');
        body.appendChild(outputDiv);

        // ── Action area (slider → replaced by result) ──
        const actionDiv = document.createElement('div');
        actionDiv.style.cssText = 'margin-top:var(--gap)';
        // Placeholder until fees load
        const sliderPlaceholder = el('div', 'text-align:center;color:var(--text-muted);font-size:var(--font-size-sm)', 'Loading\u2026');
        actionDiv.appendChild(sliderPlaceholder);
        body.appendChild(actionDiv);

        function updateOutput() {
            const fee = getSelectedFee();
            const out = totalIn - fee;
            outputDiv.innerHTML = '<div style="font-size:var(--font-size-sm);color:var(--text-muted)">Combined UTXO</div>'
                + '<div class="mono" style="font-size:var(--font-size-lg);font-weight:600">\u25c6 ' + formatAmount(Math.max(0, out)) + '</div>'
                + '<div style="font-size:var(--font-size-xs);color:var(--text-muted)">Fee: \u25c6 ' + formatAmount(fee) + '</div>';
        }

        function renderFeeOptions() {
            feeContainer.innerHTML = '';
            const options = document.createElement('div');
            options.className = 'fee-options';
            for (const l of [
                { key: 'min', label: 'Minimum', value: feeData.minFee },
                { key: 'recommended', label: 'Recommended', value: feeData.recommendedFee },
                { key: 'high', label: 'High Priority', value: feeData.highPriorityFee },
            ]) {
                const opt = document.createElement('div');
                opt.className = 'fee-option' + (feeLevel === l.key ? ' selected' : '');
                opt.innerHTML = '<div class="fee-label">' + l.label + '</div><div class="fee-amount">\u25c6 ' + formatAmount(l.value) + '</div>';
                opt.addEventListener('click', () => { feeLevel = l.key; renderFeeOptions(); updateOutput(); });
                options.appendChild(opt);
            }
            feeContainer.appendChild(options);
            updateOutput();
            // Install slider once fees are loaded
            if (!actionDiv.querySelector('.slide-confirm')) {
                actionDiv.innerHTML = '';
                const slider = createSlideConfirm('Slide to Join', doJoin);
                actionDiv.appendChild(slider);
            }
        }

        // Fetch fees
        Bridge.call('noble_api', 'estimateFee').then(f => {
            const netMin = f.networkMinFeeRate || f.network_min_fee_rate || 1;
            const netMedian = f.networkMedianFeeRate || f.network_median_fee_rate || 1;
            const localMin = f.localMinFeeRate || f.local_min_fee_rate || 1;
            const localLow = f.lowFeeRate || f.low_fee_rate || 1;
            const localRec = f.recommendedFeeRate || f.recommended_fee_rate || 2;
            const localHigh = f.highPriorityFeeRate || f.high_priority_fee_rate || 5;
            const minRate = Math.max(localLow, netMin, localMin);
            const recRate = Math.max(localRec, netMedian, netMin, localMin);
            const highRate = Math.max(localHigh, netMedian * 2, netMin, localMin);
            const txSize = (count * 150) + 40 + 60;
            const eff = txSize + Math.ceil(txSize * 0.02);
            feeData = {
                minFee: minRate * eff, recommendedFee: recRate * eff, highPriorityFee: highRate * eff,
                minFeeRate: minRate, recommendedFeeRate: recRate, highPriorityFeeRate: highRate,
            };
            renderFeeOptions();
        }).catch(err => {
            feeContainer.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">Fee error: ' + esc(err?.message || 'unknown') + '</div>';
        });

        // Submit handler (called by slider)
        async function doJoin() {
            const label = actionDiv.querySelector('.slide-confirm-label');
            if (label) label.textContent = 'Submitting\u2026';
            try {
                const result = await Bridge.call('noble_crypto', 'buildTransaction', {
                    mode: 'join', fee_rate: getSelectedFeeRate(),
                    selected_utxos: sourceUtxos.map(u => ({ txid: u.txid, vout: u.vout, value: u.value })),
                    utxos: sourceUtxos.map(u => ({ txid: u.txid, vout: u.vout, value: u.value, status: 'available' }))
                });
                if (!result.txHex) throw new Error('No txHex returned');
                const sub = await Bridge.call('noble_api', 'submitTransaction', { txHex: result.txHex });
                if (sub.accepted) {
                    actionDiv.innerHTML = '<div class="receipt-card receipt-success" style="margin:0">'
                        + '<div class="receipt-title">\u2713 Joined</div>'
                        + '<div style="font-size:var(--font-size-xs)" class="mono">' + esc(sub.txId || '') + '</div></div>';
                    setTimeout(loadData, 1500);
                } else {
                    actionDiv.innerHTML = '<div class="receipt-card receipt-error" style="margin:0">'
                        + '<div class="receipt-title">\u2717 Rejected</div>'
                        + '<div style="font-size:var(--font-size-sm);color:var(--error)">' + esc(sub.error || 'unknown') + '</div></div>';
                }
            } catch (err) {
                actionDiv.innerHTML = '<div class="receipt-card receipt-error" style="margin:0">'
                    + '<div class="receipt-title">\u2717 Failed</div>'
                    + '<div style="font-size:var(--font-size-sm);color:var(--error)">' + esc(err.message || String(err)) + '</div></div>';
            }
        }

        openModal({ title: 'Join ' + count + ' UTXOs', body });
    }

    // ── Auto-config modal (shared modal component) ──
    function openAutoConfig() {
        const body = document.createElement('div');
        const inputStyle = 'width:60px;padding:4px 6px;font-size:var(--font-size-sm);border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--glass-bg);color:inherit';
        const labelStyle = 'font-size:var(--font-size-xs);color:var(--text-muted);display:block;margin-bottom:4px';

        // Toggle
        const toggleRow = document.createElement('label');
        toggleRow.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:var(--font-size-sm);margin-bottom:12px';
        const toggleCb = document.createElement('input');
        toggleCb.type = 'checkbox';
        toggleCb.checked = autoMaintainEnabled;
        toggleCb.style.accentColor = 'var(--accent)';
        toggleRow.appendChild(toggleCb);
        toggleRow.append('Enable automatic UTXO splitting');
        body.appendChild(toggleRow);

        // Minimum ready UTXOs (trigger threshold)
        const minRow = el('div', 'margin-bottom:12px');
        minRow.appendChild(el('label', labelStyle, 'Minimum ready UTXOs (trigger split when below)'));
        const minInput = document.createElement('input');
        minInput.type = 'number'; minInput.min = '2'; minInput.max = '63';
        minInput.value = minimumReady; minInput.style.cssText = inputStyle;
        minRow.appendChild(minInput);
        body.appendChild(minRow);

        // Target ready UTXOs (how many to create)
        const targetRow = el('div', 'margin-bottom:12px');
        targetRow.appendChild(el('label', labelStyle, 'Target ready UTXOs (how many to create when splitting)'));
        const targetInput = document.createElement('input');
        targetInput.type = 'number'; targetInput.min = '2'; targetInput.max = '63';
        targetInput.value = targetReady; targetInput.style.cssText = inputStyle;
        targetRow.appendChild(targetInput);
        body.appendChild(targetRow);

        // Info
        const info = el('div', 'font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:12px');
        info.innerHTML = '<div>Network fee rate: <strong>' + feeRate + '</strong> groat/byte</div>'
            + '<div>Typical notarization: <strong>' + TYPICAL_SIZE + '</strong> bytes</div>'
            + '<div>Multiplier: <strong>5\u00d7</strong></div>'
            + '<div>Min UTXO value: <strong>' + formatAmount(minUtxoValue()) + '</strong></div>';
        body.appendChild(info);

        body.appendChild(el('div', 'font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:12px',
            'When available UTXOs fall below minimum, the smallest capable UTXO is split into target count small UTXOs. The change stays as one large UTXO.'));

        // Actions
        const actions = el('div', 'display:flex;gap:8px;flex-wrap:wrap');
        const runBtn = el('button', 'flex:1', 'Execute Auto-Split Now');
        runBtn.className = 'btn btn-primary btn-sm';
        runBtn.addEventListener('click', () => {
            minimumReady = Math.max(2, Math.min(63, parseInt(minInput.value) || 5));
            targetReady = Math.max(minimumReady, Math.min(63, parseInt(targetInput.value) || 10));
            closeModal();
            runAutoMaintain();
        });
        const saveBtn = el('button', '', 'Save Settings');
        saveBtn.className = 'btn btn-sm';
        saveBtn.addEventListener('click', () => {
            autoMaintainEnabled = toggleCb.checked;
            minimumReady = Math.max(2, Math.min(63, parseInt(minInput.value) || 5));
            targetReady = Math.max(minimumReady, Math.min(63, parseInt(targetInput.value) || 10));
            try {
                localStorage.setItem('noble.autoSplit', JSON.stringify({
                    enabled: autoMaintainEnabled, minimumReady, targetReady
                }));
            } catch {}
            closeModal();
            render();
        });
        actions.appendChild(runBtn);
        actions.appendChild(saveBtn);
        body.appendChild(actions);

        openModal({ title: 'Auto-Split Configuration', body });
    }

    // ── Auto-maintain ──
    function runAutoMaintain() {
        const available = utxos.filter(u => u.status === 'available' || u.status === 'unconfirmed');
        if (available.length >= minimumReady) {
            alert('Already have ' + available.length + ' available UTXOs (minimum: ' + minimumReady + '). No split needed.');
            return;
        }
        const minVal = minUtxoValue();
        const required = (targetReady + 1) * minVal;
        const candidates = available.filter(u => u.value >= required).sort((a, b) => a.value - b.value);
        if (candidates.length === 0) {
            alert('No UTXO large enough to split into ' + targetReady + ' pieces of ' + formatAmount(minVal) + ' each (need ' + formatAmount(required) + ').');
            return;
        }
        const c = candidates[0];
        const n = Math.min(targetReady, 63, Math.floor(c.value / minVal) - 1);
        if (n < 1) { alert('UTXO too small to split.'); return; }
        openSplitWizard(c, n);
    }

    return {
        destroy() { alive = false; },
        refresh(newState) { Object.assign(state, newState); }
    };
}
