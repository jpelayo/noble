// NOBLE Document Client — Payments (Send / Receive / History)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { formatAmount, formatSignedAmount } from '../components/amount-text.js';
import { statusBadge } from '../components/status-badge.js';
import { emptyState } from '../components/empty-state.js';
import { openModal, openWizardModal, closeModal } from '../components/modal.js';
import { renderQR } from '../components/qr-code.js';
import { esc, timeAgo, truncate, initials, showCopyFeedback } from '../utils.js';
import { TX_TYPES, txDisplayAmount, formatTxType, txStatusBadge } from '../tx-display.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    const TX_BATCH = 30;
    let displayCount = TX_BATCH;
    let historyData = null;
    let balanceData = null;
    let balanceContainer = null;
    let historyContainer = null;
    let loadInFlight = false;
    let loadRetries = 0;

    render();

    async function render() {
        if (!alive) return;
        root.innerHTML = '';
        root.classList.add('page-content');

        if (!state.hasWallet) {
            root.appendChild(emptyState({
                icon: '\u{1F4B0}',
                title: 'No Wallet',
                subtitle: 'Set up a wallet to use payments.'
            }));
            return;
        }

        root.style.padding = '8px';

        // Header with Refresh
        const header = document.createElement('div');
        header.style.cssText = 'display:flex;justify-content:flex-end;margin-bottom:4px';
        const refreshBtn = document.createElement('button');
        refreshBtn.className = 'btn btn-sm';
        refreshBtn.textContent = 'Refresh';
        refreshBtn.style.fontSize = '0.75rem';
        refreshBtn.addEventListener('click', render);
        header.appendChild(refreshBtn);
        root.appendChild(header);

        // Balance card placeholder with skeleton
        balanceContainer = document.createElement('div');
        balanceContainer.setAttribute('aria-live', 'polite');
        balanceContainer.innerHTML = '<div class="skeleton" style="height:140px;border-radius:var(--radius)"></div>';
        root.appendChild(balanceContainer);

        // Action buttons — card-style
        const actions = document.createElement('div');
        actions.className = 'action-buttons';
        actions.style.margin = '8px 0';

        const sendBtn = document.createElement('button');
        sendBtn.className = 'panel';
        sendBtn.style.cssText = 'flex:1;padding:8px;display:flex;align-items:center;gap:8px;cursor:pointer;border:1px solid var(--glass-border);transition:all 0.15s;text-align:left;font:inherit;color:inherit;margin:0';
        sendBtn.innerHTML = '<div style="width:28px;height:28px;border-radius:50%;background:var(--accent-subtle);display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:var(--accent)">\u{1F680}</div><div><div style="font-weight:700">Send</div><div style="font-size:var(--font-size-xs);color:var(--text-muted)">Transfer NOBLE</div></div>';
        sendBtn.addEventListener('click', openSendWizard);
        sendBtn.addEventListener('mouseenter', () => { sendBtn.style.borderColor = 'var(--accent)'; sendBtn.style.transform = 'translateY(-1px)'; });
        sendBtn.addEventListener('mouseleave', () => { sendBtn.style.borderColor = 'var(--glass-border)'; sendBtn.style.transform = ''; });

        const recvBtn = document.createElement('button');
        recvBtn.className = 'panel';
        recvBtn.style.cssText = 'flex:1;padding:8px;display:flex;align-items:center;gap:8px;cursor:pointer;border:1px solid var(--glass-border);transition:all 0.15s;text-align:left;font:inherit;color:inherit;margin:0';
        recvBtn.innerHTML = '<div style="width:28px;height:28px;border-radius:50%;background:color-mix(in srgb, var(--success) 12%, transparent);display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:var(--success)">\u{1F4E5}</div><div><div style="font-weight:700">Receive</div><div style="font-size:var(--font-size-xs);color:var(--text-muted)">Your address & QR</div></div>';
        recvBtn.addEventListener('click', openReceiveModal);
        recvBtn.addEventListener('mouseenter', () => { recvBtn.style.borderColor = 'var(--success)'; recvBtn.style.transform = 'translateY(-1px)'; });
        recvBtn.addEventListener('mouseleave', () => { recvBtn.style.borderColor = 'var(--glass-border)'; recvBtn.style.transform = ''; });

        const utxoBtn = document.createElement('button');
        utxoBtn.className = 'panel';
        utxoBtn.style.cssText = 'flex:1;padding:8px;display:flex;align-items:center;gap:8px;cursor:pointer;border:1px solid var(--glass-border);transition:all 0.15s;text-align:left;font:inherit;color:inherit;margin:0';
        utxoBtn.innerHTML = '<div style="width:28px;height:28px;border-radius:50%;background:color-mix(in srgb, var(--warning) 12%, transparent);display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:var(--warning)">\u2696</div><div><div style="font-weight:700">UTXOs</div><div style="font-size:var(--font-size-xs);color:var(--text-muted)">Split & manage</div></div>';
        utxoBtn.addEventListener('click', () => { if (window.App) window.App.navigateTo('utxo-maintenance'); });
        utxoBtn.addEventListener('mouseenter', () => { utxoBtn.style.borderColor = 'var(--warning)'; utxoBtn.style.transform = 'translateY(-1px)'; });
        utxoBtn.addEventListener('mouseleave', () => { utxoBtn.style.borderColor = 'var(--glass-border)'; utxoBtn.style.transform = ''; });

        actions.appendChild(sendBtn);
        actions.appendChild(recvBtn);
        actions.appendChild(utxoBtn);
        root.appendChild(actions);

        // Transaction history placeholder with skeleton
        historyContainer = document.createElement('div');
        historyContainer.id = 'payment-history';
        historyContainer.innerHTML = '<div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div>';
        root.appendChild(historyContainer);

        await loadData(balanceContainer, historyContainer);
    }

    async function loadData(balanceContainer, historyContainer) {
        if (!alive || loadInFlight) return;
        loadInFlight = true;
        const address = state.walletAddress;
        if (!address) {
            loadInFlight = false;
            balanceContainer.innerHTML = `<div class="info-card" role="status">
                <p>Wallet not loaded. Connect to a running node to view your balance and transactions.</p>
            </div>`;
            historyContainer.innerHTML = '';
            return;
        }

        try {
            // Use atomic snapshot: balance + transactions under one chain_height.
            // Eliminates race where parallel calls observe different chain tips.
            let snapshot;
            try {
                snapshot = await Bridge.call('noble_api', 'getWalletSnapshot');
            } catch {
                // Fallback for nodes that don't support snapshot yet.
                const [balance, history] = await Promise.all([
                    Bridge.call('noble_api', 'getBalance', { address }),
                    Bridge.call('noble_api', 'getWalletTransactions'),
                ]);
                snapshot = { ...balance, transactions: (history.transactions || []) };
            }
            if (!alive) return;
            loadRetries = 0;
            const balance = snapshot;
            const history = { transactions: snapshot.transactions || [] };
            balanceData = balance;
            historyData = history;
            renderBalance(balanceContainer, balance);
            renderHistory(historyContainer, history);
        } catch (err) {
            if (!alive) return;
            const msg = (err.message || '').toLowerCase();
            const isOffline = msg.includes('timeout') || msg.includes('not connected') || msg.includes('cancelled');
            if (isOffline && loadRetries < 5) {
                loadRetries++;
                setTimeout(() => { if (alive) loadData(balanceContainer, historyContainer); }, 3000);
                return;
            }
            loadRetries = 0;
            balanceContainer.innerHTML = '';
            historyContainer.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = 'error-card';
            errDiv.setAttribute('role', 'alert');
            errDiv.innerHTML = `<p>${err.message || String(err)}</p><button type="button">Retry</button>`;
            errDiv.querySelector('button').addEventListener('click', () => {
                loadRetries = 0;
                balanceContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                historyContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                loadData(balanceContainer, historyContainer);
            });
            balanceContainer.appendChild(errDiv);
        } finally {
            loadInFlight = false;
        }
    }

    function renderBalance(container, balance) {
        container.innerHTML = '';
        const chainId = state.chainId || '';
        const el = document.createElement('div');
        el.className = 'panel';
        el.style.cssText = 'padding:12px;margin-bottom:8px';
        el.innerHTML = `
            <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:var(--gap-lg)">
                <div>
                    <div style="display:inline-block;padding:4px 12px;background:var(--accent-subtle);color:var(--accent);font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;border-radius:999px;margin-bottom:var(--gap-sm)">Total Balance</div>
                    <div style="display:flex;align-items:baseline;gap:8px;margin-top:4px">
                        <span style="color:var(--accent);font-size:var(--font-size-2xl)">\u25C6</span>
                        <span class="mono" style="font-size:clamp(1.8rem, 3vw, 2.5rem);font-weight:800;letter-spacing:-0.02em">${formatAmount(balance.balance)}</span>
                        <span style="font-size:var(--font-size-base);color:var(--text-muted);font-weight:600">NOBLE</span>
                    </div>
                    ${chainId ? `<div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:4px">Chain: ${esc(chainId)}</div>` : ''}
                </div>
                <div style="display:flex;gap:var(--gap-xl)">
                    <div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Available</div>
                        <div class="mono" style="font-size:var(--font-size-lg);font-weight:600">${formatAmount(balance.available)}</div>
                        ${balance.immature_value > 0 ? `<div style="font-size:var(--font-size-xs);color:var(--warning);margin-top:2px">\u25C6 ${formatAmount(balance.immature_value)} maturing</div>` : ''}
                    </div>
                    <div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Pending</div>
                        <div class="mono" style="font-size:var(--font-size-lg);font-weight:600;${balance.pending > 0 ? 'color:var(--warning)' : ''}">${balance.pending > 0 ? '\u2212' : ''}${formatAmount(balance.pending)}</div>
                    </div>
                </div>
            </div>
        `;
        container.appendChild(el);
    }

    // ── Transaction History ──

    function renderHistory(container, data) {
        container.innerHTML = '';
        const allTxs = data.transactions || [];
        const txs = allTxs.slice(0, displayCount);

        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.style.padding = 'var(--gap-lg)';

        if (txs.length === 0) {
            panel.innerHTML = `<h3 style="font-size:var(--font-size-lg);font-weight:700;margin:0 0 var(--gap-lg)">Transaction History</h3>
                <div style="text-align:center;padding:var(--gap-xl);color:var(--text-muted)">
                    <div style="font-size:2rem;margin-bottom:var(--gap-sm)">\u{1F4B8}</div>
                    <div>No transactions yet</div>
                </div>`;
            container.appendChild(panel);
            return;
        }

        let html = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <h3 style="font-size:0.9rem;font-weight:700;margin:0">Transaction History</h3>
            <span style="font-size:var(--font-size-xs);color:var(--text-muted)">${txs.length} transaction${txs.length !== 1 ? 's' : ''}</span>
        </div>`;
        html += '<div style="display:flex;flex-direction:column;gap:4px">';

        for (const tx of txs) {
            const typeName = formatTxType(tx.tx_type ?? parseTypeLabel(tx.type));
            const counterparty = tx.recipient ? truncate(tx.recipient, 12) : '';
            const disp = txDisplayAmount(tx);
            const amount = formatSignedAmount(disp.amount, disp.direction);
            const amtColor = disp.direction === 'outgoing' ? 'var(--warning)'
                           : disp.direction === 'incoming' ? 'var(--success)' : 'var(--text-primary)';
            const badge = txStatusBadge(tx.confirmations, tx.status);
            const ago = timeAgo(tx.timestamp);

            let iconBg, iconColor, iconChar;
            if (disp.direction === 'incoming') {
                iconBg = 'color-mix(in srgb, var(--success) 12%, transparent)';
                iconColor = 'var(--success)';
                iconChar = '\u2193';
            } else if (tx.tx_type === 0x00 || tx.tx_type === 0x06 || tx.tx_type === 0x07) {
                iconBg = 'color-mix(in srgb, var(--accent) 12%, transparent)';
                iconColor = 'var(--accent)';
                iconChar = '\u{1F4C4}';
            } else {
                iconBg = 'color-mix(in srgb, var(--warning) 12%, transparent)';
                iconColor = 'var(--warning)';
                iconChar = '\u2191';
            }

            html += `<div class="tx-row" data-txid="${esc(tx.txId || '')}" style="display:flex;align-items:center;justify-content:space-between;padding:6px 8px;border-radius:var(--radius);cursor:pointer;transition:background 0.15s" tabindex="0" role="button">
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="width:28px;height:28px;border-radius:var(--radius-sm);background:${iconBg};display:flex;align-items:center;justify-content:center;font-size:0.85rem;color:${iconColor};flex-shrink:0">${iconChar}</div>
                    <div>
                        <div style="font-weight:600;font-size:var(--font-size-sm)">${typeName}</div>
                        <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${counterparty ? counterparty + ' \u00B7 ' : ''}${ago}</div>
                    </div>
                </div>
                <div style="text-align:right;flex-shrink:0;white-space:nowrap">
                    <div class="mono" style="font-weight:700;font-size:0.8rem;color:${amtColor}">${disp.amount > 0 ? '\u25C6 ' + amount : ''}</div>
                    <div data-role="status" style="font-size:0.6rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.03em">${badge.html.replace(/<[^>]+>/g, '')}</div>
                </div>
            </div>`;
        }
        html += '</div>';

        // "Load more" button if there are more transactions
        if (displayCount < allTxs.length) {
            const remaining = allTxs.length - displayCount;
            html += `<button id="load-more-txs" style="width:100%;margin-top:8px;padding:10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--glass-bg);color:var(--accent);font-weight:600;font-size:var(--font-size-sm);cursor:pointer">Show more (${remaining} remaining)</button>`;
        }

        panel.innerHTML = html;
        container.appendChild(panel);

        // Wire "Load more"
        const loadMoreBtn = panel.querySelector('#load-more-txs');
        if (loadMoreBtn) {
            loadMoreBtn.addEventListener('click', () => {
                displayCount += TX_BATCH;
                renderHistory(container, data);
            });
        }

        // Wire click + hover + keyboard
        panel.querySelectorAll('.tx-row').forEach(row => {
            row.addEventListener('mouseenter', () => { row.style.background = 'var(--accent-subtle)'; });
            row.addEventListener('mouseleave', () => { row.style.background = ''; });
            row.addEventListener('click', () => {
                const txId = row.dataset.txid;
                if (txId && window.App) App.navigateTo('tx-detail', { txid: txId });
            });
            row.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); }
            });
        });
    }

    function txDirection(tx) {
        const t = tx.tx_type ?? parseTypeLabel(tx.type);
        if (t === TX_TYPES.COINBASE) return { icon: '\u26CF', cls: 'tx-coinbase' };
        if (t === TX_TYPES.FEE_DISTRIBUTION) return { icon: '\u{1F4B0}', cls: 'tx-fee-distribution' };
        if (t === TX_TYPES.LOCKED) return { icon: '\u{1F512}', cls: 'tx-locked' };
        if (t === TX_TYPES.UNLOCKING) return { icon: '\u{1F511}', cls: 'tx-unlocking' };
        if (t === TX_TYPES.KEY_ROTATION) return { icon: '\u{1F504}', cls: 'tx-rotation' };
        if (t === TX_TYPES.BADGE_PROPOSAL || t === TX_TYPES.BADGE_VOTE || t === TX_TYPES.BADGE_REVOCATION) return { icon: '\u{1F3C5}', cls: 'tx-badge' };
        if (t === TX_TYPES.NOTARIZATION) return { icon: '\u{1F4C4}', cls: 'tx-notarization' };
        if (tx.direction === 'incoming') return { icon: '\u2B07', cls: 'tx-incoming' };
        return { icon: '\u2B06', cls: 'tx-outgoing' };
    }

    function parseTypeLabel(label) {
        if (typeof label === 'number') return label;
        if (!label) return -1;
        const lower = label.toLowerCase().replace(/[_\s-]/g, '');
        const map = { notarization: 0, transfer: 1, keyrotation: 2, badgeproposal: 3, badgevote: 4, badgerevocation: 5, locked: 6, unlocking: 7, coinbase: 16 };
        return map[lower] ?? -1;
    }

    // ── Send Wizard ──

    function openSendWizard(prefillRecipient) {
        let recipient = (typeof prefillRecipient === 'string') ? prefillRecipient : '';
        let recipientValid = false;
        let amount = '';
        let feeLevel = 'recommended';
        let feeData = null;
        let submitResult = null;
        let submitError = null;

        const wizard = openWizardModal({
            title: 'Send NOBLE',
            steps: [
                { label: 'Recipient', render: renderRecipientStep, canAdvance: () => recipientValid, onNext: null },
                { label: 'Amount', render: renderAmountStep, canAdvance: () => isValidAmount(), onNext: null },
                { label: 'Fee', render: renderFeeStep, canAdvance: () => feeData !== null, onNext: null },
                { label: 'Review', render: renderReviewStep, canAdvance: () => true, submitLabel: 'Slide to Send', slideConfirm: true, onNext: submitTransaction },
                { label: 'Result', render: renderResultStep, canAdvance: () => true, submitLabel: 'Close', hideBack: true },
            ],
            onComplete: () => { closeModal(); render(); },
            onCancel: () => {}
        });

        function renderRecipientStep(el) {
            const group = document.createElement('div');
            group.className = 'form-group';
            group.innerHTML = '<label>Recipient Address</label>';

            const input = document.createElement('input');
            input.className = 'form-input';
            input.type = 'text';
            input.autocapitalize = 'none';
            input.autocorrect = 'off';
            input.spellcheck = false;
            input.placeholder = 'nbl1... address';
            input.value = recipient;

            const feedback = document.createElement('div');
            feedback.style.cssText = 'font-size:var(--font-size-xs); margin-top:var(--gap-xs); min-height:1.2em';

            let debounceTimer = null;

            async function validateRecipient() {
                if (!recipient) {
                    recipientValid = false;
                    feedback.textContent = '';
                    wizard.updateNav();
                    return;
                }
                try {
                    const r = await Bridge.call('noble_api', 'validateAddress', { address: recipient });
                    // Guard: user may have changed input while we were awaiting
                    if (input.value.trim() !== recipient) return;
                    recipientValid = r.valid;
                    feedback.textContent = r.valid ? '\u2713 Valid address' : '\u2717 Invalid address';
                    feedback.style.color = r.valid ? 'var(--success)' : 'var(--error)';
                    wizard.updateNav();
                } catch {
                    feedback.textContent = '\u2717 Validation failed';
                    feedback.style.color = 'var(--error)';
                    recipientValid = false;
                    wizard.updateNav();
                }
            }

            input.addEventListener('input', () => {
                recipient = input.value.trim();
                recipientValid = false;
                feedback.textContent = '';
                wizard.updateNav();
                clearTimeout(debounceTimer);
                if (recipient.length >= 4) {
                    debounceTimer = setTimeout(validateRecipient, 500);
                }
            });

            input.addEventListener('blur', () => {
                clearTimeout(debounceTimer);
                validateRecipient();
            });

            group.appendChild(input);
            group.appendChild(feedback);
            el.appendChild(group);

            // Pick from contacts button
            const pickBtn = document.createElement('button');
            pickBtn.className = 'btn btn-secondary btn-sm';
            pickBtn.textContent = 'Pick from Contacts';
            pickBtn.addEventListener('click', () => openContactPicker(addr => {
                recipient = addr;
                recipientValid = true;
                input.value = addr;
                feedback.textContent = '\u2713 From contacts';
                feedback.style.color = 'var(--success)';
                wizard.updateNav();
            }));
            el.appendChild(pickBtn);

            // Auto-validate if prefilled
            if (recipient) validateRecipient();
        }

        function renderAmountStep(el) {
            const group = document.createElement('div');
            group.className = 'form-group';
            group.innerHTML = '<label>Amount (NOBLE)</label>';

            const wrap = document.createElement('div');
            wrap.className = 'amount-input-group';

            const input = document.createElement('input');
            input.className = 'form-input';
            input.type = 'text';
            input.inputMode = 'decimal';
            input.placeholder = '0.00000000';
            input.value = amount;
            input.addEventListener('input', () => { amount = input.value.trim(); wizard.updateNav(); });

            const maxBtn = document.createElement('button');
            maxBtn.className = 'btn btn-sm amount-max-btn';
            maxBtn.textContent = 'Max';
            maxBtn.addEventListener('click', () => {
                if (balanceData) {
                    const fee = feeData ? feeData.recommendedFee : 2000;
                    const maxAtomic = Math.max(0, (balanceData.available || 0) - fee);
                    amount = formatAmount(maxAtomic);
                    input.value = amount;
                }
            });

            wrap.appendChild(input);
            wrap.appendChild(maxBtn);
            group.appendChild(wrap);

            // Atomic preview
            const preview = document.createElement('div');
            preview.className = 'form-hint';
            const atomic = parseAmount(amount);
            if (atomic > 0) preview.textContent = `${atomic.toLocaleString()} atomic units`;
            group.appendChild(preview);

            // Balance warning element
            const balWarn = document.createElement('div');
            balWarn.className = 'form-hint';
            balWarn.style.color = 'var(--error)';
            balWarn.style.display = 'none';
            group.appendChild(balWarn);

            input.addEventListener('input', () => {
                const a = parseAmount(input.value.trim());
                preview.textContent = a > 0 ? `${a.toLocaleString()} groats` : '';
                // Warn if amount exceeds available balance
                if (balanceData && a > (balanceData.available || 0)) {
                    balWarn.textContent = `Exceeds available balance (\u25C6 ${formatAmount(balanceData.available)})`;
                    balWarn.style.display = '';
                } else {
                    balWarn.style.display = 'none';
                }
            });

            // Balance info
            if (balanceData) {
                const avail = document.createElement('div');
                avail.className = 'form-hint';
                avail.textContent = `Available: \u25C6 ${formatAmount(balanceData.available)}`;
                group.appendChild(avail);
            }

            el.appendChild(group);
        }

        function renderFeeStep(el) {
            if (!feeData) {
                const loading = document.createElement('p');
                loading.textContent = 'Loading fee estimates...';
                loading.style.color = 'var(--text-muted)';
                el.appendChild(loading);
                Bridge.call('noble_api', 'estimateFee').then(async (f) => {
                    // Network-aware fee rates: always meet the highest known validator minimum.
                    const netMin = f.networkMinFeeRate || f.network_min_fee_rate || 1;
                    const netMedian = f.networkMedianFeeRate || f.network_median_fee_rate || 1;
                    const localMin = f.localMinFeeRate || f.local_min_fee_rate || 1;
                    const localLow = f.lowFeeRate || f.low_fee_rate || 1;
                    const localRec = f.recommendedFeeRate || f.recommended_fee_rate || 2;
                    const localHigh = f.highPriorityFeeRate || f.high_priority_fee_rate || 5;
                    const minRate = Math.max(localLow, netMin, localMin);
                    const recRate = Math.max(localRec, netMedian, netMin, localMin);
                    const highRate = Math.max(localHigh, netMedian * 2, netMin, localMin);

                    // Estimate real tx size using the C library
                    let txSize = 450; // fallback for transfers
                    try {
                        const sizeResult = await Bridge.call('noble_crypto', 'estimateTxSize', {
                            tx_type: 'transfer',
                            recipient: recipient || state.walletAddress,
                        });
                        if (sizeResult && sizeResult.size) txSize = sizeResult.size;
                    } catch { /* use fallback */ }

                    // +2% safety margin
                    const margin = Math.ceil(txSize * 0.02);
                    const effectiveSize = txSize + margin;

                    feeData = {
                        minFee: minRate * effectiveSize,
                        recommendedFee: recRate * effectiveSize,
                        highPriorityFee: highRate * effectiveSize,
                        minFeeRate: minRate,
                        recommendedFeeRate: recRate,
                        highPriorityFeeRate: highRate,
                    };
                    wizard.renderStep();
                }).catch((err) => {
                    // Cannot estimate fees — do NOT proceed with hardcoded rates.
                    const errEl = document.createElement('div');
                    errEl.className = 'error-card';
                    errEl.innerHTML = `<p>Could not estimate fees: ${err?.message || 'node unreachable'}. Please check your connection and try again.</p>`;
                    el.innerHTML = '';
                    el.appendChild(errEl);
                });
                return;
            }

            const options = document.createElement('div');
            options.className = 'fee-options';
            const levels = [
                { key: 'min', label: 'Minimum', value: feeData.minFee },
                { key: 'recommended', label: 'Recommended', value: feeData.recommendedFee },
                { key: 'high', label: 'High Priority', value: feeData.highPriorityFee },
            ];
            for (const l of levels) {
                const opt = document.createElement('div');
                opt.className = 'fee-option' + (feeLevel === l.key ? ' selected' : '');
                opt.innerHTML = `<div class="fee-label">${l.label}</div><div class="fee-amount">\u25C6 ${formatAmount(l.value)}</div>`;
                opt.addEventListener('click', () => { feeLevel = l.key; wizard.renderStep(); });
                options.appendChild(opt);
            }
            el.appendChild(options);

            // Total debit
            const fee = getSelectedFee();
            const amountAtomic = parseAmount(amount);
            const total = amountAtomic + fee;
            const totalDiv = document.createElement('div');
            totalDiv.style.cssText = 'margin-top:var(--gap);text-align:center';
            totalDiv.innerHTML = `<div style="font-size:var(--font-size-sm);color:var(--text-muted)">Total Debit</div>
                <div class="mono" style="font-size:var(--font-size-lg);font-weight:600">\u25C6 ${formatAmount(total)}</div>`;
            el.appendChild(totalDiv);
        }

        function renderReviewStep(el) {
            const fee = getSelectedFee();
            const amountAtomic = parseAmount(amount);
            el.innerHTML = `
                <div class="detail-grid">
                    <dt>From</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(state.walletAddress)}</dd>
                    <dt>To</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(recipient)}</dd>
                    <dt>Amount</dt><dd class="mono">\u25C6 ${formatAmount(amountAtomic)}</dd>
                    <dt>Fee</dt><dd class="mono">\u25C6 ${formatAmount(fee)}</dd>
                    <dt>Total Debit</dt><dd class="mono" style="font-weight:600">\u25C6 ${formatAmount(amountAtomic + fee)}</dd>
                </div>
            `;
        }

        async function submitTransaction() {
            try {
                const fee = getSelectedFee();
                const amountAtomic = parseAmount(amount);

                // Fetch wallet UTXOs for coin selection — only use available UTXOs.
                // UTXOs with status "pending_spend" or "immature" are excluded.
                const utxoResp = await Bridge.call('noble_api', 'getAddressUtxos', { address: state.walletAddress });
                const allUtxos = utxoResp.utxos || [];
                const utxos = allUtxos
                    .filter(u => !u.status || u.status === 'available' || u.status === 'unconfirmed')
                    .map(u => ({
                        txid: u.txid,
                        vout: u.vout,
                        value: u.value,
                    }));

                if (utxos.length === 0 && allUtxos.length > 0) {
                    const pending = allUtxos.filter(u => u.status === 'pending_spend').length;
                    const immature = allUtxos.filter(u => u.status === 'immature').length;
                    throw new Error(
                        `No spendable UTXOs available. ${pending ? pending + ' locked by pending transactions. ' : ''}${immature ? immature + ' immature outputs.' : ''}Wait for pending transactions to confirm.`
                    );
                }

                const feeRate = getSelectedFeeRate();
                const signResult = await Bridge.call('noble_crypto', 'signTransfer', {
                    recipient, amount: amountAtomic, fee, fee_rate: feeRate, utxos
                });
                const submit = await Bridge.call('noble_api', 'submitTransaction', { txHex: signResult.txHex });
                submitResult = submit;
                submitError = submit.accepted ? null : 'Transaction rejected';
            } catch (err) {
                submitResult = null;
                submitError = err.message || String(err);
                // Don't return false — let wizard advance to Result step which shows the error.
            }
        }

        function renderResultStep(el) {
            if (submitError) {
                const card = document.createElement('div');
                card.className = 'receipt-card receipt-error';
                card.innerHTML = `
                    <div class="receipt-title">\u2717 Failed</div>
                    <div style="font-size:var(--font-size-sm);color:var(--error)">${esc(submitError)}</div>
                `;
                el.appendChild(card);
                return;
            }

            const card = document.createElement('div');
            card.className = 'receipt-card receipt-success';
            card.innerHTML = `
                <div class="receipt-title">\u2713 Sent Successfully</div>
                <div class="receipt-hash">${esc(submitResult?.txId || '')}</div>
            `;

            const btnRow = document.createElement('div');
            btnRow.style.cssText = 'display:flex;gap:var(--gap-sm);margin-top:var(--gap-sm);justify-content:center';

            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn btn-sm btn-secondary';
            copyBtn.textContent = 'Copy TX ID';
            copyBtn.addEventListener('click', () => {
                Bridge.call('noble_app', 'copyToClipboard', { text: submitResult?.txId || '' });
                showCopyFeedback(copyBtn, 'Copy TX ID');
            });

            const shareBtn = document.createElement('button');
            shareBtn.className = 'btn btn-sm btn-primary';
            shareBtn.textContent = '\u{1F4E4} Share';
            shareBtn.addEventListener('click', () => {
                const txId = submitResult?.txId || '';
                const shareText = `NOBLE Transaction Locator: ${txId}`;
                Bridge.call('noble_app', 'share', { text: shareText }).catch(() => {
                    // Fallback: copy to clipboard
                    Bridge.call('noble_app', 'copyToClipboard', { text: shareText });
                    showCopyFeedback(shareBtn, '\u{1F4E4} Share');
                });
            });

            btnRow.appendChild(copyBtn);
            btnRow.appendChild(shareBtn);
            card.appendChild(btnRow);
            el.appendChild(card);
        }

        function getSelectedFee() {
            if (!feeData) return 2000;
            if (feeLevel === 'min') return feeData.minFee;
            if (feeLevel === 'high') return feeData.highPriorityFee;
            return feeData.recommendedFee;
        }

        function getSelectedFeeRate() {
            if (!feeData) return 2;
            if (feeLevel === 'min') return feeData.minFeeRate || 1;
            if (feeLevel === 'high') return feeData.highPriorityFeeRate || 5;
            return feeData.recommendedFeeRate || 2;
        }

        function isValidAmount() {
            const a = parseAmount(amount);
            return a > 0;
        }
    }

    // ── Contact Picker (sub-modal) ──

    function openContactPicker(onSelect) {
        Bridge.call('noble_storage', 'getContacts').then(data => {
            const contacts = (data.contacts || []).filter(c => c.noblePubkey);
            if (contacts.length === 0) {
                return; // No contacts with pubkeys
            }

            const body = document.createElement('div');

            for (const c of contacts) {
                const row = document.createElement('div');
                row.className = 'contact-row';
                row.style.cursor = 'pointer';

                const avatar = document.createElement('div');
                avatar.className = 'contact-avatar';
                avatar.textContent = initials(c);

                const info = document.createElement('div');
                info.className = 'contact-info';
                info.innerHTML = `<div style="font-weight:500">${esc(c.displayName || c.firstName)}</div>
                    <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${truncate(c.noblePubkey, 10)}</div>`;

                row.appendChild(avatar);
                row.appendChild(info);
                row.addEventListener('click', () => {
                    pickerModal.close();
                    onSelect(c.noblePubkey);
                });
                body.appendChild(row);
            }

            const pickerModal = openModal({
                title: 'Pick Contact',
                body,
                stack: true
            });
        });
    }

    // ── Receive Modal ──

    function openReceiveModal() {
        const address = state.walletAddress;
        if (!address) return;

        const body = document.createElement('div');
        body.style.textAlign = 'center';

        // QR
        const qrContainer = document.createElement('div');
        qrContainer.className = 'qr-container';
        renderQR(qrContainer, address, 200);
        body.appendChild(qrContainer);

        // Address display
        const addrEl = document.createElement('div');
        addrEl.className = 'mono';
        addrEl.style.cssText = 'font-size:var(--font-size-xs); word-break:break-all; margin-top:var(--gap); padding:var(--gap-sm); background:var(--bg-secondary); border-radius:var(--radius-sm)';
        addrEl.textContent = address;
        body.appendChild(addrEl);

        // Buttons
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex; gap:var(--gap-sm); justify-content:center; margin-top:var(--gap)';

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn btn-primary btn-sm';
        copyBtn.textContent = 'Copy Address';
        copyBtn.addEventListener('click', () => {
            Bridge.call('noble_app', 'copyToClipboard', { text: address });
            showCopyFeedback(copyBtn, 'Copy Address');
        });

        const shareBtn = document.createElement('button');
        shareBtn.className = 'btn btn-sm';
        shareBtn.textContent = 'Share';
        shareBtn.addEventListener('click', () => {
            Bridge.call('noble_app', 'shareText', { text: address });
        });

        actions.appendChild(copyBtn);
        actions.appendChild(shareBtn);
        body.appendChild(actions);

        openModal({ title: 'Receive NOBLE', body });
    }

    // Track last known balance to detect changes that warrant a tx list refresh.
    let lastKnownBalance = state.walletBalance;

    return {
        destroy() { alive = false; closeModal(); },
        async refresh(newState) {
            Object.assign(state, newState);
            if (newState.walletBalance !== undefined) lastKnownBalance = newState.walletBalance;
            // Zero-DOM-mutation: update status badges in-place
            try {
                const snap = await Bridge.call('noble_api', 'getWalletSnapshot');
                if (!alive) return;
                const txMap = new Map((snap.transactions || []).map(t => [t.txId || t.tx_id, t]));
                root.querySelectorAll('.tx-row').forEach(row => {
                    const tx = txMap.get(row.dataset.txid);
                    if (!tx) return;
                    const el = row.querySelector('[data-role="status"]');
                    if (el) {
                        const b = txStatusBadge(tx.confirmations, tx.status);
                        el.textContent = b.html.replace(/<[^>]+>/g, '');
                    }
                });
            } catch {}
        },
        openSendWizard(recipientAddress) { openSendWizard(recipientAddress); }
    };
}

// ── Helpers ──

function parseAmount(str) {
    const n = parseFloat(str);
    if (isNaN(n) || n <= 0) return 0;
    return Math.round(n * 100_000_000);
}
