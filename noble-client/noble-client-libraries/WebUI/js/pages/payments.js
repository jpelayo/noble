// NOBLE Document Client — Payments (Send / Receive / History)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { formatAmount } from '../components/amount-text.js';
import { statusBadge } from '../components/status-badge.js';
import { emptyState } from '../components/empty-state.js';
import { openModal, openWizardModal, closeModal } from '../components/modal.js';
import { renderQR } from '../components/qr-code.js';
import { esc, timeAgo, truncate, initials, showCopyFeedback } from '../utils.js';
import { txDisplayAmount } from '../tx-display.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let historyPage = 0;
    const historyLimit = 20;
    let historyData = null;
    let balanceData = null;
    let expandedTx = null;

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

        // Page header
        const header = document.createElement('div');
        header.className = 'page-header';
        header.innerHTML = '<h1>Payments</h1><p>Send, receive, and track NOBLE transfers</p>';
        root.appendChild(header);

        // Balance card placeholder with skeleton
        const balanceContainer = document.createElement('div');
        balanceContainer.style.marginBottom = 'var(--gap)';
        balanceContainer.setAttribute('aria-live', 'polite');
        balanceContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
        root.appendChild(balanceContainer);

        // Action buttons
        const actions = document.createElement('div');
        actions.className = 'quick-actions';
        actions.style.marginBottom = 'var(--gap)';

        const sendBtn = document.createElement('button');
        sendBtn.className = 'btn btn-primary';
        sendBtn.textContent = '\u{1F4E4} Send';
        sendBtn.setAttribute('aria-label', 'Send payment');
        sendBtn.addEventListener('click', openSendWizard);

        const recvBtn = document.createElement('button');
        recvBtn.className = 'btn';
        recvBtn.textContent = '\u{1F4E5} Receive';
        recvBtn.setAttribute('aria-label', 'Receive payment');
        recvBtn.addEventListener('click', openReceiveModal);

        actions.appendChild(sendBtn);
        actions.appendChild(recvBtn);
        root.appendChild(actions);

        // Transaction history placeholder with skeleton
        const historyContainer = document.createElement('div');
        historyContainer.id = 'payment-history';
        historyContainer.innerHTML = '<div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div>';
        root.appendChild(historyContainer);

        // Load data
        await loadData(balanceContainer, historyContainer);
    }

    async function loadData(balanceContainer, historyContainer) {
        if (!alive) return;
        const address = state.walletAddress;
        if (!address) return;

        try {
            let balance, history;
            try {
                // Primary path: Bridge (Swift hydrates full tx objects)
                [balance, history] = await Promise.all([
                    Bridge.call('noble_api', 'getBalance', { address }),
                    Bridge.call('noble_api', 'getTransactionHistory', { address, page: historyPage, limit: historyLimit })
                ]);
            } catch {
                // Fallback: direct RPC (returns tx_id strings, fetch details)
                const [bal, hist] = await Promise.all([
                    Bridge.call('noble_api', 'getAddressBalance', { address }),
                    Bridge.call('noble_api', 'getAddressHistory', { address, page: historyPage, limit: historyLimit }),
                ]);
                balance = bal;
                const txIds = (hist && hist.transactions) || [];
                const txDetails = await Promise.all(
                    txIds.slice(0, 20).map(id =>
                        Bridge.call('noble_api', 'getTransaction', { tx_id: id }).catch(() => null)
                    )
                );
                history = { transactions: txDetails.filter(Boolean) };
            }
            if (!alive) return;
            balanceData = balance;
            historyData = history;
            renderBalance(balanceContainer, balance);
            renderHistory(historyContainer, history);
        } catch (err) {
            if (!alive) return;
            balanceContainer.innerHTML = '';
            historyContainer.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = 'error-card';
            errDiv.setAttribute('role', 'alert');
            errDiv.innerHTML = `<p>${err.message}</p><button type="button">Retry</button>`;
            errDiv.querySelector('button').addEventListener('click', () => {
                balanceContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                historyContainer.innerHTML = '<div class="skeleton skeleton-card"></div>';
                loadData(balanceContainer, historyContainer);
            });
            balanceContainer.appendChild(errDiv);
        }
    }

    function renderBalance(container, balance) {
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
                    <div class="kpi-value">${formatAmount(balance.pending)}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Transactions</div>
                    <div class="kpi-value">${balance.txCount}</div>
                </div>
            </div>
            <div class="chain-note">\u26A0\uFE0F Make sure you always work within the same chain your balance resides in. If you connect to a different chain, you cannot access your balance.</div>
        `;
        container.appendChild(nobleCard('Balance Summary', html));
    }

    // ── Transaction History ──

    function renderHistory(container, data) {
        container.innerHTML = '';
        const txs = data.transactions || [];

        if (txs.length === 0) {
            const card = nobleCard('Transaction History', '');
            card.querySelector('.panel-body').appendChild(emptyState({
                icon: '\u{1F4B8}',
                title: 'No Transactions',
                subtitle: 'Your transaction history will appear here.'
            }));
            container.appendChild(card);
            return;
        }

        let html = '<div class="table-scroll-wrapper"><table class="data-table"><thead><tr><th></th><th>Counterparty</th><th>Amount</th><th>Status</th><th>Time</th></tr></thead><tbody>';
        for (const tx of txs) {
            const dir = txDirection(tx);
            const counterparty = tx.counterparty ? truncate(tx.counterparty, 8) : '\u2014';
            const disp = txDisplayAmount(tx);
            const amount = formatAmount(disp.amount);
            const status = tx.confirmations >= 6 ? 'confirmed' : (tx.confirmations > 0 ? 'pending' : 'pending');
            const ago = timeAgo(tx.timestamp);
            const isExpanded = expandedTx === tx.txId;
            html += `<tr class="tx-row" data-txid="${esc(tx.txId)}" style="cursor:pointer">
                <td><span class="tx-direction ${dir.cls}">${dir.icon}</span></td>
                <td class="mono" style="font-size:var(--font-size-xs)">${counterparty}</td>
                <td class="mono">\u25C6 ${amount}</td>
                <td><span class="badge badge-${status}">${status}</span></td>
                <td style="font-size:var(--font-size-xs);color:var(--text-muted)">${ago}</td>
            </tr>`;
            if (isExpanded) {
                html += `<tr class="tx-detail-row"><td colspan="5">${renderTxDetail(tx)}</td></tr>`;
            }
        }
        html += '</tbody></table></div>';

        const card = nobleCard('Transaction History', html);

        // Keyboard accessibility for tx rows
        card.querySelectorAll('.tx-row').forEach(row => {
            row.setAttribute('tabindex', '0');
            row.setAttribute('role', 'button');
            row.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); }
            });
        });

        // Click handler for rows
        card.addEventListener('click', e => {
            const row = e.target.closest('.tx-row');
            if (!row) return;
            const txId = row.dataset.txid;
            expandedTx = expandedTx === txId ? null : txId;
            renderHistory(container, data);
        });

        // Pagination
        const pagination = document.createElement('div');
        pagination.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:var(--gap-sm) var(--gap);';

        const pageInfo = document.createElement('span');
        pageInfo.style.cssText = 'font-size:var(--font-size-xs); color:var(--text-muted)';
        pageInfo.textContent = `Page ${historyPage + 1} of ${Math.max(1, Math.ceil((data.total || 1) / historyLimit))}`;

        const btnGroup = document.createElement('div');
        btnGroup.style.display = 'flex';
        btnGroup.style.gap = 'var(--gap-sm)';

        const prevBtn = document.createElement('button');
        prevBtn.className = 'btn btn-sm btn-secondary';
        prevBtn.textContent = 'Previous';
        prevBtn.disabled = historyPage === 0;
        prevBtn.addEventListener('click', async () => {
            historyPage--;
            const h = await Bridge.call('noble_api', 'getTransactionHistory', { address: state.walletAddress, page: historyPage, limit: historyLimit });
            if (!alive) return;
            historyData = h;
            renderHistory(container, h);
        });

        const nextBtn = document.createElement('button');
        nextBtn.className = 'btn btn-sm btn-secondary';
        nextBtn.textContent = 'Next';
        nextBtn.disabled = (historyPage + 1) * historyLimit >= (data.total || 0);
        nextBtn.addEventListener('click', async () => {
            historyPage++;
            const h = await Bridge.call('noble_api', 'getTransactionHistory', { address: state.walletAddress, page: historyPage, limit: historyLimit });
            if (!alive) return;
            historyData = h;
            renderHistory(container, h);
        });

        btnGroup.appendChild(prevBtn);
        btnGroup.appendChild(nextBtn);
        pagination.appendChild(pageInfo);
        pagination.appendChild(btnGroup);
        card.appendChild(pagination);

        container.appendChild(card);
    }

    function renderTxDetail(tx) {
        const outputsHtml = (tx.outputs || []).map((o, i) =>
            `<dt>Output #${i}</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">\u25C6 ${formatAmount(o.value)} \u2192 ${esc(o.address)}</dd>`
        ).join('');
        const inputsHtml = (tx.inputs || []).map((inp, i) =>
            `<dt>Input #${i}</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(inp.txid)}:${inp.vout}</dd>`
        ).join('');
        const txDisp = txDisplayAmount(tx);
        return `<div class="detail-grid" style="padding:var(--gap-sm) 0">
            <dt>TX ID</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(tx.txId)}</dd>
            <dt>Block Height</dt><dd>${tx.blockHeight || '\u2014'}</dd>
            <dt>Confirmations</dt><dd>${tx.confirmations}</dd>
            <dt>Type</dt><dd>${esc(tx.type)}</dd>
            <dt>${txDisp.label}</dt><dd class="mono">\u25C6 ${formatAmount(txDisp.amount)}</dd>
            ${outputsHtml}
            ${inputsHtml}
            ${tx.counterparty ? `<dt>Counterparty</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(tx.counterparty)}</dd>` : ''}
            <dt>Time</dt><dd>${new Date(tx.timestamp * 1000).toLocaleString()}</dd>
        </div>`;
    }

    function txDirection(tx) {
        if (tx.type === 'notarization') return { icon: '\u{1F4C4}', cls: 'tx-notarization' };
        if (tx.direction === 'incoming') return { icon: '\u2B07', cls: 'tx-incoming' };
        return { icon: '\u2B06', cls: 'tx-outgoing' };
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
                    const minRate = f.lowFeeRate || f.networkMinFeeRate || f.low_fee_rate || f.network_min_fee_rate || 1;
                    const recRate = f.recommendedFeeRate || f.networkMedianFeeRate || f.recommended_fee_rate || f.network_median_fee_rate || 2;
                    const highRate = f.highPriorityFeeRate || f.high_priority_fee_rate || 5;

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
                }).catch(() => {
                    feeData = { minFee: 800, recommendedFee: 1600, highPriorityFee: 4000,
                                minFeeRate: 1, recommendedFeeRate: 2, highPriorityFeeRate: 5 };
                    wizard.renderStep();
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

                // Fetch wallet UTXOs for coin selection.
                const utxoResp = await Bridge.call('noble_api', 'getAddressUtxos', { address: state.walletAddress });
                const utxos = (utxoResp.utxos || []).map(u => ({
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                }));

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

    return {
        destroy() { alive = false; closeModal(); },
        refresh(newState) { Object.assign(state, newState); },
        openSendWizard(recipientAddress) { openSendWizard(recipientAddress); }
    };
}

// ── Helpers ──

function parseAmount(str) {
    const n = parseFloat(str);
    if (isNaN(n) || n <= 0) return 0;
    return Math.round(n * 100_000_000);
}
