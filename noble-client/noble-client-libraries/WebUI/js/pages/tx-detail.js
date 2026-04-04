// NOBLE Client — Transaction Detail Page
// Type-aware rendering adapted from node dashboard tx-detail.js.

import { formatAmount, formatSignedAmount } from '../components/amount-text.js';
import { TX_TYPES, TX_TYPE_NAMES, txDisplayAmount, classifyMetadata, isZeroChecksum, formatTxType, decodeMetadataValue, txStatusBadge } from '../tx-display.js';
import { openModal, closeModal } from '../components/modal.js';

export function init(root, ctx) {
    const { state, Bridge, params } = ctx;
    const txid = params?.txid;
    if (!txid) {
        root.innerHTML = '<div class="empty-state">No transaction ID provided</div>';
        return { destroy() {} };
    }

    root.innerHTML = `
        <div style="margin-bottom:var(--gap)">
            <button class="btn btn-sm" id="tx-back">&larr; Back</button>
        </div>
        <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-start">
            <h2 style="margin:0">Transaction Detail</h2>
            <button id="tx-refresh" title="Refresh" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1">&#x21BB;</button>
        </div>
        <div id="tx-loading" class="empty-state">Loading...</div>
    `;

    root.querySelector('#tx-back').addEventListener('click', () => {
        if (window.App) App.navigateBack();
    });
    root.querySelector('#tx-refresh').addEventListener('click', () => load());

    let loadInFlight = false;
    async function load() {
        if (loadInFlight) return;
        loadInFlight = true;
        let tx = null;
        let receipt = null;

        try {
            // Try getTransaction first (returns enriched tx with fee, transfer_value)
            tx = await Bridge.call('noble_api', 'getTransaction', { txId: txid });
        } catch (e) {
            console.warn('[tx-detail] getTransaction failed:', e);
        }

        if (!tx) {
            root.querySelector('#tx-loading')?.remove();
            root.innerHTML += '<div class="empty-state">Transaction not found</div>';
            return;
        }

        root.querySelector('#tx-loading')?.remove();

        // Clear previous content on refresh (prevents duplication)
        const prev = root.querySelector('#tx-content');
        if (prev) prev.remove();
        const content = document.createElement('div');
        content.id = 'tx-content';

        const txType = tx.tx_type ?? parseTypeFromLabel(tx.type);
        const metadata = tx.metadata || [];
        const { system, user, signatures } = classifyMetadata(metadata, txType);
        const disp = txDisplayAmount(tx);

        // ── Hero Section ──
        const heroEl = document.createElement('div');
        heroEl.className = 'panel';
        heroEl.style.cssText = 'text-align:center;padding:var(--gap);margin-bottom:var(--gap)';

        if ((txType === TX_TYPES.NOTARIZATION || txType === TX_TYPES.UNLOCKING) && !isZeroChecksum(tx.checksum)) {
            heroEl.innerHTML = `
                <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:4px">${txType === TX_TYPES.UNLOCKING ? 'Revealed Document Checksum' : 'Document Checksum'}</div>
                <div class="mono" style="word-break:break-all;font-size:var(--font-size-sm)">${esc(tx.checksum)}</div>
                <button class="btn btn-sm" id="copy-checksum" style="margin-top:8px">Copy Checksum</button>
            `;
        } else if (txType === TX_TYPES.LOCKED) {
            heroEl.innerHTML = `
                <div style="font-size:1.2rem">&#x1F512; Encrypted Document</div>
                <div style="color:var(--text-muted);font-size:var(--font-size-xs);margin-top:4px">Checksum and metadata encrypted with AES-256-GCM</div>
            `;
        } else if (txType === TX_TYPES.TRANSFER) {
            const heroColor = disp.direction === 'outgoing' ? 'color:var(--warning)' : disp.direction === 'incoming' ? 'color:var(--success)' : '';
            heroEl.innerHTML = `
                <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${disp.label}</div>
                <div style="font-size:clamp(1.8rem, 3vw, 2.5rem);font-weight:800;${heroColor};letter-spacing:-0.02em" class="mono">&diams; ${formatSignedAmount(disp.amount, disp.direction)}</div>
            `;
        } else if (txType === TX_TYPES.COINBASE) {
            heroEl.innerHTML = `
                <div style="font-size:var(--font-size-xs);color:var(--text-muted)"><span class="badge" style="background:var(--accent);color:#fff;font-size:0.6rem;padding:1px 6px">Coinbase</span> Block Reward</div>
                <div style="font-size:clamp(1.8rem, 3vw, 2.5rem);font-weight:800;color:var(--success);letter-spacing:-0.02em" class="mono">&diams; ${formatSignedAmount(disp.amount, 'incoming')}</div>
            `;
        } else if (txType === TX_TYPES.KEY_ROTATION) {
            heroEl.innerHTML = '<div style="font-size:1.2rem">&#x1F504; Key Rotation</div>';
        } else if (txType === TX_TYPES.BADGE_PROPOSAL) {
            heroEl.innerHTML = '<div style="font-size:1.2rem">&#x1F3C5; Badge Proposal</div>';
        } else if (txType === TX_TYPES.BADGE_VOTE) {
            heroEl.innerHTML = '<div style="font-size:1.2rem">&#x1F5F3; Badge Vote</div>';
        } else if (txType === TX_TYPES.BADGE_REVOCATION) {
            heroEl.innerHTML = '<div style="font-size:1.2rem">&#x26D4; Badge Revocation</div>';
        } else {
            heroEl.style.display = 'none';
        }
        content.appendChild(heroEl);

        // Copy button
        root.querySelector('#copy-checksum')?.addEventListener('click', () => {
            navigator.clipboard.writeText(tx.checksum).then(() => {
                const btn = root.querySelector('#copy-checksum');
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = 'Copy Checksum'; }, 1500);
            });
        });

        // ── Locked Tx: Password Decrypt ──
        if (txType === TX_TYPES.LOCKED) {
            const decryptPanel = document.createElement('div');
            decryptPanel.className = 'card';
            decryptPanel.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap);border-left:3px solid var(--warning)';
            decryptPanel.innerHTML = `
                <div style="font-size:var(--font-size-sm);font-weight:600;margin-bottom:8px">\u{1F513} Decrypt Document</div>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                    <input type="password" id="locked-pw" class="input" placeholder="Enter password" style="flex:1;min-width:150px;max-width:400px">
                    <button class="btn btn-primary btn-sm" id="locked-decrypt">Decrypt</button>
                </div>
                <div id="locked-result" style="margin-top:8px"></div>
            `;
            content.appendChild(decryptPanel);

            const pwInput = decryptPanel.querySelector('#locked-pw');
            const decryptBtn = decryptPanel.querySelector('#locked-decrypt');
            const resultDiv = decryptPanel.querySelector('#locked-result');

            decryptBtn.addEventListener('click', async () => {
                const pw = pwInput.value;
                if (!pw) return;
                decryptBtn.disabled = true;
                decryptBtn.textContent = 'Decrypting...';
                try {
                    const result = await Bridge.call('noble_crypto', 'decryptLockedTx', {
                        tx_hex: tx.tx_hex || tx.raw_hex || '',
                        password: pw
                    });
                    if (result?.decrypted_checksum) {
                        resultDiv.innerHTML = '<div style="margin-bottom:8px">'
                            + '<div style="font-size:var(--font-size-xs);color:var(--success);font-weight:600">\u2713 Decrypted</div>'
                            + '<div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:4px">Checksum:</div>'
                            + '<div class="mono" style="font-size:var(--font-size-xs);word-break:break-all">' + esc(result.decrypted_checksum) + '</div>'
                            + '</div>';
                        if (result.decrypted_metadata?.length > 0) {
                            resultDiv.innerHTML += '<div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:8px">Metadata:</div>';
                            for (const m of result.decrypted_metadata) {
                                resultDiv.innerHTML += '<div style="margin-top:4px">'
                                    + '<span style="font-size:var(--font-size-xs);color:var(--text-muted)">' + esc(m.key) + ':</span> '
                                    + '<span class="mono" style="font-size:var(--font-size-xs)">' + esc(m.value) + '</span></div>';
                            }
                        }
                        // Update hero to show decrypted checksum
                        heroEl.innerHTML = '<div style="font-size:var(--font-size-xs);color:var(--success);margin-bottom:4px">\u{1F513} Decrypted Document Checksum</div>'
                            + '<div class="mono" style="word-break:break-all;font-size:var(--font-size-sm)">' + esc(result.decrypted_checksum) + '</div>';
                        decryptBtn.textContent = '\u2713 Done';
                    } else {
                        resultDiv.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">\u26A0 Wrong password or corrupted data.</div>';
                        decryptBtn.disabled = false;
                        decryptBtn.textContent = 'Decrypt';
                    }
                } catch (e) {
                    resultDiv.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">' + esc(e.message || 'Decryption failed') + '</div>';
                    decryptBtn.disabled = false;
                    decryptBtn.textContent = 'Decrypt';
                }
            });
        }

        // ── Detail Grid ──
        const grid = document.createElement('div');
        grid.className = 'panel';
        grid.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap)';
        let html = '<dl class="tx-detail-dl">';
        html += row('TX ID', `<span class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(tx.txId || txid)}</span>`);
        html += row('Type', formatTxType(txType));
        if (tx.timestamp) html += row('Time', formatTime(tx.timestamp));

        if (txType === TX_TYPES.TRANSFER) {
            const amtStyle = disp.direction === 'outgoing' ? ' style="color:var(--warning)"' : disp.direction === 'incoming' ? ' style="color:var(--success)"' : '';
            html += row(disp.label, `<span class="mono"${amtStyle}>&diams; ${formatSignedAmount(disp.amount, disp.direction)}</span>`);
            if (tx.fee != null) html += row('Fee', `<span class="mono">&diams; ${formatAmount(tx.fee)}</span>`);
        } else if (txType === TX_TYPES.COINBASE) {
            html += row('Block Reward', `<span class="mono" style="color:var(--success)">&diams; ${formatSignedAmount(disp.amount, 'incoming')}</span>`);
        } else {
            if (tx.fee != null) html += row('Fee', `<span class="mono">&diams; ${formatAmount(tx.fee)}</span>`);
            html += row('Total Output', `<span class="mono" style="color:var(--text-muted)">&diams; ${formatAmount(tx.total_output || 0)}</span>`);
        }

        const badge = txStatusBadge(tx.confirmations, tx.status);
        html += row('Status', `<span class="badge ${badge.cls}">${badge.html}</span>`);
        if (tx.blockHeight != null) html += row('Block Height', String(tx.blockHeight));
        if (tx.confirmations != null) html += row('Confirmations', String(tx.confirmations));
        if (tx.signer) html += row('Signer', `<span class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(tx.signer)}</span>`);
        if (tx.recipient) html += row('Recipient', `<span class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(tx.recipient)}</span>`);

        html += '</dl>';
        grid.innerHTML = html;
        content.appendChild(grid);

        // ── Inputs (collapsible) ──
        const inputs = tx.inputs || [];
        const inputCount = tx.input_count ?? inputs.length;
        if (inputCount > 0) {
            const panel = document.createElement('div');
            panel.className = 'card';
            panel.style.cssText = 'padding:var(--gap-sm);margin-bottom:var(--gap-sm)';
            const isCoinbase = inputs.length === 1 && /^0+$/.test(inputs[0]?.txid);
            if (isCoinbase) {
                panel.innerHTML = `<div style="font-size:var(--font-size-xs);color:var(--text-muted)">Coinbase (new coins minted by the network)</div>`;
            } else if (inputs.length === 0 && inputCount > 0) {
                panel.innerHTML = `<div style="font-size:var(--font-size-xs);color:var(--text-muted)">${inputCount} UTXO${inputCount > 1 ? 's' : ''} consolidated</div>`;
            } else {
                const details = document.createElement('details');
                const summary = document.createElement('summary');
                summary.style.cssText = 'cursor:pointer;font-weight:600;font-size:var(--font-size-xs);color:var(--text-muted)';
                summary.textContent = `Inputs (${inputCount})`;
                details.appendChild(summary);
                const inner = document.createElement('div');
                inner.style.cssText = 'margin-top:6px';
                for (let i = 0; i < inputs.length; i++) {
                    inner.innerHTML += `<div style="margin-bottom:4px;font-size:0.65rem">
                        <span style="color:var(--text-muted)">#${i}</span>
                        <span class="mono" style="word-break:break-all">${esc(inputs[i].txid)}</span>:<strong>${inputs[i].vout}</strong>
                    </div>`;
                }
                details.appendChild(inner);
                panel.appendChild(details);
            }
            content.appendChild(panel);
        }

        // ── Outputs (collapsible) ──
        const outputs = tx.outputs || [];
        if (outputs.length > 0) {
            const panel = document.createElement('div');
            panel.className = 'card';
            panel.style.cssText = 'padding:var(--gap-sm);margin-bottom:var(--gap-sm)';
            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.style.cssText = 'cursor:pointer;font-weight:600;font-size:var(--font-size-xs);color:var(--text-muted)';
            summary.textContent = `Outputs (${outputs.length})`;
            details.appendChild(summary);
            const inner = document.createElement('div');
            inner.style.cssText = 'margin-top:6px';
            for (let i = 0; i < outputs.length; i++) {
                inner.innerHTML += `<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px;font-size:0.65rem">
                    <span class="mono" style="word-break:break-all;flex:1;margin-right:4px">#${i} &rarr; ${esc(outputs[i].address)}</span>
                    <span class="mono" style="white-space:nowrap">&diams; ${formatAmount(outputs[i].value)}</span>
                </div>`;
            }
            details.appendChild(inner);
            panel.appendChild(details);
            content.appendChild(panel);
        }

        // ── User Metadata ──
        if (user.length > 0) {
            // Parse schema descriptor to detect encoding per slot
            const schemaSlots = parseSchemaDescriptor(metadata);

            const panel = document.createElement('div');
            panel.className = 'card';
            panel.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap)';
            let mhtml = `<h3 style="margin:0 0 8px;font-size:var(--font-size-sm)">Metadata (${user.length})</h3>`;
            // Match schema slots to metadata entries by key name + positional ordering
            function findSlot(slots, key, sameKeyIdx) {
                if (!slots) return null;
                let count = 0;
                for (const [, s] of slots) {
                    if (s.key === key) {
                        if (count === sameKeyIdx) return s;
                        count++;
                    }
                }
                return null;
            }

            for (let ui = 0; ui < user.length; ui++) {
                const entry = user[ui];
                const entryIdx = metadata.indexOf(entry);
                const sameKeyBefore = user.slice(0, ui).filter(e => e.key === entry.key).length;
                const slot = findSlot(schemaSlots, entry.key, sameKeyBefore);
                const encoding = slot?.encoding || null;
                const schemaLine = slot?.raw || null;
                const isEcies = encoding === 'ecies';
                const isProtected = encoding === 'aesgcm';

                const sigMatch = signatures.find(s => s.slotIndex === entryIdx);
                const sigBadge = sigMatch ? ` <span id="sig-badge-${entryIdx}" class="badge" style="background:var(--accent);color:#fff;font-size:0.5rem;padding:1px 4px">Verifying...</span>` : '';
                const maybeEncrypted = !isEcies && !isProtected && entry.value && entry.value.length > 100 && /^[0-9a-f]+$/i.test(entry.value);
                const encBadge = isEcies ? ' <span class="badge" style="background:var(--accent);color:#fff;font-size:0.5rem;padding:1px 4px">Encrypted</span>'
                    : isProtected ? ' <span class="badge" style="background:var(--warning);color:#fff;font-size:0.5rem;padding:1px 4px">Protected</span>'
                    : maybeEncrypted ? ' <span class="badge" style="background:var(--warning);color:#fff;font-size:0.5rem;padding:1px 4px">Possibly Encrypted</span>' : '';

                const showDecrypt = isEcies || isProtected || maybeEncrypted;
                const val = (isEcies || isProtected || maybeEncrypted) ? `${(entry.value?.length || 0) / 2} bytes` : decodeMetadataValue(entry.value);
                const decryptBtnId = showDecrypt ? `decrypt-${entryIdx}` : '';
                const btnLabel = isEcies ? 'Decrypt' : isProtected ? 'Unlock' : 'Try Decrypt';
                const decryptBtn = showDecrypt ? ` <button class="btn btn-sm" id="${decryptBtnId}" style="margin-left:4px;font-size:0.6rem;padding:1px 6px">${btnLabel}</button>` : '';
                // Schema line shown above field in subdued color
                const schemaHtml = schemaLine ? `<div style="font-size:0.55rem;color:var(--text-muted);opacity:0.5;margin-bottom:1px;font-family:var(--font-mono)">${esc(schemaLine)}</div>` : '';

                mhtml += `<div style="margin-bottom:6px">${schemaHtml}
                    <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${esc(entry.key)}${sigBadge}${encBadge}${decryptBtn}</div>
                    <div class="mono" id="meta-val-${entryIdx}" style="font-size:var(--font-size-xs);word-break:break-all">${esc(val)}</div>
                </div>`;
            }
            panel.innerHTML = mhtml;
            content.appendChild(panel);

            // Wire up Decrypt/Unlock buttons
            for (let ui = 0; ui < user.length; ui++) {
                const entry = user[ui];
                const entryIdx = metadata.indexOf(entry);
                const sameKeyBefore2 = user.slice(0, ui).filter(e => e.key === entry.key).length;
                const slot2 = findSlot(schemaSlots, entry.key, sameKeyBefore2);
                const isEciesField = slot2?.encoding === 'ecies';
                const isProtectedField = slot2?.encoding === 'aesgcm';
                const isHeuristicField = !isEciesField && !isProtectedField && entry.value && entry.value.length > 100 && /^[0-9a-f]+$/i.test(entry.value);
                if (!isEciesField && !isProtectedField && !isHeuristicField) continue;
                const btn = panel.querySelector(`#decrypt-${entryIdx}`);
                if (!btn) continue;
                btn.addEventListener('click', () => {
                    openDecryptModal(entry, entryIdx, isEciesField, isProtectedField);
                });
            }

            function openDecryptModal(entry, entryIdx, isEciesField, isProtectedField) {
                const body = document.createElement('div');
                const statusDiv = document.createElement('div');
                body.appendChild(statusDiv);

                // Field info at top
                const infoDiv = document.createElement('div');
                infoDiv.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)';
                infoDiv.textContent = entry.key + ' \u2014 ' + Math.floor((entry.value?.length || 0) / 2) + ' bytes'
                    + (isEciesField ? ' (recipient-encrypted)' : isProtectedField ? ' (password-protected)' : '');
                body.appendChild(infoDiv);

                if (isEciesField) {
                    // ECIES only — auto-decrypt with wallet key
                    const eciesBtn = document.createElement('button');
                    eciesBtn.className = 'btn btn-primary';
                    eciesBtn.textContent = 'Decrypt with Wallet Key';
                    eciesBtn.style.width = '100%';
                    eciesBtn.addEventListener('click', async () => {
                        eciesBtn.disabled = true;
                        eciesBtn.textContent = 'Decrypting...';
                        try {
                            const r = await Bridge.call('noble_crypto', 'decryptEciesField', { payload_hex: entry.value });
                            if (r?.plaintext) { showDecryptSuccess(statusDiv, r.plaintext, entryIdx); eciesBtn.style.display = 'none'; }
                            else { statusDiv.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">Could not decrypt. You may not be the intended recipient.</div>'; eciesBtn.disabled = false; eciesBtn.textContent = 'Decrypt with Wallet Key'; }
                        } catch { statusDiv.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">Not encrypted for your wallet key.</div>'; eciesBtn.disabled = false; eciesBtn.textContent = 'Decrypt with Wallet Key'; }
                    });
                    body.appendChild(eciesBtn);
                } else if (isProtectedField) {
                    // Password only — AES-GCM protected field
                    buildPasswordSection(body, statusDiv, entry, entryIdx);
                } else {
                    // Unknown encoding — offer both
                    const eciesBtn = document.createElement('button');
                    eciesBtn.className = 'btn btn-primary';
                    eciesBtn.textContent = 'Try Decrypt with Wallet Key';
                    eciesBtn.style.cssText = 'width:100%;margin-bottom:var(--gap)';
                    eciesBtn.addEventListener('click', async () => {
                        eciesBtn.disabled = true;
                        eciesBtn.textContent = 'Trying...';
                        try {
                            const r = await Bridge.call('noble_crypto', 'decryptEciesField', { payload_hex: entry.value });
                            if (r?.plaintext) { showDecryptSuccess(statusDiv, r.plaintext, entryIdx); eciesBtn.style.display = 'none'; pwArea.style.display = 'none'; }
                            else { statusDiv.innerHTML = '<div style="color:var(--text-muted);font-size:var(--font-size-sm)">Not a wallet-encrypted field. Try password.</div>'; eciesBtn.disabled = false; eciesBtn.textContent = 'Try Decrypt with Wallet Key'; }
                        } catch { statusDiv.innerHTML = '<div style="color:var(--text-muted);font-size:var(--font-size-sm)">Not a wallet-encrypted field. Try password.</div>'; eciesBtn.disabled = false; eciesBtn.textContent = 'Try Decrypt with Wallet Key'; }
                    });
                    body.appendChild(eciesBtn);
                    const pwArea = document.createElement('div');
                    pwArea.style.cssText = 'border-top:1px solid var(--border);padding-top:var(--gap)';
                    buildPasswordSection(pwArea, statusDiv, entry, entryIdx);
                    body.appendChild(pwArea);
                }

                openModal({ title: isEciesField ? 'Decrypt (Wallet Key)' : isProtectedField ? 'Decrypt (Password)' : 'Decrypt Field', body });

                function buildPasswordSection(container, status, ent, idx) {
                    const pwInput = document.createElement('input');
                    pwInput.type = 'password';
                    pwInput.className = 'input';
                    pwInput.placeholder = 'Enter password';
                    pwInput.style.cssText = 'width:100%;margin-bottom:8px';
                    container.appendChild(pwInput);
                    const pwBtn = document.createElement('button');
                    pwBtn.className = 'btn btn-primary';
                    pwBtn.textContent = 'Decrypt';
                    pwBtn.style.width = '100%';
                    pwBtn.addEventListener('click', async () => {
                        const pw = pwInput.value;
                        if (!pw) return;
                        pwBtn.disabled = true;
                        pwBtn.textContent = 'Decrypting...';
                        try {
                            const plaintext = await decryptFieldWithPassword(ent.value, pw);
                            showDecryptSuccess(status, plaintext, idx);
                            pwInput.style.display = 'none'; pwBtn.style.display = 'none';
                        } catch (e) {
                            const msg = e.name === 'OperationError' ? 'Wrong password.' : (e.message || 'Decryption failed');
                            status.innerHTML = '<div style="color:var(--error);font-size:var(--font-size-sm)">\u26A0 ' + esc(msg) + '</div>';
                            pwBtn.disabled = false; pwBtn.textContent = 'Decrypt';
                        }
                    });
                    container.appendChild(pwBtn);
                }

                function showDecryptSuccess(container, plaintext, idx) {
                    container.innerHTML = '<div style="color:var(--success);font-weight:600;margin-bottom:4px">\u2713 Decrypted</div>'
                        + '<div class="mono" style="font-size:var(--font-size-sm);word-break:break-all;background:var(--glass-bg);padding:8px;border-radius:var(--radius-sm)">' + esc(plaintext) + '</div>';
                    // Update the value in the parent tx-detail page
                    const valEl = root.querySelector(`#meta-val-${idx}`);
                    if (valEl) valEl.textContent = plaintext;
                    const parentBtn = root.querySelector(`#decrypt-${idx}`);
                    if (parentBtn) {
                        parentBtn.textContent = '\u2713 Decrypted';
                        parentBtn.style.color = 'var(--success)';
                        parentBtn.disabled = true;
                    }
                }
            }

            // Wire up CMS signature verification
            for (const sig of signatures) {
                const targetEntry = metadata[sig.slotIndex];
                if (!targetEntry) continue;
                const targetIdx = metadata.indexOf(targetEntry);
                const badgeEl = panel.querySelector(`#sig-badge-${targetIdx}`);
                if (!badgeEl) continue;
                // Auto-verify on load
                (async () => {
                    try {
                        const result = await Bridge.call('noble_crypto', 'verifyMetadataField', {
                            signatureHex: sig.value,
                            fieldValue: targetEntry.value
                        });
                        if (result?.valid) {
                            const name = result.signerName || ('SKI ' + (result.signerSKI || '').slice(0, 12));
                            badgeEl.innerHTML = '\u2713 Signed by: ' + esc(name);
                            badgeEl.style.background = 'var(--success)';
                        } else {
                            badgeEl.innerHTML = '\u2717 Invalid';
                            badgeEl.style.background = 'var(--error)';
                        }
                    } catch {
                        badgeEl.innerHTML = '\u26A0 Verify failed';
                        badgeEl.style.background = 'var(--warning)';
                    }
                })();
            }
        }

        // ── Batch document linking ──
        if (user.length > 0) {
            const batchMeta = metadata.find(m => m.key === 'doc:batch');
            if (batchMeta?.value) {
                const batchPanel = document.createElement('div');
                batchPanel.className = 'card';
                batchPanel.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap)';
                batchPanel.innerHTML = '<h3 style="margin:0 0 8px;font-size:var(--font-size-sm)">Batch Documents</h3><div style="color:var(--text-muted);font-size:var(--font-size-xs)">Loading...</div>';
                content.appendChild(batchPanel);
                Bridge.call('noble_api', 'searchDocumentsByMetadata', { key: 'doc:batch', value: batchMeta.value }).then(r => {
                    const docs = (r.documents || []).filter(d => (d.txId || d.tx_id) !== (tx.txId || txid));
                    const infoDiv = batchPanel.querySelector('div:last-child');
                    if (docs.length === 0) { infoDiv.textContent = 'No other documents in this batch.'; return; }
                    infoDiv.textContent = docs.length + ' linked document' + (docs.length > 1 ? 's' : '');
                    for (const d of docs) {
                        const dtxid = d.txId || d.tx_id || '';
                        const row = document.createElement('div');
                        row.style.cssText = 'padding:4px 6px;cursor:pointer;border-radius:var(--radius-sm);transition:background 0.15s;font-size:var(--font-size-xs);margin-top:2px';
                        row.innerHTML = '<span class="mono">' + esc(dtxid.slice(0, 20)) + '\u2026</span>'
                            + (d.blockHeight ? ' <span style="color:var(--text-muted)">Block ' + esc(String(d.blockHeight)) + '</span>' : '');
                        row.addEventListener('mouseenter', () => { row.style.background = 'var(--accent-subtle)'; });
                        row.addEventListener('mouseleave', () => { row.style.background = ''; });
                        row.addEventListener('click', () => { if (window.App) App.navigateTo('tx-detail', { txid: dtxid }); });
                        batchPanel.appendChild(row);
                    }
                }).catch(() => {
                    batchPanel.querySelector('div:last-child').textContent = 'Could not load batch.';
                });
            }
        }

        // ── Encrypted locator ──
        if (tx.has_encrypted_locator) {
            const locEl = document.createElement('div');
            locEl.className = 'card';
            locEl.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap);border-left:3px solid var(--accent)';
            locEl.innerHTML = '<span class="badge" style="background:var(--accent);color:#fff;font-size:0.6rem;padding:1px 6px">Encrypted Locator</span> Available';
            content.appendChild(locEl);
        }
        root.appendChild(content);
        loadInFlight = false;
    }

    load();
    return { destroy() {} };
}

// ── Helpers ──

async function decryptFieldWithPassword(encryptedHex, password) {
    const bytes = new Uint8Array(encryptedHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const salt = bytes.slice(0, 16);
    const nonce = bytes.slice(16, 28);
    const ciphertext = bytes.slice(28);
    const enc = new TextEncoder();
    const keyHash = await crypto.subtle.digest('SHA-256',
        new Uint8Array([...enc.encode(password), ...salt]));
    const key = await crypto.subtle.importKey('raw', keyHash, 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext);
    return new TextDecoder().decode(plain);
}

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function row(label, value) {
    return `<dt style="font-size:var(--font-size-xs);color:var(--text-muted);padding:2px 0">${label}</dt><dd style="margin:0;padding:2px 0">${value}</dd>`;
}

function formatTime(ts) {
    if (!ts) return '—';
    const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    return d.toLocaleString();
}

function parseSchemaDescriptor(metadataEntries) {
    const schemaEntry = metadataEntries.find(e => e.key === 'schema' || e.key === 'schema:');
    if (!schemaEntry?.value) return null;
    // Try text first (bridge may return UTF-8), hex fallback
    let text = schemaEntry.value;
    if (/^[0-9a-f]+$/i.test(text) && text.length % 2 === 0 && text.length > 20) {
        try {
            const bytes = new Uint8Array(text.match(/.{2}/g).map(b => parseInt(b, 16)));
            text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch { /* use text as-is */ }
    }
    const slotMap = new Map();
    for (const line of text.split('\n')) {
        const trimmed = line.trim();
        const parts = trimmed.split(':');
        if (parts.length < 4) continue;
        const slotNum = parseInt(parts[0], 10);
        if (isNaN(slotNum)) continue;
        const hasTypeCode = /^T\d+$/.test(parts[1]) || parts[1] === 'SIG';
        let encoding, fieldKey;
        if (hasTypeCode && parts.length >= 5) {
            encoding = parts[3]; // v2: slot:code:vis:enc:key
            fieldKey = parts.slice(4).join(':'); // key may contain colons (e.g. doc:url)
        } else if (hasTypeCode) {
            const vis = parts[2];
            encoding = vis === 'priv' ? 'ecies' : vis === 'pwd' ? 'aesgcm' : 'utf8'; // v0
            fieldKey = parts.length > 3 ? parts.slice(3).join(':') : null;
        } else {
            encoding = parts[2]; // v1: slot:vis:enc:req:label
            fieldKey = parts.length > 4 ? parts.slice(4).join(':') : null;
        }
        slotMap.set(slotNum, { encoding, raw: trimmed, key: fieldKey });
    }
    return slotMap.size > 0 ? slotMap : null;
}

function parseTypeFromLabel(label) {
    if (!label) return -1;
    const lower = label.toLowerCase().replace(/[_\s-]/g, '');
    const map = { notarization: 0, transfer: 1, keyrotation: 2, badgeproposal: 3, badgevote: 4, badgerevocation: 5, locked: 6, unlocking: 7, coinbase: 16 };
    return map[lower] ?? -1;
}
