// NOBLE Document Client — Document Verification (3 input modes)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { statusBadge } from '../components/status-badge.js';
import { emptyState } from '../components/empty-state.js';
import { formatAmount } from '../components/amount-text.js';
import { esc, formatTimestamp } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let mode = 'file'; // file | checksum | locator
    let checksum = '';
    let verifying = false;
    let result = null;
    let versions = null;
    let selectedFile = null;

    // Handle native file drops from Swift DroppableWebView
    window._nobleHandleFileDrop = async function(droppedFiles) {
        if (mode !== 'file' || !alive || !droppedFiles?.length) return;
        selectedFile = droppedFiles[0];
        checksum = '';
        result = null;
        versions = null;
        render();
        try {
            const hashResult = await Bridge.call('noble_security', 'hashFile', { filePath: selectedFile.path });
            if (!alive) return;
            checksum = hashResult.hash;
            render();
        } catch (e) {
            console.error('[verify] hash failed:', e);
        }
    };

    render();

    function render() {
        if (!alive) return;
        root.innerHTML = '';
        root.classList.add('page-content');

        // Header
        const header = document.createElement('div');
        header.className = 'page-header';
        header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start';
        header.innerHTML = '<div><h1 style="margin:0">Verify</h1><p style="margin:4px 0 0">Check if a document is registered on the NOBLE blockchain</p></div>';
        if (result || selectedFile) {
            const clearBtn = document.createElement('button');
            clearBtn.className = 'btn btn-sm';
            clearBtn.textContent = 'Clear';
            clearBtn.addEventListener('click', () => {
                checksum = ''; result = null; versions = null; selectedFile = null;
                render();
            });
            header.appendChild(clearBtn);
        }
        root.appendChild(header);

        // Mode selector
        const seg = document.createElement('div');
        seg.className = 'segmented-control';
        seg.setAttribute('role', 'tablist');
        seg.setAttribute('aria-label', 'Verification input mode');
        seg.style.marginBottom = 'var(--gap)';

        const modes = [
            { key: 'file', label: 'File' },
            { key: 'checksum', label: 'Checksum' },
            { key: 'locator', label: 'Locator' },
            { key: 'author', label: 'Author' },
            { key: 'issuer', label: 'Issuer' },
            { key: 'mydocs', label: 'My Docs' },
        ];
        for (const m of modes) {
            const btn = document.createElement('button');
            btn.className = mode === m.key ? 'active' : '';
            btn.setAttribute('role', 'tab');
            btn.setAttribute('aria-selected', mode === m.key ? 'true' : 'false');
            btn.setAttribute('tabindex', mode === m.key ? '0' : '-1');
            btn.textContent = m.label;
            btn.addEventListener('click', () => {
                mode = m.key;
                checksum = '';
                result = null;
                versions = null;
                selectedFile = null;
                render();
            });
            seg.appendChild(btn);
        }
        seg.addEventListener('keydown', (e) => {
            const keys = modes.map(m => m.key);
            const idx = keys.indexOf(mode);
            if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
                e.preventDefault();
                const next = (idx + 1) % keys.length;
                mode = keys[next];
                checksum = ''; result = null; versions = null; selectedFile = null;
                render();
            } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
                e.preventDefault();
                const prev = (idx - 1 + keys.length) % keys.length;
                mode = keys[prev];
                checksum = ''; result = null; versions = null; selectedFile = null;
                render();
            }
        });
        root.appendChild(seg);

        // Input area
        const inputArea = document.createElement('div');
        inputArea.style.marginBottom = 'var(--gap)';
        root.appendChild(inputArea);

        switch (mode) {
            case 'file': renderFileInput(inputArea); break;
            case 'checksum': renderChecksumInput(inputArea); break;
            case 'locator': renderLocatorInput(inputArea); break;
            case 'author': renderAuthorSearch(inputArea); break;
            case 'issuer': renderIssuerSearch(inputArea); break;
            case 'mydocs': renderMyDocuments(inputArea); break;
        }

        // Loading indicator
        if (verifying) {
            const loading = document.createElement('div');
            loading.style.cssText = 'text-align:center;padding:var(--gap);color:var(--text-muted)';
            loading.setAttribute('role', 'status');
            loading.setAttribute('aria-live', 'polite');
            loading.textContent = 'Verifying...';
            root.appendChild(loading);
        }

        // Result display
        if (result && !verifying) {
            renderResult(root);
        }
    }

    // ── File Mode ──

    function renderFileInput(container) {
        if (selectedFile) {
            const card = document.createElement('div');
            card.className = 'panel';
            card.innerHTML = `
                <div class="panel-body" style="display:flex;align-items:center;gap:var(--gap-sm)">
                    <span style="color:var(--success)">\u2713</span>
                    <span class="file-name">${esc(selectedFile.name)}</span>
                    <span class="mono" style="font-size:var(--font-size-xs);color:var(--text-secondary)">${checksum ? checksum.slice(0, 16) + '\u2026' : 'hashing...'}</span>
                </div>
            `;
            container.appendChild(card);

            if (checksum && !result && !verifying) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-primary';
                btn.textContent = 'Verify on Chain';
                btn.style.marginTop = 'var(--gap-sm)';
                btn.addEventListener('click', () => doVerify());
                container.appendChild(btn);
            }
            return;
        }

        const zone = document.createElement('div');
        zone.className = 'drop-zone';
        zone.setAttribute('role', 'button');
        zone.setAttribute('aria-label', 'Drop a file or click to select');
        zone.setAttribute('tabindex', '0');
        zone.innerHTML = '<div style="font-size:2rem;margin-bottom:var(--gap-sm)">\u{1F4C4}</div><div>Drop a file here or click to select</div>';
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            e.dataTransfer.dropEffect = 'copy';
            zone.classList.add('drag-over');
        });
        zone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove('drag-over');
        });
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove('drag-over');
            // Actual file handling via native Swift drop → window._nobleHandleFileDrop
        });
        zone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); zone.click(); }
        });
        zone.addEventListener('click', async () => {
            try {
                const res = await Bridge.call('noble_app', 'openFileDialog', { multiple: false });
                if (!alive) return;
                if (res.files && res.files.length > 0) {
                    selectedFile = res.files[0];
                    render();
                    // Hash the file
                    const hashResult = await Bridge.call('noble_security', 'hashFile', { filePath: selectedFile.path });
                    if (!alive) return;
                    checksum = hashResult.hash;
                    render();
                }
            } catch {
                // cancelled
            }
        });
        container.appendChild(zone);
    }

    // ── Checksum Mode ──

    function renderChecksumInput(container) {
        const group = document.createElement('div');
        group.className = 'form-group';
        group.innerHTML = '<label>SHA-256 Checksum (64 hex characters)</label>';

        const row = document.createElement('div');
        row.className = 'search-bar';

        const input = document.createElement('input');
        input.type = 'text';
        input.maxLength = 64;
        input.placeholder = 'e.g. e3b0c44298fc1c149afbf4c8996fb924...';
        input.value = checksum;
        input.addEventListener('input', () => {
            checksum = input.value.trim().toLowerCase();
        });

        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.textContent = 'Verify';
        btn.addEventListener('click', () => {
            if (checksum.length === 64 && /^[0-9a-f]{64}$/.test(checksum)) {
                doVerify();
            }
        });

        row.appendChild(input);
        row.appendChild(btn);
        group.appendChild(row);

        const hint = document.createElement('div');
        hint.className = 'form-hint';
        hint.textContent = 'Enter the full 64-character hex checksum.';
        group.appendChild(hint);
        container.appendChild(group);
    }

    // ── Locator Mode ──

    function renderLocatorInput(container) {
        const group = document.createElement('div');
        group.className = 'form-group';
        group.innerHTML = '<label>NOBLE Document Locator</label>';

        const row = document.createElement('div');
        row.className = 'search-bar';

        const input = document.createElement('input');
        input.type = 'text';
        input.placeholder = 'noble:doc:<checksum>';
        input.addEventListener('input', () => {
            const val = input.value.trim();
            const match = val.match(/^noble:doc:([0-9a-fA-F]{64})$/);
            if (match) {
                checksum = match[1].toLowerCase();
            } else {
                checksum = '';
            }
        });

        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.textContent = 'Verify';
        btn.addEventListener('click', () => {
            if (checksum.length === 64) doVerify();
        });

        row.appendChild(input);
        row.appendChild(btn);
        group.appendChild(row);

        const hint = document.createElement('div');
        hint.className = 'form-hint';
        hint.textContent = 'Paste a noble:doc:<checksum> URI.';
        group.appendChild(hint);
        container.appendChild(group);
    }

    // ── Verification ──

    async function doVerify() {
        if (!checksum || verifying || !alive) return;
        verifying = true;
        result = null;
        versions = null;
        render();

        try {
            result = await Bridge.call('noble_api', 'verifyDocument', { checksum });
            if (!alive) return;

            if (result.registered) {
                try {
                    const v = await Bridge.call('noble_api', 'getDocumentVersions', { checksum });
                    if (!alive) return;
                    versions = v.versions || [];
                } catch {
                    versions = [];
                }
                // Fetch transaction metadata for signature detection
                if (result.registrations && result.registrations.length > 0) {
                    try {
                        const txId = result.registrations[0].txId;
                        const txDetail = await Bridge.call('noble_api', 'getTransaction', { txId });
                        if (!alive) return;
                        result.metadata = txDetail.metadata || [];
                    } catch {
                        result.metadata = [];
                    }
                }
            }
        } catch (err) {
            if (!alive) return;
            result = { error: err.message };
        }

        verifying = false;
        if (alive) render();
    }

    // ── Result Display ──

    function renderResult(container) {
        if (result.error) {
            const card = document.createElement('div');
            card.className = 'result-card result-error';
            card.innerHTML = `
                <div class="result-icon">\u26A0\uFE0F</div>
                <div class="result-title">Verification Error</div>
                <div style="color:var(--text-secondary)">${esc(result.error)}</div>
            `;
            container.appendChild(card);
            return;
        }

        if (result.registered) {
            renderMatchResult(container);
        } else {
            renderNoMatchResult(container);
        }
    }

    function renderMatchResult(container) {
        // ── Section A: Header card ──
        const header = document.createElement('div');
        header.className = 'result-card result-success';
        const regs = result.registrations || [];
        const firstReg = regs[0];
        let hHtml = '<div class="result-icon" style="color:var(--success)">\u2705</div>'
            + '<div class="result-title" style="color:var(--success)">Document Registered</div>'
            + '<div class="detail-grid" style="margin-top:var(--gap)">'
            + '<dt>Checksum</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">' + esc(result.checksum) + '</dd>';
        if (result.firstSeen) hHtml += '<dt>First Seen</dt><dd>' + formatTimestamp(result.firstSeen) + '</dd>';
        hHtml += '<dt>Registrations</dt><dd>' + regs.length + '</dd>';
        hHtml += '</div>';
        // Copy checksum button
        hHtml += '<button class="btn btn-sm" id="verify-copy-checksum" style="margin-top:8px">Copy Checksum</button>';
        header.innerHTML = hHtml;
        container.appendChild(header);
        header.querySelector('#verify-copy-checksum')?.addEventListener('click', () => {
            navigator.clipboard.writeText(result.checksum).then(() => {
                const b = header.querySelector('#verify-copy-checksum');
                if (b) { b.textContent = 'Copied!'; setTimeout(() => { b.textContent = 'Copy Checksum'; }, 1500); }
            });
        });

        // ── Section B: Registrations table ──
        if (regs.length > 0) {
            const panel = document.createElement('div');
            panel.className = 'panel';
            panel.style.cssText = 'margin-top:var(--gap);overflow-x:auto';
            let tHtml = '<div style="font-weight:600;font-size:var(--font-size-sm);padding:8px 10px">Registrations (' + regs.length + ')</div>';
            tHtml += '<table style="width:100%;border-collapse:collapse;font-size:var(--font-size-xs)">';
            tHtml += '<thead><tr style="color:var(--text-muted);text-align:left"><th style="padding:4px 10px">Block</th><th style="padding:4px 10px" class="hide-mobile">Time</th><th style="padding:4px 10px">TX ID</th><th style="padding:4px 10px">Type</th></tr></thead><tbody>';
            for (const r of regs) {
                const txid = r.txId || '';
                tHtml += '<tr class="verify-reg-row" data-txid="' + esc(txid) + '" style="cursor:pointer;transition:background 0.15s">'
                    + '<td style="padding:6px 10px" class="mono">' + esc(String(r.blockHeight || '')) + '</td>'
                    + '<td style="padding:6px 10px" class="hide-mobile">' + (r.timestamp ? formatTimestamp(r.timestamp) : '') + '</td>'
                    + '<td style="padding:6px 10px" class="mono">' + esc(txid.slice(0, 16)) + '\u2026</td>'
                    + '<td style="padding:6px 10px"><span class="badge" style="font-size:0.55rem;padding:1px 4px">' + esc(r.txType || 'Notarization') + '</span></td>'
                    + '</tr>';
            }
            tHtml += '</tbody></table>';
            panel.innerHTML = tHtml;
            container.appendChild(panel);
            // Wire clickable rows
            panel.querySelectorAll('.verify-reg-row').forEach(row => {
                row.addEventListener('mouseenter', () => { row.style.background = 'var(--accent-subtle)'; });
                row.addEventListener('mouseleave', () => { row.style.background = ''; });
                row.addEventListener('click', () => {
                    const txid = row.dataset.txid;
                    if (txid && window.App) window.App.navigateTo('tx-detail', { txid });
                });
            });
        }

        // ── Section C: Version chain ──
        const vers = result.versions || versions || [];
        if (vers.length > 1) {
            const vPanel = document.createElement('div');
            vPanel.className = 'panel';
            vPanel.style.cssText = 'margin-top:var(--gap);overflow-x:auto';
            let vHtml = '<div style="font-weight:600;font-size:var(--font-size-sm);padding:8px 10px">Version Chain (' + vers.length + ')</div>';
            vHtml += '<table style="width:100%;border-collapse:collapse;font-size:var(--font-size-xs)">';
            vHtml += '<thead><tr style="color:var(--text-muted);text-align:left"><th style="padding:4px 10px">v</th><th style="padding:4px 10px">Block</th><th style="padding:4px 10px">Checksum</th><th style="padding:4px 10px">TX ID</th></tr></thead><tbody>';
            for (const v of vers) {
                const isCurrent = v.checksum === result.checksum;
                const bg = isCurrent ? 'background:var(--accent-subtle)' : '';
                const txid = v.txId || '';
                vHtml += '<tr class="verify-ver-row" data-txid="' + esc(txid) + '" style="cursor:pointer;transition:background 0.15s;' + bg + '">'
                    + '<td style="padding:6px 10px">' + esc(String(v.version != null ? v.version : '\u2014')) + (isCurrent ? ' <span class="badge" style="font-size:0.5rem;background:var(--success);color:#fff;padding:0 3px">current</span>' : '') + '</td>'
                    + '<td style="padding:6px 10px" class="mono">' + esc(String(v.blockHeight || '')) + '</td>'
                    + '<td style="padding:6px 10px" class="mono">' + esc((v.checksum || '').slice(0, 16)) + '\u2026</td>'
                    + '<td style="padding:6px 10px" class="mono">' + esc(txid.slice(0, 12)) + '\u2026</td>'
                    + '</tr>';
            }
            vHtml += '</tbody></table>';
            vPanel.innerHTML = vHtml;
            container.appendChild(vPanel);
            vPanel.querySelectorAll('.verify-ver-row').forEach(row => {
                row.addEventListener('mouseenter', () => { if (!row.style.background.includes('accent-subtle')) row.style.background = 'var(--glass-bg)'; });
                row.addEventListener('mouseleave', () => { const isCur = row.querySelector('.badge'); if (!isCur) row.style.background = ''; });
                row.addEventListener('click', () => {
                    const txid = row.dataset.txid;
                    if (txid && window.App) window.App.navigateTo('tx-detail', { txid });
                });
            });
        }

        // ── Section D: Metadata + Signatures (from first registration's tx) ──
        if (firstReg?.txId) {
            const metaPanel = document.createElement('div');
            metaPanel.className = 'panel';
            metaPanel.style.cssText = 'margin-top:var(--gap);padding:10px';
            metaPanel.innerHTML = '<div style="font-weight:600;font-size:var(--font-size-sm);margin-bottom:8px">Metadata & Signatures</div><div style="color:var(--text-muted);font-size:var(--font-size-xs)">Loading...</div>';
            container.appendChild(metaPanel);
            // Fetch tx metadata async
            Bridge.call('noble_api', 'getTransaction', { txId: firstReg.txId }).then(tx => {
                if (!alive) return; // guard against stale async callback
                const meta = tx?.metadata || [];
                if (meta.length === 0) {
                    metaPanel.querySelector('div:last-child').textContent = 'No metadata';
                    return;
                }
                // Render metadata + signature badges
                let mHtml = '';
                const userMeta = meta.filter(m => !m.key.startsWith('schema') && !m.key.startsWith('sig:') && !m.key.startsWith('locked:') && !m.key.startsWith('unlock:'));
                for (const m of userMeta) {
                    const val = m.value || '';
                    const displayVal = val.length > 200 ? val.slice(0, 80) + '\u2026 (' + Math.floor(val.length / 2) + ' bytes)' : val;
                    mHtml += '<div style="margin-bottom:4px"><span style="font-size:var(--font-size-xs);color:var(--text-muted)">' + esc(m.key) + ':</span> <span class="mono" style="font-size:var(--font-size-xs)">' + esc(displayVal) + '</span></div>';
                }
                metaPanel.querySelector('div:last-child').innerHTML = mHtml || 'No user metadata';
                // Signature verification
                renderSignatureBadges(metaPanel, meta);
                // Batch document linking
                const batchEntry = meta.find(m => m.key === 'doc:batch');
                if (batchEntry?.value && alive) {
                    const batchDiv = document.createElement('div');
                    batchDiv.style.cssText = 'margin-top:var(--gap);padding-top:var(--gap-sm);border-top:1px solid var(--border)';
                    batchDiv.innerHTML = '<div style="font-weight:600;font-size:var(--font-size-sm);margin-bottom:6px">Batch Documents</div><div style="color:var(--text-muted);font-size:var(--font-size-xs)">Loading...</div>';
                    metaPanel.appendChild(batchDiv);
                    Bridge.call('noble_api', 'searchDocumentsByMetadata', { key: 'doc:batch', value: batchEntry.value }).then(r => {
                        if (!alive) return;
                        const docs = (r.documents || []).filter(d => (d.txId || d.tx_id) !== firstReg.txId);
                        if (docs.length === 0) {
                            batchDiv.querySelector('div:last-child').textContent = 'No other documents in this batch.';
                            return;
                        }
                        let bHtml = '';
                        for (const d of docs) {
                            const dtxid = d.txId || d.tx_id || '';
                            bHtml += '<div class="verify-batch-row" data-txid="' + esc(dtxid) + '" style="padding:4px 6px;cursor:pointer;border-radius:var(--radius-sm);transition:background 0.15s;font-size:var(--font-size-xs)">'
                                + '<span class="mono">' + esc(dtxid.slice(0, 16)) + '\u2026</span>'
                                + (d.blockHeight ? ' <span style="color:var(--text-muted)">Block ' + esc(String(d.blockHeight)) + '</span>' : '')
                                + '</div>';
                        }
                        batchDiv.querySelector('div:last-child').innerHTML = docs.length + ' linked document' + (docs.length > 1 ? 's' : '') + ':';
                        const list = document.createElement('div');
                        list.innerHTML = bHtml;
                        batchDiv.appendChild(list);
                        list.querySelectorAll('.verify-batch-row').forEach(row => {
                            row.addEventListener('mouseenter', () => { row.style.background = 'var(--accent-subtle)'; });
                            row.addEventListener('mouseleave', () => { row.style.background = ''; });
                            row.addEventListener('click', () => {
                                if (window.App) window.App.navigateTo('tx-detail', { txid: row.dataset.txid });
                            });
                        });
                    }).catch(() => {
                        batchDiv.querySelector('div:last-child').textContent = 'Could not load batch documents.';
                    });
                }
            }).catch(() => {
                metaPanel.querySelector('div:last-child').textContent = 'Could not load metadata';
            });
        }
    }

    async function renderSignatureBadges(container, metadata) {
        // Detect sig:N entries and match to their signed fields
        const sigs = [];
        for (let i = 0; i < metadata.length; i++) {
            const m = metadata[i];
            const match = (m.key || '').match(/^sig:(\d+)$/);
            if (!match) continue;
            const targetSlot = parseInt(match[1], 10);
            // Slot indices are 1-based; metadata array includes schema at index 0
            const targetField = metadata[targetSlot]; // slot N = array index N (schema at 0)
            if (!targetField) continue;
            sigs.push({ sigEntry: m, targetField, targetSlot });
        }

        if (sigs.length === 0) return;

        const panel = document.createElement('div');
        panel.className = 'panel sig-panel';
        panel.innerHTML = '<div class="panel-header">Signatures</div>';

        const body = document.createElement('div');
        body.className = 'panel-body';

        for (const sig of sigs) {
            const entry = document.createElement('div');
            entry.className = 'sig-entry';

            // Field info
            const fieldLabel = document.createElement('div');
            fieldLabel.style.cssText = 'font-weight:500;margin-bottom:2px';
            fieldLabel.textContent = `${esc(sig.targetField.key)}: "${esc(truncateStr(sig.targetField.value || '', 40))}"`;
            entry.appendChild(fieldLabel);

            // Attempt verification via bridge
            try {
                const vResult = await Bridge.call('noble_crypto', 'verifyMetadataField', {
                    signatureHex: sig.sigEntry.value || '',
                    fieldValue: sig.targetField.value || ''
                });

                const badge = document.createElement('span');
                if (vResult.valid) {
                    badge.className = 'sig-badge sig-badge-valid';
                    const name = vResult.signerName || `SKI: ${(vResult.signerSKI || '').slice(0, 12)}...`;
                    badge.textContent = `\u2713 Signed by ${name}`;
                } else if (!vResult.hasCertificate && vResult.signerSKI) {
                    badge.className = 'sig-badge sig-badge-unknown';
                    badge.textContent = `? Unknown signer (SKI: ${(vResult.signerSKI || '').slice(0, 12)}...)`;
                } else {
                    badge.className = 'sig-badge sig-badge-invalid';
                    badge.textContent = `\u2717 Invalid signature`;
                }
                entry.appendChild(badge);

                if (vResult.algorithm) {
                    const alg = document.createElement('span');
                    alg.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-xs)';
                    alg.textContent = vResult.algorithm;
                    entry.appendChild(alg);
                }

                if (vResult.error) {
                    const err = document.createElement('div');
                    err.style.cssText = 'font-size:var(--font-size-xs);color:var(--error);margin-top:2px';
                    err.textContent = vResult.error;
                    entry.appendChild(err);
                }
            } catch (e) {
                const badge = document.createElement('span');
                badge.className = 'sig-badge sig-badge-malformed';
                badge.textContent = `\u26A0 Malformed signature`;
                entry.appendChild(badge);
                const err = document.createElement('div');
                err.style.cssText = 'font-size:var(--font-size-xs);color:var(--warning);margin-top:2px';
                err.textContent = e.message || 'Could not parse CMS signature';
                entry.appendChild(err);
            }

            body.appendChild(entry);
        }

        panel.appendChild(body);
        container.appendChild(panel);
    }

    function truncateStr(s, max) {
        return s.length > max ? s.slice(0, max) + '\u2026' : s;
    }

    function renderNoMatchResult(container) {
        const card = document.createElement('div');
        card.className = 'result-card result-error';
        card.innerHTML = `
            <div class="result-icon" style="color:var(--error)">\u274C</div>
            <div class="result-title" style="color:var(--error)">Not Found</div>
            <div style="color:var(--text-secondary);margin-bottom:var(--gap-sm)">
                This checksum is not registered on the NOBLE blockchain.
            </div>
            <div class="mono" style="font-size:var(--font-size-xs);word-break:break-all;color:var(--text-muted)">${esc(checksum)}</div>
        `;

        if (state.isConnected && state.hasWallet) {
            const regBtn = document.createElement('button');
            regBtn.className = 'btn btn-primary';
            regBtn.textContent = 'Register it now';
            regBtn.style.marginTop = 'var(--gap)';
            regBtn.addEventListener('click', () => {
                Bridge.call('noble_app', 'navigateTo', { section: 'documents' });
            });
            card.appendChild(regBtn);
        }

        container.appendChild(card);
    }

    // ── Author Search ──

    function renderAuthorSearch(container) {
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'input';
        input.placeholder = 'Search author or publisher name...';
        input.style.cssText = 'width:100%;margin-bottom:var(--gap-sm)';
        container.appendChild(input);

        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.textContent = 'Search';
        btn.style.marginBottom = 'var(--gap)';
        btn.addEventListener('click', async () => {
            const q = input.value.trim();
            if (!q) return;
            btn.disabled = true;
            btn.textContent = 'Searching...';
            try {
                const [r1, r2] = await Promise.all([
                    Bridge.call('noble_api', 'searchDocumentsByMetadata', { key: 'doc:author', value: q }).catch(() => ({ documents: [] })),
                    Bridge.call('noble_api', 'searchDocumentsByMetadata', { key: 'doc:publisher', value: q }).catch(() => ({ documents: [] })),
                ]);
                const all = [...(r1.documents || []), ...(r2.documents || [])];
                const seen = new Set();
                const deduped = all.filter(d => {
                    const id = d.tx_id || d.txId;
                    if (seen.has(id)) return false;
                    seen.add(id);
                    return true;
                });
                renderSearchResults(container, deduped, 'author');
            } catch (e) {
                container.innerHTML += '<div style="color:var(--error)">Search failed: ' + esc(e.message || 'unknown') + '</div>';
            }
            btn.disabled = false;
            btn.textContent = 'Search';
        });
        container.appendChild(btn);
    }

    // ── Issuer Search ──

    function renderIssuerSearch(container) {
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'input';
        input.placeholder = 'Public key (nbl1... or hex)';
        input.style.cssText = 'width:100%;margin-bottom:var(--gap-sm)';
        container.appendChild(input);

        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.textContent = 'Search';
        btn.style.marginBottom = 'var(--gap)';
        btn.addEventListener('click', async () => {
            const q = input.value.trim();
            if (!q) return;
            btn.disabled = true;
            btn.textContent = 'Searching...';
            try {
                const r = await Bridge.call('noble_api', 'getDocumentsByIssuer', { publicKey: q });
                renderSearchResults(container, r.documents || [], 'issuer');
            } catch (e) {
                container.innerHTML += '<div style="color:var(--error)">Search failed: ' + esc(e.message || 'unknown') + '</div>';
            }
            btn.disabled = false;
            btn.textContent = 'Search';
        });
        container.appendChild(btn);
    }

    // ── My Documents ──

    function renderMyDocuments(container) {
        if (!state.walletAddress) {
            container.appendChild(emptyState({
                icon: '\u{1F4CB}',
                title: 'No Wallet',
                subtitle: 'Connect to a node to see your documents.'
            }));
            return;
        }
        container.innerHTML = '<p style="color:var(--text-muted)">Loading your documents...</p>';
        Bridge.call('noble_api', 'getDocumentsByIssuer', { publicKey: state.walletAddress }).then(r => {
            container.innerHTML = '';
            renderSearchResults(container, r.documents || [], 'mydocs');
        }).catch(e => {
            container.innerHTML = '<div style="color:var(--error)">Failed to load: ' + esc(e.message || 'unknown') + '</div>';
        });
    }

    // ── Shared search result renderer ──

    function renderSearchResults(container, docs, source) {
        // Remove previous results (keep input elements)
        const existing = container.querySelector('.search-results');
        if (existing) existing.remove();

        const wrapper = document.createElement('div');
        wrapper.className = 'search-results';

        if (docs.length === 0) {
            wrapper.innerHTML = '<div style="text-align:center;padding:var(--gap);color:var(--text-muted)">No documents found.</div>';
            container.appendChild(wrapper);
            return;
        }

        const count = document.createElement('div');
        count.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap-sm)';
        count.textContent = docs.length + ' document' + (docs.length !== 1 ? 's' : '') + ' found';
        wrapper.appendChild(count);

        for (const doc of docs) {
            const txid = doc.tx_id || doc.txId || '';
            const row = document.createElement('div');
            row.className = 'panel';
            row.style.cssText = 'padding:8px 12px;margin-bottom:4px;cursor:pointer;transition:background 0.15s';
            row.addEventListener('mouseenter', () => { row.style.background = 'var(--accent-subtle)'; });
            row.addEventListener('mouseleave', () => { row.style.background = ''; });
            row.addEventListener('click', () => {
                if (window.App) window.App.navigateTo('tx-detail', { txid });
            });

            const cs = doc.checksum || '';
            const height = doc.block_height || doc.height || '';
            const ts = doc.timestamp ? formatTimestamp(doc.timestamp) : '';
            const ver = doc.version != null ? 'v' + doc.version : '';

            row.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:4px">'
                + '<div>'
                + '<div class="mono" style="font-size:var(--font-size-xs);word-break:break-all">' + esc(cs.slice(0, 24)) + (cs.length > 24 ? '\u2026' : '') + '</div>'
                + '<div style="font-size:var(--font-size-xs);color:var(--text-muted)">'
                + (height ? 'Block ' + height + ' \u00b7 ' : '') + ts
                + '</div>'
                + '</div>'
                + '<div style="display:flex;gap:6px;align-items:center">'
                + (ver ? '<span class="badge" style="font-size:0.6rem">' + ver + '</span>' : '')
                + '<span class="mono" style="font-size:0.6rem;color:var(--text-muted)">' + esc(txid.slice(0, 12)) + '\u2026</span>'
                + '</div>'
                + '</div>';
            wrapper.appendChild(row);
        }
        container.appendChild(wrapper);
    }

    return {
        destroy() { alive = false; if (window._nobleHandleFileDrop) delete window._nobleHandleFileDrop; },
        refresh(newState) { Object.assign(state, newState); }
    };
}

