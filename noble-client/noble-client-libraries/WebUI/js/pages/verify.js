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

    render();

    function render() {
        if (!alive) return;
        root.innerHTML = '';
        root.classList.add('page-content');

        // Header
        const header = document.createElement('div');
        header.className = 'page-header';
        header.innerHTML = '<h1>Verify</h1><p>Check if a document is registered on the NOBLE blockchain</p>';
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
        zone.setAttribute('aria-label', 'Select a file to verify');
        zone.setAttribute('tabindex', '0');
        zone.innerHTML = '<div style="font-size:2rem;margin-bottom:var(--gap-sm)">\u{1F4C4}</div><div>Click to select a file</div>';
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
        const card = document.createElement('div');
        card.className = 'result-card result-success';

        let html = `
            <div class="result-icon" style="color:var(--success)">\u2705</div>
            <div class="result-title" style="color:var(--success)">Document Registered</div>
            <div class="detail-grid" style="margin-top:var(--gap)">
                <dt>Checksum</dt>
                <dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(result.checksum)}</dd>
        `;

        if (result.registrations && result.registrations.length > 0) {
            const reg = result.registrations[0];
            html += `
                <dt>Block Height</dt>
                <dd class="mono">${reg.blockHeight}</dd>
                <dt>Transaction</dt>
                <dd class="mono" style="font-size:var(--font-size-xs)">${reg.txId.slice(0, 16)}\u2026</dd>
                <dt>Timestamp</dt>
                <dd>${formatTimestamp(reg.timestamp)}</dd>
            `;
        }

        if (result.firstSeen) {
            html += `<dt>First Seen</dt><dd>${formatTimestamp(result.firstSeen)}</dd>`;
        }

        html += '</div>';
        card.innerHTML = html;
        container.appendChild(card);

        // ── Signature verification badges ──
        if (result.metadata && result.metadata.length > 0) {
            renderSignatureBadges(container, result.metadata);
        }

        // Version timeline
        if (versions && versions.length > 1) {
            const timeline = document.createElement('div');
            timeline.className = 'panel';
            timeline.style.marginTop = 'var(--gap)';
            timeline.innerHTML = '<div class="panel-header">Version History</div>';

            const body = document.createElement('div');
            body.className = 'panel-body';

            const tl = document.createElement('div');
            tl.className = 'version-timeline';

            for (const v of versions) {
                const entry = document.createElement('div');
                entry.className = 'version-entry';
                entry.innerHTML = `
                    <div class="version-height">Block #${v.blockHeight}</div>
                    <div class="version-time">${formatTimestamp(v.timestamp)}</div>
                    <div class="version-hash">${v.checksum ? v.checksum.slice(0, 24) + '\u2026' : ''}</div>
                `;
                tl.appendChild(entry);
            }

            body.appendChild(tl);
            timeline.appendChild(body);
            container.appendChild(timeline);
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

    return {
        destroy() { alive = false; },
        refresh(newState) { Object.assign(state, newState); }
    };
}

