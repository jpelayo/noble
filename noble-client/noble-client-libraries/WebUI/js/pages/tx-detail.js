// NOBLE Client — Transaction Detail Page
// Type-aware rendering adapted from node dashboard tx-detail.js.

import { formatAmount, formatSignedAmount } from '../components/amount-text.js';
import { TX_TYPES, TX_TYPE_NAMES, txDisplayAmount, classifyMetadata, isZeroChecksum, formatTxType, decodeMetadataValue, txStatusBadge } from '../tx-display.js';

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
        if (window.App) App.navigateTo('payments');
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

        const txType = tx.tx_type ?? parseTypeFromLabel(tx.type);
        const metadata = tx.metadata || [];
        const { system, user, signatures } = classifyMetadata(metadata, txType);
        const disp = txDisplayAmount(tx);

        // ── Hero Section ──
        const heroEl = document.createElement('div');
        heroEl.className = 'panel';
        heroEl.style.cssText = 'text-align:center;padding:var(--gap-xl);margin-bottom:var(--gap-lg)';

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
        root.appendChild(heroEl);

        // Copy button
        root.querySelector('#copy-checksum')?.addEventListener('click', () => {
            navigator.clipboard.writeText(tx.checksum).then(() => {
                const btn = root.querySelector('#copy-checksum');
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = 'Copy Checksum'; }, 1500);
            });
        });

        // ── Detail Grid ──
        const grid = document.createElement('div');
        grid.className = 'panel';
        grid.style.cssText = 'padding:var(--gap-lg);margin-bottom:var(--gap-lg)';
        let html = '<dl style="display:grid;grid-template-columns:auto 1fr;gap:6px 12px;margin:0">';
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

        html += '</dl>';
        grid.innerHTML = html;
        root.appendChild(grid);

        // ── Inputs ──
        const inputs = tx.inputs || [];
        if (inputs.length > 0) {
            const panel = document.createElement('div');
            panel.className = 'card';
            panel.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap)';
            const isCoinbase = inputs.length === 1 && /^0+$/.test(inputs[0].txid);
            let ihtml = `<h3 style="margin:0 0 8px;font-size:var(--font-size-sm)">Inputs (${inputs.length})</h3>`;
            if (isCoinbase) {
                ihtml += '<div style="color:var(--text-muted);font-size:var(--font-size-xs)">Coinbase (new coins minted by the network)</div>';
            } else {
                for (let i = 0; i < inputs.length; i++) {
                    ihtml += `<div style="margin-bottom:4px;font-size:var(--font-size-xs)">
                        <span style="color:var(--text-muted)">#${i}</span>
                        <span class="mono" style="word-break:break-all">${esc(inputs[i].txid)}</span>:<strong>${inputs[i].vout}</strong>
                    </div>`;
                }
            }
            panel.innerHTML = ihtml;
            root.appendChild(panel);
        }

        // ── Outputs ──
        const outputs = tx.outputs || [];
        if (outputs.length > 0) {
            const panel = document.createElement('div');
            panel.className = 'card';
            panel.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap)';
            let ohtml = `<h3 style="margin:0 0 8px;font-size:var(--font-size-sm)">Outputs (${outputs.length})</h3>`;
            for (let i = 0; i < outputs.length; i++) {
                ohtml += `<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px;font-size:var(--font-size-xs)">
                    <span class="mono" style="word-break:break-all;flex:1;margin-right:8px">#${i} &rarr; ${esc(outputs[i].address)}</span>
                    <span class="mono" style="white-space:nowrap">&diams; ${formatAmount(outputs[i].value)}</span>
                </div>`;
            }
            panel.innerHTML = ohtml;
            root.appendChild(panel);
        }

        // ── User Metadata ──
        if (user.length > 0) {
            // Parse schema descriptor to detect encoding per slot
            const schemaSlots = parseSchemaDescriptor(metadata);

            const panel = document.createElement('div');
            panel.className = 'card';
            panel.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap)';
            let mhtml = `<h3 style="margin:0 0 8px;font-size:var(--font-size-sm)">Metadata (${user.length})</h3>`;
            for (const entry of user) {
                const entryIdx = metadata.indexOf(entry);
                const slotInfo = schemaSlots?.get(entryIdx);
                const isEcies = slotInfo?.encoding === 'ecies';
                const isProtected = slotInfo?.encoding === 'aesgcm';

                const sigMatch = signatures.find(s => s.slotIndex === metadata.indexOf(metadata.find(m => m.key === entry.key)));
                const sigBadge = sigMatch ? ' <span class="badge" style="background:var(--success);color:#fff;font-size:0.5rem;padding:1px 4px">Signed</span>' : '';
                const encBadge = isEcies ? ' <span class="badge" style="background:var(--accent);color:#fff;font-size:0.5rem;padding:1px 4px">Encrypted</span>'
                    : isProtected ? ' <span class="badge" style="background:var(--warning);color:#fff;font-size:0.5rem;padding:1px 4px">Protected</span>' : '';

                const val = isEcies ? `${(entry.value?.length || 0) / 2} bytes` : decodeMetadataValue(entry.value);
                const decryptBtnId = isEcies ? `decrypt-${entryIdx}` : '';
                const decryptBtn = isEcies ? ` <button class="btn btn-sm" id="${decryptBtnId}" style="margin-left:4px;font-size:0.6rem;padding:1px 6px">Decrypt</button>` : '';

                mhtml += `<div style="margin-bottom:6px">
                    <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${esc(entry.key)}${sigBadge}${encBadge}${decryptBtn}</div>
                    <div class="mono" id="meta-val-${entryIdx}" style="font-size:var(--font-size-xs);word-break:break-all">${esc(val)}</div>
                </div>`;
            }
            panel.innerHTML = mhtml;
            root.appendChild(panel);

            // Wire up Decrypt buttons
            for (const entry of user) {
                const entryIdx = metadata.indexOf(entry);
                const slotInfo = schemaSlots?.get(entryIdx);
                if (slotInfo?.encoding !== 'ecies') continue;
                const btn = root.querySelector(`#decrypt-${entryIdx}`);
                if (!btn) continue;
                btn.addEventListener('click', async () => {
                    btn.disabled = true;
                    btn.textContent = 'Decrypting...';
                    try {
                        const result = await Bridge.call('noble_crypto', 'decryptEciesField', {
                            payload_hex: entry.value
                        });
                        if (result?.plaintext) {
                            const valEl = root.querySelector(`#meta-val-${entryIdx}`);
                            if (valEl) valEl.textContent = result.plaintext;
                            btn.textContent = 'Decrypted';
                        } else if (result?.error) {
                            btn.textContent = 'Failed';
                        }
                    } catch (e) {
                        btn.textContent = 'Not for you';
                    }
                });
            }
        }

        // ── Encrypted locator ──
        if (tx.has_encrypted_locator) {
            const locEl = document.createElement('div');
            locEl.className = 'card';
            locEl.style.cssText = 'padding:var(--gap);margin-bottom:var(--gap);border-left:3px solid var(--accent)';
            locEl.innerHTML = '<span class="badge" style="background:var(--accent);color:#fff;font-size:0.6rem;padding:1px 6px">Encrypted Locator</span> Available';
            root.appendChild(locEl);
        }
        loadInFlight = false;
    }

    load();
    // Auto-refresh every 15s (track confirmation progress)
    let alive = true;
    const autoRefreshId = setInterval(() => { if (alive) load(); }, 15_000);
    return { destroy() { alive = false; clearInterval(autoRefreshId); } };
}

// ── Helpers ──

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
    const schemaEntry = metadataEntries.find(e => e.key === 'schema');
    if (!schemaEntry?.value) return null;
    // Decode hex to UTF-8
    let text;
    try {
        const bytes = new Uint8Array(schemaEntry.value.match(/.{2}/g).map(b => parseInt(b, 16)));
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch { return null; }
    const slotMap = new Map();
    for (const line of text.split('\n')) {
        const parts = line.trim().split(':');
        if (parts.length < 4) continue;
        const slotNum = parseInt(parts[0], 10);
        if (isNaN(slotNum)) continue;
        const hasTypeCode = /^T\d+$/.test(parts[1]) || parts[1] === 'SIG';
        let encoding;
        if (hasTypeCode && parts.length >= 5) {
            encoding = parts[3]; // v2: slot:code:vis:enc:key
        } else if (hasTypeCode) {
            const vis = parts[2];
            encoding = vis === 'priv' ? 'ecies' : vis === 'pwd' ? 'aesgcm' : 'utf8'; // v0
        } else {
            encoding = parts[2]; // v1: slot:vis:enc:req:label
        }
        slotMap.set(slotNum, { encoding });
    }
    return slotMap.size > 0 ? slotMap : null;
}

function parseTypeFromLabel(label) {
    if (!label) return -1;
    const lower = label.toLowerCase().replace(/[_\s-]/g, '');
    const map = { notarization: 0, transfer: 1, keyrotation: 2, badgeproposal: 3, badgevote: 4, badgerevocation: 5, locked: 6, unlocking: 7, coinbase: 16 };
    return map[lower] ?? -1;
}
