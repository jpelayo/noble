// NOBLE — Reusable Transaction Detail View Component
// Renders a complete, type-aware transaction detail panel.
// Used by documents.js, verify.js, payments.js across all Noble client apps.

import { formatAmount } from './amount-text.js';
import { esc } from '../utils.js';
import {
    TX_TYPES, TX_TYPE_NAMES, txDisplayAmount,
    classifyMetadata, isZeroChecksum, decodeMetadataValue,
} from '../tx-display.js';

/**
 * Render a full transaction detail view into a container.
 *
 * @param {HTMLElement} container - DOM element to render into
 * @param {object} tx - Transaction data from RPC / bridge
 * @param {object} [opts] - Options
 * @param {function} [opts.onNavigate] - Navigate to another tx: onNavigate(txId)
 * @param {function} [opts.onCopyText] - Copy text: onCopyText(text)
 * @param {function} [opts.onDecryptLocked] - Decrypt locked tx: onDecryptLocked(txHex) → Promise<decrypted>
 * @param {boolean}  [opts.compact] - Compact mode for inline expansion
 */
export function renderTxDetailView(container, tx, opts = {}) {
    if (!tx) { container.innerHTML = '<p>No transaction data</p>'; return; }
    container.innerHTML = '';

    const txType = tx.tx_type ?? tx.txType ?? -1;
    const txId = tx.tx_id ?? tx.txId ?? '';
    const checksum = tx.checksum ?? '';
    const metadata = tx.metadata ?? [];
    const { system, user, signatures } = classifyMetadata(metadata, txType);
    const disp = txDisplayAmount(tx);

    // ── Hero Section ──
    const hero = el('div', 'tx-detail-hero');

    if (txType === TX_TYPES.NOTARIZATION && !isZeroChecksum(checksum)) {
        hero.classList.add('tx-detail-hero--notarization');
        hero.innerHTML = `
            <div class="tx-detail-hero__label">Document Checksum</div>
            <div class="tx-detail-hero__hash mono">${esc(checksum)}</div>
            <div class="tx-detail-hero__actions">
                <button class="btn btn-sm tx-copy-checksum">Copy</button>
            </div>
        `;
        hero.querySelector('.tx-copy-checksum')?.addEventListener('click', () => {
            copyText(checksum, hero.querySelector('.tx-copy-checksum'), opts);
        });
    } else if (txType === TX_TYPES.LOCKED) {
        hero.classList.add('tx-detail-hero--locked');
        hero.innerHTML = `
            <div class="tx-detail-hero__icon">\u{1F512}</div>
            <div class="tx-detail-hero__label">Encrypted Document</div>
            <div class="tx-detail-hero__sub">Checksum and metadata are encrypted with AES-256-GCM</div>
        `;
    } else if (txType === TX_TYPES.UNLOCKING) {
        hero.classList.add('tx-detail-hero--unlocking');
        hero.innerHTML = `
            <div class="tx-detail-hero__icon">\u{1F511}</div>
            <div class="tx-detail-hero__label">Document Unlock</div>
            <div class="tx-detail-hero__sub">Reveals the encryption password for a locked document</div>
        `;
        if (!isZeroChecksum(checksum)) {
            hero.innerHTML += `
                <div class="tx-detail-hero__hash mono" style="margin-top:var(--gap-sm)">Checksum: ${esc(checksum)}</div>
            `;
        }
    } else if (txType === TX_TYPES.TRANSFER) {
        hero.classList.add('tx-detail-hero--transfer');
        hero.innerHTML = `
            <div class="tx-detail-hero__icon">\u{1F4B8}</div>
            <div class="tx-detail-hero__label">Transfer</div>
            <div class="tx-detail-hero__amount">\u25C6 ${formatAmount(disp.amount)}</div>
        `;
    } else if (txType === TX_TYPES.COINBASE) {
        hero.classList.add('tx-detail-hero--coinbase');
        hero.innerHTML = `
            <div class="tx-detail-hero__icon">\u26CF</div>
            <div class="tx-detail-hero__label">Block Reward</div>
            <div class="tx-detail-hero__amount">\u25C6 ${formatAmount(disp.amount)}</div>
        `;
    } else if (txType === TX_TYPES.KEY_ROTATION) {
        hero.innerHTML = `<div class="tx-detail-hero__icon">\u{1F504}</div><div class="tx-detail-hero__label">Key Rotation</div>`;
    } else if (txType === TX_TYPES.BADGE_PROPOSAL) {
        hero.innerHTML = `<div class="tx-detail-hero__icon">\u{1F3C5}</div><div class="tx-detail-hero__label">Badge Proposal</div>`;
    } else if (txType === TX_TYPES.BADGE_VOTE) {
        hero.innerHTML = `<div class="tx-detail-hero__icon">\u{1F5F3}</div><div class="tx-detail-hero__label">Badge Vote</div>`;
    } else if (txType === TX_TYPES.BADGE_REVOCATION) {
        hero.innerHTML = `<div class="tx-detail-hero__icon">\u26D4</div><div class="tx-detail-hero__label">Badge Revocation</div>`;
    } else {
        hero.innerHTML = `<div class="tx-detail-hero__label">${esc(TX_TYPE_NAMES[txType] || 'Transaction')}</div>`;
    }

    // Version chain badges (from system metadata)
    const versionMeta = system.find(m => m.key === 'doc:version');
    const prevMeta = system.find(m => m.key === 'doc:prev_checksum');
    if (versionMeta || prevMeta) {
        const vDiv = el('div', 'tx-detail-hero__version');
        if (versionMeta) vDiv.innerHTML += `<span class="badge badge-version">v${esc(decodeMetadataValue(versionMeta.value))}</span> `;
        if (prevMeta) {
            const prev = decodeMetadataValue(prevMeta.value);
            vDiv.innerHTML += `<span style="font-size:var(--font-size-xs);color:var(--text-secondary)">Previous: <span class="mono">${esc(prev.slice(0, 12))}...</span></span>`;
        }
        hero.appendChild(vDiv);
    }

    container.appendChild(hero);

    // ── Detail Grid ──
    const grid = el('div', 'tx-detail-grid detail-grid');
    const fee = tx.fee ?? null;
    const status = tx.confirmation_status ?? tx.status ?? '';
    const confirmations = tx.confirmations ?? null;
    const blockHeight = tx.block_height ?? tx.blockHeight ?? null;

    let gridHtml = `
        <dt>Transaction ID</dt><dd class="mono" style="word-break:break-all">${esc(txId)}</dd>
        <dt>Type</dt><dd>${esc(TX_TYPE_NAMES[txType] || 'Unknown')}</dd>
        <dt>Timestamp</dt><dd>${formatTimestamp(tx.timestamp)}</dd>
    `;
    // Value display — type-aware
    if (txType === TX_TYPES.TRANSFER) {
        gridHtml += `<dt>Amount Sent</dt><dd>\u25C6 ${formatAmount(disp.amount)}</dd>`;
        if (fee != null) gridHtml += `<dt>Fee</dt><dd>\u25C6 ${formatAmount(fee)}</dd>`;
    } else if (txType === TX_TYPES.COINBASE) {
        gridHtml += `<dt>Block Reward</dt><dd>\u25C6 ${formatAmount(disp.amount)}</dd>`;
    } else {
        if (fee != null) gridHtml += `<dt>Fee</dt><dd>\u25C6 ${formatAmount(fee)}</dd>`;
    }
    if (tx.total_output != null && txType !== TX_TYPES.COINBASE) {
        gridHtml += `<dt>Total Output</dt><dd style="color:var(--text-muted)">\u25C6 ${formatAmount(tx.total_output)}</dd>`;
    }
    if (status) {
        const statusClass = status === 'complete' || status === 'confirmed' ? 'badge-confirmed' : '';
        gridHtml += `<dt>Status</dt><dd><span class="badge ${statusClass}">${esc(status)}</span></dd>`;
    }
    if (blockHeight != null) gridHtml += `<dt>Block</dt><dd>${blockHeight}</dd>`;
    if (confirmations != null) gridHtml += `<dt>Confirmations</dt><dd>${confirmations}</dd>`;
    if (tx.size_bytes) gridHtml += `<dt>Size</dt><dd>${tx.size_bytes} bytes</dd>`;
    if (tx.fee_rate) gridHtml += `<dt>Fee Rate</dt><dd>${tx.fee_rate} groats/byte</dd>`;
    if (tx.signer) gridHtml += `<dt>Signer</dt><dd class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(tx.signer_name ? tx.signer_name + ' ' : '')}${esc(tx.signer)}</dd>`;

    grid.innerHTML = gridHtml;
    container.appendChild(grid);

    // ── Type-specific section ──
    if (txType === TX_TYPES.LOCKED) renderLockedSection(container, system, user, signatures, opts);
    else if (txType === TX_TYPES.UNLOCKING) renderUnlockingSection(container, system, opts);
    else if (txType === TX_TYPES.KEY_ROTATION) renderKeyRotationSection(container, system);
    else if (txType === TX_TYPES.BADGE_PROPOSAL) renderBadgeProposalSection(container, system);
    else if (txType === TX_TYPES.BADGE_VOTE) renderBadgeVoteSection(container, system);
    else if (txType === TX_TYPES.BADGE_REVOCATION) renderBadgeRevocationSection(container, system);

    // ── Inputs ──
    const inputs = tx.inputs ?? [];
    if (inputs.length > 0 && !opts.compact) {
        const panel = el('div', 'panel');
        const isCoinbase = inputs.length === 1 && (inputs[0].txid === '0'.repeat(64) || inputs[0].txid === '');
        let html = `<div class="panel-header">Inputs (${inputs.length})</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>#</th><th>Previous TX</th><th>Index</th></tr></thead><tbody>`;
        inputs.forEach((inp, i) => {
            const txLink = isCoinbase
                ? '<span class="badge badge-coinbase">Coinbase</span>'
                : `<span class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(inp.txid ?? inp.txId ?? '')}</span>`;
            html += `<tr><td>${i}</td><td>${txLink}</td><td>${isCoinbase ? '\u2014' : (inp.vout ?? 0)}</td></tr>`;
        });
        html += '</tbody></table></div>';
        panel.innerHTML = html;
        container.appendChild(panel);
    }

    // ── Outputs ──
    const outputs = tx.outputs ?? [];
    if (outputs.length > 0 && !opts.compact) {
        const panel = el('div', 'panel');
        let html = `<div class="panel-header">Outputs (${outputs.length})</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>#</th><th>Value</th><th>Address</th></tr></thead><tbody>`;
        outputs.forEach((out, i) => {
            html += `<tr><td>${i}</td><td>\u25C6 ${formatAmount(out.value)}</td><td class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(out.address ?? '')}</td></tr>`;
        });
        html += '</tbody></table></div>';
        panel.innerHTML = html;
        container.appendChild(panel);
    }

    // ── User Metadata ──
    if (user.length > 0 && txType !== TX_TYPES.LOCKED) {
        renderUserMetadata(container, user, signatures, txType);
    }

    // ── Additional Signatures ──
    const addSigs = tx.additional_sigs ?? tx.additionalSigs ?? [];
    if (addSigs.length > 0 && !opts.compact) {
        const panel = el('div', 'panel');
        let html = `<div class="panel-header">Additional Signatures (${addSigs.length})</div><div class="panel-body">`;
        addSigs.forEach((sig, i) => {
            const pk = sig.public_key ?? sig.publicKey ?? '';
            const s = sig.signature ?? '';
            html += `<div class="detail-grid" style="margin-bottom:var(--gap-sm)">
                <dt>#${i + 1} Scheme</dt><dd>${sig.scheme_id ?? sig.schemeId ?? 0}</dd>
                <dt>Public Key</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(pk)}</dd>
                <dt>Signature</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(s)}</dd>
            </div>`;
        });
        html += '</div>';
        panel.innerHTML = html;
        container.appendChild(panel);
    }
}

// ── Type-specific sections ──────────────────────────────────────────

function renderLockedSection(container, system, user, signatures, opts) {
    const panel = el('div', 'panel tx-section-encryption');
    const salt = system.find(m => m.key === 'locked:salt');
    const nonce = system.find(m => m.key === 'locked:nonce');
    const encChecksum = system.find(m => m.key === 'locked:checksum');

    let html = `<div class="panel-header">\u{1F512} Encryption Details</div><div class="panel-body"><div class="detail-grid">`;
    if (salt) html += `<dt>Salt</dt><dd class="mono" style="font-size:var(--font-size-xs)">${esc(decodeMetadataValue(salt.value))}</dd>`;
    if (nonce) html += `<dt>Nonce</dt><dd class="mono" style="font-size:var(--font-size-xs)">${esc(decodeMetadataValue(nonce.value))}</dd>`;
    if (encChecksum) html += `<dt>Encrypted Checksum</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(decodeMetadataValue(encChecksum.value).slice(0, 40))}...</dd>`;
    html += `</div>`;

    if (opts.onDecryptLocked) {
        html += `<button class="btn btn-sm btn-decrypt" style="margin-top:var(--gap-sm)">\u{1F511} Decrypt with password</button>`;
    }
    html += '</div>';
    panel.innerHTML = html;

    if (opts.onDecryptLocked) {
        panel.querySelector('.btn-decrypt')?.addEventListener('click', async () => {
            const pw = prompt('Enter the document password:');
            if (!pw) return;
            try {
                const result = await opts.onDecryptLocked(pw);
                if (result) renderDecryptedResult(panel, result);
            } catch (e) {
                alert('Decryption failed: ' + (e.message || e));
            }
        });
    }
    container.appendChild(panel);

    // Encrypted user metadata
    if (user.length > 0) {
        const metaPanel = el('div', 'panel');
        let mhtml = `<div class="panel-header">Metadata (${user.length} entries)</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>Key</th><th>Value</th><th>Status</th></tr></thead><tbody>`;
        for (const entry of user) {
            const sigEntry = signatures.find(s => s.slotIndex === user.indexOf(entry));
            const sigBadge = sigEntry ? '<span class="meta-badge-signed">Signed</span> ' : '';
            mhtml += `<tr>
                <td><strong>${esc(entry.key)}</strong></td>
                <td class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${esc(decodeMetadataValue(entry.value).slice(0, 32))}...</td>
                <td>${sigBadge}<span class="meta-badge-encrypted">Encrypted</span></td>
            </tr>`;
        }
        mhtml += '</tbody></table></div>';
        metaPanel.innerHTML = mhtml;
        container.appendChild(metaPanel);
    }
}

function renderDecryptedResult(panel, result) {
    const div = el('div', 'decrypted-result');
    let html = '<div class="detail-grid" style="margin-top:var(--gap-sm)">';
    if (result.decrypted_checksum) {
        html += `<dt>Real Checksum</dt><dd class="mono" style="word-break:break-all">${esc(result.decrypted_checksum)}</dd>`;
    }
    if (result.decrypted_metadata) {
        for (const m of result.decrypted_metadata) {
            html += `<dt>${esc(m.key)}</dt><dd>${esc(m.value)}</dd>`;
        }
    }
    html += '</div>';
    div.innerHTML = html;
    panel.querySelector('.panel-body')?.appendChild(div);
    const btn = panel.querySelector('.btn-decrypt');
    if (btn) btn.remove();
}

function renderUnlockingSection(container, system, opts) {
    const panel = el('div', 'panel tx-section-unlock');
    const lockedTxId = system.find(m => m.key === 'unlock:txid');
    const password = system.find(m => m.key === 'unlock:password');

    let html = `<div class="panel-header">\u{1F511} Unlock Reference</div><div class="panel-body"><div class="detail-grid">`;
    if (lockedTxId) {
        // unlock:txid is a raw hex string — use as-is, do NOT hex-decode
        const id = typeof lockedTxId.value === 'string' ? lockedTxId.value : decodeMetadataValue(lockedTxId.value);
        html += `<dt>Locked TX</dt><dd class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(id)}</dd>`;
    }
    if (password) {
        // unlock:password is raw UTF-8 — use as-is, do NOT hex-decode
        const pw = typeof password.value === 'string' ? password.value : decodeMetadataValue(password.value);
        html += `<dt>Password</dt><dd><span class="password-mask" data-pw="${esc(pw)}">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span> <button class="btn btn-xs btn-reveal">Show</button></dd>`;
    }
    html += '</div></div>';
    panel.innerHTML = html;

    panel.querySelector('.btn-reveal')?.addEventListener('click', function () {
        const mask = panel.querySelector('.password-mask');
        if (mask.textContent.includes('\u2022')) {
            mask.textContent = mask.dataset.pw;
            this.textContent = 'Hide';
        } else {
            mask.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
            this.textContent = 'Show';
        }
    });
    container.appendChild(panel);
}

function renderKeyRotationSection(container, system) {
    const newKey = system.find(m => m.key === 'new_pubkey') || (system.length > 0 ? system[0] : null);
    if (!newKey) return;
    const panel = el('div', 'panel');
    panel.innerHTML = `<div class="panel-header">\u{1F504} Key Rotation</div><div class="panel-body"><div class="detail-grid">
        <dt>New Key</dt><dd class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(decodeMetadataValue(newKey.value))}</dd>
    </div></div>`;
    container.appendChild(panel);
}

function renderBadgeProposalSection(container, system) {
    const panel = el('div', 'panel');
    let html = `<div class="panel-header">\u{1F3C5} Badge Proposal</div><div class="panel-body"><div class="detail-grid">`;
    for (const m of system) {
        html += `<dt>${esc(m.key.replace('_', ' '))}</dt><dd>${esc(decodeMetadataValue(m.value))}</dd>`;
    }
    html += '</div></div>';
    panel.innerHTML = html;
    container.appendChild(panel);
}

function renderBadgeVoteSection(container, system) {
    const panel = el('div', 'panel');
    const proposal = system.find(m => m.key === 'proposal_hash');
    const vote = system.find(m => m.key === 'vote');
    let html = `<div class="panel-header">\u{1F5F3} Badge Vote</div><div class="panel-body"><div class="detail-grid">`;
    if (proposal) html += `<dt>Proposal</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(decodeMetadataValue(proposal.value))}</dd>`;
    if (vote) {
        const v = decodeMetadataValue(vote.value);
        const cls = v === 'approve' ? 'badge-confirmed' : 'badge-error';
        html += `<dt>Vote</dt><dd><span class="badge ${cls}">${esc(v)}</span></dd>`;
    }
    html += '</div></div>';
    panel.innerHTML = html;
    container.appendChild(panel);
}

function renderBadgeRevocationSection(container, system) {
    const panel = el('div', 'panel');
    const badge = system.find(m => m.key === 'badge_id');
    panel.innerHTML = `<div class="panel-header">\u26D4 Badge Revocation</div><div class="panel-body"><div class="detail-grid">
        <dt>Badge ID</dt><dd class="mono">${esc(badge ? decodeMetadataValue(badge.value) : '\u2014')}</dd>
    </div></div>`;
    container.appendChild(panel);
}

function renderUserMetadata(container, user, signatures, txType) {
    const panel = el('div', 'panel');
    let html = `<div class="panel-header">Metadata (${user.length} entries)</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>Key</th><th>Value</th><th>Status</th></tr></thead><tbody>`;
    user.forEach((entry, i) => {
        const value = decodeMetadataValue(entry.value);
        const sigEntry = signatures.find(s => s.slotIndex === i);
        let status = '';
        if (sigEntry) status += '<span class="meta-badge-signed">Signed</span> ';
        html += `<tr>
            <td><strong>${esc(entry.key)}</strong></td>
            <td class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(value)}</td>
            <td>${status || '<span style="color:var(--text-muted)">\u2014</span>'}</td>
        </tr>`;
    });
    html += '</tbody></table></div>';
    panel.innerHTML = html;
    container.appendChild(panel);
}

// ── Helpers ──────────────────────────────────────────────────────────

function el(tag, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    return e;
}

function formatTimestamp(ts) {
    if (!ts) return '\u2014';
    const d = new Date(ts * 1000);
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
        + ', ' + d.toLocaleTimeString();
}

function copyText(text, btn, opts) {
    if (opts.onCopyText) {
        opts.onCopyText(text);
    } else {
        navigator.clipboard?.writeText(text);
    }
    if (btn) {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
    }
}
