/**
 * NOBLE Dashboard — Transaction Detail Page
 * Type-aware rendering with metadata classification, encryption status,
 * and CMS signature badges.
 */

import { formatTimestamp, formatFee, formatNumber, formatScheme, bytesToHex, truncateHash } from '../utils.js';
import { renderMetadataWithSchema } from '../schema-parser.js';
import { TX_TYPES, TX_TYPE_NAMES, txDisplayAmount, classifyMetadata, isZeroChecksum, formatTxType } from '../tx-display.js';

export function init(root, ctx) {
  const { rpc, params } = ctx;
  const txid = params.txid;

  root.innerHTML = `
    <div class="page-header">
      <h1>Transaction Detail</h1>
      <p class="mono" style="word-break:break-all">${esc(txid)}</p>
    </div>
    <div id="tx-loading" class="empty-state">Loading...</div>
  `;

  async function load() {
    let receipt = null;

    try {
      receipt = await rpc.call('noble_getTransactionReceipt', { tx_id: txid });
    } catch {
      try {
        const lookup = await rpc.call('noble_lookupChecksum', { checksum: txid });
        if (lookup.found && lookup.records.length > 0) {
          receipt = await rpc.call('noble_getTransactionReceipt', { tx_id: lookup.records[0].tx_id });
        }
      } catch (e2) {
        console.warn('tx-detail: checksum lookup failed:', e2);
      }
    }

    root.querySelector('#tx-loading')?.remove();

    if (!receipt) {
      root.innerHTML += '<div class="empty-state">Transaction not found</div>';
      return;
    }

    const tx = receipt.transaction || receipt.tx;
    const txId = receipt.tx_id || tx.tx_id || txid;
    const txType = tx.tx_type;
    const metadata = tx.metadata || [];
    const { system, user, signatures } = classifyMetadata(metadata);
    const disp = txDisplayAmount(tx);

    // ── Type-aware Hero Section ──
    const heroEl = document.createElement('div');
    heroEl.className = 'checksum-hero';

    if ((txType === TX_TYPES.NOTARIZATION || txType === TX_TYPES.UNLOCKING) && !isZeroChecksum(tx.checksum)) {
      // Document checksum hero
      heroEl.innerHTML = `
        <div class="checksum-hero__label">${txType === TX_TYPES.UNLOCKING ? 'Revealed Document Checksum' : 'Document Checksum'}</div>
        <div class="checksum-hero__value mono">${tx.checksum}</div>
        <div class="checksum-hero__actions">
          <button class="btn btn-sm" id="copy-checksum">Copy</button>
          <a href="#/verify?checksum=${tx.checksum}" class="btn btn-sm btn-link">Verify this document &rarr;</a>
        </div>
      `;
    } else if (txType === TX_TYPES.LOCKED) {
      heroEl.innerHTML = `
        <div class="checksum-hero__label" style="font-size:1.5rem">&#x1F512; Encrypted Document</div>
        <div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-top:4px">
          Checksum and metadata are encrypted with AES-256-GCM
        </div>
      `;
    } else if (txType === TX_TYPES.TRANSFER) {
      heroEl.innerHTML = `
        <div class="checksum-hero__label">Transfer</div>
        <div class="checksum-hero__value">&diams; ${formatFee(disp.amount)}</div>
      `;
    } else if (txType === TX_TYPES.COINBASE) {
      heroEl.innerHTML = `
        <div class="checksum-hero__label"><span class="badge coinbase">Coinbase</span> Block Reward</div>
        <div class="checksum-hero__value">&diams; ${formatFee(disp.amount)}</div>
      `;
    } else if (txType === TX_TYPES.KEY_ROTATION) {
      heroEl.innerHTML = `<div class="checksum-hero__label">&#x1F504; Key Rotation</div>`;
    } else if (txType === TX_TYPES.BADGE_PROPOSAL) {
      heroEl.innerHTML = `<div class="checksum-hero__label">&#x1F3C5; Badge Proposal</div>`;
    } else if (txType === TX_TYPES.BADGE_VOTE) {
      heroEl.innerHTML = `<div class="checksum-hero__label">&#x1F5F3; Badge Vote</div>`;
    } else if (txType === TX_TYPES.BADGE_REVOCATION) {
      heroEl.innerHTML = `<div class="checksum-hero__label">&#x26D4; Badge Revocation</div>`;
    } else {
      heroEl.style.display = 'none';
    }
    root.appendChild(heroEl);

    // Copy button
    root.querySelector('#copy-checksum')?.addEventListener('click', () => {
      navigator.clipboard.writeText(tx.checksum).then(() => {
        const btn = root.querySelector('#copy-checksum');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      });
    });

    // Version chain badges
    const versionMeta = metadata.find(m => m.key === 'doc:version');
    const prevChecksumMeta = metadata.find(m => m.key === 'doc:prev_checksum');
    if (versionMeta || prevChecksumMeta) {
      const versionEl = document.createElement('div');
      versionEl.className = 'checksum-hero__version';
      const verValue = versionMeta ? decodeHexOrUtf8(versionMeta.value) : null;
      const prevValue = prevChecksumMeta ? decodeHexOrUtf8(prevChecksumMeta.value) : null;
      let html = '';
      if (verValue) html += `<span class="badge badge-version">v${esc(verValue)}</span> `;
      if (prevValue) html += `<span style="font-size:var(--font-size-xs);color:var(--text-secondary)">Previous: <a href="#/verify?checksum=${esc(prevValue)}" class="mono">${truncateHash(prevValue, 12)}</a></span>`;
      versionEl.innerHTML = html;
      heroEl.appendChild(versionEl);
    }

    // Successor versions
    if (!isZeroChecksum(tx.checksum)) {
      try {
        const versionsRes = await rpc.call('noble_getDocumentVersions', { checksum: tx.checksum });
        if (versionsRes.count > 1) {
          const nextVersions = versionsRes.versions.filter(v => v.checksum !== tx.checksum);
          if (nextVersions.length > 0) {
            const nextEl = document.createElement('div');
            nextEl.className = 'checksum-hero__next-versions';
            nextEl.innerHTML = `<span style="font-size:var(--font-size-xs);color:var(--text-secondary)">
              Newer version${nextVersions.length > 1 ? 's' : ''}:
              ${nextVersions.slice(0, 3).map(v => `<a href="#/tx/${v.tx_id}" class="mono">${v.version ? 'v' + v.version : truncateHash(v.tx_id, 8)}</a>`).join(', ')}
              ${nextVersions.length > 3 ? `<span>+${nextVersions.length - 3} more</span>` : ''}
            </span>`;
            heroEl.appendChild(nextEl);
          }
        }
      } catch { /* version chain lookup not critical */ }
    }

    // Encrypted locator indicator
    if (tx.has_encrypted_locator) {
      const locatorEl = document.createElement('div');
      locatorEl.className = 'checksum-hero__locator';
      const recipientCount = tx.locator_recipient_count || 1;
      locatorEl.innerHTML = `<span class="badge badge-encrypted">Encrypted Locator</span> Available (${recipientCount} recipient${recipientCount !== 1 ? 's' : ''}) &mdash; <a href="#/verify?tab=locator&tx=${txId}">Decrypt &rarr;</a>`;
      heroEl.appendChild(locatorEl);
    }

    // ── Detail Grid ──
    const status = receipt.status || tx.confirmation_status || 'unknown';
    const blockHeight = receipt.block_height;
    const confirmations = receipt.confirmations;

    const grid = document.createElement('dl');
    grid.className = 'detail-grid';
    let gridHtml = `
      <dt>Transaction ID</dt><dd class="mono" style="word-break:break-all">${esc(txId)}</dd>
      <dt>Type</dt><dd>${formatTxType(txType)}</dd>
      <dt>Timestamp</dt><dd>${formatTimestamp(tx.timestamp)}</dd>
    `;

    // Type-aware value display
    if (txType === TX_TYPES.TRANSFER) {
      gridHtml += `<dt>Amount Sent</dt><dd>${formatFee(disp.amount)} (${formatNumber(disp.amount)} groats)</dd>`;
      if (tx.fee != null) gridHtml += `<dt>Fee</dt><dd>${formatFee(tx.fee)} (${formatNumber(tx.fee)} groats)</dd>`;
    } else if (txType === TX_TYPES.COINBASE) {
      gridHtml += `<dt>Block Reward</dt><dd>${formatFee(disp.amount)} (${formatNumber(disp.amount)} groats)</dd>`;
    } else {
      // Notarization, Locked, Unlocking, Key Rotation, Badge types.
      // The fee (input − outputs) is the real cost; the change is covered by
      // the Balance Changes ledger below, so no misleading "Total Output".
      if (tx.fee != null) gridHtml += `<dt>Fee</dt><dd>${formatFee(tx.fee)} (${formatNumber(tx.fee)} groats)</dd>`;
    }

    if (tx.gateway_address) {
      gridHtml += `<dt>Gateway</dt><dd class="mono" style="word-break:break-all" title="Receives 50% of the fee">${tx.gateway_address}</dd>`;
    }
    gridHtml += `<dt>Status</dt><dd><span class="badge ${status === 'complete' || status === 'confirmed' ? 'badge-confirmed' : ''}">${esc(status)}</span></dd>`;
    if (blockHeight != null) gridHtml += `<dt>Block Height</dt><dd><a href="#/block/${blockHeight}">${blockHeight}</a></dd>`;
    if (confirmations != null) gridHtml += `<dt>Confirmations</dt><dd>${confirmations}</dd>`;
    if (tx.size_bytes) gridHtml += `<dt>Size</dt><dd>${formatNumber(tx.size_bytes)} bytes</dd>`;
    if (tx.fee_rate) gridHtml += `<dt>Fee Rate</dt><dd>${tx.fee_rate} groats/byte</dd>`;
    grid.innerHTML = gridHtml;
    root.appendChild(grid);

    // ── Balance Changes ledger (who paid/received what, net per address) ──
    renderBalanceChanges(root, tx);

    // ── Type-specific sections ──
    if (txType === TX_TYPES.LOCKED) {
      renderLockedSection(root, system, user, signatures);
    } else if (txType === TX_TYPES.UNLOCKING) {
      renderUnlockingSection(root, system);
    } else if (txType === TX_TYPES.KEY_ROTATION) {
      const newKey = system.find(m => m.key === 'new_pubkey');
      if (newKey) {
        const p = document.createElement('div'); p.className = 'panel';
        p.innerHTML = `<div class="panel-header">&#x1F504; Key Rotation</div><div class="panel-body"><dl class="detail-grid"><dt>New Key</dt><dd class="mono" style="word-break:break-all">${esc(decodeHexOrUtf8(newKey.value))}</dd></dl></div>`;
        root.appendChild(p);
      }
    } else if (txType === TX_TYPES.BADGE_PROPOSAL) {
      renderSystemMetaPanel(root, '&#x1F3C5; Badge Proposal', system);
    } else if (txType === TX_TYPES.BADGE_VOTE) {
      const proposal = system.find(m => m.key === 'proposal_hash');
      const vote = system.find(m => m.key === 'vote');
      const p = document.createElement('div'); p.className = 'panel';
      let h = '<div class="panel-header">&#x1F5F3; Badge Vote</div><div class="panel-body"><dl class="detail-grid">';
      if (proposal) h += `<dt>Proposal</dt><dd class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${esc(decodeHexOrUtf8(proposal.value))}</dd>`;
      if (vote) {
        const v = decodeHexOrUtf8(vote.value);
        h += `<dt>Vote</dt><dd><span class="badge ${v === 'approve' ? 'confirmed' : ''}">${esc(v)}</span></dd>`;
      }
      h += '</dl></div>';
      p.innerHTML = h; root.appendChild(p);
    } else if (txType === TX_TYPES.BADGE_REVOCATION) {
      renderSystemMetaPanel(root, '&#x26D4; Badge Revocation', system);
    }

    // ── Inputs panel ──
    const inputs = tx.inputs || [];
    // Addresses that funded this tx — used to tag change outputs below.
    const payerSet = new Set(inputs.filter(i => i.address).map(i => i.address));
    if (inputs.length > 0) {
      const inputPanel = document.createElement('div'); inputPanel.className = 'panel';
      const isCoinbase = inputs.length === 1 && inputs[0].txid === '0'.repeat(64);
      // Show resolved value/address columns when the backend supplied them.
      const resolved = inputs.some(i => i.value != null || i.address != null);
      let inputHtml = `<div class="panel-header">Inputs (${inputs.length})</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>#</th><th>Previous Tx</th><th>Output Index</th>${resolved ? '<th>Value</th><th>Address</th>' : ''}</tr></thead><tbody>`;
      inputs.forEach((inp, i) => {
        const txLink = isCoinbase
          ? '<span class="badge coinbase">Coinbase (new coins)</span>'
          : `<a href="#/tx/${inp.txid}" class="mono" style="word-break:break-all">${inp.txid}</a>`;
        const extra = resolved
          ? `<td>${inp.value != null ? formatFee(inp.value) : '&mdash;'}</td><td class="mono" style="word-break:break-all">${inp.address ? esc(inp.address) : '&mdash;'}</td>`
          : '';
        inputHtml += `<tr><td>${i}</td><td>${txLink}</td><td>${isCoinbase ? '&mdash;' : inp.vout}</td>${extra}</tr>`;
      });
      inputHtml += '</tbody></table></div>';
      inputPanel.innerHTML = inputHtml;
      root.appendChild(inputPanel);
    }

    // ── Outputs panel ──
    const outputs = tx.outputs || [];
    if (outputs.length > 0) {
      const outputPanel = document.createElement('div'); outputPanel.className = 'panel';
      let outputHtml = `<div class="panel-header">Outputs (${outputs.length})</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>#</th><th>Value</th><th>Address</th></tr></thead><tbody>`;
      outputs.forEach((out, i) => {
        // An output back to a funding address is change, not a payment.
        const changeTag = payerSet.has(out.address)
          ? ' <span class="tag-change">change</span>' : '';
        outputHtml += `<tr><td>${i}</td><td>${formatFee(out.value)}</td><td class="mono" style="word-break:break-all">${esc(out.address)}${changeTag}</td></tr>`;
      });
      outputHtml += '</tbody></table></div>';
      outputPanel.innerHTML = outputHtml;
      root.appendChild(outputPanel);
    }

    // ── Issuer signature ──
    const sigPanel = document.createElement('div'); sigPanel.className = 'panel';
    if (tx.signer) {
      sigPanel.innerHTML = `<div class="panel-header">Issuer Signature</div><div class="panel-body"><dl class="detail-grid">
        <dt>Signer</dt><dd>${tx.signer_name ? `<strong>${tx.signer_name}</strong> ` : ''}<span class="mono"><a href="#/verify?tab=issuer&issuer=${tx.signer}" title="View all documents by this issuer">${tx.signer}</a></span></dd>
        ${tx.recipient ? `<dt>Recipient</dt><dd><span class="mono">${tx.recipient}</span></dd>` : ''}
      </dl></div>`;
    } else if (tx.issuer_sig) {
      sigPanel.innerHTML = `<div class="panel-header">Issuer Signature</div><div class="panel-body"><dl class="detail-grid">
        <dt>Scheme</dt><dd>${formatScheme(tx.issuer_sig.scheme_id)}</dd>
        <dt>Public Key</dt><dd class="mono"><a href="#/verify?tab=issuer&issuer=${bytesToHex(tx.issuer_sig.public_key)}">${bytesToHex(tx.issuer_sig.public_key)}</a></dd>
        <dt>Signature</dt><dd class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${bytesToHex(tx.issuer_sig.signature)}</dd>
      </dl></div>`;
    } else {
      sigPanel.innerHTML = `<div class="panel-header">Issuer Signature</div><div class="panel-body"><em>Not available</em></div>`;
    }
    root.appendChild(sigPanel);

    // ── Additional signatures ──
    if ((tx.additional_sigs || []).length > 0) {
      const addSigPanel = document.createElement('div'); addSigPanel.className = 'panel';
      let sigHtml = `<div class="panel-header">Additional Signatures (${tx.additional_sigs.length})</div><div class="panel-body">`;
      tx.additional_sigs.forEach((sig, i) => {
        sigHtml += `<dl class="detail-grid" style="margin-bottom:var(--gap)">
          <dt>Sig #${i + 1} Scheme</dt><dd>${formatScheme(sig.scheme_id)}</dd>
          <dt>Public Key</dt><dd class="mono">${bytesToHex(sig.public_key)}</dd>
          <dt>Signature</dt><dd class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${bytesToHex(sig.signature)}</dd>
        </dl>`;
      });
      sigHtml += '</div>';
      addSigPanel.innerHTML = sigHtml;
      root.appendChild(addSigPanel);
    }

    // ── User Metadata ──
    if (user.length > 0 && txType !== TX_TYPES.LOCKED) {
      renderUserMetadataPanel(root, user, signatures, metadata);
    }
  }

  load();
  return { destroy() {} };
}

// ── Type-specific section renderers ──

function renderLockedSection(root, system, user, signatures) {
  const salt = system.find(m => m.key === 'locked:salt');
  const nonce = system.find(m => m.key === 'locked:nonce');
  const encChecksum = system.find(m => m.key === 'locked:checksum');

  const panel = document.createElement('div');
  panel.className = 'panel';
  panel.style.borderLeft = '3px solid var(--warning, #f59e0b)';
  let html = '<div class="panel-header">&#x1F512; Encryption Details</div><div class="panel-body"><dl class="detail-grid">';
  if (salt) html += `<dt>Salt</dt><dd class="mono" style="font-size:var(--font-size-xs)">${esc(decodeHexOrUtf8(salt.value))}</dd>`;
  if (nonce) html += `<dt>Nonce</dt><dd class="mono" style="font-size:var(--font-size-xs)">${esc(decodeHexOrUtf8(nonce.value))}</dd>`;
  if (encChecksum) {
    const val = decodeHexOrUtf8(encChecksum.value);
    html += `<dt>Encrypted Checksum</dt><dd class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(val.slice(0, 40))}${val.length > 40 ? '...' : ''}</dd>`;
  }
  html += '</dl></div>';
  panel.innerHTML = html;
  root.appendChild(panel);

  // Encrypted user metadata
  if (user.length > 0) {
    const metaPanel = document.createElement('div'); metaPanel.className = 'panel';
    let mhtml = `<div class="panel-header">Metadata (${user.length} entries)</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>Key</th><th>Value</th><th>Status</th></tr></thead><tbody>`;
    for (const entry of user) {
      const val = decodeHexOrUtf8(entry.value);
      const sigMatch = signatures.find(s => s.slotIndex === user.indexOf(entry));
      const sigBadge = sigMatch ? '<span class="badge" style="background:var(--success,#22c55e);color:#fff;font-size:0.6rem;padding:1px 4px;margin-right:4px">Signed</span>' : '';
      mhtml += `<tr>
        <td><strong>${esc(entry.key)}</strong></td>
        <td class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);word-break:break-all">${esc(val.slice(0, 32))}${val.length > 32 ? '...' : ''}</td>
        <td>${sigBadge}<span class="badge" style="background:var(--warning,#f59e0b);color:#000;font-size:0.6rem;padding:1px 4px">Encrypted</span></td>
      </tr>`;
    }
    mhtml += '</tbody></table></div>';
    metaPanel.innerHTML = mhtml;
    root.appendChild(metaPanel);
  }
}

function renderUnlockingSection(root, system) {
  const lockedTx = system.find(m => m.key === 'unlock:txid');
  const password = system.find(m => m.key === 'unlock:password');

  const panel = document.createElement('div'); panel.className = 'panel';
  panel.style.borderLeft = '3px solid var(--success, #22c55e)';
  let html = '<div class="panel-header">&#x1F511; Unlock Reference</div><div class="panel-body"><dl class="detail-grid">';
  if (lockedTx) {
    // unlock:txid is a raw hex string from the API — use as-is, do NOT hex-decode
    const id = typeof lockedTx.value === 'string' ? lockedTx.value : decodeHexOrUtf8(lockedTx.value);
    html += `<dt>Locked Transaction</dt><dd><a href="#/tx/${esc(id)}" class="mono" style="word-break:break-all">${esc(id)}</a></dd>`;
  }
  if (password) {
    // unlock:password is a raw UTF-8 string — use as-is, do NOT hex-decode
    const pw = typeof password.value === 'string' ? password.value : decodeHexOrUtf8(password.value);
    html += `<dt>Password</dt><dd><span id="unlock-pw-mask">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span> <button class="btn btn-sm" id="toggle-pw">Show</button></dd>`;
    html += `<input type="hidden" id="unlock-pw-value" value="${esc(pw)}">`;
  }
  html += '</dl></div>';
  panel.innerHTML = html;

  const toggleBtn = panel.querySelector('#toggle-pw');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const mask = panel.querySelector('#unlock-pw-mask');
      const val = panel.querySelector('#unlock-pw-value').value;
      if (mask.textContent.includes('\u2022')) {
        mask.textContent = val;
        mask.classList.add('mono');
        toggleBtn.textContent = 'Hide';
      } else {
        mask.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
        mask.classList.remove('mono');
        toggleBtn.textContent = 'Show';
      }
    });
  }
  root.appendChild(panel);
}

function renderSystemMetaPanel(root, title, system) {
  if (system.length === 0) return;
  const panel = document.createElement('div'); panel.className = 'panel';
  let html = `<div class="panel-header">${title}</div><div class="panel-body"><dl class="detail-grid">`;
  for (const m of system) {
    const label = m.key.replace(/_/g, ' ');
    html += `<dt>${esc(label)}</dt><dd class="mono" style="word-break:break-all">${esc(decodeHexOrUtf8(m.value))}</dd>`;
  }
  html += '</dl></div>';
  panel.innerHTML = html;
  root.appendChild(panel);
}

function renderUserMetadataPanel(root, user, signatures, allMetadata) {
  // Try schema-aware rendering first
  const metadataEntries = allMetadata.map(m => ({
    key: m.key,
    value: Array.isArray(m.value) ? m.value.map(b => b.toString(16).padStart(2, '0')).join('') : m.value,
  }));

  const metaPanel = document.createElement('div'); metaPanel.className = 'panel';
  let html = `<div class="panel-header">Metadata (${user.length} entries)</div><div class="panel-body" style="padding:0">`;

  if (signatures.length > 0) {
    // Show status column when signatures exist
    html += '<table class="data-table"><thead><tr><th>Key</th><th>Value</th><th>Status</th></tr></thead><tbody>';
    for (const entry of user) {
      const val = decodeHexOrUtf8(entry.value);
      const idx = allMetadata.indexOf(allMetadata.find(m => m.key === entry.key));
      const sigMatch = signatures.find(s => s.slotIndex === idx);
      const sigBadge = sigMatch ? '<span class="badge" style="background:var(--success,#22c55e);color:#fff;font-size:0.6rem;padding:1px 4px">Signed</span>' : '<span style="color:var(--text-muted)">&mdash;</span>';
      html += `<tr><td><strong>${esc(entry.key)}</strong></td><td class="mono" style="word-break:break-all">${esc(val)}</td><td>${sigBadge}</td></tr>`;
    }
    html += '</tbody></table>';
  } else {
    // Schema-aware or raw rendering without status column
    html += renderMetadataWithSchema(metadataEntries);
  }

  html += '</div>';
  metaPanel.innerHTML = html;
  root.appendChild(metaPanel);
}

// ── Balance Changes ledger ──

/** NOBLE amount without the " NOBLE" suffix, magnitude only. */
function amtBare(groats) {
  return formatFee(Math.abs(groats)).replace(' NOBLE', '');
}
/** Signed compact amount: "−0.005401" / "+0.005401" / "0". */
function fmtSigned(groats) {
  if (groats === 0) return '0';
  return (groats < 0 ? '−' : '+') + amtBare(groats);
}

/**
 * Per-party net-delta ledger for a transaction.
 * Returns { mode, parties[], ... }. A party has { addr|label, paidIn,
 * received, net, role, isPayer, isFee }. paidIn/received === null means
 * "unknown" (privacy-stripped or pruned), rendered as "—".
 */
export function computeLedger(tx) {
  const inputs = tx.inputs || [];
  const outputs = tx.outputs || [];
  const fee = (tx.fee != null) ? tx.fee : null;
  const signer = tx.signer;

  // Coinbase / fee-distribution: no real inputs — coins minted or collected.
  const isCoinbaseStyle = (tx.tx_type === TX_TYPES.COINBASE)
    || (tx.tx_type === TX_TYPES.FEE_DISTRIBUTION)
    || (inputs.length === 1 && inputs[0].txid === '0'.repeat(64));
  if (isCoinbaseStyle) {
    const label = tx.tx_type === TX_TYPES.FEE_DISTRIBUTION ? 'fee income' : 'block reward';
    return {
      mode: 'coinbase',
      parties: outputs.map(o => ({ addr: o.address, role: label, paidIn: null, received: o.value, net: o.value })),
    };
  }

  const payers = new Set(inputs.filter(i => i.address).map(i => i.address));
  const inputsResolved = inputs.length > 0 && inputs.every(i => i.value != null && i.address != null);

  if (inputsResolved) {
    const map = new Map();
    const party = (addr) => {
      if (!map.has(addr)) map.set(addr, { addr, paidIn: 0, received: 0, isPayer: payers.has(addr) });
      return map.get(addr);
    };
    for (const inp of inputs) party(inp.address).paidIn += inp.value;
    for (const out of outputs) party(out.address).received += out.value;

    const parties = [...map.values()]
      .map(p => ({ ...p, net: p.received - p.paidIn, role: p.isPayer ? 'signer' : 'recipient' }))
      .sort((a, b) => (a.isPayer === b.isPayer) ? 0 : (a.isPayer ? -1 : 1));

    if (fee != null && fee > 0) {
      parties.push({ addr: null, label: 'network fee → validator', paidIn: 0, received: fee, net: fee, isFee: true });
    }
    const totalIn = parties.reduce((s, p) => s + (p.paidIn || 0), 0);
    const totalRecv = parties.reduce((s, p) => s + (p.received || 0), 0);
    const netSum = parties.reduce((s, p) => s + p.net, 0);
    return { mode: 'full', parties, totalIn, totalRecv, balanced: netSum === 0 };
  }

  // Degraded: transfers strip inputs (privacy) or the source tx was pruned.
  // Change returns to self and nets out.
  const payments = outputs.filter(o => o.address !== signer);
  const paymentsTotal = payments.reduce((s, o) => s + o.value, 0);
  const isTransfer = tx.tx_type === TX_TYPES.TRANSFER;
  // transfer_value is ONLY meaningful for transfers: for a notarization
  // (all outputs are change to self) the backend's fallback returns the
  // full change amount — treating that as a payment showed the signer
  // "paying" ~its whole input. Non-transfers pay nothing but the fee.
  const transferVal = isTransfer
    ? ((tx.transfer_value != null && tx.transfer_value > 0) ? tx.transfer_value : paymentsTotal)
    : paymentsTotal;
  const feeVal = (fee != null) ? fee : 0;
  const parties = [];
  if (signer) parties.push({ addr: signer, role: 'signer', isPayer: true, paidIn: null, received: null, net: -(transferVal + feeVal) });
  for (const o of payments) parties.push({ addr: o.address, role: 'recipient', paidIn: null, received: o.value, net: o.value });
  if (fee != null && fee > 0) parties.push({ addr: null, label: 'network fee → validator', isFee: true, paidIn: null, received: fee, net: fee });
  const note = tx.confirmation_status === 'pending'
    ? 'pending — inputs not yet confirmed'
    : (inputs.length === 0 ? 'sender inputs hidden (privacy)' : 'some inputs unresolved (pruned source)');
  return { mode: 'partial', parties, note };
}

function renderBalanceChanges(root, tx) {
  const ledger = computeLedger(tx);
  if (!ledger.parties.length) return;

  const roleBadge = (p) => {
    if (p.isFee) return '';
    const cls = p.role === 'signer' ? 'badge-signer' : (p.role === 'recipient' ? 'badge-recipient' : 'badge-reward');
    return ` <span class="badge ${cls}">${esc(p.role)}</span>`;
  };
  const partyCell = (p) => p.isFee
    ? `<span style="color:var(--text-muted)">${esc(p.label)}</span>`
    : `<span class="mono" title="${esc(p.addr || '')}">${esc(truncateHash(p.addr || '', 8))}</span>${roleBadge(p)}`;
  const numCell = (v, isChange) => (v == null)
    ? '<td class="num" style="color:var(--text-muted)">&mdash;</td>'
    : (v === 0 ? '<td class="num" style="color:var(--text-muted)">&mdash;</td>'
      : `<td class="num">${amtBare(v)}${isChange ? ' <span class="tag-change">change</span>' : ''}</td>`);
  const netCell = (n) => {
    const cls = n < 0 ? 'amt-neg' : (n > 0 ? 'amt-pos' : '');
    return `<td class="num ${cls}"><strong>${fmtSigned(n)}</strong></td>`;
  };

  const rows = ledger.parties.map(p => {
    const isChange = !p.isFee && p.isPayer && p.received > 0;
    return `<tr><td>${partyCell(p)}</td>${numCell(p.paidIn)}${numCell(p.received, isChange)}${netCell(p.net)}</tr>`;
  }).join('');

  let foot = '';
  if (ledger.mode === 'full') {
    foot = `<tfoot><tr class="ledger-totals">
      <td>totals</td><td class="num">${amtBare(ledger.totalIn)}</td>
      <td class="num">${amtBare(ledger.totalRecv)}</td>
      <td class="num">${ledger.balanced ? '0' : ''}</td></tr></tfoot>`;
  }
  const headerBadge = ledger.mode === 'full' && ledger.balanced
    ? ' <span class="badge badge-confirmed">balanced &check;</span>' : '';
  const note = ledger.note
    ? `<div style="padding:6px 12px;color:var(--text-muted);font-size:var(--font-size-xs)">${esc(ledger.note)}</div>`
    : '';

  const panel = document.createElement('div');
  panel.className = 'panel';
  panel.innerHTML = `<div class="panel-header">Balance Changes${headerBadge}</div>
    <div class="panel-body" style="padding:0">
      <table class="data-table ledger">
        <thead><tr><th>Party</th><th class="num">Paid in</th><th class="num">Received</th><th class="num">Net</th></tr></thead>
        <tbody>${rows}</tbody>${foot}
      </table>${note}
    </div>`;
  root.appendChild(panel);
}

// ── Helpers ──

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function decodeHexOrUtf8(value) {
  if (Array.isArray(value)) return new TextDecoder().decode(new Uint8Array(value));
  if (typeof value === 'string') {
    if (!/^[0-9a-fA-F]+$/.test(value)) return value;
    try {
      const bytes = [];
      for (let i = 0; i < value.length; i += 2) bytes.push(parseInt(value.substring(i, i + 2), 16));
      const text = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
      if (/^[\x20-\x7E\t\n\r]+$/.test(text)) return text;
    } catch { /* not valid UTF-8 hex */ }
    return value;
  }
  return String(value);
}
