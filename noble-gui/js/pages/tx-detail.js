/**
 * NOBLE Dashboard — Transaction Detail Page
 */

import { formatTimestamp, formatFee, formatScheme, bytesToHex, truncateHash } from '../utils.js';
import { renderMetadataWithSchema } from '../schema-parser.js';

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
      // Try as tx_id — use getTransactionReceipt for full context
      receipt = await rpc.call('noble_getTransactionReceipt', { tx_id: txid });
    } catch {
      // Try as checksum lookup
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

    // Normalize: real API returns { transaction, status, ... }, mock returns { tx, tx_id, ... }
    const tx = receipt.transaction || receipt.tx;
    const txId = receipt.tx_id || tx.tx_id || txid;
    const isZeroChecksum = /^0+$/.test(tx.checksum);

    // ── Checksum hero block ──
    const heroEl = document.createElement('div');
    heroEl.className = 'checksum-hero';
    if (isZeroChecksum) {
      heroEl.innerHTML = `
        <div class="checksum-hero__label" style="opacity:0.5">Document Checksum</div>
        <div class="checksum-hero__muted">No document checksum (non-notarization transaction)</div>
      `;
    } else {
      heroEl.innerHTML = `
        <div class="checksum-hero__label">Document Checksum</div>
        <div class="checksum-hero__value mono">${tx.checksum}</div>
        <div class="checksum-hero__actions">
          <button class="btn btn-sm" id="copy-checksum" title="Copy checksum">Copy</button>
          <a href="#/verify?checksum=${tx.checksum}" class="btn btn-sm btn-link">Verify this document &rarr;</a>
        </div>
      `;
    }
    root.appendChild(heroEl);

    // Copy button handler
    const copyBtn = root.querySelector('#copy-checksum');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(tx.checksum).then(() => {
          copyBtn.textContent = 'Copied!';
          setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
        });
      });
    }

    // ── Version badge (from metadata) ──
    const versionMeta = tx.metadata.find(m => m.key === 'doc:version');
    const prevChecksumMeta = tx.metadata.find(m => m.key === 'doc:prev_checksum');
    if (versionMeta || prevChecksumMeta) {
      const versionEl = document.createElement('div');
      versionEl.className = 'checksum-hero__version';
      const verValue = versionMeta ? decodeHexOrUtf8(versionMeta.value) : null;
      const prevValue = prevChecksumMeta ? decodeHexOrUtf8(prevChecksumMeta.value) : null;
      let html = '';
      if (verValue) {
        html += `<span class="badge badge-version">v${esc(verValue)}</span> `;
      }
      if (prevValue) {
        html += `<span style="font-size:var(--font-size-xs);color:var(--text-secondary)">Previous version: <a href="#/verify?checksum=${esc(prevValue)}" class="mono">${truncateHash(prevValue, 12)}</a></span>`;
      }
      versionEl.innerHTML = html;
      heroEl.appendChild(versionEl);
    }

    // Check for successors (next versions)
    if (!isZeroChecksum) {
      try {
        const versionsRes = await rpc.call('noble_getDocumentVersions', { checksum: tx.checksum });
        if (versionsRes.count > 1) {
          const nextVersions = versionsRes.versions.filter(v => v.checksum !== tx.checksum);
          if (nextVersions.length > 0) {
            const nextEl = document.createElement('div');
            nextEl.className = 'checksum-hero__next-versions';
            nextEl.innerHTML = `
              <span style="font-size:var(--font-size-xs);color:var(--text-secondary)">
                Newer version${nextVersions.length > 1 ? 's' : ''}:
                ${nextVersions.slice(0, 3).map(v =>
                  `<a href="#/tx/${v.tx_id}" class="mono">${v.version ? 'v' + v.version : truncateHash(v.tx_id, 8)}</a>`
                ).join(', ')}
                ${nextVersions.length > 3 ? `<span>+${nextVersions.length - 3} more</span>` : ''}
              </span>
            `;
            heroEl.appendChild(nextEl);
          }
        }
      } catch { /* version chain lookup not critical */ }
    }

    // ── Encrypted locator indicator ──
    if (tx.has_encrypted_locator) {
      const locatorEl = document.createElement('div');
      locatorEl.className = 'checksum-hero__locator';
      const recipientCount = tx.locator_recipient_count || 1;
      locatorEl.innerHTML = `
        <span class="badge badge-encrypted">Encrypted Locator</span>
        Available (${recipientCount} recipient${recipientCount !== 1 ? 's' : ''})
        &mdash; <a href="#/verify?tab=locator&tx=${txId}">Decrypt &rarr;</a>
      `;
      heroEl.appendChild(locatorEl);
    }

    // ── Detail grid (checksum removed — shown in hero above) ──
    const status = receipt.status || 'unknown';
    const blockHeight = receipt.block_height;
    const confirmations = receipt.confirmations;

    const grid = document.createElement('dl');
    grid.className = 'detail-grid';
    grid.innerHTML = `
      <dt>Transaction ID</dt><dd class="mono" style="word-break:break-all">${esc(txId)}</dd>
      <dt>Type</dt><dd>${tx.tx_type != null ? formatTxType(tx.tx_type) : (tx.version || '&mdash;')}</dd>
      <dt>Timestamp</dt><dd>${formatTimestamp(tx.timestamp)}</dd>
      <dt>Total Output</dt><dd>${formatFee(tx.total_output)} (${tx.total_output} atomic)</dd>
      <dt>Fee</dt><dd title="Fee is implicit in UTXO model (sum of inputs - sum of outputs)">&mdash;</dd>
      ${(tx.gateway_address || null) ? `
      <dt>Gateway</dt><dd class="mono" title="This node receives 50% of the fee">${truncateHash(tx.gateway_address, 12)}</dd>
      ` : ''}
      <dt>Status</dt><dd><span class="badge ${status === 'confirmed' ? 'confirmed' : ''}">${esc(status)}</span></dd>
      ${blockHeight != null ? `<dt>Block Height</dt><dd><a href="#/block/${blockHeight}">${blockHeight}</a></dd>` : ''}
      ${confirmations != null ? `<dt>Confirmations</dt><dd>${confirmations}</dd>` : ''}
    `;
    root.appendChild(grid);

    // ── Inputs panel ──
    const inputs = tx.inputs || [];
    if (inputs.length > 0) {
      const inputPanel = document.createElement('div');
      inputPanel.className = 'panel';
      const isCoinbase = inputs.length === 1 && inputs[0].txid === '0'.repeat(64);
      let inputHtml = `<div class="panel-header">Inputs (${inputs.length})</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>#</th><th>Previous Tx</th><th>Output Index</th></tr></thead><tbody>`;
      inputs.forEach((inp, i) => {
        const txLink = isCoinbase
          ? '<span class="badge coinbase">Coinbase (new coins)</span>'
          : `<a href="#/tx/${inp.txid}" class="mono">${truncateHash(inp.txid)}</a>`;
        inputHtml += `<tr><td>${i}</td><td>${txLink}</td><td>${isCoinbase ? '&mdash;' : inp.vout}</td></tr>`;
      });
      inputHtml += '</tbody></table></div>';
      inputPanel.innerHTML = inputHtml;
      root.appendChild(inputPanel);
    }

    // ── Outputs panel ──
    const outputs = tx.outputs || [];
    if (outputs.length > 0) {
      const outputPanel = document.createElement('div');
      outputPanel.className = 'panel';
      let outputHtml = `<div class="panel-header">Outputs (${outputs.length})</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>#</th><th>Value</th><th>Address</th></tr></thead><tbody>`;
      outputs.forEach((out, i) => {
        outputHtml += `<tr><td>${i}</td><td>${formatFee(out.value)}</td><td class="mono">${truncateHash(out.address, 16)}</td></tr>`;
      });
      outputHtml += '</tbody></table></div>';
      outputPanel.innerHTML = outputHtml;
      root.appendChild(outputPanel);
    }

    // Publisher signature / signer
    const sigPanel = document.createElement('div');
    sigPanel.className = 'panel';
    if (tx.signer) {
      // UTXO-model RPC returns a flat `signer` hex string
      sigPanel.innerHTML = `
        <div class="panel-header">Publisher Signature</div>
        <div class="panel-body">
          <dl class="detail-grid">
            <dt>Signer</dt><dd class="mono"><a href="#/verify?tab=publisher&publisher=${tx.signer}" title="View all documents by this publisher">${tx.signer}</a></dd>
          </dl>
        </div>
      `;
    } else if (tx.publisher_sig) {
      sigPanel.innerHTML = `
        <div class="panel-header">Publisher Signature</div>
        <div class="panel-body">
          <dl class="detail-grid">
            <dt>Scheme</dt><dd>${formatScheme(tx.publisher_sig.scheme_id)}</dd>
            <dt>Public Key</dt><dd class="mono"><a href="#/verify?tab=publisher&publisher=${bytesToHex(tx.publisher_sig.public_key)}" title="View all documents by this publisher">${bytesToHex(tx.publisher_sig.public_key)}</a></dd>
            <dt>Signature</dt><dd class="mono">${bytesToHex(tx.publisher_sig.signature)}</dd>
          </dl>
        </div>
      `;
    } else {
      sigPanel.innerHTML = `
        <div class="panel-header">Publisher Signature</div>
        <div class="panel-body"><em>Not available</em></div>
      `;
    }
    root.appendChild(sigPanel);

    // Additional signatures
    if ((tx.additional_sigs || []).length > 0) {
      const addSigPanel = document.createElement('div');
      addSigPanel.className = 'panel';
      const addSigs = tx.additional_sigs || [];
      let sigHtml = '<div class="panel-header">Additional Signatures (' + addSigs.length + ')</div><div class="panel-body">';
      addSigs.forEach((sig, i) => {
        sigHtml += `
          <dl class="detail-grid" style="margin-bottom:var(--gap)">
            <dt>Sig #${i + 1} Scheme</dt><dd>${formatScheme(sig.scheme_id)}</dd>
            <dt>Public Key</dt><dd class="mono">${bytesToHex(sig.public_key)}</dd>
            <dt>Signature</dt><dd class="mono">${bytesToHex(sig.signature)}</dd>
          </dl>
        `;
      });
      sigHtml += '</div>';
      addSigPanel.innerHTML = sigHtml;
      root.appendChild(addSigPanel);
    }

    // Metadata (schema-aware rendering)
    if (tx.metadata.length > 0) {
      // Convert metadata entries to the format expected by schema-parser:
      // { key: string, value: hex-encoded string }
      const metadataEntries = tx.metadata.map(m => ({
        key: m.key,
        value: Array.isArray(m.value)
          ? m.value.map(b => b.toString(16).padStart(2, '0')).join('')
          : m.value,
      }));

      const metaPanel = document.createElement('div');
      metaPanel.className = 'panel';
      metaPanel.innerHTML =
        '<div class="panel-header">Metadata (' + tx.metadata.length + ' entries)</div>' +
        '<div class="panel-body" style="padding:0">' +
        renderMetadataWithSchema(metadataEntries) +
        '</div>';
      root.appendChild(metaPanel);
    }
  }

  load();
  return { destroy() {} };
}

/** Escape HTML to prevent XSS */
function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

/** Format a tx_type byte into a human-readable label */
function formatTxType(txType) {
  switch (txType) {
    case 0x00: return 'Notarization';
    case 0x01: return 'Transfer';
    case 0x02: return 'Key Rotation';
    case 0x03: return 'Badge Proposal';
    case 0x04: return 'Badge Vote';
    case 0x05: return 'Badge Revocation';
    case 0x10: return '<span class="badge coinbase">Coinbase</span>';
    default: return `Type 0x${txType.toString(16).padStart(2, '0')}`;
  }
}

/** Decode a metadata value that may be hex-encoded UTF-8 or an array of byte values */
function decodeHexOrUtf8(value) {
  if (Array.isArray(value)) {
    return new TextDecoder().decode(new Uint8Array(value));
  }
  if (typeof value === 'string') {
    // Try hex decode
    try {
      const bytes = [];
      for (let i = 0; i < value.length; i += 2) {
        bytes.push(parseInt(value.substring(i, i + 2), 16));
      }
      return new TextDecoder().decode(new Uint8Array(bytes));
    } catch { return value; }
  }
  return String(value);
}
