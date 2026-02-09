/**
 * NOBLE Dashboard — Transaction Detail Page
 */

import { formatTimestamp, formatFee, formatScheme, bytesToHex, truncateHash } from '../utils.js';

export function init(root, ctx) {
  const { rpc, params } = ctx;
  const txid = params.txid;

  root.innerHTML = `
    <div class="page-header">
      <h1>Transaction Detail</h1>
      <p class="mono">${truncateHash(txid, 16)}</p>
    </div>
    <div id="tx-loading" class="empty-state">Loading...</div>
  `;

  async function load() {
    let txResult = null;

    try {
      // Try as tx_id
      txResult = await rpc.call('noble_getTransaction', { tx_id: txid });
    } catch {
      // Try as checksum lookup
      try {
        const lookup = await rpc.call('noble_lookupChecksum', { checksum: txid });
        if (lookup.found && lookup.records.length > 0) {
          txResult = await rpc.call('noble_getTransaction', { tx_id: lookup.records[0].tx_id });
        }
      } catch { /* give up */ }
    }

    root.querySelector('#tx-loading')?.remove();

    if (!txResult) {
      root.innerHTML += '<div class="empty-state">Transaction not found</div>';
      return;
    }

    const tx = txResult.tx;

    // Detail grid
    const grid = document.createElement('dl');
    grid.className = 'detail-grid';
    grid.innerHTML = `
      <dt>Transaction ID</dt><dd class="mono">${txResult.tx_id}</dd>
      <dt>Version</dt><dd>${tx.version}</dd>
      <dt>Checksum</dt><dd class="mono">${tx.checksum}</dd>
      <dt>Timestamp</dt><dd>${formatTimestamp(tx.timestamp)}</dd>
      <dt>Fee</dt><dd>${formatFee(tx.fee)} (${tx.fee} atomic)</dd>
      <dt>Status</dt><dd><span class="badge confirmed">${txResult.status}</span></dd>
      <dt>Block Height</dt><dd><a href="#/block/${txResult.block_height}">${txResult.block_height}</a></dd>
      <dt>Confirmations</dt><dd>${txResult.confirmations}</dd>
    `;
    root.appendChild(grid);

    // Publisher signature
    const sigPanel = document.createElement('div');
    sigPanel.className = 'panel';
    sigPanel.innerHTML = `
      <div class="panel-header">Publisher Signature</div>
      <div class="panel-body">
        <dl class="detail-grid">
          <dt>Scheme</dt><dd>${formatScheme(tx.publisher_sig.scheme_id)}</dd>
          <dt>Public Key</dt><dd class="mono">${bytesToHex(tx.publisher_sig.public_key)}</dd>
          <dt>Signature</dt><dd class="mono">${bytesToHex(tx.publisher_sig.signature)}</dd>
        </dl>
      </div>
    `;
    root.appendChild(sigPanel);

    // Additional signatures
    if (tx.additional_sigs.length > 0) {
      const addSigPanel = document.createElement('div');
      addSigPanel.className = 'panel';
      let sigHtml = '<div class="panel-header">Additional Signatures (' + tx.additional_sigs.length + ')</div><div class="panel-body">';
      tx.additional_sigs.forEach((sig, i) => {
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

    // Metadata
    if (tx.metadata.length > 0) {
      const metaPanel = document.createElement('div');
      metaPanel.className = 'panel';
      let metaHtml = '<div class="panel-header">Metadata (' + tx.metadata.length + ' entries)</div><div class="panel-body" style="padding:0"><table class="data-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>';
      for (const entry of tx.metadata) {
        const valueStr = tryUtf8(entry.value);
        metaHtml += `<tr><td><strong>${escapeHtml(entry.key)}</strong></td><td class="mono">${escapeHtml(valueStr)}</td></tr>`;
      }
      metaHtml += '</tbody></table></div>';
      metaPanel.innerHTML = metaHtml;
      root.appendChild(metaPanel);
    }
  }

  load();
  return { destroy() {} };
}

function tryUtf8(bytes) {
  try {
    const arr = new Uint8Array(bytes);
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(arr);
    // Check if printable
    if (/^[\x20-\x7E\t\n\r]+$/.test(decoded)) return decoded;
  } catch { /* not valid UTF-8 */ }
  return bytesToHex(bytes);
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
