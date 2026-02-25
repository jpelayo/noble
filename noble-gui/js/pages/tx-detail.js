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
        &mdash; <a href="#/verify?tab=locator&tx=${txResult.tx_id}">Decrypt &rarr;</a>
      `;
      heroEl.appendChild(locatorEl);
    }

    // ── Detail grid (checksum removed — shown in hero above) ──
    const grid = document.createElement('dl');
    grid.className = 'detail-grid';
    grid.innerHTML = `
      <dt>Transaction ID</dt><dd class="mono">${txResult.tx_id}</dd>
      <dt>Version</dt><dd>${tx.version}</dd>
      <dt>Timestamp</dt><dd>${formatTimestamp(tx.timestamp)}</dd>
      <dt>Fee</dt><dd>${formatFee(tx.fee)} (${tx.fee} atomic)</dd>
      ${tx.gateway_address ? `
      <dt>Gateway</dt><dd class="mono" title="This node receives 50% of the fee">${truncateHash(tx.gateway_address, 12)}</dd>
      <dt>Fee Split</dt><dd>Validator: ${Math.ceil(tx.fee / 2)} &middot; Gateway: ${Math.floor(tx.fee / 2)}</dd>
      ` : ''}
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
          <dt>Public Key</dt><dd class="mono"><a href="#/verify?tab=publisher&publisher=${bytesToHex(tx.publisher_sig.public_key)}" title="View all documents by this publisher">${bytesToHex(tx.publisher_sig.public_key)}</a></dd>
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
