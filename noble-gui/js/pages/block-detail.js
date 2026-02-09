/**
 * NOBLE Dashboard — Block Detail Page
 */

import { formatNumber, truncateHash, formatTimestamp, formatScheme, bytesToHex, formatFee } from '../utils.js';

export function init(root, ctx) {
  const { rpc, params } = ctx;
  const height = parseInt(params.height, 10);

  root.innerHTML = `
    <div class="page-header">
      <h1>Block #${formatNumber(height)}</h1>
      <p>Full block details and transaction list</p>
    </div>
    <div id="block-loading" class="empty-state">Loading...</div>
  `;

  async function load() {
    try {
      const block = await rpc.call('noble_getBlock', { height });
      const h = block.header;

      root.querySelector('#block-loading')?.remove();

      // Header detail grid
      const grid = document.createElement('dl');
      grid.className = 'detail-grid';
      grid.innerHTML = `
        <dt>Height</dt><dd>${formatNumber(h.height)}</dd>
        <dt>Version</dt><dd>${h.version}</dd>
        <dt>Timestamp</dt><dd>${formatTimestamp(h.timestamp)}</dd>
        <dt>Prev Block Hash</dt><dd class="mono">${h.prev_block_hash}</dd>
        <dt>Merkle Root</dt><dd class="mono">${h.merkle_root}</dd>
        <dt>Transaction Count</dt><dd>${h.tx_count}</dd>
        <dt>Validator ID</dt><dd class="mono">${formatValidatorKey(h.validator_id)}</dd>
        <dt>Validator Scheme</dt><dd>${formatScheme(h.validator_sig.scheme_id)}</dd>
        <dt>Signature</dt><dd class="mono">${truncateHash(bytesToHex(h.validator_sig.signature), 16)}</dd>
      `;
      root.appendChild(grid);

      // Transactions table
      if (block.transactions.length > 0) {
        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.innerHTML = `
          <div class="panel-header">Transactions (${block.transactions.length})</div>
          <div class="panel-body" style="padding:0">
            <table class="data-table">
              <thead><tr><th>#</th><th>Checksum</th><th>Fee</th><th>Sigs</th><th>Metadata</th></tr></thead>
              <tbody id="block-txs"></tbody>
            </table>
          </div>
        `;
        root.appendChild(panel);

        const tbody = panel.querySelector('#block-txs');
        block.transactions.forEach((tx, i) => {
          const tr = document.createElement('tr');
          tr.className = 'clickable';
          // We need to derive tx_id. In the mock, we can use checksum as lookup.
          const txId = tx.checksum; // Use checksum for lookup in mock mode
          tr.innerHTML = `
            <td>${i + 1}</td>
            <td class="mono">${truncateHash(tx.checksum)}</td>
            <td>${formatFee(tx.fee)}</td>
            <td>${1 + tx.additional_sigs.length}</td>
            <td>${tx.metadata.length} entries</td>
          `;
          tr.addEventListener('click', () => {
            // Navigate to tx detail via checksum lookup
            location.hash = `#/tx/${tx.checksum}`;
          });
          tbody.appendChild(tr);
        });
      }

      // Navigation
      const nav = document.createElement('div');
      nav.className = 'pagination';
      nav.innerHTML = `
        <button id="bd-prev" ${height <= 0 ? 'disabled' : ''}>Prev Block</button>
        <span class="page-info">Block #${formatNumber(height)}</span>
        <button id="bd-next">Next Block</button>
      `;
      root.appendChild(nav);

      nav.querySelector('#bd-prev')?.addEventListener('click', () => {
        location.hash = `#/block/${height - 1}`;
      });
      nav.querySelector('#bd-next')?.addEventListener('click', () => {
        location.hash = `#/block/${height + 1}`;
      });

    } catch (e) {
      const loading = root.querySelector('#block-loading');
      if (loading) loading.textContent = `Block not found: ${e.message || e}`;
    }
  }

  load();
  return { destroy() {} };
}

function formatValidatorKey(validatorId) {
  if (validatorId?.Ed25519) {
    return `Ed25519:${bytesToHex(validatorId.Ed25519)}`;
  }
  if (validatorId?.Secp256k1) {
    return `secp256k1:${bytesToHex(validatorId.Secp256k1)}`;
  }
  return 'Unknown';
}
