/**
 * NOBLE Dashboard — Block Detail Page
 */

import { formatNumber, truncateHash, formatTimestamp, formatFee } from '../utils.js';

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
      const block = await rpc.call('noble_getBlock', [height]);

      root.querySelector('#block-loading')?.remove();

      // Header detail grid
      const grid = document.createElement('dl');
      grid.className = 'detail-grid';
      grid.innerHTML = `
        <dt>Height</dt><dd>${formatNumber(block.height)}</dd>
        <dt>Hash</dt><dd class="mono">${block.hash}</dd>
        <dt>Timestamp</dt><dd>${formatTimestamp(block.timestamp)}</dd>
        <dt>Prev Block Hash</dt><dd class="mono">${block.prev_hash}</dd>
        <dt>Merkle Root</dt><dd class="mono">${block.merkle_root}</dd>
        <dt>Transaction Count</dt><dd>${block.tx_count}</dd>
        <dt>Validator ID</dt><dd class="mono">${truncateHash(block.validator_id, 16)}</dd>
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
              <thead><tr><th>#</th><th>Tx ID</th><th>Total Output</th><th>Type</th><th>Inputs / Outputs</th></tr></thead>
              <tbody id="block-txs"></tbody>
            </table>
          </div>
        `;
        root.appendChild(panel);

        const tbody = panel.querySelector('#block-txs');
        block.transactions.forEach((tx, i) => {
          const isCoinbase = tx.tx_type === 0x10 || (tx.inputs && tx.inputs.length === 1 && tx.inputs[0].txid === '0'.repeat(64));
          const typeLabel = isCoinbase ? '<span class="badge coinbase">Coinbase</span>' : `Type ${tx.tx_type}`;
          const tr = document.createElement('tr');
          tr.className = 'clickable';
          tr.innerHTML = `
            <td>${i}</td>
            <td class="mono">${truncateHash(tx.tx_id)}</td>
            <td>${formatFee(tx.total_output)}</td>
            <td>${typeLabel}</td>
            <td>${(tx.inputs || []).length} in / ${(tx.outputs || []).length} out</td>
          `;
          tr.addEventListener('click', () => {
            location.hash = `#/tx/${tx.tx_id}`;
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

