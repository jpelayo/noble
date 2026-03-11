/**
 * NOBLE Dashboard — Transactions Search Page
 */

import { truncateHash, formatFee, timeAgo, isHex64 } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;

  root.innerHTML = `
    <div class="page-header">
      <h1>Transaction Explorer</h1>
      <p>Search by transaction ID or document checksum (64-char hex)</p>
    </div>

    <div class="search-bar">
      <input type="text" id="tx-search-input" placeholder="Enter tx_id or checksum (64-char hex)..." />
      <button id="tx-search-btn">Search</button>
    </div>

    <div id="tx-results"></div>
  `;

  const input = root.querySelector('#tx-search-input');
  const btn = root.querySelector('#tx-search-btn');
  const results = root.querySelector('#tx-results');

  async function doSearch() {
    const query = input.value.trim().toLowerCase();
    if (!query) return;

    results.innerHTML = '<div class="empty-state">Searching...</div>';

    if (!isHex64(query)) {
      results.innerHTML = '<div class="empty-state">Please enter a valid 64-character hex string</div>';
      return;
    }

    try {
      // Try as tx_id first
      try {
        const txResult = await rpc.call('noble_getTransaction', { tx_id: query });
        renderTxResult(txResult);
        return;
      } catch { /* not found as tx_id, try as checksum */ }

      // Try as checksum
      const lookup = await rpc.call('noble_lookupChecksum', { checksum: query });
      if (lookup.found && lookup.records.length > 0) {
        renderChecksumResults(query, lookup.records);
        return;
      }

      results.innerHTML = '<div class="empty-state">No results found for this hash</div>';
    } catch (e) {
      results.innerHTML = `<div class="empty-state">Search error: ${e.message || e}</div>`;
    }
  }

  function renderTxResult(txResult) {
    results.innerHTML = `
      <div class="panel">
        <div class="panel-header">Transaction Found</div>
        <div class="panel-body" style="padding:0">
          <table class="data-table">
            <thead><tr><th>Tx ID</th><th>Block</th><th>Total Output</th><th>Status</th><th>Confirmations</th></tr></thead>
            <tbody>
              <tr class="clickable" id="tx-result-row">
                <td class="mono">${truncateHash(txResult.tx_id)}</td>
                <td>${txResult.block_height}</td>
                <td>${formatFee(txResult.tx.total_output)}</td>
                <td><span class="badge confirmed">${txResult.status}</span></td>
                <td>${txResult.confirmations}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
    results.querySelector('#tx-result-row')?.addEventListener('click', () => {
      location.hash = `#/tx/${txResult.tx_id}`;
    });
  }

  function renderChecksumResults(checksum, records) {
    let rows = '';
    for (const r of records) {
      rows += `
        <tr class="clickable" data-txid="${r.tx_id}">
          <td class="mono">${truncateHash(r.tx_id)}</td>
          <td>${r.block_height}</td>
          <td>${timeAgo(r.timestamp)}</td>
        </tr>
      `;
    }
    results.innerHTML = `
      <div class="panel">
        <div class="panel-header">Checksum Registrations (${records.length})</div>
        <div class="panel-body" style="padding:0">
          <table class="data-table">
            <thead><tr><th>Tx ID</th><th>Block Height</th><th>Time</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
    `;
    results.querySelectorAll('tr.clickable').forEach(tr => {
      tr.addEventListener('click', () => {
        location.hash = `#/tx/${tr.dataset.txid}`;
      });
    });
  }

  btn.addEventListener('click', doSearch);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSearch(); });

  return { destroy() {} };
}
