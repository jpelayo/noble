/**
 * NOBLE Dashboard — Transactions Search Page
 */

import { truncateHash, formatFee, timeAgo, isHex64 } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;

  root.innerHTML = `
    <div class="page-header">
      <h1>Transaction Explorer</h1>
      <p>Search by transaction ID, document checksum, or wallet address</p>
    </div>

    <div class="search-bar">
      <input type="text" id="tx-search-input" placeholder="tx_id, checksum, or address (nbl1..., bc1...)" />
      <button id="tx-search-btn">Search</button>
    </div>

    <div id="tx-results"></div>
  `;

  const input = root.querySelector('#tx-search-input');
  const btn = root.querySelector('#tx-search-btn');
  const results = root.querySelector('#tx-results');

  function isAddress(q) {
    const lc = q.toLowerCase();
    // Noble native (nbl1p..., nbl1q...)
    if (lc.startsWith('nbl1')) return true;
    // Bitcoin bech32/bech32m (bc1q..., bc1p..., tb1...)
    if (lc.startsWith('bc1') || lc.startsWith('tb1')) return true;
    // Bitcoin P2PKH (1...) and P2SH (3...)
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(q)) return true;
    return false;
  }

  async function doSearch() {
    const query = input.value.trim();
    if (!query) return;

    results.innerHTML = '<div class="empty-state">Searching...</div>';

    try {
      // 1. Address lookup (nbl1..., bc1..., legacy 1.../3...)
      if (isAddress(query)) {
        await searchAddress(query);
        return;
      }

      // 2. Hex hash — try as tx_id, then checksum
      const hex = query.toLowerCase();
      if (!isHex64(hex)) {
        results.innerHTML = '<div class="empty-state">Enter a valid address (nbl1..., bc1...) or 64-character hex hash</div>';
        return;
      }

      try {
        const txResult = await rpc.call('noble_getTransaction', { tx_id: hex });
        renderTxResult(txResult);
        return;
      } catch { /* not found as tx_id, try as checksum */ }

      const lookup = await rpc.call('noble_lookupChecksum', { checksum: hex });
      if (lookup.found && lookup.records.length > 0) {
        renderChecksumResults(hex, lookup.records);
        return;
      }

      results.innerHTML = '<div class="empty-state">No results found for this hash</div>';
    } catch (e) {
      results.innerHTML = `<div class="empty-state">Search error: ${e.message || e}</div>`;
    }
  }

  async function searchAddress(address) {
    try {
      const [balance, history] = await Promise.all([
        rpc.call('noble_getAddressBalance', { address }),
        rpc.call('noble_getAddressHistory', { address, page: 0, limit: 20 }),
      ]);

      let html = `
        <div class="panel">
          <div class="panel-header">Address Balance</div>
          <div class="panel-body">
            <dl class="detail-grid">
              <dt>Address</dt><dd class="mono" style="word-break:break-all">${address}</dd>
              <dt>Balance</dt><dd>${formatFee(balance.balance)}</dd>
              <dt>Available</dt><dd>${formatFee(balance.available)}</dd>
              <dt>Pending</dt><dd>${formatFee(balance.pending)}</dd>
              <dt>UTXOs</dt><dd>${balance.utxo_count ?? '—'}</dd>
            </dl>
          </div>
        </div>
      `;

      // history.transactions is Vec<String> — just tx_id hex strings.
      // Fetch full details for each. Show "details unavailable" for failures.
      const txIds = (history.transactions || []).filter(id => id && id.length > 0);
      if (txIds.length > 0) {
        const txResults = await Promise.all(
          txIds.slice(0, 20).map(id =>
            rpc.call('noble_getTransaction', { tx_id: id })
              .then(tx => ({ id, tx, ok: true }))
              .catch(() => ({ id, tx: null, ok: false }))
          )
        );

        html += `
          <div class="panel" style="margin-top:var(--gap)">
            <div class="panel-header">Transaction History (${txIds.length})</div>
            <div class="panel-body" style="padding:0">
              <table class="data-table">
                <thead><tr><th>Tx ID</th><th>Type</th><th>Amount</th><th>Time</th></tr></thead>
                <tbody>
        `;
        for (const r of txResults) {
          if (r.ok && r.tx) {
            const txId = r.tx.tx_id || r.id;
            const amount = r.tx.total_output != null ? formatFee(r.tx.total_output) : '—';
            const type = r.tx.tx_type != null ? formatTxType(r.tx.tx_type) : '—';
            const time = r.tx.timestamp ? timeAgo(r.tx.timestamp) : '—';
            html += `<tr class="clickable" onclick="location.hash='#/tx/${txId}'">
              <td class="mono">${truncateHash(txId)}</td>
              <td>${type}</td>
              <td>${amount}</td>
              <td>${time}</td>
            </tr>`;
          } else {
            html += `<tr class="clickable" onclick="location.hash='#/tx/${r.id}'">
              <td class="mono">${truncateHash(r.id)}</td>
              <td colspan="3" style="color:var(--text-muted)">Details unavailable</td>
            </tr>`;
          }
        }
        html += '</tbody></table></div></div>';
      } else {
        html += '<div class="empty-state" style="margin-top:var(--gap)">No transaction history for this address</div>';
      }

      results.innerHTML = html;
    } catch (e) {
      results.innerHTML = `<div class="empty-state">Address lookup failed: ${e.message || e}</div>`;
    }
  }

  function formatTxType(t) {
    const types = { 0: 'Notarization', 1: 'Transfer', 2: 'Key Rotation', 3: 'Badge Proposal',
      4: 'Badge Vote', 5: 'Badge Revocation', 6: 'Locked', 7: 'Unlocking', 16: 'Coinbase' };
    return types[t] || `Type ${t}`;
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
