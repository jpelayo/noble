/**
 * NOBLE Dashboard — Document Verification Page
 */

import { truncateHash, formatTimestamp, isHex64 } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;

  root.innerHTML = `
    <div class="page-header">
      <h1>Document Verification</h1>
      <p>Verify document integrity by checking its SHA-256 checksum against the NOBLE blockchain</p>
    </div>

    <div class="panel">
      <div class="panel-header">Check Document Checksum</div>
      <div class="panel-body">
        <div class="search-bar">
          <input type="text" id="verify-input" placeholder="Paste SHA-256 checksum (64-char hex)..." />
          <button id="verify-btn">Verify</button>
        </div>
        <div id="verify-result"></div>
      </div>
    </div>
  `;

  const input = root.querySelector('#verify-input');
  const btn = root.querySelector('#verify-btn');
  const result = root.querySelector('#verify-result');

  async function verify() {
    const checksum = input.value.trim().toLowerCase();
    if (!checksum) return;

    if (!isHex64(checksum)) {
      result.innerHTML = '<div class="empty-state">Please enter a valid 64-character hex string (SHA-256)</div>';
      return;
    }

    result.innerHTML = '<div class="empty-state">Verifying...</div>';

    try {
      const res = await rpc.call('noble_verifyDocument', { checksum });

      if (!res.registered) {
        result.innerHTML = `
          <div style="padding:var(--gap-lg);text-align:center">
            <div style="font-size:2rem;color:var(--warning);margin-bottom:var(--gap)">&#9888;</div>
            <h3 style="color:var(--warning)">Not Found</h3>
            <p style="color:var(--text-secondary);margin-top:var(--gap-sm)">
              This checksum has not been registered on the NOBLE blockchain.
            </p>
            <p class="mono" style="color:var(--text-muted);font-size:var(--font-size-xs);margin-top:var(--gap)">${checksum}</p>
          </div>
        `;
        return;
      }

      let rows = '';
      for (const reg of res.registrations) {
        rows += `
          <tr class="clickable" data-txid="${reg.tx_id}">
            <td>${reg.block_height}</td>
            <td>${formatTimestamp(reg.timestamp)}</td>
            <td class="mono">${truncateHash(reg.tx_id)}</td>
          </tr>
        `;
      }

      result.innerHTML = `
        <div style="padding:var(--gap-lg);text-align:center;margin-bottom:var(--gap)">
          <div style="font-size:2rem;color:var(--success);margin-bottom:var(--gap)">&#10004;</div>
          <h3 style="color:var(--success)">Verified</h3>
          <p style="color:var(--text-secondary);margin-top:var(--gap-sm)">
            This document has been registered ${res.registrations.length} time(s) on the NOBLE blockchain.
          </p>
          <p style="color:var(--text-muted);font-size:var(--font-size-xs);margin-top:var(--gap-sm)">
            First seen: ${formatTimestamp(res.first_seen)}
          </p>
        </div>
        <table class="data-table">
          <thead><tr><th>Block Height</th><th>Timestamp</th><th>Transaction ID</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;

      result.querySelectorAll('tr.clickable').forEach(tr => {
        tr.addEventListener('click', () => {
          location.hash = `#/tx/${tr.dataset.txid}`;
        });
      });

    } catch (e) {
      result.innerHTML = `<div class="empty-state">Verification error: ${e.message || e}</div>`;
    }
  }

  btn.addEventListener('click', verify);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') verify(); });

  return { destroy() {} };
}
