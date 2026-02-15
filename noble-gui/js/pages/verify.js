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
        const locatorBadge = reg.has_encrypted_locator
          ? `<span style="display:inline-block;padding:2px 6px;border-radius:3px;font-size:var(--font-size-xs);background:var(--info,#3b82f6);color:#fff">Locator (${reg.locator_recipient_count})</span>`
          : '';
        const attestBadge = reg.attestation_count > 0
          ? `<span style="display:inline-block;padding:2px 6px;border-radius:3px;font-size:var(--font-size-xs);background:var(--accent);color:#fff;margin-left:4px">${reg.attestation_count} Attest.</span>`
          : '';
        rows += `
          <tr class="clickable" data-txid="${reg.tx_id}">
            <td>${reg.block_height}</td>
            <td>${formatTimestamp(reg.timestamp)}</td>
            <td class="mono">${truncateHash(reg.tx_id)}</td>
            <td>${locatorBadge}${attestBadge}</td>
          </tr>
        `;
      }

      // Build attestation detail rows if any registrations have them
      let attestationSection = '';
      const regsWithAttestations = res.registrations.filter(r => r.attestations && r.attestations.length > 0);
      if (regsWithAttestations.length > 0) {
        let attestRows = '';
        for (const reg of regsWithAttestations) {
          for (const att of reg.attestations) {
            attestRows += `
              <tr>
                <td class="mono">${truncateHash(reg.tx_id)}</td>
                <td>${att.scheme.toUpperCase()}</td>
                <td>${att.scope}</td>
                <td class="mono">${truncateHash(att.signer_fingerprint)}</td>
                <td>${att.signature_size} bytes</td>
              </tr>
            `;
          }
        }
        attestationSection = `
          <div style="margin-top:var(--gap-lg)">
            <h4 style="margin-bottom:var(--gap-sm)">External Attestations</h4>
            <table class="data-table">
              <thead><tr><th>Transaction</th><th>Scheme</th><th>Scope</th><th>Signer Fingerprint</th><th>Signature</th></tr></thead>
              <tbody>${attestRows}</tbody>
            </table>
          </div>
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
          <thead><tr><th>Block Height</th><th>Timestamp</th><th>Transaction ID</th><th>Privacy</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        ${attestationSection}
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
