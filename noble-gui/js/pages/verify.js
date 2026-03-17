/**
 * NOBLE Dashboard — Document Verification Page
 * Three tabs: Verify by Checksum | Decrypt Locator | Search by Issuer
 */

import { truncateHash, formatTimestamp, isHex64 } from '../utils.js';

export function init(root, ctx) {
  const { rpc, params } = ctx;

  // Determine initial tab from query params
  const initialTab = params.tab === 'locator' ? 'locator'
    : params.tab === 'author' ? 'author'
    : params.tab === 'issuer' ? 'issuer'
    : 'checksum';
  const prefillChecksum = params.checksum || '';
  const prefillTx = params.tx || '';
  const prefillIssuer = params.issuer || '';

  root.innerHTML = `
    <div class="page-header">
      <h1>Document Verification</h1>
      <p>Verify document integrity, decrypt locators, or search by issuer</p>
    </div>

    <div class="verify-tabs" style="display:flex;gap:0;margin-bottom:var(--gap-lg);border-bottom:2px solid var(--border)">
      <button class="verify-tab" data-tab="checksum" style="padding:var(--gap-sm) var(--gap);border:none;background:none;cursor:pointer;font-size:var(--font-size-sm);font-weight:600;color:var(--text-secondary);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.15s">Verify by Checksum</button>
      <button class="verify-tab" data-tab="locator" style="padding:var(--gap-sm) var(--gap);border:none;background:none;cursor:pointer;font-size:var(--font-size-sm);font-weight:600;color:var(--text-secondary);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.15s">Decrypt Locator</button>
      <button class="verify-tab" data-tab="author" style="padding:var(--gap-sm) var(--gap);border:none;background:none;cursor:pointer;font-size:var(--font-size-sm);font-weight:600;color:var(--text-secondary);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.15s">Search by Author</button>
      <button class="verify-tab" data-tab="issuer" style="padding:var(--gap-sm) var(--gap);border:none;background:none;cursor:pointer;font-size:var(--font-size-sm);font-weight:600;color:var(--text-secondary);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.15s">Search by Issuer</button>
    </div>

    <!-- Checksum tab -->
    <div id="tab-checksum" class="verify-tab-content">
      <div class="panel">
        <div class="panel-header">Check Document Checksum</div>
        <div class="panel-body">
          <div class="search-bar">
            <input type="text" id="verify-input" placeholder="Paste SHA-256 checksum (64-char hex)..." value="${esc(prefillChecksum)}" />
            <button id="verify-btn">Verify</button>
          </div>
          <div id="verify-result"></div>
        </div>
      </div>
    </div>

    <!-- Locator tab -->
    <div id="tab-locator" class="verify-tab-content" style="display:none">
      <div class="panel">
        <div class="panel-header">Decrypt Encrypted Locator</div>
        <div class="panel-body">
          <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)">
            Enter the Transaction ID of a transaction containing an encrypted locator. If you are an authorized recipient, the locator will be decrypted.
          </p>
          <div class="search-bar">
            <input type="text" id="locator-input" placeholder="Transaction ID (64-char hex)..." value="${esc(prefillTx)}" />
            <button id="locator-btn">Decrypt</button>
          </div>
          <div id="locator-result"></div>
        </div>
      </div>
    </div>

    <!-- Author tab -->
    <div id="tab-author" class="verify-tab-content" style="display:none">
      <div class="panel">
        <div class="panel-header">Search Documents by Author or Publisher</div>
        <div class="panel-body">
          <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)">
            Enter an author or publisher name to find all documents they have registered. Searches the <code>author</code> and <code>publisher</code> metadata fields.
          </p>
          <div class="search-bar">
            <input type="text" id="author-input" placeholder="Author or publisher name..." />
            <button id="author-btn">Search</button>
          </div>
          <div id="author-result"></div>
        </div>
      </div>
    </div>

    <!-- Issuer tab -->
    <div id="tab-issuer" class="verify-tab-content" style="display:none">
      <div class="panel">
        <div class="panel-header">Search Documents by Issuer</div>
        <div class="panel-body">
          <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)">
            Enter an issuer's public key (hex) to find all documents they have registered on the NOBLE blockchain.
          </p>
          <div class="search-bar">
            <input type="text" id="issuer-input" placeholder="Issuer public key (hex)..." value="${esc(prefillIssuer)}" />
            <button id="issuer-btn">Search</button>
          </div>
          <div id="issuer-result"></div>
        </div>
      </div>
    </div>
  `;

  // ── Tab switching ──
  const tabs = root.querySelectorAll('.verify-tab');
  const tabContents = {
    checksum: root.querySelector('#tab-checksum'),
    locator: root.querySelector('#tab-locator'),
    author: root.querySelector('#tab-author'),
    issuer: root.querySelector('#tab-issuer'),
  };

  function switchTab(name) {
    for (const [key, el] of Object.entries(tabContents)) {
      el.style.display = key === name ? 'block' : 'none';
    }
    tabs.forEach(t => {
      const active = t.dataset.tab === name;
      t.style.color = active ? 'var(--accent)' : 'var(--text-secondary)';
      t.style.borderBottomColor = active ? 'var(--accent)' : 'transparent';
    });
  }

  tabs.forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));
  switchTab(initialTab);

  // ── Checksum verification ──
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

      // ── Inline version chain from enriched response ──
      if (res.version_chain && res.version_chain.length > 1) {
        const versionDiv = document.createElement('div');
        versionDiv.style.marginTop = 'var(--gap-lg)';
        let versionRows = '';
        for (const v of res.version_chain) {
          const isCurrent = v.checksum === checksum;
          versionRows += `
            <tr class="${isCurrent ? '' : 'clickable'}" data-txid="${v.tx_id}" style="${isCurrent ? 'background:var(--bg-tertiary)' : ''}">
              <td>${v.version || '—'}</td>
              <td>${v.block_height}</td>
              <td>${formatTimestamp(v.timestamp)}</td>
              <td class="mono">${truncateHash(v.checksum)}</td>
              <td class="mono">${truncateHash(v.tx_id)}</td>
              <td>${isCurrent ? '<span class="badge confirmed">Current</span>' : ''}</td>
            </tr>
          `;
        }
        versionDiv.innerHTML = `
          <h4 style="margin-bottom:var(--gap-sm)">Version Chain (${res.version_chain.length} version${res.version_chain.length > 1 ? 's' : ''})</h4>
          <table class="data-table">
            <thead><tr><th>Ver.</th><th>Block</th><th>Timestamp</th><th>Checksum</th><th>Transaction</th><th></th></tr></thead>
            <tbody>${versionRows}</tbody>
          </table>
        `;
        result.appendChild(versionDiv);

        versionDiv.querySelectorAll('tr.clickable').forEach(tr => {
          tr.addEventListener('click', () => {
            location.hash = `#/tx/${tr.dataset.txid}`;
          });
        });
      }

    } catch (e) {
      result.innerHTML = `<div class="empty-state">Verification error: ${e.message || e}</div>`;
    }
  }

  btn.addEventListener('click', verify);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') verify(); });

  // Auto-verify if checksum was prefilled via query param
  if (prefillChecksum && isHex64(prefillChecksum)) {
    verify();
  }

  // ── Locator decryption ──
  const locatorInput = root.querySelector('#locator-input');
  const locatorBtn = root.querySelector('#locator-btn');
  const locatorResult = root.querySelector('#locator-result');

  async function decryptLocator() {
    const txId = locatorInput.value.trim().toLowerCase();
    if (!txId) return;

    if (!isHex64(txId)) {
      locatorResult.innerHTML = '<div class="empty-state">Please enter a valid 64-character hex Transaction ID</div>';
      return;
    }

    locatorResult.innerHTML = '<div class="empty-state">Decrypting...</div>';

    try {
      const res = await rpc.call('noble_decryptLocator', { tx_id: txId });

      if (!res.success) {
        const reason = res.error === 'unauthorized'
          ? 'You are not a recipient of this locator'
          : res.error === 'no_locator'
            ? 'This transaction does not contain an encrypted locator'
            : (res.error || 'Decryption failed');
        locatorResult.innerHTML = `
          <div style="padding:var(--gap-lg);text-align:center">
            <div style="font-size:2rem;color:var(--warning);margin-bottom:var(--gap)">&#9888;</div>
            <h3 style="color:var(--warning)">${esc(reason)}</h3>
            <p class="mono" style="color:var(--text-muted);font-size:var(--font-size-xs);margin-top:var(--gap)">${txId}</p>
          </div>
        `;
        return;
      }

      // Successful decryption
      const meta = res.locator_metadata || {};
      locatorResult.innerHTML = `
        <div style="padding:var(--gap-lg);text-align:center;margin-bottom:var(--gap)">
          <div style="font-size:2rem;color:var(--success);margin-bottom:var(--gap)">&#128274;</div>
          <h3 style="color:var(--success)">Locator Decrypted</h3>
        </div>
        <div style="padding:var(--gap);background:var(--bg-tertiary);border-radius:var(--radius);border:1px solid var(--border);margin-bottom:var(--gap)">
          <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap-xs)">Document Location</div>
          <div class="mono" style="font-size:var(--font-size-sm);word-break:break-all;padding:var(--gap-sm);background:var(--bg-primary);border-radius:var(--radius-sm)">${esc(res.plaintext)}</div>
          <div style="display:flex;gap:var(--gap-sm);margin-top:var(--gap-sm)">
            <button class="btn btn-sm" id="locator-copy">Copy</button>
            <a href="${esc(res.plaintext)}" target="_blank" rel="noopener" class="btn btn-sm btn-secondary" id="locator-open">Open</a>
          </div>
        </div>
        <div style="margin-top:var(--gap)">
          <div style="font-size:var(--font-size-xs);font-weight:600;text-transform:uppercase;color:var(--text-muted);margin-bottom:var(--gap-sm)">Locator Metadata</div>
          <dl class="detail-grid">
            <dt>Has Locator</dt><dd>${meta.has_locator !== undefined ? (meta.has_locator ? 'Yes' : 'No') : 'Yes'}</dd>
            <dt>Recipients</dt><dd>${meta.recipient_count || 'N/A'}</dd>
            <dt>Encryption</dt><dd>${esc(meta.encryption_scheme || 'ECIES-X25519')}</dd>
            <dt>Transaction</dt><dd class="mono"><a href="#/tx/${txId}">${truncateHash(txId)}</a></dd>
          </dl>
        </div>
      `;

      // Copy button
      const copyBtn = root.querySelector('#locator-copy');
      if (copyBtn) {
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(res.plaintext).then(() => {
            copyBtn.textContent = 'Copied!';
            setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
          });
        });
      }

    } catch (e) {
      locatorResult.innerHTML = `<div class="empty-state">Decryption error: ${e.message || e}</div>`;
    }
  }

  locatorBtn.addEventListener('click', decryptLocator);
  locatorInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') decryptLocator(); });

  // Auto-decrypt if tx was prefilled via query param
  if (prefillTx && isHex64(prefillTx)) {
    decryptLocator();
  }

  // ── Issuer search ──
  const issuerInput = root.querySelector('#issuer-input');
  const issuerBtn = root.querySelector('#issuer-btn');
  const issuerResult = root.querySelector('#issuer-result');

  async function searchIssuer() {
    const pubkey = issuerInput.value.trim();
    if (!pubkey) return;

    if (!/^[0-9a-fA-F]{64,68}$/.test(pubkey)) {
      issuerResult.innerHTML = '<div class="empty-state">Please enter a valid hex public key (64-68 characters)</div>';
      return;
    }

    issuerResult.innerHTML = '<div class="empty-state">Searching...</div>';

    try {
      const res = await rpc.call('noble_getDocumentsByIssuer', { public_key: pubkey });

      if (!res.documents || res.documents.length === 0) {
        issuerResult.innerHTML = `
          <div style="padding:var(--gap-lg);text-align:center">
            <div style="font-size:2rem;color:var(--text-muted);margin-bottom:var(--gap)">&#128269;</div>
            <h3 style="color:var(--text-secondary)">No Documents Found</h3>
            <p style="color:var(--text-muted);font-size:var(--font-size-sm);margin-top:var(--gap-sm)">
              No notarizations found for this issuer key.
            </p>
          </div>
        `;
        return;
      }

      let rows = '';
      for (const doc of res.documents) {
        rows += `
          <tr class="clickable" data-txid="${doc.tx_id}">
            <td>${doc.block_height}</td>
            <td>${formatTimestamp(doc.timestamp)}</td>
            <td class="mono">${truncateHash(doc.checksum)}</td>
            <td class="mono">${truncateHash(doc.tx_id)}</td>
            <td>${doc.version || '—'}</td>
          </tr>
        `;
      }

      issuerResult.innerHTML = `
        <div style="padding:var(--gap);text-align:center;margin-bottom:var(--gap)">
          <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">
            Found <strong>${res.count}</strong> document(s) by this issuer
          </p>
        </div>
        <table class="data-table">
          <thead><tr><th>Block</th><th>Timestamp</th><th>Checksum</th><th>Transaction</th><th>Version</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;

      issuerResult.querySelectorAll('tr.clickable').forEach(tr => {
        tr.addEventListener('click', () => {
          location.hash = `#/tx/${tr.dataset.txid}`;
        });
      });

    } catch (e) {
      issuerResult.innerHTML = `<div class="empty-state">Search error: ${e.message || e}</div>`;
    }
  }

  issuerBtn.addEventListener('click', searchIssuer);
  issuerInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') searchIssuer(); });

  // Auto-search if issuer was prefilled via query param
  if (prefillIssuer) {
    searchIssuer();
  }

  // ── Author / publisher metadata search ──
  const authorInput = root.querySelector('#author-input');
  const authorBtn = root.querySelector('#author-btn');
  const authorResult = root.querySelector('#author-result');

  async function searchAuthor() {
    const name = authorInput.value.trim();
    if (!name) return;

    authorResult.innerHTML = '<div class="empty-state">Searching...</div>';

    try {
      // Search both "author" and "publisher" metadata keys.
      const [authorRes, pubRes] = await Promise.all([
        rpc.call('noble_searchDocumentsByMetadata', { key: 'author', value: name }),
        rpc.call('noble_searchDocumentsByMetadata', { key: 'publisher', value: name }),
      ]);

      // Merge and deduplicate by tx_id.
      const seen = new Set();
      const docs = [];
      for (const doc of [...(authorRes.documents || []), ...(pubRes.documents || [])]) {
        if (!seen.has(doc.tx_id)) {
          seen.add(doc.tx_id);
          docs.push(doc);
        }
      }

      if (docs.length === 0) {
        authorResult.innerHTML = `
          <div style="padding:var(--gap-lg);text-align:center">
            <div style="font-size:2rem;color:var(--text-muted);margin-bottom:var(--gap)">&#128269;</div>
            <h3 style="color:var(--text-secondary)">No Documents Found</h3>
            <p style="color:var(--text-muted);font-size:var(--font-size-sm);margin-top:var(--gap-sm)">
              No documents found with author or publisher matching "${esc(name)}".
            </p>
          </div>
        `;
        return;
      }

      let rows = '';
      for (const doc of docs) {
        rows += `
          <tr class="clickable" data-txid="${doc.tx_id}">
            <td>${doc.block_height}</td>
            <td>${formatTimestamp(doc.timestamp)}</td>
            <td class="mono">${truncateHash(doc.checksum)}</td>
            <td class="mono">${truncateHash(doc.tx_id)}</td>
            <td>${doc.version || '\u2014'}</td>
          </tr>
        `;
      }

      authorResult.innerHTML = `
        <div style="padding:var(--gap);text-align:center;margin-bottom:var(--gap)">
          <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">
            Found <strong>${docs.length}</strong> document(s) by "${esc(name)}"
          </p>
        </div>
        <table class="data-table">
          <thead><tr><th>Block</th><th>Timestamp</th><th>Checksum</th><th>Transaction</th><th>Version</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;

      authorResult.querySelectorAll('tr.clickable').forEach(tr => {
        tr.addEventListener('click', () => {
          location.hash = `#/tx/${tr.dataset.txid}`;
        });
      });

    } catch (e) {
      authorResult.innerHTML = `<div class="empty-state">Search error: ${e.message || e}</div>`;
    }
  }

  authorBtn.addEventListener('click', searchAuthor);
  authorInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') searchAuthor(); });

  return { destroy() {} };
}

/** Escape HTML to prevent XSS */
function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
