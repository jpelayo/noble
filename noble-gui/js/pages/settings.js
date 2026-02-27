/**
 * NOBLE Dashboard — Settings Page
 * IP access control management and system configuration.
 */

export function init(root, ctx) {
  const { rpc } = ctx;

  root.innerHTML = `
    <div class="page-header">
      <h1>Settings</h1>
      <p>Node access control and configuration</p>
    </div>

    <!-- IP Access Control -->
    <div class="panel">
      <div class="panel-header">
        <span>IP Access Control</span>
        <span id="s-access-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Control which remote IPs can access the RPC and dashboard. <code>127.0.0.1</code> is always allowed.
          An empty list means localhost-only access.
        </p>

        <div id="s-ip-list" style="margin-bottom:var(--gap)"></div>

        <div style="display:flex;gap:var(--gap-sm);align-items:center;margin-bottom:var(--gap)">
          <input id="s-new-ip" type="text" placeholder="e.g. 192.168.1.0/24 or 10.0.0.5"
            style="flex:1;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
          <button id="s-add-ip" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm);white-space:nowrap">Add</button>
        </div>

        <div id="s-ip-error" style="color:var(--error);font-size:var(--font-size-xs);margin-bottom:var(--gap);display:none"></div>

        <div style="display:flex;gap:var(--gap-sm);align-items:center">
          <button id="s-save-ips" class="btn-sm" style="padding:6px 14px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Save Changes</button>
          <span id="s-save-msg" style="font-size:var(--font-size-xs);color:var(--text-muted)"></span>
        </div>

        <div style="margin-top:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);font-size:var(--font-size-xs);color:var(--text-muted)">
          <strong>Note:</strong> Switching between localhost-only (empty list) and remote access (non-empty list)
          requires a node restart because the bind address changes between <code>127.0.0.1</code> and <code>0.0.0.0</code>.
          Updating entries within an existing non-empty list takes effect immediately.
        </div>
      </div>
    </div>

    <!-- Authentication Status -->
    <div class="panel">
      <div class="panel-header">Authentication</div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-auth-info">
          <dt>TOTP Status</dt>
          <dd id="s-totp-status">--</dd>
          <dt>Auth Mode</dt>
          <dd id="s-auth-mode">--</dd>
        </dl>
        <!-- TOTP Rotation (shown only when TOTP is active) -->
        <div id="s-totp-rotate-section" style="display:none;margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Rotate TOTP Secret</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0 0 var(--gap-sm)">
            Enter your current 6-digit TOTP code to rotate the shared secret.
            The new secret will be displayed once — store it immediately.
          </p>
          <div style="display:flex;gap:var(--gap-sm);align-items:center;margin-bottom:var(--gap-sm)">
            <input id="s-totp-code" type="text" maxlength="6" placeholder="6-digit code"
              style="width:120px;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm);text-align:center">
            <button id="s-totp-rotate-btn" class="btn-sm" style="padding:6px 14px;background:var(--warning,#f0a500);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Rotate Secret</button>
          </div>
          <div id="s-totp-rotate-result" style="display:none;padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);font-size:var(--font-size-xs)"></div>
          <div id="s-totp-rotate-error" style="color:var(--error);font-size:var(--font-size-xs);display:none"></div>
        </div>
      </div>
    </div>

    <!-- Validator Key -->
    <div class="panel">
      <div class="panel-header">
        <span>Validator Key</span>
        <span id="s-vkey-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-vkey-details">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
      </div>
    </div>

    <!-- P2P Identity -->
    <div class="panel">
      <div class="panel-header">P2P Identity</div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-p2p-details">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
      </div>
    </div>

    <!-- Gateway Key -->
    <div class="panel">
      <div class="panel-header">
        <span>Gateway Key</span>
        <span id="s-gw-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-gw-details">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
      </div>
    </div>

    <!-- Node Ports -->
    <div class="panel">
      <div class="panel-header">Port Configuration</div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-ports">
        </dl>
      </div>
    </div>

    <!-- TLS Certificate -->
    <div class="panel">
      <div class="panel-header">
        <span>TLS Certificate</span>
        <span id="s-tls-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-tls-details"></dl>

        <div style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Regenerate Self-Signed Certificate</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0 0 var(--gap-sm)">
            Writes new certificate files to disk. <strong>Restart the node</strong> for the new cert to load.
          </p>
          <button id="s-tls-regen-btn" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Regenerate Certificate</button>
          <span id="s-tls-regen-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-sm)"></span>
        </div>

        <div style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Upload CA-Signed Certificate</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0 0 var(--gap-sm)">
            Replace the self-signed cert with a certificate from a trusted CA. Key must match the certificate.
            <strong>Restart the node</strong> after upload.
          </p>
          <div style="display:grid;gap:var(--gap-sm)">
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Certificate PEM (required)</label>
              <textarea id="s-tls-cert-pem" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;..."
                style="width:100%;box-sizing:border-box;padding:6px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"></textarea>
            </div>
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Private Key PEM (required)</label>
              <textarea id="s-tls-key-pem" rows="4" placeholder="-----BEGIN PRIVATE KEY-----&#10;..."
                style="width:100%;box-sizing:border-box;padding:6px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"></textarea>
            </div>
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Intermediate Chain PEM (optional)</label>
              <textarea id="s-tls-chain-pem" rows="3" placeholder="-----BEGIN CERTIFICATE-----&#10;... (optional intermediate/chain)"
                style="width:100%;box-sizing:border-box;padding:6px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"></textarea>
            </div>
            <div style="display:flex;align-items:center;gap:var(--gap-sm)">
              <button id="s-tls-upload-btn" class="btn-sm" style="padding:6px 14px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Upload &amp; Replace</button>
              <span id="s-tls-upload-msg" style="font-size:var(--font-size-xs);color:var(--text-muted)"></span>
            </div>
          </div>
          <div id="s-tls-upload-error" style="color:var(--error);font-size:var(--font-size-xs);margin-top:var(--gap-sm);display:none"></div>
        </div>
      </div>
    </div>
  `;

  // DOM refs
  const accessBadge = root.querySelector('#s-access-badge');
  const ipListEl = root.querySelector('#s-ip-list');
  const newIpInput = root.querySelector('#s-new-ip');
  const addBtn = root.querySelector('#s-add-ip');
  const errorEl = root.querySelector('#s-ip-error');
  const saveBtn = root.querySelector('#s-save-ips');
  const saveMsg = root.querySelector('#s-save-msg');
  const totpStatus = root.querySelector('#s-totp-status');
  const authMode = root.querySelector('#s-auth-mode');
  const portsEl = root.querySelector('#s-ports');
  // TOTP rotation refs
  const totpRotateSection = root.querySelector('#s-totp-rotate-section');
  const totpCodeInput = root.querySelector('#s-totp-code');
  const totpRotateBtn = root.querySelector('#s-totp-rotate-btn');
  const totpRotateResult = root.querySelector('#s-totp-rotate-result');
  const totpRotateError = root.querySelector('#s-totp-rotate-error');
  // Validator key refs
  const vkeyBadge = root.querySelector('#s-vkey-badge');
  const vkeyDetails = root.querySelector('#s-vkey-details');
  // P2P identity refs
  const p2pDetails = root.querySelector('#s-p2p-details');
  // Gateway key refs
  const gwBadge = root.querySelector('#s-gw-badge');
  const gwDetails = root.querySelector('#s-gw-details');
  // TLS cert refs
  const tlsBadge = root.querySelector('#s-tls-badge');
  const tlsDetails = root.querySelector('#s-tls-details');
  const tlsRegenBtn = root.querySelector('#s-tls-regen-btn');
  const tlsRegenMsg = root.querySelector('#s-tls-regen-msg');
  const tlsCertPem = root.querySelector('#s-tls-cert-pem');
  const tlsKeyPem = root.querySelector('#s-tls-key-pem');
  const tlsChainPem = root.querySelector('#s-tls-chain-pem');
  const tlsUploadBtn = root.querySelector('#s-tls-upload-btn');
  const tlsUploadMsg = root.querySelector('#s-tls-upload-msg');
  const tlsUploadError = root.querySelector('#s-tls-upload-error');

  let allowedIps = [];

  // Validate an IP or CIDR string
  function isValidIpOrCidr(str) {
    const trimmed = str.trim();
    if (!trimmed) return false;
    // Simple IPv4 pattern
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    // IPv4 with CIDR
    const ipv4Cidr = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    // IPv6 pattern (simplified)
    const ipv6 = /^[0-9a-fA-F:]+$/;
    // IPv6 with CIDR
    const ipv6Cidr = /^[0-9a-fA-F:]+\/\d{1,3}$/;
    return ipv4.test(trimmed) || ipv4Cidr.test(trimmed) || ipv6.test(trimmed) || ipv6Cidr.test(trimmed);
  }

  // Render the IP list
  function renderIpList() {
    if (allowedIps.length === 0) {
      ipListEl.innerHTML = `<div style="color:var(--text-muted);font-size:var(--font-size-sm);font-style:italic">No remote IPs configured (localhost-only access)</div>`;
      return;
    }
    ipListEl.innerHTML = allowedIps.map((ip, i) => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 8px;margin-bottom:2px;background:var(--bg-tertiary);border-radius:var(--radius-sm)">
        <code style="font-size:var(--font-size-sm)">${ip}</code>
        <button class="ip-remove" data-index="${i}" style="background:none;border:none;color:var(--error);cursor:pointer;font-size:var(--font-size-sm);padding:2px 6px" title="Remove">&times;</button>
      </div>
    `).join('');

    // Remove handlers
    ipListEl.querySelectorAll('.ip-remove').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.index);
        allowedIps.splice(idx, 1);
        renderIpList();
      });
    });
  }

  // Add new IP
  addBtn.addEventListener('click', () => {
    const value = newIpInput.value.trim();
    if (!value) return;
    if (!isValidIpOrCidr(value)) {
      errorEl.textContent = `Invalid IP or CIDR: "${value}"`;
      errorEl.style.display = 'block';
      return;
    }
    if (allowedIps.includes(value)) {
      errorEl.textContent = `"${value}" is already in the list`;
      errorEl.style.display = 'block';
      return;
    }
    errorEl.style.display = 'none';
    allowedIps.push(value);
    newIpInput.value = '';
    renderIpList();
  });

  newIpInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addBtn.click();
  });

  // Save
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    saveMsg.textContent = 'Saving...';
    errorEl.style.display = 'none';
    try {
      const result = await rpc.call('noble_setAllowedIps', { allowed_ips: allowedIps });
      saveMsg.textContent = result.message || 'Saved';
      saveMsg.style.color = 'var(--success)';
      updateBadge();
    } catch (e) {
      errorEl.textContent = e.message || 'Failed to save';
      errorEl.style.display = 'block';
      saveMsg.textContent = '';
    } finally {
      saveBtn.disabled = false;
      setTimeout(() => { saveMsg.textContent = ''; }, 5000);
    }
  });

  function updateBadge() {
    if (allowedIps.length > 0) {
      accessBadge.textContent = 'Remote Access Enabled';
      accessBadge.className = 'badge inbound';
    } else {
      accessBadge.textContent = 'Localhost Only';
      accessBadge.className = 'badge outbound';
    }
  }

  // --- TLS cert helpers ---
  function renderTlsCert(info) {
    if (!info || !info.enabled) {
      tlsBadge.textContent = 'TLS Disabled';
      tlsBadge.className = 'badge';
      tlsBadge.style.background = 'var(--text-muted)';
      tlsDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">TLS is not enabled on this node.</dt>';
      tlsRegenBtn.disabled = true;
      tlsUploadBtn.disabled = true;
      return;
    }
    tlsRegenBtn.disabled = false;
    tlsUploadBtn.disabled = false;

    if (info.plaintext_mode) {
      tlsBadge.textContent = 'Plaintext Fallback';
      tlsBadge.className = 'badge';
      tlsBadge.style.background = 'var(--error)';
    } else if (info.auto_generated) {
      tlsBadge.textContent = 'Self-Signed';
      tlsBadge.className = 'badge outbound';
      tlsBadge.style.background = '';
    } else {
      tlsBadge.textContent = 'CA-Signed';
      tlsBadge.className = 'badge inbound';
      tlsBadge.style.background = '';
    }

    // Expiry badge color
    let expiryHtml = '--';
    if (info.expires_at) {
      const days = info.days_remaining;
      let color = 'var(--success)';
      if (days !== null && days !== undefined) {
        if (days <= 0) color = 'var(--error)';
        else if (days <= 30) color = 'var(--error)';
        else if (days <= 90) color = 'var(--warning, #f0a500)';
        const label = days <= 0 ? 'EXPIRED' : `${days} days`;
        const dateStr = info.expires_at.replace('T', ' ').replace('Z', ' UTC').slice(0, 20);
        expiryHtml = `${dateStr} <span style="color:${color};font-weight:600">(${label})</span>`;
      } else {
        expiryHtml = info.expires_at;
      }
    }

    const fp = info.fingerprint || '';
    const fpDisplay = fp.length > 16 ? fp.slice(0, 8) + '…' + fp.slice(-8) : fp;
    const sanList = (info.sans || []).join(', ') || '--';

    tlsDetails.innerHTML = `
      <dt>Fingerprint (SHA-256)</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${fpDisplay}</code>
        ${fp ? `<button class="btn-copy-fp btn-sm" data-fp="${fp}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>` : ''}
      </dd>
      <dt>Expires</dt><dd>${expiryHtml}</dd>
      <dt>SANs</dt><dd style="font-size:var(--font-size-xs);word-break:break-all">${sanList}</dd>
    `;

    tlsDetails.querySelector('.btn-copy-fp')?.addEventListener('click', (e) => {
      const full = e.currentTarget.dataset.fp;
      navigator.clipboard?.writeText(full).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }

  tlsRegenBtn.addEventListener('click', async () => {
    tlsRegenBtn.disabled = true;
    tlsRegenMsg.style.color = 'var(--text-muted)';
    tlsRegenMsg.textContent = 'Regenerating...';
    try {
      const result = await rpc.call('noble_regenerateTlsCert', { extra_sans: [] });
      tlsRegenMsg.style.color = 'var(--success)';
      tlsRegenMsg.textContent = `Done — new fingerprint: ${result.fingerprint.slice(0, 16)}… Restart node to apply.`;
      // Refresh the cert panel to show updated info.
      loadTlsCert();
    } catch (e) {
      tlsRegenMsg.style.color = 'var(--error)';
      tlsRegenMsg.textContent = e.message || 'Regeneration failed';
    } finally {
      tlsRegenBtn.disabled = false;
    }
  });

  tlsUploadBtn.addEventListener('click', async () => {
    tlsUploadError.style.display = 'none';
    tlsUploadMsg.textContent = '';
    const certPem = tlsCertPem.value.trim();
    const keyPem = tlsKeyPem.value.trim();
    const chainPem = tlsChainPem.value.trim() || null;
    if (!certPem || !keyPem) {
      tlsUploadError.textContent = 'Certificate PEM and Private Key PEM are required.';
      tlsUploadError.style.display = 'block';
      return;
    }
    tlsUploadBtn.disabled = true;
    tlsUploadMsg.style.color = 'var(--text-muted)';
    tlsUploadMsg.textContent = 'Uploading...';
    try {
      const result = await rpc.call('noble_uploadTlsCert', { cert_pem: certPem, key_pem: keyPem, chain_pem: chainPem });
      tlsUploadMsg.style.color = 'var(--success)';
      tlsUploadMsg.textContent = `Uploaded — SHA-256: ${result.fingerprint.slice(0, 16)}… Restart node to apply.`;
      tlsCertPem.value = '';
      tlsKeyPem.value = '';
      tlsChainPem.value = '';
      loadTlsCert();
    } catch (e) {
      tlsUploadError.textContent = e.message || 'Upload failed';
      tlsUploadError.style.display = 'block';
      tlsUploadMsg.textContent = '';
    } finally {
      tlsUploadBtn.disabled = false;
    }
  });

  async function loadTlsCert() {
    try {
      const info = await rpc.call('noble_getTlsCertInfo');
      renderTlsCert(info);
    } catch {
      tlsDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Unable to load TLS certificate info.</dt>';
    }
  }

  // --- TOTP Rotation ---
  totpRotateBtn.addEventListener('click', async () => {
    totpRotateError.style.display = 'none';
    totpRotateResult.style.display = 'none';
    const code = totpCodeInput.value.trim();
    if (code.length !== 6 || !/^\d{6}$/.test(code)) {
      totpRotateError.textContent = 'Enter a valid 6-digit TOTP code.';
      totpRotateError.style.display = 'block';
      return;
    }
    totpRotateBtn.disabled = true;
    try {
      // Hash the 6-digit code with SHA-256 (matching the middleware expectation).
      const encoder = new TextEncoder();
      const codeBytes = encoder.encode(code);
      const hashBuf = await crypto.subtle.digest('SHA-256', codeBytes);
      const hashHex = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      const result = await rpc.call('noble_rotateTotpSecret', { current_code_hash: hashHex });

      // Show new secret with auto-clear timer.
      let countdown = 60;
      let timerHandle;
      function showSecret() {
        totpRotateResult.style.display = 'block';
        totpRotateResult.style.color = 'var(--success)';
        totpRotateResult.innerHTML = `
          <p style="margin:0 0 var(--gap-xs);font-weight:600">New TOTP Secret (clears in <span id="s-totp-countdown">${countdown}s</span>)</p>
          <p style="margin:0 0 var(--gap-xs)"><strong>Base32:</strong> <code>${result.secret_base32}</code></p>
          <p style="margin:0;word-break:break-all"><strong>otpauth:</strong> <code style="font-size:10px">${result.otpauth_uri}</code></p>
        `;
        timerHandle = setInterval(() => {
          countdown--;
          const countEl = totpRotateResult.querySelector('#s-totp-countdown');
          if (countEl) countEl.textContent = countdown + 's';
          if (countdown <= 0) {
            clearInterval(timerHandle);
            totpRotateResult.style.display = 'none';
            totpRotateResult.innerHTML = '';
          }
        }, 1000);
      }
      showSecret();
      totpCodeInput.value = '';
    } catch (e) {
      totpRotateError.textContent = e.message || 'Rotation failed';
      totpRotateError.style.display = 'block';
    } finally {
      totpRotateBtn.disabled = false;
    }
  });

  // --- Validator Key card ---
  function renderValidatorKey(info) {
    if (!info || !info.enabled) {
      vkeyBadge.textContent = 'Observer Mode';
      vkeyBadge.className = 'badge';
      vkeyBadge.style.background = 'var(--text-muted)';
      vkeyDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Node is running in observer mode — no validator key configured.</dt>';
      return;
    }
    vkeyBadge.textContent = 'Active';
    vkeyBadge.className = 'badge inbound';
    vkeyBadge.style.background = '';

    const pk = info.pubkey_hex || '';
    const pkDisplay = pk.length > 16 ? pk.slice(0, 8) + '…' + pk.slice(-8) : pk;

    vkeyDetails.innerHTML = `
      <dt>Public Key</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${pkDisplay}</code>
        ${pk ? `<button class="btn-copy-vkey btn-sm" data-pk="${pk}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>` : ''}
      </dd>
      <dt>Scheme</dt><dd>${info.scheme || '--'}</dd>
      <dt>Key Path</dt><dd style="font-size:var(--font-size-xs);word-break:break-all">${info.key_path || '--'}</dd>
    `;
    vkeyDetails.querySelector('.btn-copy-vkey')?.addEventListener('click', (e) => {
      const full = e.currentTarget.dataset.pk;
      navigator.clipboard?.writeText(full).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }

  // --- P2P Identity card ---
  function renderP2pIdentity(nodeInfo) {
    const peerId = (nodeInfo && nodeInfo.peer_id) || '';
    if (!peerId) {
      p2pDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Peer ID not available.</dt>';
      return;
    }
    const peerIdDisplay = peerId.length > 20 ? peerId.slice(0, 12) + '…' + peerId.slice(-8) : peerId;
    p2pDetails.innerHTML = `
      <dt>Peer ID</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${peerIdDisplay}</code>
        <button class="btn-copy-peerid btn-sm" data-pid="${peerId}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>
      </dd>
    `;
    p2pDetails.querySelector('.btn-copy-peerid')?.addEventListener('click', (e) => {
      navigator.clipboard?.writeText(e.currentTarget.dataset.pid).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }

  // --- Gateway Key card ---
  function renderGatewayKey(info) {
    if (!info || !info.enabled) {
      gwBadge.textContent = 'Disabled';
      gwBadge.className = 'badge';
      gwBadge.style.background = 'var(--text-muted)';
      gwDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Gateway fee split is not configured.</dt>';
      return;
    }
    gwBadge.textContent = 'Enabled';
    gwBadge.className = 'badge inbound';
    gwBadge.style.background = '';

    const gk = info.gateway_key || '';
    const gkDisplay = gk.length > 16 ? gk.slice(0, 8) + '…' + gk.slice(-8) : gk;
    const sourceLabel = info.key_source === 'config_file' ? 'key file' : 'wallet-derived';

    gwDetails.innerHTML = `
      <dt>Gateway Key</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${gkDisplay}</code>
        ${gk ? `<button class="btn-copy-gk btn-sm" data-gk="${gk}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>` : ''}
      </dd>
      <dt>Source</dt><dd>${sourceLabel}</dd>
    `;
    gwDetails.querySelector('.btn-copy-gk')?.addEventListener('click', (e) => {
      navigator.clipboard?.writeText(e.currentTarget.dataset.gk).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }

  // Load data
  async function loadSettings() {
    // Load TLS cert info in parallel (independent from other calls).
    loadTlsCert();

    try {
      const [ipResult, nodeInfo, vkeyInfo, gwInfo] = await Promise.all([
        rpc.call('noble_getAllowedIps'),
        rpc.call('noble_getNodeInfo'),
        rpc.call('noble_getValidatorKeyInfo').catch(() => null),
        rpc.call('noble_getGatewayInfo').catch(() => null),
      ]);

      // IP Access Control
      allowedIps = ipResult.allowed_ips || [];
      renderIpList();
      updateBadge();

      // Auth status + TOTP rotation button
      const hasAuth = rpc.hasAuthToken ? rpc.hasAuthToken() : false;
      totpStatus.textContent = hasAuth ? 'Active (authenticated)' : 'Not configured';
      authMode.textContent = hasAuth ? 'TOTP (SHA-256 hashed bearer token)' : 'None';
      if (hasAuth) {
        totpRotateSection.style.display = 'block';
      }

      // Ports
      portsEl.innerHTML = `
        <dt>RPC (JSON-RPC)</dt><dd>${nodeInfo.rpc_port}</dd>
        <dt>WebSocket</dt><dd>${nodeInfo.ws_port}</dd>
        <dt>P2P</dt><dd>${nodeInfo.p2p_port}</dd>
        <dt>Dashboard (GUI)</dt><dd>8785</dd>
      `;

      // New key/identity cards
      renderValidatorKey(vkeyInfo);
      renderP2pIdentity(nodeInfo);
      renderGatewayKey(gwInfo);
    } catch (e) {
      console.error('[settings] load:', e);
    }
  }

  loadSettings();

  return {
    destroy() {},
  };
}
