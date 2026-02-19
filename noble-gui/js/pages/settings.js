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
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:var(--gap-sm) 0 0">
          TOTP rotation is available via the <code>noble_rotateTotpSecret</code> RPC method.
        </p>
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

  // Load data
  async function loadSettings() {
    try {
      const [ipResult, nodeInfo] = await Promise.all([
        rpc.call('noble_getAllowedIps'),
        rpc.call('noble_getNodeInfo'),
      ]);

      // IP Access Control
      allowedIps = ipResult.allowed_ips || [];
      renderIpList();
      updateBadge();

      // Auth status
      const hasAuth = rpc.hasAuthToken ? rpc.hasAuthToken() : false;
      totpStatus.textContent = hasAuth ? 'Active (authenticated)' : 'Not configured';
      authMode.textContent = hasAuth ? 'TOTP (SHA-256 hashed bearer token)' : 'None';

      // Ports
      portsEl.innerHTML = `
        <dt>RPC (JSON-RPC)</dt><dd>${nodeInfo.rpc_port}</dd>
        <dt>WebSocket</dt><dd>${nodeInfo.ws_port}</dd>
        <dt>P2P</dt><dd>${nodeInfo.p2p_port}</dd>
        <dt>Dashboard (GUI)</dt><dd>8785</dd>
      `;
    } catch (e) {
      console.error('[settings] load:', e);
    }
  }

  loadSettings();

  return {
    destroy() {},
  };
}
