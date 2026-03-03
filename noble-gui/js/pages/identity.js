/**
 * NOBLE Dashboard — Node Identity Page
 * Self-identification configuration and peer identity directory
 */

import { formatNumber } from '../utils.js';
import { countrySelectHtml } from '../countries.js';

const GOV_CLASSES = {
  individual: { label: 'Individual', color: '#6b7280' },
  private: { label: 'Private', color: '#3b82f6' },
  public: { label: 'Public', color: '#ef4444' },
};

const ORG_TYPES = {
  individual: ['Individual'],
  private: ['PrivateNonProfit', 'PrivateCorporation', 'PrivateStartup', 'PrivateAcademic', 'PrivateInstitution'],
  public: ['PublicNational', 'PublicRegional', 'PublicSupranational', 'PublicCorporation', 'PublicAcademic', 'PublicInstitution'],
};

const ORG_TYPE_LABELS = {
  Individual: 'Individual',
  PrivateNonProfit: 'Fully privately funded non-profit institution or NGO',
  PrivateCorporation: 'Fully privately funded for-profit corporation',
  PrivateStartup: 'Fully privately funded for-profit startup',
  PrivateAcademic: 'Fully privately funded for-profit academic institution',
  PrivateInstitution: 'Fully privately funded for-profit institution',
  PublicNational: 'National public administration entity',
  PublicRegional: 'Regional or municipal public administration entity',
  PublicSupranational: 'Publicly funded supranational organization',
  PublicCorporation: 'Publicly funded corporation or startup',
  PublicAcademic: 'Publicly funded academic institution',
  PublicInstitution: 'Publicly funded institution or NGO',
};

const NODE_ROLE_COMPOSITE = [
  { value: 'Validator',       label: 'Full Node Validator — produces blocks and votes',         role: 'Validator',   validate: true,  vote: true  },
  { value: 'BlockProducer',   label: 'Full Node Block Producer — produces blocks, no voting',   role: 'Validator',   validate: true,  vote: false },
  { value: 'VoterNode',       label: 'Full Node Voter — votes on candidates, no production',    role: 'FullNode',    validate: false, vote: true  },
  { value: 'FullNode',        label: 'Full Node Observer — no consensus participation',         role: 'FullNode',    validate: false, vote: false },
  { value: 'ArchiveNode',     label: 'Archive Node — full history, no consensus',               role: 'ArchiveNode', validate: false, vote: false },
  { value: 'Gateway',         label: 'Gateway — transaction relay, no consensus',               role: 'Gateway',     validate: false, vote: false },
  { value: 'VotingGateway',   label: 'Voting Gateway — transaction relay and votes',            role: 'Gateway',     validate: false, vote: true  },
  { value: 'LightClient',     label: 'Light Client — minimal, no consensus',                    role: 'LightClient', validate: false, vote: false },
];

function govClassForOrgType(orgType) {
  for (const [cls, types] of Object.entries(ORG_TYPES)) {
    if (types.includes(orgType)) return cls;
  }
  return 'individual';
}

function govBadge(govClass) {
  const info = GOV_CLASSES[govClass] || GOV_CLASSES.individual;
  return `<span class="gov-badge" style="background:${info.color};color:#fff">${info.label}</span>`;
}

function orgTypeLabel(orgType) {
  return ORG_TYPE_LABELS[orgType] || orgType.replace(/([A-Z])/g, ' $1').trim();
}

function buildOrgTypeOptions(selected) {
  let html = '';
  for (const [group, types] of Object.entries(ORG_TYPES)) {
    const label = GOV_CLASSES[group]?.label || group;
    html += `<optgroup label="${label}">`;
    for (const t of types) {
      const sel = t === selected ? ' selected' : '';
      html += `<option value="${t}"${sel}>${orgTypeLabel(t)}</option>`;
    }
    html += '</optgroup>';
  }
  return html;
}

function buildCompositeRoleOptions(role, validate, vote) {
  const match = NODE_ROLE_COMPOSITE.find(c =>
    c.role === role && c.validate === validate && c.vote === vote
  ) || NODE_ROLE_COMPOSITE.find(c => c.role === role) || NODE_ROLE_COMPOSITE[3];
  return NODE_ROLE_COMPOSITE.map(c => {
    const sel = c.value === match.value ? ' selected' : '';
    return `<option value="${c.value}"${sel}>${c.label}</option>`;
  }).join('');
}

export function init(root, ctx) {
  const { rpc } = ctx;
  const unsubs = [];

  root.innerHTML = `
    <div class="page-header"><h1>Node Identity</h1><p>Self-identification for PoR reputation</p></div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">My Node Identity</div>
        <div class="panel-body">
          <form id="id-form" class="identity-form">
            <div class="form-group">
              <label for="id-node-name">Node Name</label>
              <input type="text" id="id-node-name" maxlength="64" placeholder="e.g. my-noble-node">
            </div>
            <div class="form-group">
              <label for="id-org-type">Organization Type</label>
              <div class="select-with-badge">
                <select id="id-org-type"></select>
                <span id="id-gov-badge"></span>
              </div>
            </div>
            <div class="form-group">
              <label for="id-org-name">Organization Name</label>
              <input type="text" id="id-org-name" maxlength="128" placeholder="Optional">
            </div>
            <div class="form-group">
              <label for="id-node-role">Node Role</label>
              <select id="id-node-role"></select>
            </div>
            <div class="form-group">
              <label for="id-email">Contact Email (optional)</label>
              <input type="email" id="id-email" placeholder="Optional">
              <small class="form-hint warning-hint">This email will be publicly broadcast to all network peers via GossipSub. Consider using an alias or generic address (e.g. nodes@yourdomain.com).</small>
            </div>
            <div class="form-group">
              <label for="id-website">Website</label>
              <input type="url" id="id-website" placeholder="Optional">
            </div>
            <div class="form-group">
              <label>Host Address</label>
              <div style="display:flex;align-items:center;gap:var(--gap-md);margin-bottom:var(--gap-sm);flex-wrap:wrap">
                <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:var(--font-size-sm)">
                  <input type="radio" name="host-mode" value="ip" checked> Public IP
                </label>
                <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:var(--font-size-sm)">
                  <input type="radio" name="host-mode" value="lan"> LAN IP
                </label>
                <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:var(--font-size-sm)">
                  <input type="radio" name="host-mode" value="dns"> DNS Hostname
                </label>
              </div>
              <div id="id-host-ip-row" style="display:flex;gap:var(--gap-sm)">
                <input type="text" id="id-host-ip" placeholder="e.g. 203.0.113.42" style="flex:1">
                <button type="button" class="btn btn-sm" id="id-detect-host">Detect</button>
              </div>
              <div id="id-host-lan-row" style="display:none;flex-direction:column;gap:var(--gap-sm)">
                <input type="text" id="id-host-lan" placeholder="e.g. 192.168.1.100">
                <small class="form-hint" style="margin:0">For local testnet only. Not reachable from the internet.</small>
              </div>
              <div id="id-host-dns-row" style="display:none">
                <input type="text" id="id-host-dns" placeholder="e.g. noble.example.com">
              </div>
              <small class="form-hint">Address broadcast to peers. "Detect" queries your external IP via ipinfo.io and others.</small>
              <input type="hidden" id="id-host">
            </div>
            <div class="form-group">
              <label for="id-country">Country</label>
              ${countrySelectHtml('id-country')}
            </div>
            <button type="submit" class="btn btn-primary" id="id-save">Save &amp; Broadcast</button>
            <span id="id-status" class="form-status"></span>
          </form>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">Network Peers Identity</div>
        <div class="panel-body" style="padding:0">
          <table class="data-table">
            <thead>
              <tr>
                <th>Peer</th>
                <th>Node Name</th>
                <th>Org Type</th>
                <th>Gov. Class</th>
                <th>Role</th>
                <th>PKI</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody id="id-peers"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">My Public Keys</div>
      <div class="panel-body" id="id-keys-body">
        <p style="color:var(--text-secondary)">Loading keys...</p>
      </div>
    </div>

    <div class="panel" id="pki-panel">
      <div class="panel-header">PKI Identity</div>
      <div class="panel-body" id="pki-body">
        <!-- Populated by JS -->
      </div>
    </div>

    <div id="id-peer-detail" class="panel" style="display:none">
      <div class="panel-header">Peer Details</div>
      <div class="panel-body">
        <dl class="detail-grid" id="id-peer-dl"></dl>
      </div>
    </div>
  `;

  const form = root.querySelector('#id-form');
  const orgTypeSelect = root.querySelector('#id-org-type');
  const nodeRoleSelect = root.querySelector('#id-node-role');
  const govBadgeEl = root.querySelector('#id-gov-badge');
  const statusEl = root.querySelector('#id-status');
  const peersBody = root.querySelector('#id-peers');
  const peerDetail = root.querySelector('#id-peer-detail');
  const peerDl = root.querySelector('#id-peer-dl');
  function updateGovBadge() {
    const cls = govClassForOrgType(orgTypeSelect.value);
    govBadgeEl.innerHTML = govBadge(cls);
  }

  orgTypeSelect.addEventListener('change', updateGovBadge);

  // Host address mode toggle
  const hostIpRow = root.querySelector('#id-host-ip-row');
  const hostLanRow = root.querySelector('#id-host-lan-row');
  const hostDnsRow = root.querySelector('#id-host-dns-row');
  const hostIpInput = root.querySelector('#id-host-ip');
  const hostLanInput = root.querySelector('#id-host-lan');
  const hostDnsInput = root.querySelector('#id-host-dns');
  const hostRadios = root.querySelectorAll('input[name="host-mode"]');

  function showHostMode(mode) {
    hostIpRow.style.display = mode === 'ip' ? 'flex' : 'none';
    hostLanRow.style.display = mode === 'lan' ? 'flex' : 'none';
    hostDnsRow.style.display = mode === 'dns' ? 'block' : 'none';
  }

  hostRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      showHostMode(root.querySelector('input[name="host-mode"]:checked').value);
    });
  });

  // Detect external IP
  root.querySelector('#id-detect-host').addEventListener('click', async () => {
    const btn = root.querySelector('#id-detect-host');
    btn.disabled = true; btn.textContent = '...';
    try {
      const result = await rpc.call('noble_detectExternalIp');
      hostIpInput.value = result.ip;
    } catch (e) {
      console.warn('[identity] detect IP failed:', e);
      btn.textContent = 'Failed';
      setTimeout(() => { btn.textContent = 'Detect'; }, 2000);
      return;
    } finally {
      btn.disabled = false;
      if (btn.textContent === '...') btn.textContent = 'Detect';
    }
  });

  /** True if `ip` looks like a private/LAN address (RFC 1918, CGNAT/Tailscale, link-local, loopback). */
  function isLanIp(ip) {
    return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.)/.test(ip);
  }

  /** Build the host_address multiaddr from the current mode + inputs. */
  function getHostAddress() {
    const mode = root.querySelector('input[name="host-mode"]:checked').value;
    if (mode === 'ip') {
      const ip = hostIpInput.value.trim();
      if (!ip) return '';
      return ip.startsWith('/') ? ip : `/ip4/${ip}/tcp/8780`;
    }
    if (mode === 'lan') {
      const ip = hostLanInput.value.trim();
      if (!ip) return '';
      return ip.startsWith('/') ? ip : `/ip4/${ip}/tcp/8780`;
    }
    const dns = hostDnsInput.value.trim();
    if (!dns) return '';
    return `/dns4/${dns}/tcp/8780`;
  }

  /** Parse a host_address multiaddr and populate the correct mode + input. */
  function setHostAddress(addr) {
    if (!addr) return;
    if (addr.startsWith('/dns4/')) {
      root.querySelector('input[name="host-mode"][value="dns"]').checked = true;
      showHostMode('dns');
      const parts = addr.split('/');
      hostDnsInput.value = parts[2] || '';
    } else if (addr.startsWith('/ip4/') || addr.startsWith('/ip6/')) {
      const parts = addr.split('/');
      const ip = parts[2] || '';
      if (isLanIp(ip)) {
        root.querySelector('input[name="host-mode"][value="lan"]').checked = true;
        showHostMode('lan');
        hostLanInput.value = ip;
      } else {
        root.querySelector('input[name="host-mode"][value="ip"]').checked = true;
        showHostMode('ip');
        hostIpInput.value = ip;
      }
    } else {
      // Unknown format — try to detect LAN
      if (isLanIp(addr)) {
        root.querySelector('input[name="host-mode"][value="lan"]').checked = true;
        showHostMode('lan');
        hostLanInput.value = addr;
      } else {
        hostIpInput.value = addr;
      }
    }
  }

  // Load current identity
  async function loadIdentity() {
    try {
      const identity = await rpc.call('noble_getNodeIdentity');
      root.querySelector('#id-node-name').value = identity.node_name || '';
      orgTypeSelect.innerHTML = buildOrgTypeOptions(identity.org_type || 'Individual');
      nodeRoleSelect.innerHTML = buildCompositeRoleOptions(
        identity.node_role || 'FullNode',
        !!identity.wants_to_validate,
        !!identity.wants_to_vote
      );
      root.querySelector('#id-org-name').value = identity.org_name || '';
      root.querySelector('#id-email').value = identity.contact_email || '';
      root.querySelector('#id-website').value = identity.website || '';
      setHostAddress(identity.host_address || '');
      root.querySelector('#id-country').value = identity.country_code || '';
      updateGovBadge();
    } catch (e) {
      console.error('[identity] load:', e);
      orgTypeSelect.innerHTML = buildOrgTypeOptions('Individual');
      nodeRoleSelect.innerHTML = buildCompositeRoleOptions('FullNode', false, false);
      updateGovBadge();
    }
  }

  // Load peer identity data from peer memory
  async function loadPeers() {
    try {
      const peers = await rpc.call('noble_getPeerMemory');
      if (!peers || peers.length === 0) {
        peersBody.innerHTML = '<tr><td colspan="7" class="empty-state">No peer identity data available</td></tr>';
        return;
      }
      peersBody.innerHTML = peers.map((p, i) => {
        const cls = govClassForOrgType(p.org_type || '');
        const ago = Math.floor(Date.now() / 1000 - p.last_seen);
        const agoStr = ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.floor(ago / 60)}m ago` : `${Math.floor(ago / 3600)}h ago`;
        const orgDisplay = orgTypeLabel(p.org_type || '');
        const compositeRole = NODE_ROLE_COMPOSITE.find(c =>
          c.role === p.node_role && c.validate === !!p.wants_to_validate && c.vote === !!p.wants_to_vote
        );
        const roleDisplay = compositeRole ? compositeRole.label.split(' — ')[0] : (p.node_role || '').replace(/([A-Z])/g, ' $1').trim();
        const peerKey = p.identity_key || p.peer_id || '';
        return `<tr class="clickable-row" data-idx="${i}">
          <td class="mono">${truncatePeerId(peerKey)} <button class="btn-copy" data-copy="${esc(peerKey)}" title="Copy identity key">&#128203;</button></td>
          <td>${esc(p.node_name)}</td>
          <td>${orgDisplay}</td>
          <td>${govBadge(cls)}</td>
          <td>${roleDisplay}</td>
          <td><span class="badge-pki-none">N/A</span></td>
          <td>${agoStr}</td>
        </tr>`;
      }).join('');

      // Click handler for detail expansion
      peersBody.querySelectorAll('.clickable-row').forEach(row => {
        row.addEventListener('click', () => {
          const idx = parseInt(row.dataset.idx, 10);
          const p = peers[idx];
          if (!p) return;
          const detailComposite = NODE_ROLE_COMPOSITE.find(c =>
            c.role === p.node_role && c.validate === !!p.wants_to_validate && c.vote === !!p.wants_to_vote
          );
          const detailRoleLabel = detailComposite ? detailComposite.label : (p.node_role || '').replace(/([A-Z])/g, ' $1').trim();
          const peerKey = p.identity_key || p.peer_id || '';
          peerDl.innerHTML = `
            <dt>Identity Key</dt><dd class="mono">${esc(peerKey)} <button class="btn-copy" data-copy="${esc(peerKey)}" title="Copy identity key">&#128203;</button></dd>
            ${p.peer_id ? `<dt>Peer ID</dt><dd class="mono">${esc(p.peer_id)}</dd>` : ''}
            <dt>Node Name</dt><dd>${esc(p.node_name)}</dd>
            <dt>Org Type</dt><dd>${orgTypeLabel(p.org_type || '')}</dd>
            <dt>Governance</dt><dd>${govBadge(govClassForOrgType(p.org_type || ''))}</dd>
            <dt>Role</dt><dd>${detailRoleLabel}</dd>
            <dt>Host Address</dt><dd class="mono">${esc(p.host_address || p.last_addr || 'N/A')}</dd>
            <dt>Country</dt><dd>${esc(p.country_code || 'N/A')}</dd>
            <dt>Last Seen</dt><dd>${new Date(p.last_seen * 1000).toLocaleString()}</dd>
          `;
          peerDetail.style.display = 'block';
        });
      });
    } catch (e) {
      console.error('[identity] peers:', e);
      peersBody.innerHTML = '<tr><td colspan="7" class="empty-state">Failed to load peer data</td></tr>';
    }
  }

  // --- My Keys Panel ---
  async function loadMyKeys() {
    const container = root.querySelector('#id-keys-body');
    try {
      const [addrResp, nodeInfo] = await Promise.all([
        rpc.call('noble_listAddresses'),
        rpc.call('noble_getNodeInfo'),
      ]);
      const keys = addrResp.keys || [];
      if (keys.length === 0) {
        container.innerHTML = '<p style="color:var(--text-secondary)">No keys in wallet. Create or import a key on the Wallet page.</p>';
        return;
      }
      const validatorHex = nodeInfo.validator_pubkey || '';
      container.innerHTML = keys.map(k => {
        const isValidator = validatorHex && k.pubkey_hex === validatorHex;
        const badge = isValidator ? ' <span class="badge-pki-verified">Validator</span>' : '';
        const schemeBadge = k.scheme === 'secp256k1'
          ? '<span style="color:var(--warning)">secp256k1</span>'
          : '<span style="color:var(--info,#3b82f6)">ed25519</span>';
        let btcHtml = '';
        if (k.bitcoin_addresses && k.bitcoin_addresses.length > 0) {
          btcHtml = '<div style="margin-top:8px"><strong>Bitcoin Addresses:</strong></div>' +
            k.bitcoin_addresses.map(ba =>
              `<div style="display:flex;align-items:center;gap:6px;margin:4px 0 4px 12px">
                <span style="min-width:48px;color:var(--text-secondary)">${esc((ba.address_type || '').toUpperCase())}</span>
                <span class="mono" style="font-size:12px;word-break:break-all">${esc(ba.address)}</span>
                <button class="btn-copy" data-copy="${esc(ba.address)}" title="Copy ${esc(ba.address_type)} address">&#128203;</button>
              </div>`
            ).join('');
        }
        return `<div style="border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:12px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            ${schemeBadge}${badge}
          </div>
          <div style="display:flex;align-items:center;gap:6px">
            <span class="mono" style="font-size:12px;word-break:break-all">${esc(k.pubkey_hex)}</span>
            <button class="btn-copy" data-copy="${esc(k.pubkey_hex)}" title="Copy public key hex">&#128203;</button>
          </div>
          ${btcHtml}
        </div>`;
      }).join('');
    } catch (e) {
      console.error('[identity] keys:', e);
      container.innerHTML = '<p style="color:var(--text-secondary)">Could not load keys</p>';
    }
  }

  // --- PKI Identity Management ---

  function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const prev = btn.textContent;
      btn.textContent = 'Copied!';
      btn.disabled = true;
      setTimeout(() => { btn.textContent = prev; btn.disabled = false; }, 1500);
    }).catch(() => {
      btn.textContent = 'Failed';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
  }

  async function loadPkiStatus() {
    const pkiBody = root.querySelector('#pki-body');
    try {
      const status = await rpc.call('noble_getPkiStatus');
      if (status.configured) {
        renderPkiBound(pkiBody, status);
      } else {
        renderPkiUpload(pkiBody);
      }
    } catch {
      renderPkiUpload(pkiBody);
    }
  }

  function renderPkiBound(container, status) {
    const fpShort = (status.fingerprint || '').slice(0, 16) + '...';
    const expiryDate = status.expiry ? new Date(status.expiry * 1000).toLocaleDateString() : 'N/A';
    const boundDate = status.bound_at ? new Date(status.bound_at * 1000).toLocaleString() : 'N/A';

    container.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px">
        <span class="badge-pki-verified">Verified</span>
        <span style="color:var(--text-secondary)">PKI Identity is configured</span>
      </div>
      <dl class="detail-grid" style="margin-bottom:16px">
        <dt>Certificate CN</dt><dd>${esc(status.cn || 'Unknown')}</dd>
        <dt>Fingerprint</dt>
        <dd style="display:flex;align-items:center;gap:6px">
          <span class="mono">${esc(fpShort)}</span>
          <button type="button" class="btn" id="pki-copy-fp" style="padding:2px 8px;font-size:0.8em">Copy</button>
        </dd>
        <dt>Expiry</dt><dd>${expiryDate}</dd>
        <dt>Certificate Chain</dt><dd>Certificate chain: ${formatNumber(status.chain_length || 0)} certificates</dd>
        <dt>Bound At</dt><dd>${boundDate}</dd>
      </dl>
      <button type="button" class="btn btn-danger" id="pki-remove">Remove PKI Binding</button>
    `;

    container.querySelector('#pki-copy-fp').addEventListener('click', function() {
      copyToClipboard(status.fingerprint || '', this);
    });

    container.querySelector('#pki-remove').addEventListener('click', async function() {
      if (!confirm('Remove your PKI identity binding? This will clear the certificate association from your node.')) return;
      this.disabled = true;
      this.textContent = 'Removing...';
      try {
        await rpc.call('noble_removePkiBinding');
        renderPkiUpload(container);
      } catch (err) {
        this.disabled = false;
        this.textContent = 'Remove PKI Binding';
        const errMsg = document.createElement('div');
        errMsg.style.cssText = 'color:var(--danger);margin-top:8px';
        errMsg.textContent = `Error: ${err.message || err}`;
        container.appendChild(errMsg);
        setTimeout(() => errMsg.remove(), 5000);
      }
    });
  }

  function renderPkiUpload(container) {
    container.innerHTML = `
      <div style="color:var(--text-secondary);margin-bottom:16px">PKI Identity: Not configured</div>
      <div class="form-group">
        <label for="pki-file">PKCS#12 Certificate File</label>
        <input type="file" id="pki-file" accept=".p12,.pfx" style="padding:6px 0">
      </div>
      <div class="form-group">
        <label for="pki-pass">PKCS#12 Password</label>
        <input type="password" id="pki-pass" autocomplete="off" spellcheck="false" placeholder="Password that protects the .p12 file">
        <small style="color:var(--text-muted);display:block;margin-top:4px">This is the password set when the PKCS#12 file was created. You are not creating a new password.</small>
      </div>
      <button type="button" class="btn btn-primary" id="pki-upload">Upload &amp; Inspect</button>
      <span id="pki-status" class="form-status"></span>
    `;

    container.querySelector('#pki-upload').addEventListener('click', async function() {
      const fileInput = container.querySelector('#pki-file');
      const passInput = container.querySelector('#pki-pass');
      const statusSpan = container.querySelector('#pki-status');

      if (!fileInput.files || fileInput.files.length === 0) {
        statusSpan.textContent = 'Please select a .p12 or .pfx file';
        statusSpan.style.color = 'var(--danger)';
        return;
      }

      const file = fileInput.files[0];
      this.disabled = true;
      statusSpan.textContent = 'Reading file...';
      statusSpan.style.color = 'var(--text-secondary)';

      try {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        // Convert to base64 — use a loop to avoid call stack overflow on large files
        let binary = '';
        const chunkSize = 8192;
        for (let i = 0; i < bytes.length; i += chunkSize) {
          const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
          binary += String.fromCharCode.apply(null, chunk);
        }
        const base64 = btoa(binary);

        const passphrase = passInput.value;

        statusSpan.textContent = 'Uploading...';
        const result = await rpc.call('noble_uploadPkcs12', { file_data: base64, passphrase });

        // Wipe passphrase from DOM immediately
        passInput.value = 'x'.repeat(passInput.value.length);
        passInput.value = '';
        // Clear file input
        fileInput.value = '';

        if (result.success) {
          renderPkiConfirm(container, result);
        } else {
          statusSpan.textContent = `Error: ${result.error || 'Upload failed'}`;
          statusSpan.style.color = 'var(--danger)';
          this.disabled = false;
        }
      } catch (err) {
        // Wipe passphrase on error too
        passInput.value = 'x'.repeat(passInput.value.length);
        passInput.value = '';
        fileInput.value = '';

        statusSpan.textContent = `Error: ${err.message || err}`;
        statusSpan.style.color = 'var(--danger)';
        this.disabled = false;
      }
    });
  }

  function renderPkiConfirm(container, result) {
    const fpShort = (result.fingerprint || '').slice(0, 16) + '...';
    const expiryDate = result.expiry ? new Date(result.expiry * 1000).toLocaleDateString() : 'N/A';

    container.innerHTML = `
      <div style="color:var(--success);margin-bottom:16px;font-weight:600">Certificate inspected successfully</div>
      <dl class="detail-grid" style="margin-bottom:16px">
        <dt>Certificate CN</dt><dd>${esc(result.cn || 'Unknown')}</dd>
        <dt>Fingerprint</dt>
        <dd style="display:flex;align-items:center;gap:6px">
          <span class="mono">${esc(fpShort)}</span>
          <button type="button" class="btn" id="pki-confirm-copy-fp" style="padding:2px 8px;font-size:0.8em">Copy</button>
        </dd>
        <dt>Expiry</dt><dd>${expiryDate}</dd>
        <dt>Certificate Chain</dt><dd>Certificate chain: ${formatNumber(result.chain_length || 0)} certificates</dd>
      </dl>
      <div style="display:flex;gap:8px">
        <button type="button" class="btn btn-primary" id="pki-confirm-bind">Confirm Binding</button>
        <button type="button" class="btn" id="pki-confirm-cancel">Cancel</button>
      </div>
      <span id="pki-confirm-status" class="form-status"></span>
    `;

    container.querySelector('#pki-confirm-copy-fp').addEventListener('click', function() {
      copyToClipboard(result.fingerprint || '', this);
    });

    container.querySelector('#pki-confirm-bind').addEventListener('click', async function() {
      this.disabled = true;
      const statusSpan = container.querySelector('#pki-confirm-status');
      statusSpan.textContent = 'Binding...';
      statusSpan.style.color = 'var(--text-secondary)';
      try {
        await rpc.call('noble_bindPkiIdentity', { fingerprint: result.fingerprint });
        // Reload to show bound state
        await loadPkiStatus();
      } catch (err) {
        statusSpan.textContent = `Error: ${err.message || err}`;
        statusSpan.style.color = 'var(--danger)';
        this.disabled = false;
      }
    });

    container.querySelector('#pki-confirm-cancel').addEventListener('click', () => {
      renderPkiUpload(container);
    });
  }

  // Save & broadcast
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    statusEl.textContent = 'Saving...';
    statusEl.style.color = 'var(--text-secondary)';
    try {
      const composite = NODE_ROLE_COMPOSITE.find(c => c.value === nodeRoleSelect.value);
      await rpc.call('noble_setNodeIdentity', {
        node_name: root.querySelector('#id-node-name').value,
        org_type: orgTypeSelect.value,
        org_name: root.querySelector('#id-org-name').value,
        node_role: composite.role,
        contact_email: root.querySelector('#id-email').value,
        website: root.querySelector('#id-website').value,
        host_address: getHostAddress(),
        country_code: root.querySelector('#id-country').value.trim().toUpperCase() || undefined,
        wants_to_validate: composite.validate,
        wants_to_vote: composite.vote,
      });
      statusEl.textContent = 'Saved & broadcast!';
      statusEl.style.color = 'var(--success)';
      setTimeout(() => { statusEl.textContent = ''; }, 3000);
    } catch (err) {
      statusEl.textContent = `Error: ${err.message || err}`;
      statusEl.style.color = 'var(--danger)';
    }
  });

  loadIdentity();
  loadMyKeys();
  loadPeers();
  loadPkiStatus();

  // ── Copy-to-clipboard delegation ──
  root.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-copy');
    if (btn) {
      e.stopPropagation();
      navigator.clipboard?.writeText(btn.dataset.copy).catch(() => {});
      btn.textContent = '\u2713';
      setTimeout(() => { btn.textContent = '\u{1F4CB}'; }, 1200);
    }
  });

  // Refresh peers every 30s
  const peerInterval = setInterval(loadPeers, 30_000);
  unsubs.push(() => clearInterval(peerInterval));

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}

function participationLabel(wantsValidate, wantsVote) {
  if (wantsValidate && wantsVote) return '<span class="participation-tag" style="border-color:var(--success);color:var(--success)">Full Validator</span>';
  if (wantsValidate) return '<span class="participation-tag" style="border-color:var(--warning);color:var(--warning)">Block Producer</span>';
  if (wantsVote) return '<span class="participation-tag" style="border-color:var(--info, #3b82f6);color:var(--info, #3b82f6)">Voter Only</span>';
  return '<span class="participation-tag" style="border-color:var(--text-secondary);color:var(--text-secondary)">Watcher</span>';
}

function pkiStatusBadge(attestation) {
  if (attestation && attestation.scheme === 'pkcs7') {
    const cn = attestation.signer_cn || 'Verified';
    return `<span class="badge-pki-verified" title="${esc(cn)}">Verified</span>`;
  }
  return '<span class="badge-pki-none">None</span>';
}

function truncatePeerId(pid) {
  if (!pid || pid.length < 16) return pid || '';
  return pid.slice(0, 12) + '...' + pid.slice(-6);
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
