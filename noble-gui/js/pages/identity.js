/**
 * NOBLE Dashboard — Node Identity Page
 * Self-identification configuration and peer identity directory
 */

import { formatNumber } from '../utils.js';

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
              <label for="id-host">Host Address</label>
              <input type="text" id="id-host" placeholder="e.g. /ip4/1.2.3.4/tcp/8780">
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
      root.querySelector('#id-host').value = identity.host_address || '';
      updateGovBadge();
    } catch (e) {
      console.error('[identity] load:', e);
      orgTypeSelect.innerHTML = buildOrgTypeOptions('Individual');
      nodeRoleSelect.innerHTML = buildCompositeRoleOptions('FullNode', false, false);
      updateGovBadge();
    }
  }

  // Load peer announces
  async function loadPeers() {
    try {
      const peers = await rpc.call('noble_getPeerAnnounces');
      if (!peers || peers.length === 0) {
        peersBody.innerHTML = '<tr><td colspan="7" class="empty-state">No peer identity data available</td></tr>';
        return;
      }
      peersBody.innerHTML = peers.map((p, i) => {
        const cls = p.governance_class || govClassForOrgType(p.org_type);
        const ago = Math.floor(Date.now() / 1000 - p.last_seen);
        const agoStr = ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.floor(ago / 60)}m ago` : `${Math.floor(ago / 3600)}h ago`;
        const orgDisplay = orgTypeLabel(p.org_type || '');
        const compositeRole = NODE_ROLE_COMPOSITE.find(c =>
          c.role === p.node_role && c.validate === !!p.wants_to_validate && c.vote === !!p.wants_to_vote
        );
        const roleDisplay = compositeRole ? compositeRole.label.split(' — ')[0] : (p.node_role || '').replace(/([A-Z])/g, ' $1').trim();
        const pkiBadge = pkiStatusBadge(p.pki_attestation);
        return `<tr class="clickable-row" data-idx="${i}">
          <td class="mono">${truncatePeerId(p.peer_id)}</td>
          <td>${esc(p.node_name)}</td>
          <td>${orgDisplay}</td>
          <td>${govBadge(cls)}</td>
          <td>${roleDisplay}</td>
          <td>${pkiBadge}</td>
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
          const pkiDetail = p.pki_attestation
            ? `<dt>PKI Status</dt><dd>${pkiStatusBadge(p.pki_attestation)}</dd>
               <dt>PKI Signer</dt><dd>${esc(p.pki_attestation.signer_cn || 'Unknown')}</dd>
               <dt>PKI Fingerprint</dt><dd class="mono">${esc((p.pki_attestation.signer_fingerprint || '').slice(0, 16))}...</dd>`
            : `<dt>PKI Status</dt><dd>${pkiStatusBadge(null)}</dd>`;
          peerDl.innerHTML = `
            <dt>Peer ID</dt><dd class="mono">${esc(p.peer_id)}</dd>
            <dt>Node Name</dt><dd>${esc(p.node_name)}</dd>
            <dt>Org Type</dt><dd>${orgTypeLabel(p.org_type || '')}</dd>
            <dt>Governance</dt><dd>${govBadge(p.governance_class || govClassForOrgType(p.org_type))}</dd>
            <dt>Role</dt><dd>${detailRoleLabel}</dd>
            ${pkiDetail}
            <dt>Contact</dt><dd>${esc(p.contact_email || 'N/A')}</dd>
            <dt>Website</dt><dd>${p.website ? `<a href="${esc(p.website)}" target="_blank">${esc(p.website)}</a>` : 'N/A'}</dd>
            <dt>Host Address</dt><dd class="mono">${esc(p.host_address || 'N/A')}</dd>
            <dt>Identity Key</dt><dd class="mono">${esc(p.identity_key || 'N/A')}</dd>
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
        host_address: root.querySelector('#id-host').value,
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
  loadPeers();

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
