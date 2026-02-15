/**
 * NOBLE Dashboard — Node Identity Page
 * Self-identification configuration and peer identity directory
 */

import { formatNumber } from '../utils.js';

const GOV_CLASSES = {
  individual: { label: 'Individual', color: '#6b7280' },
  'non-profit': { label: 'Non-Profit', color: '#10b981' },
  'for-profit': { label: 'For-Profit', color: '#3b82f6' },
  government: { label: 'Government', color: '#ef4444' },
  institution: { label: 'Institution', color: '#8b5cf6' },
};

const ORG_TYPES = {
  individual: ['Individual', 'IndependentResearcher'],
  'non-profit': ['University', 'ResearchLab', 'NGO', 'Foundation', 'OpenSourceProject', 'Cooperative', 'CommunityGroup', 'ReligiousOrganization'],
  'for-profit': ['Enterprise', 'Startup', 'InfrastructureProvider', 'FinancialInstitution'],
  government: ['GovernmentFederal', 'GovernmentRegional', 'GovernmentMunicipal', 'MilitaryOrDefense', 'CentralBank'],
  institution: ['Hospital', 'Museum', 'MediaOutlet'],
};

const NODE_ROLES = ['FullNode', 'Validator', 'ArchiveNode', 'LightClient', 'Gateway'];

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

function buildOrgTypeOptions(selected) {
  let html = '';
  for (const [group, types] of Object.entries(ORG_TYPES)) {
    const label = GOV_CLASSES[group]?.label || group;
    html += `<optgroup label="${label}">`;
    for (const t of types) {
      const sel = t === selected ? ' selected' : '';
      html += `<option value="${t}"${sel}>${t.replace(/([A-Z])/g, ' $1').trim()}</option>`;
    }
    html += '</optgroup>';
  }
  return html;
}

function buildNodeRoleOptions(selected) {
  return NODE_ROLES.map(r => {
    const sel = r === selected ? ' selected' : '';
    return `<option value="${r}"${sel}>${r.replace(/([A-Z])/g, ' $1').trim()}</option>`;
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
              <input type="text" id="id-host" placeholder="e.g. /ip4/1.2.3.4/tcp/9333">
            </div>
            <fieldset class="form-group participation-fieldset">
              <legend>Consensus Participation</legend>
              <label class="checkbox-label">
                <input type="checkbox" id="id-wants-validate">
                <span>I want to produce blocks (validate)</span>
              </label>
              <label class="checkbox-label">
                <input type="checkbox" id="id-wants-vote">
                <span>I want to cast consensus votes</span>
              </label>
              <div id="id-participation-badge" class="participation-badge"></div>
            </fieldset>
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
                <th>Participation</th>
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
  const wantsValidateEl = root.querySelector('#id-wants-validate');
  const wantsVoteEl = root.querySelector('#id-wants-vote');
  const participationBadge = root.querySelector('#id-participation-badge');

  function updateGovBadge() {
    const cls = govClassForOrgType(orgTypeSelect.value);
    govBadgeEl.innerHTML = govBadge(cls);
  }

  function updateParticipationBadge() {
    const v = wantsValidateEl.checked;
    const vo = wantsVoteEl.checked;
    let label, color;
    if (v && vo) { label = 'Full Validator'; color = 'var(--success)'; }
    else if (v) { label = 'Block Producer'; color = 'var(--warning)'; }
    else if (vo) { label = 'Voter Only'; color = 'var(--info, #3b82f6)'; }
    else { label = 'Watcher / Observer'; color = 'var(--text-secondary)'; }
    participationBadge.innerHTML = `<span class="participation-tag" style="border-color:${color};color:${color}">${label}</span>`;
  }

  orgTypeSelect.addEventListener('change', updateGovBadge);
  wantsValidateEl.addEventListener('change', updateParticipationBadge);
  wantsVoteEl.addEventListener('change', updateParticipationBadge);

  // Load current identity
  async function loadIdentity() {
    try {
      const identity = await rpc.call('noble_getNodeIdentity');
      root.querySelector('#id-node-name').value = identity.node_name || '';
      orgTypeSelect.innerHTML = buildOrgTypeOptions(identity.org_type || 'Individual');
      nodeRoleSelect.innerHTML = buildNodeRoleOptions(identity.node_role || 'FullNode');
      root.querySelector('#id-org-name').value = identity.org_name || '';
      root.querySelector('#id-email').value = identity.contact_email || '';
      root.querySelector('#id-website').value = identity.website || '';
      root.querySelector('#id-host').value = identity.host_address || '';
      wantsValidateEl.checked = !!identity.wants_to_validate;
      wantsVoteEl.checked = !!identity.wants_to_vote;
      updateGovBadge();
      updateParticipationBadge();
    } catch (e) {
      console.error('[identity] load:', e);
      orgTypeSelect.innerHTML = buildOrgTypeOptions('Individual');
      nodeRoleSelect.innerHTML = buildNodeRoleOptions('FullNode');
      updateGovBadge();
      updateParticipationBadge();
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
        const orgDisplay = (p.org_type || '').replace(/([A-Z])/g, ' $1').trim();
        const roleDisplay = (p.node_role || '').replace(/([A-Z])/g, ' $1').trim();
        const pLabel = participationLabel(p.wants_to_validate, p.wants_to_vote);
        return `<tr class="clickable-row" data-idx="${i}">
          <td class="mono">${truncatePeerId(p.peer_id)}</td>
          <td>${esc(p.node_name)}</td>
          <td>${orgDisplay}</td>
          <td>${govBadge(cls)}</td>
          <td>${roleDisplay}</td>
          <td>${pLabel}</td>
          <td>${agoStr}</td>
        </tr>`;
      }).join('');

      // Click handler for detail expansion
      peersBody.querySelectorAll('.clickable-row').forEach(row => {
        row.addEventListener('click', () => {
          const idx = parseInt(row.dataset.idx, 10);
          const p = peers[idx];
          if (!p) return;
          const pLabel = participationLabel(p.wants_to_validate, p.wants_to_vote);
          peerDl.innerHTML = `
            <dt>Peer ID</dt><dd class="mono">${esc(p.peer_id)}</dd>
            <dt>Node Name</dt><dd>${esc(p.node_name)}</dd>
            <dt>Org Type</dt><dd>${(p.org_type || '').replace(/([A-Z])/g, ' $1').trim()}</dd>
            <dt>Governance</dt><dd>${govBadge(p.governance_class || govClassForOrgType(p.org_type))}</dd>
            <dt>Role</dt><dd>${(p.node_role || '').replace(/([A-Z])/g, ' $1').trim()}</dd>
            <dt>Participation</dt><dd>${pLabel}</dd>
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
      await rpc.call('noble_setNodeIdentity', {
        node_name: root.querySelector('#id-node-name').value,
        org_type: orgTypeSelect.value,
        org_name: root.querySelector('#id-org-name').value,
        node_role: nodeRoleSelect.value,
        contact_email: root.querySelector('#id-email').value,
        website: root.querySelector('#id-website').value,
        host_address: root.querySelector('#id-host').value,
        wants_to_validate: wantsValidateEl.checked,
        wants_to_vote: wantsVoteEl.checked,
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
