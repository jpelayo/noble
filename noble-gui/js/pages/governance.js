/**
 * NOBLE Dashboard — Governance Page
 * Badge proposals, DAO polls, voting, and validator badge management.
 */

import { truncateHash, timeAgo } from '../utils.js';

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function init(root, ctx) {
  const { rpc } = ctx;
  let alive = true;

  root.innerHTML = `
    <div class="page-header">
      <h1>Governance</h1>
      <p>Badge proposals, DAO polls, and validator voting</p>
    </div>

    <!-- My Status -->
    <div class="panel" id="gov-status">
      <div class="panel-header">My Validator Status</div>
      <div class="panel-body" id="gov-status-body">Loading...</div>
    </div>

    <!-- Active Items (proposals + polls) -->
    <div class="panel" id="gov-active">
      <div class="panel-header">Active Governance Items</div>
      <div class="panel-body" id="gov-active-body">Loading...</div>
    </div>

    <!-- Badge Holders -->
    <div class="panel" id="gov-holders">
      <div class="panel-header">Badge Holders</div>
      <div class="panel-body" id="gov-holders-body">Loading...</div>
    </div>

    <!-- Create -->
    <div class="panel" id="gov-create">
      <div class="panel-header">Create Proposal or Poll</div>
      <div class="panel-body" id="gov-create-body">
        <div style="display:flex;gap:var(--gap);margin-bottom:var(--gap)">
          <button class="btn btn-sm" id="gov-tab-badge" style="flex:1">Badge Proposal</button>
          <button class="btn btn-sm btn-outline" id="gov-tab-poll" style="flex:1">DAO Poll</button>
        </div>
        <div id="gov-create-form"></div>
      </div>
    </div>

    <!-- History -->
    <div class="panel" id="gov-history">
      <div class="panel-header">History</div>
      <div class="panel-body" id="gov-history-body">Loading...</div>
    </div>
  `;

  const statusBody = root.querySelector('#gov-status-body');
  const activeBody = root.querySelector('#gov-active-body');
  const holdersBody = root.querySelector('#gov-holders-body');
  const createForm = root.querySelector('#gov-create-form');
  const historyBody = root.querySelector('#gov-history-body');

  // ── Tab toggle ──
  let createTab = 'badge';
  const tabBadge = root.querySelector('#gov-tab-badge');
  const tabPoll = root.querySelector('#gov-tab-poll');
  tabBadge.addEventListener('click', () => { createTab = 'badge'; renderCreateForm(); updateTabStyles(); });
  tabPoll.addEventListener('click', () => { createTab = 'poll'; renderCreateForm(); updateTabStyles(); });

  function updateTabStyles() {
    tabBadge.className = createTab === 'badge' ? 'btn btn-sm' : 'btn btn-sm btn-outline';
    tabPoll.className = createTab === 'poll' ? 'btn btn-sm' : 'btn btn-sm btn-outline';
  }

  // ── Create form rendering ──
  function renderCreateForm() {
    if (createTab === 'badge') {
      createForm.innerHTML = `
        <div class="form-group">
          <label>Target Public Key</label>
          <input type="text" id="gov-badge-target" placeholder="nbl1p... or hex" class="input" />
        </div>
        <div class="form-group">
          <label>Proposal Type</label>
          <select id="gov-badge-type" class="input">
            <option value="grant">Grant Badge</option>
            <option value="revoke">Revoke Badge</option>
          </select>
        </div>
        <div class="form-group">
          <label>Reason (optional for revoke)</label>
          <input type="text" id="gov-badge-reason" placeholder="Reason" class="input" />
        </div>
        <button class="btn" id="gov-badge-submit">Submit Badge Proposal</button>
        <div id="gov-badge-result" style="margin-top:var(--gap-sm);font-size:var(--font-size-sm)"></div>
      `;
      root.querySelector('#gov-badge-submit').addEventListener('click', submitBadgeProposal);
    } else {
      createForm.innerHTML = `
        <div class="form-group">
          <label>Question</label>
          <input type="text" id="gov-poll-question" placeholder="Should we...?" class="input" />
        </div>
        <div class="form-group">
          <label>Duration (cycles, 1 cycle = 20 min)</label>
          <input type="number" id="gov-poll-duration" value="72" min="1" max="720" class="input" />
        </div>
        <button class="btn" id="gov-poll-submit">Create DAO Poll</button>
        <div id="gov-poll-result" style="margin-top:var(--gap-sm);font-size:var(--font-size-sm)"></div>
      `;
      root.querySelector('#gov-poll-submit').addEventListener('click', submitDaoPoll);
    }
  }

  // ── Load all data ──
  let loadInFlight = false;
  async function loadAll() {
    if (!alive || loadInFlight) return;
    loadInFlight = true;
    try {
      await Promise.all([loadStatus(), loadActive(), loadHolders(), loadHistory()]);
    } finally {
      loadInFlight = false;
    }
  }

  async function loadStatus() {
    try {
      const status = await rpc.call('noble_getMyBadgeStatus');
      if (!alive) return;
      const hasBadge = status?.has_badge;
      const bootstrap = status?.bootstrap_mode;
      statusBody.innerHTML = `
        <div class="inline-dl">
          <span class="dt">Badge</span>
          <span class="dd">${hasBadge ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-muted">None</span>'}</span>
          <span class="dt">Bootstrap Mode</span>
          <span class="dd">${bootstrap ? '<span class="badge badge-warning">Active</span> (badge not required)' : 'Off'}</span>
        </div>
      `;
    } catch (e) {
      statusBody.innerHTML = `<p class="text-muted">Could not load status: ${escapeHtml(e.message || e)}</p>`;
    }
  }

  async function loadActive() {
    try {
      const [proposals, polls] = await Promise.all([
        rpc.call('noble_getActiveProposals'),
        rpc.call('noble_getActivePolls'),
      ]);
      if (!alive) return;
      const items = [];

      // Badge proposals
      if (proposals?.length) {
        for (const p of proposals) {
          const target = truncateHash(p.target_pubkey || '', 8);
          const typeLabel = p.proposal_type === 'grant' ? 'Grant' : 'Revoke';
          items.push(`
            <div class="list-item" style="display:flex;justify-content:space-between;align-items:center;padding:var(--gap-sm) 0;border-bottom:1px solid var(--border)">
              <div>
                <span class="badge badge-info">${typeLabel}</span>
                <strong>${target}</strong>
                ${p.reason ? `<span class="text-muted"> &mdash; ${escapeHtml(p.reason)}</span>` : ''}
                <div class="text-muted" style="font-size:var(--font-size-xs)">For: ${p.votes_for || 0} / Against: ${p.votes_against || 0}</div>
              </div>
              <div style="display:flex;gap:4px">
                <button class="btn btn-sm btn-success gov-vote-badge" data-hash="${p.proposal_hash}" data-vote="for">For</button>
                <button class="btn btn-sm btn-danger gov-vote-badge" data-hash="${p.proposal_hash}" data-vote="against">Against</button>
              </div>
            </div>
          `);
        }
      }

      // DAO polls
      if (polls?.length) {
        for (const p of polls) {
          const yes = p.votes_yes || 0;
          const no = p.votes_no || 0;
          const abstain = p.votes_abstain || 0;
          items.push(`
            <div class="list-item" style="display:flex;justify-content:space-between;align-items:center;padding:var(--gap-sm) 0;border-bottom:1px solid var(--border)">
              <div>
                <span class="badge badge-accent">Poll</span>
                <strong>${escapeHtml(p.question)}</strong>
                <div class="text-muted" style="font-size:var(--font-size-xs)">Yes: ${yes} / No: ${no} / Abstain: ${abstain} &mdash; expires cycle ${p.expires_at_cycle || '?'}</div>
              </div>
              <div style="display:flex;gap:4px">
                <button class="btn btn-sm btn-success gov-vote-poll" data-id="${p.poll_id}" data-vote="yes">Yes</button>
                <button class="btn btn-sm btn-danger gov-vote-poll" data-id="${p.poll_id}" data-vote="no">No</button>
                <button class="btn btn-sm btn-outline gov-vote-poll" data-id="${p.poll_id}" data-vote="abstain">Abstain</button>
              </div>
            </div>
          `);
        }
      }

      activeBody.innerHTML = items.length
        ? items.join('')
        : '<p class="text-muted">No active governance items.</p>';

      // Wire vote buttons
      activeBody.querySelectorAll('.gov-vote-badge').forEach(btn => {
        btn.addEventListener('click', () => voteBadge(btn.dataset.hash, btn.dataset.vote));
      });
      activeBody.querySelectorAll('.gov-vote-poll').forEach(btn => {
        btn.addEventListener('click', () => votePoll(btn.dataset.id, btn.dataset.vote));
      });
    } catch (e) {
      activeBody.innerHTML = `<p class="text-muted">Could not load active items: ${escapeHtml(e.message || e)}</p>`;
    }
  }

  async function loadHolders() {
    try {
      const holders = await rpc.call('noble_getBadgeHolders');
      if (!alive) return;
      if (!holders?.length) {
        holdersBody.innerHTML = '<p class="text-muted">No badge holders.</p>';
        return;
      }
      const rows = holders.map(h => `
        <tr>
          <td style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${truncateHash(h.pubkey || '', 10)}</td>
          <td>${escapeHtml(h.node_name || '—')}</td>
          <td>${h.status || '—'}</td>
          <td>${h.granted_at_height ? `Height ${h.granted_at_height}` : '—'}</td>
        </tr>
      `).join('');
      holdersBody.innerHTML = `
        <table class="mini-table"><thead><tr><th>Public Key</th><th>Name</th><th>Status</th><th>Granted</th></tr></thead>
        <tbody>${rows}</tbody></table>
      `;
    } catch (e) {
      holdersBody.innerHTML = `<p class="text-muted">Could not load badge holders: ${escapeHtml(e.message || e)}</p>`;
    }
  }

  async function loadHistory() {
    try {
      const [proposals, polls] = await Promise.all([
        rpc.call('noble_getProposalHistory', { limit: 50 }),
        rpc.call('noble_getPollHistory', { limit: 50 }),
      ]);
      if (!alive) return;
      const rows = [];

      if (proposals?.length) {
        for (const p of proposals) {
          rows.push(`<tr>
            <td><span class="badge badge-info">${p.proposal_type || '?'}</span></td>
            <td>${truncateHash(p.target_pubkey || '', 8)}</td>
            <td>${p.votes_for || 0}/${p.votes_against || 0}</td>
            <td>${p.result || '—'}</td>
            <td>Cycle ${p.cycle || '—'}</td>
          </tr>`);
        }
      }

      if (polls?.length) {
        for (const p of polls) {
          rows.push(`<tr>
            <td><span class="badge badge-accent">Poll</span></td>
            <td>${escapeHtml(truncateHash(p.question || '', 30))}</td>
            <td>${p.votes_yes || 0}Y/${p.votes_no || 0}N/${p.votes_abstain || 0}A</td>
            <td>${p.status || '—'}</td>
            <td>Cycle ${p.created_at_cycle || '—'}</td>
          </tr>`);
        }
      }

      historyBody.innerHTML = rows.length
        ? `<table class="mini-table"><thead><tr><th>Type</th><th>Target/Question</th><th>Votes</th><th>Result</th><th>Cycle</th></tr></thead><tbody>${rows.join('')}</tbody></table>`
        : '<p class="text-muted">No governance history.</p>';
    } catch (e) {
      historyBody.innerHTML = `<p class="text-muted">Could not load history: ${escapeHtml(e.message || e)}</p>`;
    }
  }

  // ── Actions ──

  async function voteBadge(hash, vote) {
    try {
      await rpc.call('noble_voteBadgeProposal', { proposal_hash: hash, vote });
      await loadActive();
    } catch (e) {
      alert('Vote failed: ' + (e.message || e));
    }
  }

  async function votePoll(pollId, vote) {
    try {
      await rpc.call('noble_votePoll', { poll_id: pollId, vote });
      await loadActive();
    } catch (e) {
      alert('Vote failed: ' + (e.message || e));
    }
  }

  async function submitBadgeProposal() {
    const target = root.querySelector('#gov-badge-target')?.value?.trim();
    const type = root.querySelector('#gov-badge-type')?.value;
    const reason = root.querySelector('#gov-badge-reason')?.value?.trim();
    const resultEl = root.querySelector('#gov-badge-result');
    if (!target) { resultEl.textContent = 'Target public key is required.'; return; }
    try {
      resultEl.textContent = 'Submitting...';
      await rpc.call('noble_proposeBadge', { target_pubkey: target, proposal_type: type, reason: reason || undefined });
      resultEl.innerHTML = '<span style="color:var(--success)">Proposal submitted.</span>';
      await loadActive();
    } catch (e) {
      resultEl.innerHTML = `<span style="color:var(--error)">Failed: ${escapeHtml(e.message || e)}</span>`;
    }
  }

  async function submitDaoPoll() {
    const question = root.querySelector('#gov-poll-question')?.value?.trim();
    const duration = parseInt(root.querySelector('#gov-poll-duration')?.value || '72', 10);
    const resultEl = root.querySelector('#gov-poll-result');
    if (!question) { resultEl.textContent = 'Question is required.'; return; }
    try {
      resultEl.textContent = 'Creating...';
      await rpc.call('noble_createPoll', { question, expires_cycles: duration });
      resultEl.innerHTML = '<span style="color:var(--success)">Poll created.</span>';
      await loadActive();
    } catch (e) {
      resultEl.innerHTML = `<span style="color:var(--error)">Failed: ${escapeHtml(e.message || e)}</span>`;
    }
  }

  // ── Init ──
  renderCreateForm();
  loadAll();

  return {
    destroy() { alive = false; },
    refresh() { loadAll(); },
  };
}
