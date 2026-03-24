// NOBLE Client — Governance Page
// Badge management + DAO polls. All non-consensus voting.

import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { emptyState } from '../components/empty-state.js';
import { formatAmount } from '../components/amount-text.js';
import { esc, timeAgo } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    if (!state.isConnected) {
        root.appendChild(emptyState({ icon: '\u{1F517}', title: 'Not Connected', subtitle: 'Connect to a node to participate in governance.' }));
        return { destroy() { alive = false; }, refresh() {} };
    }

    root.classList.add('page-content');

    // Header
    const header = document.createElement('div');
    header.className = 'page-header';
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start';
    header.innerHTML = '<div><h1>Governance</h1><p>Badge management and community polls</p></div><button id="gov-refresh" title="Refresh" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1">&#x21BB;</button>';
    root.appendChild(header);
    root.querySelector('#gov-refresh').addEventListener('click', loadAll);

    // Section containers
    const statusContainer = document.createElement('div');
    statusContainer.style.marginBottom = 'var(--gap)';
    root.appendChild(statusContainer);

    const activeContainer = document.createElement('div');
    activeContainer.style.marginBottom = 'var(--gap)';
    root.appendChild(activeContainer);

    const holdersContainer = document.createElement('div');
    holdersContainer.style.marginBottom = 'var(--gap)';
    root.appendChild(holdersContainer);

    const createContainer = document.createElement('div');
    createContainer.style.marginBottom = 'var(--gap)';
    root.appendChild(createContainer);

    const historyContainer = document.createElement('div');
    root.appendChild(historyContainer);

    let myBadge = null;
    let activeItems = [];
    let badgeHolders = [];
    let historyItems = [];
    let loadInFlight = false;

    loadAll();

    async function loadAll() {
        if (!alive || loadInFlight) return;
        loadInFlight = true;
        try {
            const [badge, proposals, polls, holders, propHistory, pollHistory] = await Promise.all([
                Bridge.call('noble_api', 'getMyBadgeStatus').catch(() => null),
                Bridge.call('noble_api', 'getActiveProposals').catch(() => []),
                Bridge.call('noble_api', 'getActivePolls').catch(() => []),
                Bridge.call('noble_api', 'getBadgeHolders').catch(() => []),
                Bridge.call('noble_api', 'getProposalHistory', { limit: 50 }).catch(() => []),
                Bridge.call('noble_api', 'getPollHistory', { limit: 50 }).catch(() => []),
            ]);
            myBadge = badge;
            activeItems = [
                ...(proposals || []).map(p => ({ ...p, _kind: 'badge' })),
                ...(polls || []).map(p => ({ ...p, _kind: 'dao' })),
            ].sort((a, b) => (a.expires_at_cycle || 0) - (b.expires_at_cycle || 0));
            badgeHolders = holders || [];
            historyItems = [
                ...(propHistory || []).map(p => ({ ...p, _kind: 'badge' })),
                ...(pollHistory || []).map(p => ({ ...p, _kind: 'dao' })),
            ].sort((a, b) => (b.created_at_cycle || 0) - (a.created_at_cycle || 0));
        } catch (e) {
            console.error('[governance] load:', e);
        } finally {
            loadInFlight = false;
        }
        if (alive) render();
    }

    function render() {
        renderStatus();
        renderActive();
        renderHolders();
        renderCreate();
        renderHistory();
    }

    // ── Section 1: My Status ──
    function renderStatus() {
        statusContainer.innerHTML = '';
        const currentCycle = state.syncStatus?.cycleNumber || 0;
        const inBootstrap = currentCycle < 4320;
        let html = '';
        if (myBadge && myBadge.has_badge) {
            html = `<div style="display:flex;align-items:center;gap:var(--gap-sm)">
                <span style="font-size:1.5rem">\u{1F3C5}</span>
                <div>
                    <div style="font-weight:600;color:var(--success)">Badge: Active</div>
                    <div style="font-size:var(--font-size-xs);color:var(--text-muted)">Granted cycle ${myBadge.granted_at_cycle || '?'} &middot; You can propose and vote</div>
                </div>
            </div>`;
        } else if (inBootstrap) {
            html = `<div style="display:flex;align-items:center;gap:var(--gap-sm)">
                <span style="font-size:1.5rem">\u{1F331}</span>
                <div>
                    <div style="font-weight:600;color:var(--accent)">Bootstrap Mode (cycle ${currentCycle} / 4320)</div>
                    <div style="font-size:var(--font-size-xs);color:var(--text-muted)">All validators can propose and vote during bootstrap</div>
                </div>
            </div>`;
        } else {
            html = `<div style="display:flex;align-items:center;gap:var(--gap-sm)">
                <span style="font-size:1.5rem">\u{1F6AB}</span>
                <div>
                    <div style="font-weight:600;color:var(--text-muted)">No Badge</div>
                    <div style="font-size:var(--font-size-xs);color:var(--text-muted)">A badge proposal must be submitted and approved by existing holders</div>
                </div>
            </div>`;
        }
        const card = nobleCard('My Governance Status', html);
        statusContainer.appendChild(card);
    }

    // ── Section 2: Active Proposals & Polls ──
    function renderActive() {
        activeContainer.innerHTML = '';
        const currentCycle = state.syncStatus?.cycleNumber || 0;
        let html = '';
        if (activeItems.length === 0) {
            html = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">No active governance items.</p>';
        } else {
            html = '<div class="table-scroll-wrapper"><table class="data-table" style="font-size:var(--font-size-xs)"><thead><tr><th>Type</th><th>Description</th><th>Votes</th><th>Expires</th><th>Action</th></tr></thead><tbody>';
            for (let i = 0; i < activeItems.length; i++) {
                const item = activeItems[i];
                const remaining = Math.max(0, (item.expires_at_cycle || 0) - currentCycle);
                const expHours = Math.round(remaining * 20 / 60);
                const expLabel = expHours > 24 ? `${Math.round(expHours / 24)}d` : `${expHours}h`;

                let typeLabel, desc, voteHtml, actionHtml;
                if (item._kind === 'badge') {
                    const pt = item.proposal_type === 'revoke' ? '\u274C Revoke' : '\u{1F3C5} Grant';
                    typeLabel = `<span class="badge" style="font-size:0.7em">${pt}</span>`;
                    desc = `${item.proposal_type === 'revoke' ? 'Revoke' : 'Grant'} badge ${item.target_name || item.target_pubkey || ''}`;
                    const total = item.total_eligible_voters || 1;
                    const forPct = Math.round((item.votes_for || 0) / total * 100);
                    voteHtml = `<div style="display:flex;align-items:center;gap:4px"><div style="width:60px;height:6px;background:var(--bg-tertiary);border-radius:3px;overflow:hidden"><div style="width:${forPct}%;height:100%;background:var(--success)"></div></div> ${item.votes_for || 0}/${total}</div>`;
                    actionHtml = `<button class="btn btn-sm gov-vote-btn" data-idx="${i}" data-vote="true" style="padding:1px 8px;font-size:0.7em">For</button> <button class="btn btn-sm gov-vote-btn" data-idx="${i}" data-vote="false" style="padding:1px 8px;font-size:0.7em">Against</button>`;
                } else {
                    typeLabel = '<span class="badge tx-dao" style="font-size:0.7em">\u{1F5F3} Poll</span>';
                    desc = item.question || '';
                    const total = item.total_eligible || 1;
                    const yesPct = Math.round((item.votes_yes || 0) / total * 100);
                    voteHtml = `<div style="display:flex;align-items:center;gap:4px"><div style="width:60px;height:6px;background:var(--bg-tertiary);border-radius:3px;overflow:hidden"><div style="width:${yesPct}%;height:100%;background:var(--success)"></div></div> ${item.votes_yes || 0}Y ${item.votes_no || 0}N</div>`;
                    actionHtml = `<button class="btn btn-sm gov-poll-btn" data-idx="${i}" data-vote="yes" style="padding:1px 8px;font-size:0.7em">Yes</button> <button class="btn btn-sm gov-poll-btn" data-idx="${i}" data-vote="no" style="padding:1px 8px;font-size:0.7em">No</button> <button class="btn btn-sm gov-poll-btn" data-idx="${i}" data-vote="abstain" style="padding:1px 8px;font-size:0.7em">Abstain</button>`;
                }
                html += `<tr><td>${typeLabel}</td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(desc)}">${esc(desc)}</td><td>${voteHtml}</td><td>${expLabel}</td><td id="gov-action-${i}">${actionHtml}</td></tr>`;
            }
            html += '</tbody></table></div>';
        }
        const card = nobleCard(`Active Governance Items (${activeItems.length})`, html);
        activeContainer.appendChild(card);

        // Wire vote buttons
        card.querySelectorAll('.gov-vote-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const idx = parseInt(btn.dataset.idx, 10);
                const item = activeItems[idx];
                const cell = card.querySelector(`#gov-action-${idx}`);
                cell.innerHTML = '<span style="color:var(--text-muted)">Voting...</span>';
                try {
                    await Bridge.call('noble_api', 'voteBadgeProposal', { proposal_hash: item.proposal_hash, vote: btn.dataset.vote === 'true' });
                    cell.innerHTML = '<span style="color:var(--success)">\u2713 Voted</span>';
                } catch (e) {
                    cell.innerHTML = `<span style="color:var(--error)">${esc(e.message || 'Failed')}</span>`;
                }
            });
        });
        card.querySelectorAll('.gov-poll-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const idx = parseInt(btn.dataset.idx, 10);
                const item = activeItems[idx];
                const cell = card.querySelector(`#gov-action-${idx}`);
                cell.innerHTML = '<span style="color:var(--text-muted)">Voting...</span>';
                try {
                    await Bridge.call('noble_api', 'votePoll', { poll_id: item.poll_id, vote: btn.dataset.vote });
                    cell.innerHTML = `<span style="color:var(--success)">\u2713 ${btn.dataset.vote}</span>`;
                } catch (e) {
                    cell.innerHTML = `<span style="color:var(--error)">${esc(e.message || 'Failed')}</span>`;
                }
            });
        });
    }

    // ── Section 3: Badge Holders ──
    function renderHolders() {
        holdersContainer.innerHTML = '';
        let html = '';
        if (badgeHolders.length === 0) {
            html = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">No badge holders yet.</p>';
        } else {
            html = '<div class="table-scroll-wrapper"><table class="data-table" style="font-size:var(--font-size-xs)"><thead><tr><th>Validator</th><th>Address</th><th>Status</th><th>Granted</th><th>Last Seen</th></tr></thead><tbody>';
            for (const h of badgeHolders) {
                const addr = h.pubkey || '';
                const addrShort = addr.length > 20 ? addr.slice(0, 10) + '\u2026' + addr.slice(-8) : addr;
                const statusCls = h.status === 'active' ? 'color:var(--success)' : 'color:var(--warning)';
                html += `<tr><td>${esc(h.node_name || 'Unknown')}</td><td class="mono" title="${esc(addr)}">${esc(addrShort)}</td><td style="${statusCls}">${esc(h.status || 'unknown')}</td><td>Cycle ${h.granted_at_height || '?'}</td><td>${h.last_seen ? timeAgo(h.last_seen) : '--'}</td></tr>`;
            }
            html += '</tbody></table></div>';
        }
        const details = document.createElement('details');
        details.className = 'panel';
        details.style.cssText = 'border:1px solid var(--border);border-radius:var(--radius)';
        details.innerHTML = `<summary style="padding:var(--gap-sm) var(--gap);cursor:pointer;font-weight:600;font-size:var(--font-size-sm)">Badge Holders (${badgeHolders.length})</summary><div style="padding:0 var(--gap) var(--gap)">${html}</div>`;
        holdersContainer.appendChild(details);
    }

    // ── Section 4: Create ──
    function renderCreate() {
        createContainer.innerHTML = '';
        const details = document.createElement('details');
        details.className = 'panel';
        details.style.cssText = 'border:1px solid var(--border);border-radius:var(--radius)';
        details.innerHTML = `
            <summary style="padding:var(--gap-sm) var(--gap);cursor:pointer;font-weight:600;font-size:var(--font-size-sm)">Create Proposal or Poll</summary>
            <div style="padding:var(--gap)">
                <div style="display:flex;gap:var(--gap-sm);margin-bottom:var(--gap)">
                    <button class="btn btn-sm gov-create-tab" data-tab="badge" style="font-weight:600">Badge Proposal</button>
                    <button class="btn btn-sm gov-create-tab" data-tab="dao">DAO Poll</button>
                </div>
                <div id="gov-create-badge" style="display:none">
                    <div class="form-group"><label style="font-size:var(--font-size-xs)">Target Address (nbl1... or hex)</label>
                    <input id="gov-badge-target" type="text" class="form-input" placeholder="nbl1p..." style="font-family:var(--font-mono);font-size:var(--font-size-sm)"></div>
                    <div class="form-group"><label style="font-size:var(--font-size-xs)">Type</label>
                    <select id="gov-badge-type" class="form-input" style="font-size:var(--font-size-sm)"><option value="grant">Grant</option><option value="revoke">Revoke</option></select></div>
                    <div class="form-group" id="gov-badge-reason-group" style="display:none"><label style="font-size:var(--font-size-xs)">Reason</label>
                    <select id="gov-badge-reason" class="form-input" style="font-size:var(--font-size-sm)"><option value="DuplicateProposal">Duplicate Proposal</option><option value="ProtocolAbuse">Protocol Abuse</option><option value="ExtendedAbsence">Extended Absence</option><option value="Misrepresentation">Misrepresentation</option><option value="Other">Other</option></select></div>
                    <button id="gov-badge-submit" class="btn btn-primary btn-sm" style="margin-top:var(--gap-sm)">Submit Badge Proposal</button>
                    <div id="gov-badge-msg" style="font-size:var(--font-size-xs);margin-top:var(--gap-xs)"></div>
                </div>
                <div id="gov-create-dao" style="display:none">
                    <div class="form-group"><label style="font-size:var(--font-size-xs)">Question (max 500 chars)</label>
                    <textarea id="gov-dao-question" class="form-input" rows="3" maxlength="500" placeholder="Should we..." style="font-size:var(--font-size-sm)"></textarea>
                    <div style="text-align:right;font-size:var(--font-size-xs);color:var(--text-muted)"><span id="gov-dao-chars">0</span>/500</div></div>
                    <div class="form-group"><label style="font-size:var(--font-size-xs)">Voting Window</label>
                    <select id="gov-dao-window" class="form-input" style="font-size:var(--font-size-sm)"><option value="72">24 hours (72 cycles)</option><option value="144">48 hours</option><option value="216">72 hours</option><option value="504">7 days</option><option value="720">10 days</option></select></div>
                    <button id="gov-dao-submit" class="btn btn-primary btn-sm" style="margin-top:var(--gap-sm)">Create DAO Poll</button>
                    <div id="gov-dao-msg" style="font-size:var(--font-size-xs);margin-top:var(--gap-xs)"></div>
                </div>
            </div>`;
        createContainer.appendChild(details);

        // Tab switching
        const badgePanel = details.querySelector('#gov-create-badge');
        const daoPanel = details.querySelector('#gov-create-dao');
        details.querySelectorAll('.gov-create-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                badgePanel.style.display = btn.dataset.tab === 'badge' ? '' : 'none';
                daoPanel.style.display = btn.dataset.tab === 'dao' ? '' : 'none';
            });
        });
        // Default to badge tab
        badgePanel.style.display = '';

        // Show/hide reason dropdown
        const typeSelect = details.querySelector('#gov-badge-type');
        const reasonGroup = details.querySelector('#gov-badge-reason-group');
        typeSelect.addEventListener('change', () => {
            reasonGroup.style.display = typeSelect.value === 'revoke' ? '' : 'none';
        });

        // Char counter
        const textarea = details.querySelector('#gov-dao-question');
        const charCount = details.querySelector('#gov-dao-chars');
        textarea.addEventListener('input', () => { charCount.textContent = textarea.value.length; });

        // Badge submit
        details.querySelector('#gov-badge-submit').addEventListener('click', async () => {
            const msg = details.querySelector('#gov-badge-msg');
            const target = details.querySelector('#gov-badge-target').value.trim();
            if (!target) { msg.innerHTML = '<span style="color:var(--error)">Enter target address</span>'; return; }
            msg.innerHTML = '<span style="color:var(--text-muted)">Submitting...</span>';
            try {
                const params = { target_pubkey: target, proposal_type: typeSelect.value };
                if (typeSelect.value === 'revoke') params.reason = details.querySelector('#gov-badge-reason').value;
                const res = await Bridge.call('noble_api', 'proposeBadge', params);
                msg.innerHTML = `<span style="color:var(--success)">Proposal submitted. TX: ${res.tx_hash || 'ok'}</span>`;
                setTimeout(loadAll, 2000);
            } catch (e) {
                msg.innerHTML = `<span style="color:var(--error)">${esc(e.message || 'Failed')}</span>`;
            }
        });

        // DAO submit
        details.querySelector('#gov-dao-submit').addEventListener('click', async () => {
            const msg = details.querySelector('#gov-dao-msg');
            const question = textarea.value.trim();
            if (!question) { msg.innerHTML = '<span style="color:var(--error)">Enter a question</span>'; return; }
            msg.innerHTML = '<span style="color:var(--text-muted)">Creating poll...</span>';
            try {
                const window_cycles = parseInt(details.querySelector('#gov-dao-window').value, 10);
                const res = await Bridge.call('noble_api', 'createPoll', { question, expires_cycles: window_cycles });
                msg.innerHTML = `<span style="color:var(--success)">Poll created. ID: ${res.poll_id || 'ok'}</span>`;
                setTimeout(loadAll, 2000);
            } catch (e) {
                msg.innerHTML = `<span style="color:var(--error)">${esc(e.message || 'Failed')}</span>`;
            }
        });
    }

    // ── Section 5: History ──
    function renderHistory() {
        historyContainer.innerHTML = '';
        let html = '';
        if (historyItems.length === 0) {
            html = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">No governance history yet.</p>';
        } else {
            html = '<div class="table-scroll-wrapper"><table class="data-table" style="font-size:var(--font-size-xs)"><thead><tr><th>Type</th><th>Description</th><th>Result</th><th>Votes</th><th>Cycle</th></tr></thead><tbody>';
            for (const item of historyItems) {
                let typeLabel, desc, result, votes;
                if (item._kind === 'badge') {
                    typeLabel = item.proposal_type === 'revoke' ? '\u274C Revoke' : '\u{1F3C5} Grant';
                    desc = `${item.proposal_type === 'revoke' ? 'Revoke' : 'Grant'} ${item.target_name || item.target_pubkey || ''}`;
                    result = item.status === 'passed'
                        ? `<span style="color:var(--success)">\u2705 Passed (${item.votes_for}/${item.total_eligible_voters})</span>`
                        : `<span style="color:var(--error)">\u274C ${item.status} (${item.votes_for}/${item.total_eligible_voters})</span>`;
                    votes = `${item.votes_for || 0}F ${item.votes_against || 0}A`;
                } else {
                    typeLabel = '\u{1F5F3} Poll';
                    desc = item.question || '';
                    const total = (item.votes_yes || 0) + (item.votes_no || 0) + (item.votes_abstain || 0);
                    const yesPct = total > 0 ? Math.round((item.votes_yes || 0) / total * 100) : 0;
                    result = `<span>\u{1F4CA} YES ${yesPct}%</span>`;
                    votes = `${item.votes_yes || 0}Y ${item.votes_no || 0}N ${item.votes_abstain || 0}A`;
                }
                html += `<tr><td>${typeLabel}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(desc)}">${esc(desc)}</td><td>${result}</td><td>${votes}</td><td>Cycle ${item.created_at_cycle || '?'}</td></tr>`;
            }
            html += '</tbody></table></div>';
        }
        const details = document.createElement('details');
        details.className = 'panel';
        details.style.cssText = 'border:1px solid var(--border);border-radius:var(--radius)';
        details.innerHTML = `<summary style="padding:var(--gap-sm) var(--gap);cursor:pointer;font-weight:600;font-size:var(--font-size-sm)">Governance History (${historyItems.length})</summary><div style="padding:0 var(--gap) var(--gap)">${html}</div>`;
        historyContainer.appendChild(details);
    }

    // Auto-refresh every 15s
    const autoRefreshId = setInterval(() => { if (alive) loadAll(); }, 15_000);

    return {
        destroy() { alive = false; clearInterval(autoRefreshId); },
        refresh(newState) { Object.assign(state, newState); loadAll(); }
    };
}
