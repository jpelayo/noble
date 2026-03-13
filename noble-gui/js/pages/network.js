/**
 * NOBLE Dashboard — Network Page
 * Peer table + distribution chart + sync status
 */

import { formatNumber, truncateHash } from '../utils.js';

function extractIpFromMultiaddr(ma) {
  if (!ma) return null;
  const m = ma.match(/\/ip[46]\/([^/]+)/);
  return m ? m[1] : ma; // Return raw string if not a multiaddr
}

export function init(root, ctx) {
  const { rpc, ws } = ctx;
  const unsubs = [];
  let peerChart = null;

  root.innerHTML = `
    <div class="page-header" style="display:flex;align-items:baseline;gap:var(--gap-sm)">
      <div><h1 style="display:inline">Network</h1><p>Connected peers and sync status</p></div>
      <button id="net-ban-gear" title="Ban Management" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1;margin-top:4px">&#9881;</button>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Peers</div>
        <div class="kpi-value" id="net-total">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Inbound</div>
        <div class="kpi-value" id="net-inbound">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Outbound</div>
        <div class="kpi-value" id="net-outbound">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Sync Status</div>
        <div class="kpi-value" id="net-sync">--</div>
      </div>
    </div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Peer Distribution</div>
        <div class="panel-body"><div id="net-chart" class="chart-container small"></div></div>
      </div>
      <div class="panel">
        <div class="panel-header">Sync Progress</div>
        <div class="panel-body" id="net-sync-detail"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">Dial Peer</div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Manually connect to a peer by entering their multiaddr.
        </p>
        <div style="display:flex;gap:var(--gap-sm);align-items:center">
          <input id="net-dial-addr" type="text" placeholder="e.g. node.infinitecontext.com or 192.168.5.20"
            style="flex:1;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
          <button id="net-dial-btn" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm);white-space:nowrap">Dial Peer</button>
        </div>
        <div id="net-dial-msg" style="font-size:var(--font-size-xs);margin-top:var(--gap-sm);display:none"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">Peer Table</div>
      <div class="panel-body" style="padding:0">
        <table class="data-table">
          <thead>
            <tr>
              <th>Peer ID</th>
              <th>Name</th>
              <th>Address</th>
              <th>Country</th>
              <th>Status</th>
              <th>Direction</th>
              <th>Ban Score</th>
            </tr>
          </thead>
          <tbody id="net-peers"></tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span>Connectivity Log</span>
        <button class="btn btn-sm" id="net-log-clear">Clear</button>
      </div>
      <div class="panel-body" style="padding:0;max-height:260px;overflow-y:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th style="width:80px;white-space:nowrap">Time</th>
              <th style="width:100px;white-space:nowrap">Event</th>
              <th>Peer</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody id="net-conn-log"></tbody>
        </table>
      </div>
    </div>

    <!-- Ban Management Modal -->
    <div id="net-ban-modal" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);align-items:center;justify-content:center">
      <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:900px;width:95%;max-height:80vh;overflow-y:auto;padding:var(--gap-lg)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap)">
          <h2 style="margin:0;font-size:1.2rem">Ban Management</h2>
          <button id="ban-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.5rem;cursor:pointer;padding:0 4px;line-height:1" title="Close">&times;</button>
        </div>
        <div style="display:flex;gap:var(--gap-sm);margin-bottom:var(--gap);border-bottom:1px solid var(--border);padding-bottom:var(--gap-sm)">
          <button class="ban-tab btn-sm" data-tab="banned" style="padding:6px 14px;border-radius:var(--radius-sm);border:1px solid var(--border);cursor:pointer;background:var(--accent);color:#fff">Banned Peers</button>
          <button class="ban-tab btn-sm" data-tab="manual" style="padding:6px 14px;border-radius:var(--radius-sm);border:1px solid var(--border);cursor:pointer;background:var(--bg-tertiary);color:var(--text-primary)">Manual Ban</button>
          <button class="ban-tab btn-sm" data-tab="scores" style="padding:6px 14px;border-radius:var(--radius-sm);border:1px solid var(--border);cursor:pointer;background:var(--bg-tertiary);color:var(--text-primary)">Active Scores</button>
        </div>
        <div id="ban-tab-banned">
          <table class="data-table" style="width:100%">
            <thead><tr><th>Peer ID</th><th>Name</th><th>Reason</th><th>Expires</th><th></th></tr></thead>
            <tbody id="ban-list-body"></tbody>
          </table>
          <p id="ban-list-empty" style="color:var(--text-muted);text-align:center;padding:var(--gap);display:none">No banned peers</p>
        </div>
        <div id="ban-tab-manual" style="display:none">
          <div style="display:flex;flex-direction:column;gap:var(--gap-sm)">
            <label style="font-size:var(--font-size-sm);color:var(--text-secondary)">Peer ID (hex)</label>
            <input id="ban-peer-id" type="text" placeholder="Hex-encoded peer ID" style="padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
            <label style="font-size:var(--font-size-sm);color:var(--text-secondary)">Reason</label>
            <select id="ban-reason" style="padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-size:var(--font-size-sm)">
              <option value="manual_ban">Manual Ban</option>
              <option value="invalid_block">Invalid Block</option>
              <option value="invalid_transaction">Invalid Transaction</option>
              <option value="protocol_violation">Protocol Violation</option>
              <option value="duplicate_proposal">Duplicate Proposal</option>
              <option value="excessive_connections">Excessive Connections</option>
              <option value="unresponsive">Unresponsive</option>
              <option value="invalid_vote">Invalid Vote</option>
              <option value="invalid_announce">Invalid Announce</option>
              <option value="tx_flood">TX Flood</option>
              <option value="evidence_received">Evidence Received</option>
              <option value="misrepresentation">Misrepresentation</option>
            </select>
            <label style="font-size:var(--font-size-sm);color:var(--text-secondary)">Duration</label>
            <select id="ban-duration" style="padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-size:var(--font-size-sm)">
              <option value="3600">1 hour</option>
              <option value="21600">6 hours</option>
              <option value="86400" selected>24 hours</option>
              <option value="604800">7 days</option>
              <option value="0">Permanent</option>
            </select>
            <button id="ban-submit-btn" class="btn-sm" style="padding:8px 16px;background:var(--error);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;align-self:flex-start;margin-top:var(--gap-sm)">Ban Peer</button>
            <div id="ban-submit-msg" style="font-size:var(--font-size-xs);display:none"></div>
          </div>
        </div>
        <div id="ban-tab-scores" style="display:none">
          <table class="data-table" style="width:100%">
            <thead><tr><th>Peer ID</th><th>Name</th><th>Score</th><th>Bar</th><th>Last Reason</th></tr></thead>
            <tbody id="ban-scores-body"></tbody>
          </table>
          <p id="ban-scores-empty" style="color:var(--text-muted);text-align:center;padding:var(--gap);display:none">No peers with active ban scores</p>
        </div>
      </div>
    </div>
  `;

  const netTotal = root.querySelector('#net-total');
  const netInbound = root.querySelector('#net-inbound');
  const netOutbound = root.querySelector('#net-outbound');
  const netSync = root.querySelector('#net-sync');
  const netSyncDetail = root.querySelector('#net-sync-detail');
  const peersTbody = root.querySelector('#net-peers');
  const dialAddrInput = root.querySelector('#net-dial-addr');
  const dialBtn = root.querySelector('#net-dial-btn');
  const dialMsg = root.querySelector('#net-dial-msg');

  dialBtn.addEventListener('click', async () => {
    const addr = dialAddrInput.value.trim();
    if (!addr) return;
    dialBtn.disabled = true;
    dialMsg.style.display = 'block';
    dialMsg.style.color = 'var(--text-muted)';
    dialMsg.textContent = 'Dialing...';
    try {
      const result = await rpc.call('noble_dialPeer', { multiaddr: addr });
      if (result.success) {
        dialMsg.style.color = 'var(--success)';
        dialMsg.textContent = result.message || 'Connected';
        dialAddrInput.value = '';
        setTimeout(loadNetwork, 1000);
      } else {
        dialMsg.style.color = 'var(--error)';
        dialMsg.textContent = result.message || 'Connection failed';
      }
      setTimeout(() => { dialMsg.style.display = 'none'; }, 8000);
    } catch (e) {
      dialMsg.style.color = 'var(--error)';
      dialMsg.textContent = e.message || 'Failed to dial peer';
    } finally {
      dialBtn.disabled = false;
    }
  });
  dialAddrInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') dialBtn.click();
  });

  async function loadNetwork() {
    try {
      const [networkInfo, peers, syncStatus] = await Promise.all([
        rpc.call('noble_getNetworkInfo'),
        rpc.call('noble_getPeerInfo'),
        rpc.call('noble_getSyncStatus'),
      ]);

      netTotal.textContent = formatNumber(networkInfo.peer_count);
      netInbound.textContent = formatNumber(networkInfo.inbound);
      netOutbound.textContent = formatNumber(networkInfo.outbound);
      netSync.textContent = syncStatus.state;

      // Sync detail
      netSyncDetail.innerHTML = `
        <dl class="detail-grid">
          <dt>State</dt><dd>${syncStatus.state}</dd>
          <dt>Current Height</dt><dd>${formatNumber(syncStatus.current_height)}</dd>
          <dt>Highest Known</dt><dd>${formatNumber(syncStatus.highest_known)}</dd>
          <dt>Progress</dt><dd>${(syncStatus.progress * 100).toFixed(1)}%</dd>
        </dl>
      `;

      // Peer table
      renderPeerTable(peers);

      // Peer distribution chart
      if (typeof echarts !== 'undefined') {
        initPeerChart(networkInfo.inbound, networkInfo.outbound);
      }
    } catch (e) {
      console.error('[network] load:', e);
    }
  }

  function renderPeerTable(peers) {
    peersTbody.innerHTML = '';
    // Sort: connected first, then disconnected
    const sorted = [...peers].sort((a, b) => {
      if (a.status === b.status) return 0;
      return a.status === 'connected' ? -1 : 1;
    });
    for (const peer of sorted) {
      const tr = document.createElement('tr');
      const dir = peer.direction || 'none';
      const dirClass = dir === 'inbound' ? 'inbound' : dir === 'outbound' ? 'outbound' : '';
      const name = peer.node_name || '<span style="color:var(--text-muted)">&mdash;</span>';
      const rawIp = extractIpFromMultiaddr(peer.addr);
      const addr = rawIp
        ? `<span class="mono" style="font-size:var(--font-size-xs)">${rawIp} <button class="btn-copy" data-copy="${rawIp}" title="Copy IP">&#128203;</button></span>`
        : '<span style="color:var(--text-muted)">&mdash;</span>';
      const country = peer.country_code || '<span style="color:var(--text-muted)">&mdash;</span>';
      const banScore = peer.ban_score || 0;
      const banScoreColor = banScore > 50 ? 'var(--error)' : banScore > 0 ? 'var(--warning)' : 'var(--text-muted)';
      const cats = peer.misbehavior_categories || [];
      const banTitle = cats.length > 0
        ? ` title="${cats.join(', ')}"`
        : '';
      const isConnected = peer.status === 'connected';
      const statusBadge = isConnected
        ? '<span style="display:inline-block;padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--font-size-xs);font-weight:600;background:rgba(16,185,129,0.15);color:var(--success)">Connected</span>'
        : '<span style="display:inline-block;padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--font-size-xs);font-weight:600;background:var(--bg-tertiary);color:var(--text-muted)">Disconnected</span>';
      tr.innerHTML = `
        <td class="mono">${truncateHash(peer.peer_id, 8)} <button class="btn-copy" data-copy="${peer.peer_id}" title="Copy peer ID">&#128203;</button></td>
        <td>${name}</td>
        <td>${addr}</td>
        <td>${country}</td>
        <td>${statusBadge}</td>
        <td><span class="badge ${dirClass}">${dir}</span></td>
        <td style="color:${banScoreColor};font-weight:600"${banTitle}>${banScore}</td>
      `;
      if (!isConnected) tr.style.opacity = '0.6';
      peersTbody.appendChild(tr);
    }
  }

  function initPeerChart(inbound, outbound) {
    const dom = root.querySelector('#net-chart');
    if (!dom || typeof echarts === 'undefined') return;
    peerChart = echarts.init(dom);
    peerChart.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie',
        radius: ['45%', '70%'],
        label: {
          color: 'var(--text-primary)',
          formatter: '{b}: {c}',
        },
        data: [
          { value: inbound, name: 'Inbound', itemStyle: { color: '#10b981' } },
          { value: outbound, name: 'Outbound', itemStyle: { color: '#3b82f6' } },
        ],
      }],
    });
    const ro = new ResizeObserver(() => peerChart?.resize());
    ro.observe(dom);
    unsubs.push(() => { ro.disconnect(); peerChart?.dispose(); });
  }

  // ── Connectivity log (reads from global window._connLog) ──
  const connLogBody = root.querySelector('#net-conn-log');

  function renderConnLog() {
    const entries = window._connLog || [];
    if (entries.length === 0) {
      connLogBody.innerHTML = '<tr><td colspan="4" class="empty-state">No connectivity events yet</td></tr>';
      return;
    }
    connLogBody.innerHTML = entries.slice().reverse().map(e => {
      const evColor = e.event === 'disconnected' ? 'var(--warning,#fbbf24)'
        : 'var(--error,#f87171)';
      const name = e.node_name || '';
      const pid = e.peer_id ? e.peer_id.slice(0, 12) + '...' : '';
      const peer = name || pid || '—';
      const parts = [];
      if (e.direction) parts.push(e.direction);
      if (e.addr) parts.push(e.addr);
      if (e.reason) parts.push(e.reason);
      if (e.event === 'connected' && parts.length === 0) parts.push('session established');
      if (e.event === 'disconnected' && !e.reason) parts.push('connection closed (no reason given)');
      const detail = parts.join(' \u00b7 ');
      return `<tr>
        <td class="mono" style="font-size:var(--font-size-xs);white-space:nowrap">${e.time}</td>
        <td style="white-space:nowrap"><span style="color:${evColor};font-weight:600;font-size:var(--font-size-xs);text-transform:uppercase">${e.event}</span></td>
        <td style="font-size:var(--font-size-sm)" title="${esc(pid)}">${esc(peer)}</td>
        <td style="font-size:var(--font-size-sm);color:var(--text-secondary)">${esc(detail)}</td>
      </tr>`;
    }).join('');
    connLogBody.parentElement.scrollTop = 0;
  }

  root.querySelector('#net-log-clear').addEventListener('click', () => {
    window._connLog = [];
    renderConnLog();
  });

  // Render existing global events (captured while on other pages).
  renderConnLog();

  // Re-render when new events arrive from app.js global handler.
  // Also refresh the peer table so ban scores update in real time.
  const onNewLog = async () => {
    renderConnLog();
    try {
      const peers = await rpc.call('noble_getPeerInfo');
      renderPeerTable(peers);
    } catch { /* ignore */ }
  };
  window.addEventListener('noble-conn-log', onNewLog);
  unsubs.push(() => window.removeEventListener('noble-conn-log', onNewLog));

  // WS: peer updates — refresh peer table (logging is handled globally in app.js).
  unsubs.push(ws.subscribe('peerUpdates', async () => {
    try {
      const peers = await rpc.call('noble_getPeerInfo');
      renderPeerTable(peers);
    } catch { /* ignore */ }
  }));

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

  // ── Ban Management Modal ──
  const banGear = root.querySelector('#net-ban-gear');
  const banModal = root.querySelector('#net-ban-modal');
  const banModalClose = root.querySelector('#ban-modal-close');
  let banPollInterval = null;

  function openBanModal() {
    banModal.style.display = 'flex';
    loadBannedPeers();
    banPollInterval = setInterval(loadBannedPeers, 10000);
  }
  function closeBanModal() {
    banModal.style.display = 'none';
    if (banPollInterval) { clearInterval(banPollInterval); banPollInterval = null; }
  }
  banGear.addEventListener('click', openBanModal);
  banModalClose.addEventListener('click', closeBanModal);
  banModal.addEventListener('click', (e) => { if (e.target === banModal) closeBanModal(); });

  // Tab switching
  const banTabs = root.querySelectorAll('.ban-tab');
  banTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      banTabs.forEach(t => { t.style.background = 'var(--bg-tertiary)'; t.style.color = 'var(--text-primary)'; });
      tab.style.background = 'var(--accent)'; tab.style.color = '#fff';
      root.querySelector('#ban-tab-banned').style.display = tab.dataset.tab === 'banned' ? '' : 'none';
      root.querySelector('#ban-tab-manual').style.display = tab.dataset.tab === 'manual' ? '' : 'none';
      root.querySelector('#ban-tab-scores').style.display = tab.dataset.tab === 'scores' ? '' : 'none';
      if (tab.dataset.tab === 'scores') loadBanScores();
      if (tab.dataset.tab === 'banned') loadBannedPeers();
    });
  });

  async function loadBannedPeers() {
    try {
      const bans = await rpc.call('noble_listBannedPeers');
      const tbody = root.querySelector('#ban-list-body');
      const empty = root.querySelector('#ban-list-empty');
      tbody.innerHTML = '';
      if (!bans || bans.length === 0) {
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      for (const b of bans) {
        const tr = document.createElement('tr');
        const expiry = new Date(b.banned_until * 1000).toLocaleString();
        const name = b.node_name || '<span style="color:var(--text-muted)">&mdash;</span>';
        const reason = `${b.reason_category}${b.reason_subject ? ': ' + b.reason_subject : ''}`;
        const evHash = b.evidence_hash ? ` <span class="mono" style="opacity:0.6" title="${b.evidence_hash}">[ev:${b.evidence_hash.slice(0,8)}]</span>` : '';
        tr.innerHTML = `
          <td class="mono" style="font-size:var(--font-size-xs)">${truncateHash(b.peer_id, 8)}</td>
          <td>${name}</td>
          <td style="font-size:var(--font-size-xs)">${reason}${evHash}</td>
          <td style="font-size:var(--font-size-xs)">${expiry}</td>
          <td><button class="btn-sm unban-btn" data-pid="${b.peer_id}" style="padding:4px 10px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Unban</button></td>
        `;
        tbody.appendChild(tr);
      }
    } catch (e) { console.error('[ban-modal] load bans:', e); }
  }

  // Unban delegation
  root.addEventListener('click', async (e) => {
    const btn = e.target.closest('.unban-btn');
    if (!btn) return;
    const pid = btn.dataset.pid;
    btn.disabled = true;
    try {
      await rpc.call('noble_unbanPeer', { peer_id: pid });
      loadBannedPeers();
    } catch (err) { console.error('[ban-modal] unban:', err); }
    btn.disabled = false;
  });

  // Manual ban submit
  const banSubmitBtn = root.querySelector('#ban-submit-btn');
  const banSubmitMsg = root.querySelector('#ban-submit-msg');
  banSubmitBtn.addEventListener('click', async () => {
    const peerId = root.querySelector('#ban-peer-id').value.trim();
    if (!peerId) return;
    const reason = root.querySelector('#ban-reason').value;
    const durVal = parseInt(root.querySelector('#ban-duration').value, 10);
    const durSecs = durVal === 0 ? 31536000 : durVal; // 0 = "permanent" → 1 year
    banSubmitBtn.disabled = true;
    banSubmitMsg.style.display = 'block';
    banSubmitMsg.style.color = 'var(--text-muted)';
    banSubmitMsg.textContent = 'Banning...';
    try {
      const result = await rpc.call('noble_banPeer', { peer_id: peerId, reason, duration_secs: durSecs });
      if (result.success) {
        banSubmitMsg.style.color = 'var(--success)';
        banSubmitMsg.textContent = 'Peer banned successfully';
        root.querySelector('#ban-peer-id').value = '';
        loadBannedPeers();
      } else {
        banSubmitMsg.style.color = 'var(--error)';
        banSubmitMsg.textContent = 'Ban failed';
      }
    } catch (err) {
      banSubmitMsg.style.color = 'var(--error)';
      banSubmitMsg.textContent = err.message || 'Ban failed';
    }
    banSubmitBtn.disabled = false;
    setTimeout(() => { banSubmitMsg.style.display = 'none'; }, 5000);
  });

  // Active scores tab
  async function loadBanScores() {
    try {
      const peers = await rpc.call('noble_getPeerInfo');
      const withScore = (peers || []).filter(p => p.ban_score > 0 && p.status === 'connected');
      const tbody = root.querySelector('#ban-scores-body');
      const empty = root.querySelector('#ban-scores-empty');
      tbody.innerHTML = '';
      if (withScore.length === 0) { empty.style.display = ''; return; }
      empty.style.display = 'none';
      for (const p of withScore.sort((a, b) => b.ban_score - a.ban_score)) {
        const tr = document.createElement('tr');
        const name = p.node_name || '<span style="color:var(--text-muted)">&mdash;</span>';
        const pct = Math.min(100, p.ban_score);
        const barColor = pct > 50 ? 'var(--error)' : pct > 25 ? 'var(--warning)' : 'var(--success)';
        const lastReason = p.last_ban_reason ? `${p.last_ban_reason.category}` : '&mdash;';
        tr.innerHTML = `
          <td class="mono" style="font-size:var(--font-size-xs)">${truncateHash(p.peer_id, 8)}</td>
          <td>${name}</td>
          <td style="font-weight:600;color:${barColor}">${p.ban_score}</td>
          <td><div style="background:var(--bg-tertiary);border-radius:2px;height:8px;width:100px;overflow:hidden"><div style="background:${barColor};height:100%;width:${pct}%"></div></div></td>
          <td style="font-size:var(--font-size-xs)">${lastReason}</td>
        `;
        tbody.appendChild(tr);
      }
    } catch (e) { console.error('[ban-modal] load scores:', e); }
  }

  unsubs.push(() => { if (banPollInterval) clearInterval(banPollInterval); });

  // WS reconnect: refresh peer table and network stats
  function onWsReconnect() { loadNetwork(); }
  window.addEventListener('noble-ws-reconnect', onWsReconnect);
  unsubs.push(() => window.removeEventListener('noble-ws-reconnect', onWsReconnect));

  loadNetwork();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
