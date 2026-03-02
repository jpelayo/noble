/**
 * NOBLE Dashboard — Network Page
 * Peer table + distribution chart + sync status
 */

import { formatNumber, truncateHash } from '../utils.js';

export function init(root, ctx) {
  const { rpc, ws } = ctx;
  const unsubs = [];
  let peerChart = null;

  root.innerHTML = `
    <div class="page-header"><h1>Network</h1><p>Connected peers and sync status</p></div>

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
          <input id="net-dial-addr" type="text" placeholder="e.g. 192.168.5.20 or /ip4/1.2.3.4/tcp/8780"
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
              <th>Direction</th>
              <th>Ban Score</th>
            </tr>
          </thead>
          <tbody id="net-peers"></tbody>
        </table>
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
    for (const peer of peers) {
      const tr = document.createElement('tr');
      const dirClass = peer.direction === 'Inbound' ? 'inbound' : 'outbound';
      const name = peer.node_name || '<span style="color:var(--text-muted)">&mdash;</span>';
      const addr = peer.addr
        ? `<span class="mono" style="font-size:var(--font-size-xs)">${peer.addr}</span>`
        : '<span style="color:var(--text-muted)">&mdash;</span>';
      const country = peer.country_code || '<span style="color:var(--text-muted)">&mdash;</span>';
      const banScore = peer.ban_score || 0;
      const banScoreColor = banScore > 50 ? 'var(--error)' : banScore > 0 ? 'var(--warning)' : 'var(--text-muted)';
      const banTitle = peer.last_ban_reason
        ? ` title="${peer.last_ban_reason.category}: ${peer.last_ban_reason.subject || ''}"`
        : '';
      tr.innerHTML = `
        <td class="mono">${truncateHash(peer.peer_id, 8)}</td>
        <td>${name}</td>
        <td>${addr}</td>
        <td>${country}</td>
        <td><span class="badge ${dirClass}">${peer.direction}</span></td>
        <td style="color:${banScoreColor};font-weight:600"${banTitle}>${banScore}</td>
      `;
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

  // WS: peer updates
  ws.subscribe('peerUpdates', async () => {
    try {
      const peers = await rpc.call('noble_getPeerInfo');
      renderPeerTable(peers);
    } catch { /* ignore */ }
  });
  unsubs.push(() => ws.unsubscribe('peerUpdates'));

  loadNetwork();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
