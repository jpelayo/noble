/**
 * NOBLE Dashboard — Overview Page
 * KPI cards + recent blocks + recent txs + charts
 */

import { formatNumber, truncateHash, timeAgo, formatFee } from '../utils.js';

export function init(root, ctx) {
  const { rpc, ws, state, subscribe } = ctx;
  const unsubs = [];
  let txPerBlockChart = null;

  root.innerHTML = `
    <div class="page-header"><h1>Overview</h1><p>NOBLE blockchain at a glance</p></div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Block Height</div>
        <div class="kpi-value" id="ov-height">--</div>
        <div class="kpi-sub">chain tip</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Peers</div>
        <div class="kpi-value" id="ov-peers">--</div>
        <div class="kpi-sub">connected nodes</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Mempool</div>
        <div class="kpi-value" id="ov-mempool">--</div>
        <div class="kpi-sub">pending transactions</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Cycle Phase</div>
        <div class="kpi-value" id="ov-phase">--</div>
        <div class="kpi-sub" id="ov-phase-timer"></div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-header">Transactions per Block</div>
        <div class="panel-body"><div id="ov-tx-chart" class="chart-container small"></div></div>
      </div>
    </div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Recent Blocks</div>
        <div class="panel-body" style="padding:0">
          <table class="data-table">
            <thead><tr><th>Height</th><th>Hash</th><th>Txs</th><th>Time</th></tr></thead>
            <tbody id="ov-blocks"></tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">Recent Transactions</div>
        <div class="panel-body" style="padding:0">
          <table class="data-table">
            <thead><tr><th>Tx ID</th><th>Fee</th><th>Time</th></tr></thead>
            <tbody id="ov-txs"></tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  // Check if node is configured as validator; show banner if observer-only.
  (async () => {
    try {
      const ident = await rpc.call('noble_getNodeIdentity');
      if (!ident.wants_to_validate && !ident.wants_to_vote) {
        const banner = document.createElement('div');
        banner.className = 'setup-banner';
        banner.innerHTML = `
          <span>This node is running as an observer — not configured as a validator.</span>
          <a href="#/setup" class="btn btn-sm">Configure Node</a>
        `;
        const header = root.querySelector('.page-header');
        if (header) header.after(banner);
      }
    } catch { /* RPC not available — skip banner */ }
  })();

  const ovHeight = root.querySelector('#ov-height');
  const ovPeers = root.querySelector('#ov-peers');
  const ovMempool = root.querySelector('#ov-mempool');
  const ovPhase = root.querySelector('#ov-phase');
  const ovPhaseTimer = root.querySelector('#ov-phase-timer');
  const ovBlocks = root.querySelector('#ov-blocks');
  const ovTxs = root.querySelector('#ov-txs');

  function flashKpi(el, val) {
    el.textContent = val;
    el.classList.add('flash');
    setTimeout(() => el.classList.remove('flash'), 600);
  }

  unsubs.push(subscribe('blockHeight', (v) => flashKpi(ovHeight, formatNumber(v))));
  unsubs.push(subscribe('peerCount', (v) => { ovPeers.textContent = formatNumber(v); }));
  unsubs.push(subscribe('mempoolSize', (v) => { ovMempool.textContent = formatNumber(v); }));
  unsubs.push(subscribe('cyclePhase', (v) => { ovPhase.textContent = v; }));

  // Initialize KPI from current state
  ovHeight.textContent = formatNumber(state.blockHeight);
  ovPeers.textContent = formatNumber(state.peerCount);
  ovMempool.textContent = formatNumber(state.mempoolSize);
  ovPhase.textContent = state.cyclePhase;

  // Cycle countdown
  let countdownInterval = null;
  async function updateCycleCountdown() {
    try {
      const cs = await rpc.call('noble_getCycleStatus');
      let remaining = cs.phase_remaining_secs;
      ovPhaseTimer.textContent = `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')} remaining`;
      clearInterval(countdownInterval);
      countdownInterval = setInterval(() => {
        remaining--;
        if (remaining <= 0) { updateCycleCountdown(); return; }
        ovPhaseTimer.textContent = `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')} remaining`;
      }, 1000);
    } catch { /* ignore */ }
  }
  updateCycleCountdown();

  // Recent blocks table
  async function loadRecentBlocks() {
    try {
      const count = await rpc.call('noble_getBlockCount');
      const start = Math.max(0, count.height - 9);
      const blocks = await rpc.call('noble_getBlockRange', { start, end: count.height });
      ovBlocks.innerHTML = '';
      for (const b of blocks.reverse()) {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.innerHTML = `
          <td>${formatNumber(b.header.height)}</td>
          <td class="mono">${truncateHash(b.hash)}</td>
          <td>${b.header.tx_count}</td>
          <td>${timeAgo(b.header.timestamp)}</td>
        `;
        tr.addEventListener('click', () => { location.hash = `#/block/${b.header.height}`; });
        ovBlocks.appendChild(tr);
      }

      // Update chart
      if (typeof echarts !== 'undefined' && blocks.length > 0) {
        initTxChart(blocks.reverse());
      }
    } catch (e) {
      console.error('[overview] loadRecentBlocks:', e);
    }
  }

  // Recent mempool txs
  async function loadRecentTxs() {
    try {
      const info = await rpc.call('noble_getMempoolInfo');
      ovTxs.innerHTML = '';
      for (const entry of (info.entries || []).slice(0, 10)) {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.innerHTML = `
          <td class="mono">${truncateHash(entry.tx_id)}</td>
          <td>${formatFee(entry.fee)}</td>
          <td>${timeAgo(entry.received_at)}</td>
        `;
        tr.addEventListener('click', () => { location.hash = `#/tx/${entry.tx_id}`; });
        ovTxs.appendChild(tr);
      }
    } catch (e) {
      console.error('[overview] loadRecentTxs:', e);
    }
  }

  // ECharts: tx per block line chart
  function initTxChart(blocks) {
    const dom = root.querySelector('#ov-tx-chart');
    if (!dom || typeof echarts === 'undefined') return;
    const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? undefined : undefined;
    txPerBlockChart = echarts.init(dom);
    txPerBlockChart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 40, right: 16, top: 16, bottom: 30 },
      xAxis: {
        type: 'category',
        data: blocks.map(b => `#${b.header.height}`),
        axisLabel: { color: 'var(--chart-text)' },
        axisLine: { lineStyle: { color: 'var(--chart-grid)' } },
      },
      yAxis: {
        type: 'value',
        axisLabel: { color: 'var(--chart-text)' },
        splitLine: { lineStyle: { color: 'var(--chart-grid)' } },
      },
      series: [{
        type: 'line',
        smooth: true,
        areaStyle: { opacity: 0.15 },
        symbolSize: 4,
        data: blocks.map(b => b.header.tx_count),
        itemStyle: { color: '#3b82f6' },
        areaStyle: { color: 'rgba(59,130,246,0.15)' },
      }],
    });
    const ro = new ResizeObserver(() => txPerBlockChart?.resize());
    ro.observe(dom);
    unsubs.push(() => { ro.disconnect(); txPerBlockChart?.dispose(); });
  }

  // WS: new blocks refresh
  ws.subscribe('newBlocks', () => {
    loadRecentBlocks();
  });
  unsubs.push(() => ws.unsubscribe('newBlocks'));

  ws.subscribe('newTransactions', () => {
    loadRecentTxs();
  });
  unsubs.push(() => ws.unsubscribe('newTransactions'));

  loadRecentBlocks();
  loadRecentTxs();

  return {
    destroy() {
      clearInterval(countdownInterval);
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
