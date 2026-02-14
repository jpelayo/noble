/**
 * NOBLE Dashboard — Node Health Page
 * Node info, storage gauge, uptime
 */

import { formatNumber, formatBytes, formatDuration } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;
  const unsubs = [];
  let storageChart = null;

  root.innerHTML = `
    <div class="page-header"><h1>Node Health</h1><p>System information and resource usage</p></div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Version</div>
        <div class="kpi-value" id="h-version">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Uptime</div>
        <div class="kpi-value" id="h-uptime">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Storage Used</div>
        <div class="kpi-value" id="h-storage">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Connection</div>
        <div class="kpi-value" id="h-connection">--</div>
        <div class="kpi-sub" id="h-connection-sub"></div>
      </div>
    </div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Storage Usage</div>
        <div class="panel-body"><div id="h-storage-chart" class="chart-container small"></div></div>
      </div>
      <div class="panel">
        <div class="panel-header">Node Details</div>
        <div class="panel-body">
          <dl class="detail-grid" id="h-details">
          </dl>
        </div>
      </div>
    </div>
  `;

  const hVersion = root.querySelector('#h-version');
  const hUptime = root.querySelector('#h-uptime');
  const hStorage = root.querySelector('#h-storage');
  const hConnection = root.querySelector('#h-connection');
  const hConnectionSub = root.querySelector('#h-connection-sub');
  const hDetails = root.querySelector('#h-details');

  async function loadNodeInfo() {
    try {
      const info = await rpc.call('noble_getNodeInfo');
      const syncStatus = await rpc.call('noble_getSyncStatus');

      const swVer = info.software_version || `${info.version}`;
      hVersion.textContent = `v${swVer}`;
      // Upgrade notice if a newer version was seen on the network
      if (info.latest_network_version && info.latest_network_version > swVer) {
        hVersion.innerHTML = `v${swVer} <span class="badge warning">Update available: v${info.latest_network_version}</span>`;
      }
      hUptime.textContent = formatDuration(info.uptime_secs);
      hStorage.textContent = formatBytes(info.storage_bytes);

      const connected = syncStatus.synced;
      hConnection.textContent = connected ? 'Online' : 'Syncing';
      hConnection.style.color = connected ? 'var(--success)' : 'var(--warning)';
      hConnectionSub.textContent = `${syncStatus.state}`;

      // Details grid
      hDetails.innerHTML = `
        <dt>Software</dt><dd>v${info.software_version || info.version}</dd>
        <dt>Network Latest</dt><dd>v${info.latest_network_version || '—'}</dd>
        <dt>Protocol</dt><dd>${info.protocol_version || info.version}</dd>
        <dt>Chain ID</dt><dd>0x${info.chain_id.toString(16).toUpperCase()}</dd>
        <dt>Uptime</dt><dd>${formatDuration(info.uptime_secs)}</dd>
        <dt>Storage</dt><dd>${formatBytes(info.storage_bytes)} / ${formatBytes(info.storage_capacity_bytes)}</dd>
        <dt>Data Directory</dt><dd class="mono">${info.data_dir}</dd>
        <dt>RPC Port</dt><dd>${info.rpc_port}</dd>
        <dt>WebSocket Port</dt><dd>${info.ws_port}</dd>
        <dt>P2P Port</dt><dd>${info.p2p_port}</dd>
      `;

      // Storage gauge chart
      if (typeof echarts !== 'undefined') {
        initStorageGauge(info.storage_bytes, info.storage_capacity_bytes);
      }
    } catch (e) {
      console.error('[health] load:', e);
    }
  }

  function initStorageGauge(used, capacity) {
    const dom = root.querySelector('#h-storage-chart');
    if (!dom || typeof echarts === 'undefined') return;
    storageChart = echarts.init(dom);
    const percent = Math.round((used / capacity) * 100);
    storageChart.setOption({
      series: [{
        type: 'gauge',
        min: 0,
        max: 100,
        progress: { show: true, width: 18 },
        axisLine: {
          lineStyle: {
            width: 18,
            color: [
              [0.3, '#10b981'],
              [0.7, '#f59e0b'],
              [1, '#ef4444'],
            ],
          },
        },
        axisTick: { show: false },
        splitLine: { length: 10, lineStyle: { width: 2, color: '#999' } },
        axisLabel: { distance: 20, color: '#999', fontSize: 11 },
        pointer: { itemStyle: { color: 'auto' } },
        anchor: { show: true, size: 20, itemStyle: { borderWidth: 2 } },
        title: { show: true, offsetCenter: [0, '70%'], fontSize: 14, color: 'var(--text-secondary)' },
        detail: {
          valueAnimation: true,
          fontSize: 24,
          fontWeight: 700,
          offsetCenter: [0, '40%'],
          formatter: '{value}%',
          color: 'auto',
        },
        data: [{ value: percent, name: `${formatBytes(used)} / ${formatBytes(capacity)}` }],
      }],
    });
    const ro = new ResizeObserver(() => storageChart?.resize());
    ro.observe(dom);
    unsubs.push(() => { ro.disconnect(); storageChart?.dispose(); });
  }

  // Refresh uptime every 60s
  const uptimeInterval = setInterval(async () => {
    try {
      const info = await rpc.call('noble_getNodeInfo');
      hUptime.textContent = formatDuration(info.uptime_secs);
    } catch { /* ignore */ }
  }, 60_000);
  unsubs.push(() => clearInterval(uptimeInterval));

  loadNodeInfo();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
