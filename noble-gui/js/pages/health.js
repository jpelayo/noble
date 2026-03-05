/**
 * NOBLE Dashboard — Node Health Page
 * Node info, storage gauge, uptime
 */

import { formatNumber, formatBytes, formatDuration, formatChainLabel } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;
  const unsubs = [];


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

    <div class="panel">
      <div class="panel-header">Node Details</div>
      <div class="panel-body">
        <dl class="detail-grid" id="h-details">
        </dl>
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
      hStorage.textContent = info.storage_bytes != null ? formatBytes(info.storage_bytes) : 'N/A';

      const connected = syncStatus.synced;
      hConnection.textContent = connected ? 'Online' : 'Syncing';
      hConnection.style.color = connected ? 'var(--success)' : 'var(--warning)';
      hConnectionSub.textContent = `${syncStatus.state}`;

      // Details grid
      hDetails.innerHTML = `
        <dt>Software</dt><dd>v${info.software_version || info.version}</dd>
        <dt>Network Latest</dt><dd>v${info.latest_network_version || '—'}</dd>
        <dt>Protocol</dt><dd>${info.protocol_version || info.version}</dd>
        <dt>Chain</dt><dd>${info.chain_id ? formatChainLabel(info) : '\u2014'}</dd>
        <dt>Uptime</dt><dd>${formatDuration(info.uptime_secs)}</dd>
        <dt>Storage</dt><dd>${info.storage_bytes != null ? formatBytes(info.storage_bytes) : 'N/A'} / ${info.storage_capacity_bytes != null ? formatBytes(info.storage_capacity_bytes) : 'N/A'}</dd>
        <dt>Data Directory</dt><dd class="mono">${info.data_dir || 'N/A'}</dd>
        <dt>RPC Port</dt><dd>${info.rpc_port}</dd>
        <dt>WebSocket Port</dt><dd>${info.ws_port}</dd>
        <dt>P2P Port</dt><dd>${info.p2p_port}</dd>
      `;

    } catch (e) {
      console.error('[health] load:', e);
    }
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
