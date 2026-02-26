/**
 * NOBLE Dashboard — Storage Management Page
 * Chain pruning status, storage info, pruning controls
 */

import { formatNumber, formatBytes } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;
  const unsubs = [];

  root.innerHTML = `
    <div class="page-header"><h1>Storage</h1><p>Chain data management and pruning controls</p></div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Chain Height</div>
        <div class="kpi-value" id="st-height">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Pruning Mode</div>
        <div class="kpi-value" id="st-mode">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Pruned Up To</div>
        <div class="kpi-value" id="st-pruned">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Lowest Full Block</div>
        <div class="kpi-value" id="st-lowest">--</div>
      </div>
    </div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Storage Info</div>
        <div class="panel-body">
          <dl class="detail-grid" id="st-info-grid"></dl>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">Pruning Status</div>
        <div class="panel-body">
          <dl class="detail-grid" id="st-pruning-grid"></dl>
          <div id="st-pruning-actions" style="margin-top:1rem;text-align:right"></div>
        </div>
      </div>
    </div>

    <div class="panel" style="margin-top:1rem">
      <div class="panel-header">Block Retention</div>
      <div class="panel-body">
        <div id="st-retention-chart" class="chart-container small"></div>
      </div>
    </div>
  `;

  const stHeight = root.querySelector('#st-height');
  const stMode = root.querySelector('#st-mode');
  const stPruned = root.querySelector('#st-pruned');
  const stLowest = root.querySelector('#st-lowest');
  const infoGrid = root.querySelector('#st-info-grid');
  const pruningGrid = root.querySelector('#st-pruning-grid');
  let retentionChart = null;

  async function loadStorage() {
    try {
      const [storageInfo, pruningStatus] = await Promise.all([
        rpc.call('noble_getStorageInfo'),
        rpc.call('noble_getPruningStatus'),
      ]);

      // KPI cards
      stHeight.textContent = formatNumber(storageInfo.chain_height);
      stMode.textContent = storageInfo.pruning_mode;
      stMode.style.color = storageInfo.pruning_mode === 'archive'
        ? 'var(--success)' : 'var(--warning)';
      stPruned.textContent = storageInfo.pruned_up_to > 0
        ? formatNumber(storageInfo.pruned_up_to) : 'None';
      stLowest.textContent = formatNumber(storageInfo.lowest_full_height);

      // Storage info detail grid
      infoGrid.innerHTML = `
        <dt>Chain Height</dt><dd>${formatNumber(storageInfo.chain_height)}</dd>
        <dt>Pruning Mode</dt><dd>${storageInfo.pruning_mode}</dd>
        <dt>Keep Blocks</dt><dd>${formatNumber(storageInfo.keep_blocks)}</dd>
        <dt>Pruned Up To</dt><dd>${storageInfo.pruned_up_to > 0 ? formatNumber(storageInfo.pruned_up_to) : 'N/A'}</dd>
        <dt>Lowest Full Height</dt><dd>${formatNumber(storageInfo.lowest_full_height)}</dd>
      `;

      // Pruning status detail grid
      pruningGrid.innerHTML = `
        <dt>Mode</dt><dd>${pruningStatus.mode}</dd>
        <dt>Blocks Pruned</dt><dd>${formatNumber(pruningStatus.blocks_pruned)}</dd>
        <dt>Transactions Removed</dt><dd>${formatNumber(pruningStatus.transactions_removed)}</dd>
        <dt>Lowest Full Height</dt><dd>${formatNumber(pruningStatus.lowest_full_height)}</dd>
        <dt>More Remaining</dt><dd>${pruningStatus.more_remaining ? 'Yes' : 'No'}</dd>
      `;

      // Retention chart
      if (typeof echarts !== 'undefined') {
        initRetentionChart(storageInfo);
      }
    } catch (e) {
      console.error('[storage] load:', e);
      infoGrid.innerHTML = '<dt>Error</dt><dd>Failed to load storage info</dd>';
    }
  }

  function initRetentionChart(info) {
    const dom = root.querySelector('#st-retention-chart');
    if (!dom || typeof echarts === 'undefined') return;
    retentionChart = echarts.init(dom);

    const pruned = info.pruned_up_to;
    const full = info.chain_height - info.lowest_full_height + 1;
    const kept = info.keep_blocks;

    retentionChart.setOption({
      tooltip: { trigger: 'item', formatter: '{b}: {c} blocks ({d}%)' },
      legend: { bottom: 0, textStyle: { color: 'var(--text-secondary)' } },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: true,
        itemStyle: { borderRadius: 4, borderColor: 'var(--bg-primary)', borderWidth: 2 },
        label: { show: true, formatter: '{b}\n{c}' },
        data: [
          ...(pruned > 0 ? [{ value: pruned, name: 'Pruned', itemStyle: { color: '#6b7280' } }] : []),
          { value: full, name: 'Full Blocks', itemStyle: { color: '#10b981' } },
          { value: Math.max(0, kept - full), name: 'Retention Buffer', itemStyle: { color: '#3b82f6' } },
        ].filter(d => d.value > 0),
      }],
    });

    const ro = new ResizeObserver(() => retentionChart?.resize());
    ro.observe(dom);
    unsubs.push(() => { ro.disconnect(); retentionChart?.dispose(); });
  }

  // Refresh every 30s
  const refreshInterval = setInterval(loadStorage, 30_000);
  unsubs.push(() => clearInterval(refreshInterval));

  loadStorage();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
