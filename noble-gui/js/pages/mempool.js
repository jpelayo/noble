/**
 * NOBLE Dashboard — Mempool Page
 * Fee histogram + live transaction stream
 */

import { formatNumber, formatFee, formatBytes, truncateHash, timeAgo } from '../utils.js';
import { txDisplayAmount, TX_TYPE_SHORT } from '../tx-display.js';

export function init(root, ctx) {
  const { rpc, ws } = ctx;
  const unsubs = [];
  let feeChart = null;

  root.innerHTML = `
    <div class="page-header"><h1>Mempool</h1><p>Pending transactions and fee distribution</p></div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Pending Txs</div>
        <div class="kpi-value" id="mp-count">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Size</div>
        <div class="kpi-value" id="mp-size">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Min Fee Rate</div>
        <div class="kpi-value" id="mp-min-fee">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Max Fee Rate</div>
        <div class="kpi-value" id="mp-max-fee">--</div>
      </div>
    </div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Fee Distribution</div>
        <div class="panel-body"><div id="mp-fee-chart" class="chart-container small"></div></div>
      </div>
      <div class="panel">
        <div class="panel-header">Live Transaction Stream</div>
        <div class="panel-body" style="padding:0">
          <div id="mp-stream" class="tx-stream"></div>
        </div>
      </div>
    </div>
  `;

  const mpCount = root.querySelector('#mp-count');
  const mpSize = root.querySelector('#mp-size');
  const mpMinFee = root.querySelector('#mp-min-fee');
  const mpMaxFee = root.querySelector('#mp-max-fee');
  const stream = root.querySelector('#mp-stream');

  async function loadMempoolInfo() {
    try {
      const info = await rpc.call('noble_getMempoolInfo');
      mpCount.textContent = formatNumber(info.count);
      mpSize.textContent = formatBytes(info.total_bytes);
      mpMinFee.textContent = formatNumber(info.min_fee_rate) + ' g/B';
      mpMaxFee.textContent = formatNumber(info.max_fee_rate) + ' g/B';

      // Fee histogram chart
      if (typeof echarts !== 'undefined' && info.fee_histogram) {
        initFeeChart(info.fee_histogram);
      }

      // Initial stream items
      for (const entry of (info.entries || []).slice(0, 20)) {
        appendStreamItem(entry);
      }
    } catch (e) {
      console.error('[mempool] load:', e);
    }
  }

  function initFeeChart(histogram) {
    const dom = root.querySelector('#mp-fee-chart');
    if (!dom || typeof echarts === 'undefined') return;
    feeChart = echarts.init(dom);
    feeChart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 40, right: 16, top: 16, bottom: 30 },
      xAxis: {
        type: 'category',
        data: histogram.map(b => b.label),
        axisLabel: { color: 'var(--chart-text)' },
        axisLine: { lineStyle: { color: 'var(--chart-grid)' } },
      },
      yAxis: {
        type: 'value',
        axisLabel: { color: 'var(--chart-text)' },
        splitLine: { lineStyle: { color: 'var(--chart-grid)' } },
      },
      series: [{
        type: 'bar',
        data: histogram.map(b => b.count),
        barMaxWidth: 40,
        itemStyle: {
          color: '#3b82f6',
          borderRadius: [4, 4, 0, 0],
        },
      }],
    });
    const ro = new ResizeObserver(() => feeChart?.resize());
    ro.observe(dom);
    unsubs.push(() => { ro.disconnect(); feeChart?.dispose(); });
  }

  function appendStreamItem(entry) {
    const item = document.createElement('div');
    item.className = 'tx-stream-item';
    const typeLabel = entry.tx_type != null ? (TX_TYPE_SHORT[entry.tx_type] || `Type ${entry.tx_type}`) : '';
    const typeBadge = typeLabel ? `<span class="badge" style="font-size:0.65rem;padding:1px 5px">${typeLabel}</span>` : '';
    const disp = txDisplayAmount(entry);
    const amountStr = formatFee(disp.amount);
    const feeStr = disp.showFee && entry.fee != null ? `fee ${formatFee(entry.fee)}` : '';
    item.innerHTML = `
      <span class="mono">${truncateHash(entry.tx_id)}</span>
      <span>${typeBadge}</span>
      <span>${amountStr}</span>
      <span style="color:var(--text-muted)">${feeStr}</span>
      <span>${entry.received_at ? timeAgo(entry.received_at) : ''}</span>
    `;
    item.addEventListener('click', () => { location.hash = `#/tx/${entry.tx_id}`; });
    stream.prepend(item);
    while (stream.children.length > 20) stream.lastElementChild.remove();
  }

  // WS: new transactions
  unsubs.push(ws.subscribe('newTransactions', (entry) => {
    appendStreamItem(entry);
    const cur = parseInt(mpCount.textContent.replace(/,/g, ''), 10) || 0;
    mpCount.textContent = formatNumber(cur + 1);
  }));

  // Periodically refresh full mempool stats (size, fees, histogram).
  // newTransactions WS only provides per-tx updates, not full stats recalc.
  unsubs.push(ws.subscribe('newBlocks', () => loadMempoolInfo()));

  // WS reconnect: refresh mempool data
  function onWsReconnect() { loadMempoolInfo(); }
  window.addEventListener('noble-ws-reconnect', onWsReconnect);
  unsubs.push(() => window.removeEventListener('noble-ws-reconnect', onWsReconnect));

  loadMempoolInfo();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
