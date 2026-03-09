/**
 * NOBLE Dashboard — Blocks Page (paginated block list)
 */

import { formatNumber, truncateHash, timeAgo } from '../utils.js';

const PAGE_SIZE = 50;
const CYCLE_SECS = 1200; // 4 × 300s phases (used only for gap-cycle time estimate)

export function init(root, ctx) {
  const { rpc } = ctx;
  let currentPage = 0;
  let totalHeight = 0;

  root.innerHTML = `
    <div class="page-header"><h1>Block Explorer</h1><p>Browse all blocks on the NOBLE chain</p></div>

    <div class="panel">
      <div class="panel-body" style="padding:0">
        <table class="data-table">
          <thead>
            <tr>
              <th>Cycle</th>
              <th>Height</th>
              <th>Block Hash</th>
              <th>Transactions</th>
              <th>Validator</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody id="blocks-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="pagination">
      <button id="blocks-prev">Prev</button>
      <span class="page-info" id="blocks-page-info"></span>
      <button id="blocks-next">Next</button>
    </div>
  `;

  const tbody = root.querySelector('#blocks-tbody');
  const prevBtn = root.querySelector('#blocks-prev');
  const nextBtn = root.querySelector('#blocks-next');
  const pageInfo = root.querySelector('#blocks-page-info');

  async function loadPage(page) {
    try {
      const count = await rpc.call('noble_getBlockCount');
      totalHeight = count.height;
      const totalPages = Math.max(1, Math.ceil(totalHeight / PAGE_SIZE));
      currentPage = Math.max(0, Math.min(page, totalPages - 1));

      // Show newest first: page 0 = highest blocks.
      // Height 0 (genesis placeholder) has no stored block — start from 1.
      const endHeight = totalHeight - currentPage * PAGE_SIZE;
      const startHeight = Math.max(1, endHeight - PAGE_SIZE + 1);

      const rangeSize = endHeight - startHeight + 1;
      const blocks = await rpc.call('noble_getBlockRange', [startHeight, rangeSize]);

      // Blocks come in ascending order; reverse for newest-first display.
      const desc = blocks.reverse();

      tbody.innerHTML = '';
      for (let i = 0; i < desc.length; i++) {
        const b = desc[i];
        const cycle = b.cycle != null ? b.cycle : '—';

        // Insert empty-cycle rows for any gap between this block and the next
        // (next = lower height, older). If the previous block's cycle is more
        // than 1 ahead, cycles in between produced no block.
        if (i > 0 && desc[i - 1].cycle != null && b.cycle != null) {
          const prevCycle = desc[i - 1].cycle;
          for (let gap = prevCycle - 1; gap > b.cycle; gap--) {
            const gapTr = document.createElement('tr');
            gapTr.style.cssText = 'opacity:0.45';
            gapTr.innerHTML = `
              <td style="color:var(--text-muted)">${gap}</td>
              <td colspan="3" style="color:var(--text-muted);font-style:italic;text-align:center">no proposals</td>
              <td></td>
              <td></td>
            `;
            tbody.appendChild(gapTr);
          }
        }

        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.innerHTML = `
          <td>${cycle}</td>
          <td>${formatNumber(b.height)}</td>
          <td class="mono">${truncateHash(b.hash)}</td>
          <td>${b.tx_count}</td>
          <td class="mono">${truncateHash(b.validator_id, 12)}</td>
          <td>${timeAgo(b.timestamp)}</td>
        `;
        tr.addEventListener('click', () => { location.hash = `#/block/${b.height}`; });
        tbody.appendChild(tr);
      }

      prevBtn.disabled = currentPage === 0;
      nextBtn.disabled = currentPage >= totalPages - 1;
      pageInfo.textContent = `Page ${currentPage + 1} of ${totalPages}`;
    } catch (e) {
      console.error('[blocks] loadPage:', e);
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Failed to load blocks</td></tr>';
    }
  }

  prevBtn.addEventListener('click', () => loadPage(currentPage - 1));
  nextBtn.addEventListener('click', () => loadPage(currentPage + 1));

  // WS reconnect: refresh current page
  function onWsReconnect() { loadPage(currentPage); }
  window.addEventListener('noble-ws-reconnect', onWsReconnect);

  // WS: auto-refresh on new blocks
  const { ws } = ctx;
  const unsubs = [];
  if (ws && ws.subscribe) {
    unsubs.push(ws.subscribe('newBlocks', () => {
      if (currentPage === 0) loadPage(0);  // only auto-refresh if viewing newest
    }));
  }
  unsubs.push(() => window.removeEventListener('noble-ws-reconnect', onWsReconnect));

  loadPage(0);

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
