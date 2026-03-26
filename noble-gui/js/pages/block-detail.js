/**
 * NOBLE Dashboard — Block Detail Page
 */

import { formatNumber, truncateHash, formatTimestamp, formatFee } from '../utils.js';
import { txDisplayAmount, TX_TYPE_NAMES } from '../tx-display.js';

export function init(root, ctx) {
  const { rpc, params } = ctx;
  const height = parseInt(params.height, 10);

  root.innerHTML = `
    <div class="page-header">
      <h1>Block #${formatNumber(height)}</h1>
      <p>Full block details and transaction list</p>
    </div>
    <div id="block-loading" class="empty-state">Loading...</div>
  `;

  async function load() {
    try {
      // Fetch block data, votes, and name sources in parallel
      const [block, votes, peerMemory, identity, nodeInfo] = await Promise.all([
        rpc.call('noble_getBlock', [height]),
        rpc.call('noble_getBlockVotes', [height]).catch(() => null),
        rpc.call('noble_getPeerMemory').catch(() => []),
        rpc.call('noble_getNodeIdentity').catch(() => ({})),
        rpc.call('noble_getNodeInfo').catch(() => ({})),
      ]);

      root.querySelector('#block-loading')?.remove();

      // Names pre-resolved by backend — no client-side name maps.
      const validatorName = block.validator_name;
      const validatorDisplay = validatorName
        ? `<strong>${esc(validatorName)}</strong> <span class="mono" style="opacity:0.5">${block.validator_id}</span>`
        : `<span class="mono">${block.validator_id}</span>`;

      // Header detail grid
      const grid = document.createElement('dl');
      grid.className = 'detail-grid';
      grid.innerHTML = `
        <dt>Height</dt><dd>${formatNumber(block.height)}</dd>
        <dt>Hash</dt><dd class="mono">${block.hash}</dd>
        <dt>Timestamp</dt><dd>${formatTimestamp(block.timestamp)}</dd>
        <dt>Prev Block Hash</dt><dd class="mono">${block.prev_hash}</dd>
        <dt>Merkle Root</dt><dd class="mono">${block.merkle_root}</dd>
        <dt>Transaction Count</dt><dd>${block.tx_count}</dd>
        <dt>Validator</dt><dd>${validatorDisplay}</dd>
      `;

      // Add consensus row if votes are available
      const strengthBadge = votes
        ? (votes.strength === 'Strong'
          ? '<span class="badge consensus-strong">Strong</span>'
          : '<span class="badge consensus-plurality">Plurality</span>')
        : '';
      if (votes) {
        const witnessInfo = `${votes.unique_witness_count} witness${votes.unique_witness_count !== 1 ? 'es' : ''}`;
        const cycleInfo = `Cycle ${formatNumber(votes.cycle_number)}`;
        grid.innerHTML += `
          <dt>Consensus</dt>
          <dd>${strengthBadge} ${witnessInfo} &middot; ${cycleInfo}</dd>
        `;
      }

      root.appendChild(grid);

      // Consensus legitimacy panel
      if (!votes || (!votes.r1_voters.length && !votes.r2_voters.length)) {
        const noVotePanel = document.createElement('div');
        noVotePanel.className = 'panel';
        noVotePanel.innerHTML = `
          <div class="panel-header">Consensus Legitimacy</div>
          <div class="panel-body"><p class="text-muted">Vote data unavailable for this block.</p></div>
        `;
        root.appendChild(noVotePanel);
      } else if (votes) {
        const total = votes.voter_count || 1;
        const r1For = votes.r1_voters.length;
        const r2For = votes.r2_voters.length;
        const r1Against = total - r1For;
        const r2Against = total - r2For;
        const r1Pct = Math.round(r1For / total * 100);
        const r2Pct = Math.round(r2For / total * 100);
        const totalWitnesses = votes.unique_witness_count;

        const votePanel = document.createElement('div');
        votePanel.className = 'panel';
        votePanel.innerHTML = `
          <div class="panel-header">Consensus Legitimacy</div>
          <div class="panel-body">
            <div style="margin-bottom:var(--gap)">
              <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
                <span><span class="badge consensus-r1">R1</span> Round 1</span>
                <span>${r1For} FOR / ${r1Against} against &mdash; <strong>${r1Pct}%</strong></span>
              </div>
              <div style="height:10px;background:var(--bg-tertiary);border-radius:5px;overflow:hidden;display:flex">
                <div style="width:${r1Pct}%;background:var(--success);transition:width 0.3s"></div>
                <div style="width:${100 - r1Pct}%;background:var(--error-bg, rgba(239,68,68,0.3))"></div>
              </div>
            </div>
            ${r2For > 0 ? `<div style="margin-bottom:var(--gap)">
              <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
                <span><span class="badge consensus-r2">R2</span> Round 2</span>
                <span>${r2For} FOR / ${r2Against} against &mdash; <strong>${r2Pct}%</strong></span>
              </div>
              <div style="height:10px;background:var(--bg-tertiary);border-radius:5px;overflow:hidden;display:flex">
                <div style="width:${r2Pct}%;background:var(--success);transition:width 0.3s"></div>
                <div style="width:${100 - r2Pct}%;background:var(--error-bg, rgba(239,68,68,0.3))"></div>
              </div>
            </div>` : `<div style="margin-bottom:var(--gap)">
              <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px;opacity:0.5">
                <span><span class="badge consensus-r2">R2</span> Skipped</span>
                <span>R1 decisive</span>
              </div>
            </div>`}
            <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
              ${totalWitnesses} unique witnesses out of ${total} voters &middot; ${strengthBadge}
            </div>
            <details>
              <summary style="cursor:pointer;font-size:var(--font-size-sm);color:var(--accent);user-select:none">
                Show ${totalWitnesses} individual votes
              </summary>
              <table class="data-table" style="margin-top:var(--gap-sm)">
                <thead><tr><th>Round</th><th>Validator</th><th>Key</th></tr></thead>
                <tbody id="block-votes"></tbody>
              </table>
            </details>
          </div>
        `;
        root.appendChild(votePanel);

        const voteBody = votePanel.querySelector('#block-votes');
        const r1Keys = new Set(votes.r1_voters.map(v => v.validator_key));

        votes.r1_voters.forEach(v => {
          const inR2 = votes.r2_voters.some(r2 => r2.validator_key === v.validator_key);
          const roundLabel = inR2
            ? '<span class="badge consensus-r1">R1</span> <span class="badge consensus-r2">R2</span>'
            : '<span class="badge consensus-r1">R1</span>';
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td>${roundLabel}</td>
            <td>${esc(v.name || v.validator_key)}</td>
            <td class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${v.validator_key}</td>
          `;
          voteBody.appendChild(tr);
        });

        votes.r2_voters
          .filter(v => !r1Keys.has(v.validator_key))
          .forEach(v => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td><span class="badge consensus-r2">R2</span></td>
              <td>${esc(v.name || v.validator_key)}</td>
              <td class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${v.validator_key}</td>
            `;
            voteBody.appendChild(tr);
          });
      }

      // Transactions table
      if (block.transactions.length > 0) {
        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.innerHTML = `
          <div class="panel-header">Transactions (${block.transactions.length})</div>
          <div class="panel-body" style="padding:0;max-height:500px;overflow-y:auto">
            <table class="data-table">
              <thead style="position:sticky;top:0;z-index:1;background:var(--bg-secondary)"><tr><th>#</th><th>Tx ID</th><th>Amount</th><th>Type</th><th>Inputs / Outputs</th></tr></thead>
              <tbody id="block-txs"></tbody>
            </table>
          </div>
        `;
        root.appendChild(panel);

        const tbody = panel.querySelector('#block-txs');
        block.transactions.forEach((tx, i) => {
          let typeLabel;
          if (tx.tx_type === 0x10) {
            typeLabel = '<span class="badge coinbase">Block Reward</span>';
          } else if (tx.tx_type === 0x11) {
            typeLabel = '<span class="badge tx-fee-distribution">Fee Distribution</span>';
          } else {
            typeLabel = TX_TYPE_NAMES[tx.tx_type] || `Type ${tx.tx_type}`;
          }
          const disp = txDisplayAmount(tx);
          const tr = document.createElement('tr');
          tr.className = 'clickable';
          tr.innerHTML = `
            <td>${i}</td>
            <td class="mono" style="word-break:break-all;font-size:var(--font-size-xs)">${tx.tx_id}</td>
            <td>${formatFee(disp.amount)}</td>
            <td>${typeLabel}</td>
            <td>${(tx.inputs || []).length} in / ${(tx.outputs || []).length} out</td>
          `;
          tr.addEventListener('click', () => {
            location.hash = `#/tx/${tx.tx_id}`;
          });
          tbody.appendChild(tr);
        });
      }

      // Navigation
      const nav = document.createElement('div');
      nav.className = 'pagination';
      nav.innerHTML = `
        <button id="bd-prev" ${height <= 0 ? 'disabled' : ''}>Prev Block</button>
        <span class="page-info">Block #${formatNumber(height)}</span>
        <button id="bd-next">Next Block</button>
      `;
      root.appendChild(nav);

      nav.querySelector('#bd-prev')?.addEventListener('click', () => {
        location.hash = `#/block/${height - 1}`;
      });
      nav.querySelector('#bd-next')?.addEventListener('click', () => {
        location.hash = `#/block/${height + 1}`;
      });

    } catch (e) {
      const loading = root.querySelector('#block-loading');
      if (loading) loading.textContent = `Block not found: ${e.message || e}`;
    }
  }

  load();
  return { destroy() {} };
}

/** Escape HTML special characters to prevent XSS. */
function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

