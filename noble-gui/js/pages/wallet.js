/**
 * NOBLE Dashboard — Wallet Inspector Page
 * Read-only view of node wallet: balance, incoming subsidies+fees, outgoing transfers.
 * Spending functionality requires a separate secure application.
 */

import { formatNumber, formatFee, formatTimestamp, timeAgo, truncateHash, bytesToHex } from '../utils.js';

export function init(root, ctx) {
  const { rpc, ws } = ctx;
  const unsubs = [];
  let currentPage = 0;
  const PAGE_SIZE = 20;

  root.innerHTML = `
    <div class="page-header">
      <h1>Wallet</h1>
      <p>Node wallet inspector — incoming subsidies, fees, and transfers (read-only)</p>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Balance</div>
        <div class="kpi-value" id="w-balance">--</div>
        <div class="kpi-sub" id="w-balance-atomic"></div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Available</div>
        <div class="kpi-value" id="w-available" style="color:var(--success)">--</div>
        <div class="kpi-sub">Confirmed (depth &ge; 6)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Pending</div>
        <div class="kpi-value" id="w-pending" style="color:var(--warning)">--</div>
        <div class="kpi-sub">Awaiting confirmation depth</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Earned</div>
        <div class="kpi-value" id="w-earned">--</div>
        <div class="kpi-sub" id="w-earned-sub"></div>
      </div>
    </div>

    <!-- Wallet identity -->
    <div class="panel">
      <div class="panel-header">Wallet Identity</div>
      <div class="panel-body">
        <dl class="detail-grid" id="w-identity">
        </dl>
      </div>
    </div>

    <!-- Balance breakdown -->
    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Income Breakdown</div>
        <div class="panel-body" id="w-income-breakdown"></div>
      </div>
      <div class="panel">
        <div class="panel-header">Recent Activity</div>
        <div class="panel-body" id="w-recent-activity"></div>
      </div>
    </div>

    <!-- Transaction history -->
    <div class="panel">
      <div class="panel-header">
        <span>Transaction History</span>
        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
          <select id="w-filter" style="padding:2px 6px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-size:var(--font-size-xs)">
            <option value="all">All</option>
            <option value="incoming">Incoming</option>
            <option value="outgoing">Outgoing</option>
            <option value="subsidy">Subsidies</option>
            <option value="fee_income">Fees</option>
          </select>
          <span id="w-tx-count" style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)"></span>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th style="width:30px"></th>
              <th>Type</th>
              <th>Description</th>
              <th>Amount</th>
              <th>Balance After</th>
              <th>Confirmations</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody id="w-transactions"></tbody>
        </table>
      </div>
      <div class="pagination" id="w-pagination"></div>
    </div>

    <div style="text-align:center;color:var(--text-muted);font-size:var(--font-size-xs);padding:var(--gap)">
      This is a read-only inspector. To send transactions, use the NOBLE CLI wallet or a dedicated signing application.
    </div>
  `;

  // ── DOM refs ──
  const wBalance = root.querySelector('#w-balance');
  const wBalanceAtomic = root.querySelector('#w-balance-atomic');
  const wAvailable = root.querySelector('#w-available');
  const wPending = root.querySelector('#w-pending');
  const wEarned = root.querySelector('#w-earned');
  const wEarnedSub = root.querySelector('#w-earned-sub');
  const wIdentity = root.querySelector('#w-identity');
  const wIncomeBreakdown = root.querySelector('#w-income-breakdown');
  const wRecentActivity = root.querySelector('#w-recent-activity');
  const wTransactions = root.querySelector('#w-transactions');
  const wTxCount = root.querySelector('#w-tx-count');
  const wPagination = root.querySelector('#w-pagination');
  const wFilter = root.querySelector('#w-filter');

  let allTransactions = [];

  // ── Load wallet info ──
  async function loadWallet() {
    try {
      const [info, txResult] = await Promise.all([
        rpc.call('noble_getWalletInfo'),
        rpc.call('noble_getWalletTransactions'),
      ]);

      // KPI cards
      wBalance.textContent = formatNoble(info.balance);
      wBalanceAtomic.textContent = `${formatNumber(info.balance)} atomic units`;
      wAvailable.textContent = formatNoble(info.available);
      wPending.textContent = formatNoble(info.pending);
      wEarned.textContent = formatNoble(info.total_earned);
      wEarnedSub.textContent = `from ${formatNumber(info.blocks_validated)} blocks validated`;

      // Identity
      const keyHex = bytesToHex(info.public_key.Ed25519 || info.public_key.Secp256k1 || []);
      const scheme = info.public_key.Ed25519 ? 'Ed25519' : 'secp256k1';
      wIdentity.innerHTML = `
        <dt>Address</dt><dd class="mono">${info.address}</dd>
        <dt>Public Key</dt><dd class="mono">${keyHex}</dd>
        <dt>Scheme</dt><dd>${scheme}</dd>
        <dt>Derived From</dt><dd>Node validator key (primary)</dd>
        <dt>Blocks Validated</dt><dd>${formatNumber(info.blocks_validated)}</dd>
        <dt>First Active</dt><dd>${formatTimestamp(info.first_active)}</dd>
      `;

      // Income breakdown
      const subsidyTotal = txResult.transactions
        .filter(t => t.type === 'subsidy')
        .reduce((s, t) => s + t.amount, 0);
      const feeTotal = txResult.transactions
        .filter(t => t.type === 'fee_income')
        .reduce((s, t) => s + t.amount, 0);
      const outTotal = txResult.transactions
        .filter(t => t.direction === 'outgoing')
        .reduce((s, t) => s + t.amount, 0);
      const totalIncome = subsidyTotal + feeTotal;

      const subsidyPct = totalIncome > 0 ? Math.round(subsidyTotal / totalIncome * 100) : 0;
      const feePct = 100 - subsidyPct;

      wIncomeBreakdown.innerHTML = `
        <div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
            <span>Block Subsidies</span>
            <span class="mono">${formatNoble(subsidyTotal)} (${subsidyPct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${subsidyPct}%;background:var(--accent);border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>
        <div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
            <span>Transaction Fees</span>
            <span class="mono">${formatNoble(feeTotal)} (${feePct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${feePct}%;background:var(--success);border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>
        <div style="padding-top:var(--gap-sm);border-top:1px solid var(--border);display:flex;justify-content:space-between;font-size:var(--font-size-sm)">
          <span>Total Outgoing</span>
          <span class="mono" style="color:var(--error)">${outTotal > 0 ? '-' : ''}${formatNoble(outTotal)}</span>
        </div>
      `;

      // Recent activity (last 5 transactions)
      const recent = txResult.transactions.slice(0, 5);
      wRecentActivity.innerHTML = recent.map(tx => {
        const isIn = tx.direction === 'incoming';
        const color = isIn ? 'var(--success)' : 'var(--error)';
        const sign = isIn ? '+' : '-';
        const icon = typeIcon(tx.type);
        return `<div style="display:flex;justify-content:space-between;align-items:center;padding:var(--gap-xs) 0;border-bottom:1px solid var(--border);font-size:var(--font-size-sm)">
          <div style="display:flex;align-items:center;gap:var(--gap-sm)">
            <span style="font-size:var(--font-size-base)">${icon}</span>
            <div>
              <div>${typeLabel(tx.type)}</div>
              <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${timeAgo(tx.timestamp)}</div>
            </div>
          </div>
          <span class="mono" style="color:${color};font-weight:600">${sign}${formatNoble(tx.amount)}</span>
        </div>`;
      }).join('');

      // Store transactions for filtering/pagination
      allTransactions = txResult.transactions;
      currentPage = 0;
      renderTransactions();

    } catch (e) {
      console.error('[wallet] load:', e);
    }
  }

  // ── Render transaction table ──
  function renderTransactions() {
    const filter = wFilter.value;
    let filtered = allTransactions;
    if (filter === 'incoming') filtered = allTransactions.filter(t => t.direction === 'incoming');
    else if (filter === 'outgoing') filtered = allTransactions.filter(t => t.direction === 'outgoing');
    else if (filter === 'subsidy') filtered = allTransactions.filter(t => t.type === 'subsidy');
    else if (filter === 'fee_income') filtered = allTransactions.filter(t => t.type === 'fee_income');

    wTxCount.textContent = `${filtered.length} transactions`;

    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    const start = currentPage * PAGE_SIZE;
    const page = filtered.slice(start, start + PAGE_SIZE);

    wTransactions.innerHTML = '';
    for (const tx of page) {
      const isIn = tx.direction === 'incoming';
      const color = isIn ? 'var(--success)' : 'var(--error)';
      const sign = isIn ? '+' : '-';
      const icon = typeIcon(tx.type);
      const confText = tx.confirmations >= 6
        ? `<span style="color:var(--success)">${formatNumber(tx.confirmations)}</span>`
        : tx.confirmations > 0
          ? `<span style="color:var(--warning)">${tx.confirmations} / 6</span>`
          : `<span style="color:var(--text-muted)">pending</span>`;

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-size:var(--font-size-base);text-align:center">${icon}</td>
        <td><span class="badge ${isIn ? 'inbound' : 'outbound'}">${tx.type.replace('_', ' ')}</span></td>
        <td>
          <div style="font-size:var(--font-size-sm)">${tx.description}</div>
          ${tx.tx_id ? `<div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${truncateHash(tx.tx_id, 8)}</div>` : ''}
        </td>
        <td class="mono" style="font-weight:600;color:${color};white-space:nowrap">${sign}${formatNoble(tx.amount)}</td>
        <td class="mono" style="font-size:var(--font-size-xs)">${formatNoble(tx.running_balance)}</td>
        <td style="font-size:var(--font-size-xs)">${confText}</td>
        <td style="font-size:var(--font-size-xs);white-space:nowrap">${timeAgo(tx.timestamp)}</td>
      `;
      wTransactions.appendChild(tr);
    }

    // Pagination
    if (totalPages > 1) {
      wPagination.innerHTML = `
        <button id="w-prev" ${currentPage === 0 ? 'disabled' : ''}>&#8592; Prev</button>
        <span class="page-info">Page ${currentPage + 1} of ${totalPages}</span>
        <button id="w-next" ${currentPage >= totalPages - 1 ? 'disabled' : ''}>Next &#8594;</button>
      `;
      wPagination.querySelector('#w-prev')?.addEventListener('click', () => { currentPage--; renderTransactions(); });
      wPagination.querySelector('#w-next')?.addEventListener('click', () => { currentPage++; renderTransactions(); });
    } else {
      wPagination.innerHTML = '';
    }
  }

  // Filter change
  wFilter.addEventListener('change', () => { currentPage = 0; renderTransactions(); });

  // WS: refresh on new block (might include new subsidy)
  ws.subscribe('newBlocks', () => loadWallet());
  unsubs.push(() => ws.unsubscribe('newBlocks'));

  loadWallet();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}

// ── Helpers ──

function formatNoble(atomicUnits) {
  const noble = atomicUnits / 1_000_000;
  if (noble >= 100) return `${noble.toFixed(2)} NOBLE`;
  if (noble >= 1) return `${noble.toFixed(4)} NOBLE`;
  if (noble >= 0.001) return `${noble.toFixed(6)} NOBLE`;
  if (atomicUnits === 0) return '0.00 NOBLE';
  return `${atomicUnits} atomic`;
}

function typeIcon(type) {
  switch (type) {
    case 'subsidy': return '&#9670;'; // diamond — block reward
    case 'fee_income': return '&#9733;'; // star — fee income
    case 'transfer_in': return '&#8595;'; // down arrow — received
    case 'transfer_out': return '&#8593;'; // up arrow — sent
    default: return '&#8226;';
  }
}

function typeLabel(type) {
  switch (type) {
    case 'subsidy': return 'Block Subsidy';
    case 'fee_income': return 'Fee Income';
    case 'transfer_in': return 'Transfer In';
    case 'transfer_out': return 'Transfer Out';
    default: return type;
  }
}
