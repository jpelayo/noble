/**
 * NOBLE Dashboard — Wallet Inspector Page
 * Read-only view of node wallet: balance, incoming subsidies+fees, outgoing transfers.
 * Spending functionality requires a separate secure application.
 */

import { formatNumber, formatFee, formatTimestamp, timeAgo, truncateHash, bytesToHex } from '../utils.js';
import { createMnemonicGrid, startAutoClearTimer, wipeInput, destroySecureElements } from '../wallet-security.js';
import { TX_TYPES, TX_TYPE_NAMES } from '../tx-display.js';

export function init(root, ctx) {
  const { rpc, ws } = ctx;
  const unsubs = [];
  let currentPage = 0;
  const PAGE_SIZE = 20;

  root.innerHTML = `
    <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-start">
      <div>
        <h1>Wallet</h1>
        <p>Node wallet inspector — incoming subsidies, fees, and transfers (read-only)</p>
      </div>
      <button id="w-wallet-gear" title="Mnemonic Wallet Tool" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1;margin-top:4px">&#9881;</button>
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

    <!-- Reward Address (read-only — edit in Settings) -->
    <div class="panel">
      <div class="panel-header">
        <span>Reward Address</span>
        <span id="w-reward-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Your node earns block rewards and gateway fee splits. Change the reward address in <a href="#settings" style="color:var(--accent)">Settings</a>.
        </p>
        <dl class="detail-grid" id="w-reward-info">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
      </div>
    </div>

    <!-- Read-only wallet info banner -->
    <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:var(--gap);margin-bottom:var(--gap);display:flex;align-items:center;gap:var(--gap)">
      <span style="font-size:1.3rem">&#x1F512;</span>
      <div style="font-size:var(--font-size-sm);color:var(--text-secondary)">
        <strong>Read-only wallet.</strong> The node does not hold spending keys.
        Use <code style="color:var(--accent)">noble-tool wallet</code> or a separate client to send transactions.
      </div>
    </div>

    <!-- Wallet identity -->
    <div class="panel">
      <div class="panel-header">
        <span>Wallet Identity</span>
        <button id="w-refresh" class="btn btn-secondary btn-sm" style="padding:2px 10px;font-size:var(--font-size-xs)">Refresh</button>
      </div>
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
            <option value="subsidies">Subsidies</option>
            <option value="fees">Fee Income</option>
            <option value="transfers">Transfers</option>
            <option value="documents">Documents</option>
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
              <th>Counterparty</th>
              <th>Amount</th>
              <th>Status</th>
              <th>Confirmations</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody id="w-transactions"></tbody>
        </table>
      </div>
      <div class="pagination" id="w-pagination"></div>
    </div>

    <!-- Mnemonic Wallet — gear button triggers modal -->
    <div id="w-mnemonic-panel"></div>

    <!-- Modal overlay -->
    <div id="w-wallet-modal" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);align-items:center;justify-content:center">
      <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:900px;width:92%;max-height:85vh;overflow-y:auto;padding:var(--gap-lg);position:relative">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap)">
          <h3 style="margin:0">Mnemonic Wallet</h3>
          <button id="w-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.5rem;cursor:pointer;padding:0 4px;line-height:1" title="Close">&times;</button>
        </div>
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
          Generate or import a Noble wallet offline. Nothing is saved to the node.
        </p>
        <div style="display:flex;gap:var(--gap);flex-wrap:wrap;margin-bottom:var(--gap)">
          <button id="w-generate-btn" class="btn btn-primary" style="padding:8px 16px">Generate New Wallet</button>
          <button id="w-import-btn" class="btn btn-secondary" style="padding:8px 16px">Import from Mnemonic</button>
        </div>
        <div id="w-generate-area"></div>
        <div id="w-import-area"></div>
      </div>
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
  const wRewardBadge = root.querySelector('#w-reward-badge');
  const wRewardInfo = root.querySelector('#w-reward-info');

  let allTransactions = [];
  let loadInFlight = false;

  // ── Load reward address (read-only display) ──
  async function loadRewardAddress() {
    try {
      const res = await rpc.call('noble_getRewardAddress');
      if (res.configured) {
        wRewardBadge.textContent = 'Configured';
        wRewardBadge.className = 'badge inbound';
        wRewardInfo.innerHTML = `
          <dt>Address</dt><dd class="mono">${res.address}</dd>
          <dt>Type</dt><dd>${res.address_type || 'Unknown'}</dd>
          <dt>Wire Key</dt><dd class="mono" style="font-size:var(--font-size-xs)">${res.wire_hex || '--'}</dd>
        `;
      } else {
        wRewardBadge.textContent = 'Not Configured';
        wRewardBadge.className = 'badge outbound';
        wRewardInfo.innerHTML = `<dt style="grid-column:1/-1;color:var(--text-muted)">No reward address configured. Set one in <a href="#settings" style="color:var(--accent)">Settings</a>.</dt>`;
      }
    } catch (e) {
      console.error('[wallet] load reward address:', e);
      wRewardInfo.innerHTML = `<dt style="grid-column:1/-1;color:var(--text-muted)">Could not load reward address.</dt>`;
    }
  }

  loadRewardAddress();

  // ── Load wallet info ──
  async function loadWallet() {
    if (loadInFlight) return;
    loadInFlight = true;
    try {
      const info = await rpc.call('noble_getWalletInfo');

      // KPI cards
      wBalance.textContent = formatNoble(info.balance);
      wBalanceAtomic.textContent = `${formatNumber(info.balance)} atomic units`;
      wAvailable.textContent = formatNoble(info.available);
      wPending.textContent = formatNoble(info.pending);

      // Identity — show key count and balances
      wIdentity.innerHTML = `
        <dt>Keys</dt><dd>${info.key_count} key${info.key_count !== 1 ? 's' : ''} in keystore</dd>
        <dt>Status</dt><dd>${info.unlocked ? '<span style="color:var(--success)">Unlocked</span>' : '<span style="color:var(--text-muted)">Locked</span>'}</dd>
        <dt>Balance</dt><dd class="mono">${formatNoble(info.balance)}</dd>
        <dt>Available</dt><dd class="mono">${formatNoble(info.available)}</dd>
        <dt>Pending</dt><dd class="mono">${formatNoble(info.pending)}</dd>
      `;

      // Load transactions separately so identity panel works even if this fails
      let txResult = { transactions: [] };
      try { txResult = await rpc.call('noble_getWalletTransactions'); } catch (e) { console.error('[wallet] tx history:', e); }

      // Total Earned — sum of incoming tx amounts (block rewards + fee distributions + received transfers)
      const totalEarned = txResult.transactions
        .filter(t => t.direction === 'incoming')
        .reduce((s, t) => s + (t.amount || 0), 0);
      const blocksValidated = txResult.transactions
        .filter(t => t.tx_type === TX_TYPES.COINBASE)
        .length;
      wEarned.textContent = formatNoble(totalEarned);
      wEarnedSub.textContent = blocksValidated > 0
        ? `from ${formatNumber(blocksValidated)} block${blocksValidated !== 1 ? 's' : ''} validated`
        : '';

      // Income breakdown — by tx_type numeric codes
      const rewardTotal = txResult.transactions
        .filter(t => t.tx_type === TX_TYPES.COINBASE)
        .reduce((s, t) => s + (t.amount || 0), 0);
      const feeTotal = txResult.transactions
        .filter(t => t.tx_type === TX_TYPES.FEE_DISTRIBUTION)
        .reduce((s, t) => s + (t.amount || 0), 0);
      const otherIncome = txResult.transactions
        .filter(t => t.direction === 'incoming' && t.tx_type !== TX_TYPES.COINBASE && t.tx_type !== TX_TYPES.FEE_DISTRIBUTION)
        .reduce((s, t) => s + (t.amount || 0), 0);
      const outTotal = txResult.transactions
        .filter(t => t.direction === 'outgoing')
        .reduce((s, t) => s + (t.amount || 0), 0);
      const totalIncome = rewardTotal + feeTotal + otherIncome;

      const rewardPct = totalIncome > 0 ? Math.round(rewardTotal / totalIncome * 100) : 0;
      const feePct = totalIncome > 0 ? Math.round(feeTotal / totalIncome * 100) : 0;
      const otherPct = totalIncome > 0 ? Math.max(0, 100 - rewardPct - feePct) : 0;

      if (txResult.transactions.length === 0) {
        wIncomeBreakdown.innerHTML = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">No transaction history yet. Income data will appear once the node validates blocks.</p>';
        wRecentActivity.innerHTML = '<p style="color:var(--text-muted);font-size:var(--font-size-sm)">No recent activity.</p>';
        allTransactions = [];
        renderTransactions();
        return;
      }

      wIncomeBreakdown.innerHTML = `
        <div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
            <span>Block Rewards</span>
            <span class="mono">${formatNoble(rewardTotal)} (${rewardPct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${rewardPct}%;background:var(--accent);border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>
        <div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
            <span>Fee Income</span>
            <span class="mono">${formatNoble(feeTotal)} (${feePct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${feePct}%;background:var(--success);border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>
        ${otherIncome > 0 ? `<div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
            <span>Other Income</span>
            <span class="mono">${formatNoble(otherIncome)} (${otherPct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${otherPct}%;background:var(--info, #60a5fa);border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>` : ''}
        <div style="padding-top:var(--gap-sm);border-top:1px solid var(--border);display:flex;justify-content:space-between;font-size:var(--font-size-sm)">
          <span>Total Outgoing</span>
          <span class="mono" style="color:var(--error)">${outTotal > 0 ? '-' : ''}${formatNoble(outTotal)}</span>
        </div>
      `;

      // Recent activity (last 5 transactions)
      const recent = txResult.transactions.slice(0, 5);
      wRecentActivity.innerHTML = recent.map(tx => {
        const isIn = tx.direction === 'incoming' || tx.direction === 'self';
        const color = isIn ? 'var(--success)' : 'var(--error)';
        const sign = isIn ? '+' : '-';
        const icon = txIcon(tx.tx_type);
        const label = TX_TYPE_NAMES[tx.tx_type] || tx.type || 'Unknown';
        return `<div style="display:flex;justify-content:space-between;align-items:center;padding:var(--gap-xs) 0;border-bottom:1px solid var(--border);font-size:var(--font-size-sm)">
          <div style="display:flex;align-items:center;gap:var(--gap-sm)">
            <span style="font-size:var(--font-size-base)">${icon}</span>
            <div>
              <div>${label}</div>
              <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${timeAgo(tx.timestamp)}</div>
            </div>
          </div>
          <span class="mono" style="color:${color};font-weight:600">${sign}${formatNoble(tx.amount || 0)}</span>
        </div>`;
      }).join('');

      // Store transactions for filtering/pagination
      allTransactions = txResult.transactions;
      currentPage = 0;
      renderTransactions();

    } catch (e) {
      console.error('[wallet] load:', e);
    } finally {
      loadInFlight = false;
    }
  }

  // ── Render transaction table ──
  function renderTransactions() {
    const filter = wFilter.value;
    let filtered = allTransactions;
    if (filter === 'incoming') filtered = allTransactions.filter(t => t.direction === 'incoming');
    else if (filter === 'outgoing') filtered = allTransactions.filter(t => t.direction === 'outgoing');
    else if (filter === 'subsidies') filtered = allTransactions.filter(t => t.tx_type === TX_TYPES.COINBASE);
    else if (filter === 'fees') filtered = allTransactions.filter(t => t.tx_type === TX_TYPES.FEE_DISTRIBUTION);
    else if (filter === 'transfers') filtered = allTransactions.filter(t => t.tx_type === TX_TYPES.TRANSFER);
    else if (filter === 'documents') filtered = allTransactions.filter(t => t.tx_type === TX_TYPES.NOTARIZATION || t.tx_type === TX_TYPES.LOCKED || t.tx_type === TX_TYPES.UNLOCKING);

    wTxCount.textContent = `${filtered.length} transactions`;

    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    const start = currentPage * PAGE_SIZE;
    const page = filtered.slice(start, start + PAGE_SIZE);

    wTransactions.innerHTML = '';
    for (const tx of page) {
      const isIn = tx.direction === 'incoming' || tx.direction === 'self';
      const color = isIn ? 'var(--success)' : 'var(--error)';
      const sign = isIn ? '+' : '-';
      const icon = txIcon(tx.tx_type);
      const label = TX_TYPE_NAMES[tx.tx_type] || tx.type || 'Unknown';
      const statusHtml = txStatusHtml(tx.status, tx.confirmations);
      const counterparty = tx.counterparty || '';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-size:var(--font-size-base);text-align:center">${icon}</td>
        <td><span class="badge ${isIn ? 'inbound' : 'outbound'}">${label}</span></td>
        <td>
          <div style="font-size:var(--font-size-sm)">${counterparty}</div>
          ${tx.tx_id ? `<div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${truncateHash(tx.tx_id, 8)}</div>` : ''}
        </td>
        <td class="mono" style="font-weight:600;color:${color};white-space:nowrap">${sign}${formatNoble(tx.amount || 0)}</td>
        <td style="font-size:var(--font-size-xs)">${statusHtml}</td>
        <td style="font-size:var(--font-size-xs)">${tx.confirmations > 0 ? formatNumber(tx.confirmations) : '--'}</td>
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

  // ── Mnemonic wallet modal (security-hardened) ──
  const walletGear = root.querySelector('#w-wallet-gear');
  const walletModal = root.querySelector('#w-wallet-modal');
  const modalClose = root.querySelector('#w-modal-close');
  const generateBtn = root.querySelector('#w-generate-btn');
  const importBtn = root.querySelector('#w-import-btn');
  const generateArea = root.querySelector('#w-generate-area');
  const importArea = root.querySelector('#w-import-area');
  const mnemonicPanel = root.querySelector('#w-mnemonic-panel');
  let activeGenerateForm = null;
  let activeImportForm = null;
  let autoClearHandle = null;

  function openWalletModal() { walletModal.style.display = 'flex'; }
  function closeWalletModal() {
    if (activeGenerateForm) { activeGenerateForm.destroy(); activeGenerateForm = null; generateArea.innerHTML = ''; }
    if (activeImportForm) { activeImportForm.destroy(); activeImportForm = null; importArea.innerHTML = ''; }
    if (autoClearHandle) { autoClearHandle.stop(); autoClearHandle = null; }
    destroySecureElements(walletModal);
    walletModal.style.display = 'none';
  }
  walletGear.addEventListener('click', openWalletModal);
  modalClose.addEventListener('click', closeWalletModal);
  walletModal.addEventListener('click', (e) => { if (e.target === walletModal) closeWalletModal(); });

  generateBtn.addEventListener('click', async () => {
    // Collapse import, toggle generate
    if (activeImportForm) { activeImportForm.destroy(); activeImportForm = null; importArea.innerHTML = ''; }
    if (activeGenerateForm) { activeGenerateForm.destroy(); activeGenerateForm = null; generateArea.innerHTML = ''; return; }
    // Clear any previous terminal output
    generateArea.querySelectorAll('.terminal-output').forEach(t => t.remove());

    generateArea.innerHTML = '';
    try {
      generateBtn.disabled = true;
      generateBtn.textContent = 'Generating...';
      const result = await rpc.call('noble_generateMnemonic', {
        word_count: 24,
        passphrase: '',
      });
      generateArea.innerHTML = '';

      // Show mnemonic in secure grid
      const words = result.mnemonic.split(/\s+/);
      // Critical ephemeral wallet warning
      const critBox = document.createElement('div');
      critBox.style.cssText = 'background:var(--error-bg, rgba(239,68,68,0.1));border:2px solid var(--error);border-radius:var(--radius);padding:var(--gap);margin-bottom:var(--gap)';
      critBox.innerHTML = `
        <strong style="color:var(--error);font-size:var(--font-size-sm)">CRITICAL: This wallet is ephemeral</strong>
        <p style="color:var(--text-secondary);font-size:var(--font-size-xs);margin:var(--gap-sm) 0 0">
          The node does NOT hold spending keys. Back up these 24 words now.
          Without them, any income sent to this address is <strong>permanently lost</strong>.
          Use <code>noble-tool wallet</code> or a separate client wallet to spend your node balance.
        </p>`;
      generateArea.appendChild(critBox);

      const header = document.createElement('div');
      header.style.cssText = 'font-weight:600;margin-bottom:var(--gap-sm);color:var(--warning)';
      header.textContent = 'Backup Your Mnemonic Phrase';
      generateArea.appendChild(header);

      const gridEl = createMnemonicGrid(generateArea, words);

      const warning = document.createElement('div');
      warning.style.cssText = 'font-size:var(--font-size-xs);color:var(--error);margin-top:var(--gap-sm)';
      warning.textContent = 'Write these words down and store them securely. They cannot be recovered from the node.';
      generateArea.appendChild(warning);

      // Auto-clear timer (5 minutes)
      autoClearHandle = startAutoClearTimer(generateArea, gridEl, 300_000);

      // Terminal output with full key info
      const termEl = document.createElement('div');
      termEl.className = 'terminal-output';
      termEl.innerHTML = formatTerminalOutput(result, false);
      generateArea.appendChild(termEl);

    } catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'color:var(--error);font-size:var(--font-size-sm);margin-top:var(--gap-sm)';
      err.textContent = 'Failed to generate: ' + (e.message || e);
      generateArea.appendChild(err);
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate New Wallet';
    }
  });

  importBtn.addEventListener('click', () => {
    // Collapse generate, toggle import
    if (activeGenerateForm) { activeGenerateForm.destroy(); activeGenerateForm = null; generateArea.innerHTML = ''; }
    if (autoClearHandle) { autoClearHandle.stop(); autoClearHandle = null; }
    if (activeImportForm) { activeImportForm.destroy(); activeImportForm = null; importArea.innerHTML = ''; return; }
    importArea.querySelectorAll('.terminal-output').forEach(t => t.remove());

    importArea.innerHTML = '';
    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'padding:var(--gap);background:var(--bg-tertiary);border-radius:var(--radius);border:1px solid var(--border)';

    const label = document.createElement('label');
    label.style.cssText = 'font-size:var(--font-size-sm);font-weight:600;display:block;margin-bottom:var(--gap-sm)';
    label.textContent = 'Enter Mnemonic Phrase';
    wrapper.appendChild(label);

    const textarea = document.createElement('textarea');
    textarea.rows = 3;
    textarea.autocomplete = 'off';
    textarea.spellcheck = false;
    textarea.placeholder = 'Enter your 12 or 24 word mnemonic phrase...';
    textarea.style.cssText = 'width:100%;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:var(--gap-sm);font-family:var(--font-mono);font-size:var(--font-size-sm);resize:vertical';
    wrapper.appendChild(textarea);

    const resultEl = document.createElement('div');
    resultEl.style.cssText = 'display:none;margin-top:var(--gap-sm);font-size:var(--font-size-sm)';
    wrapper.appendChild(resultEl);

    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:var(--gap-sm);margin-top:var(--gap-sm)';

    const submitBtn = document.createElement('button');
    submitBtn.className = 'btn';
    submitBtn.style.cssText = 'padding:6px 14px';
    submitBtn.textContent = 'Import';
    submitBtn.addEventListener('click', async () => {
      const words = textarea.value.trim();
      if (!words) { resultEl.style.display = 'block'; resultEl.innerHTML = '<span style="color:var(--error)">Please enter your mnemonic phrase.</span>'; return; }
      try {
        const result = await rpc.call('noble_importMnemonic', {
          mnemonic: words,
          passphrase: '',
        });
        // Wipe inputs
        wipeInput(textarea);

        resultEl.style.display = 'block';
        if (result.already_exists) {
          resultEl.innerHTML = `<span style="color:var(--warning)">Key already exists.</span>`;
        } else {
          resultEl.innerHTML = `<span style="color:var(--success)">Key imported successfully.</span>`;
        }
        // Terminal output with full key info (no mnemonic display for import)
        const importTermEl = document.createElement('div');
        importTermEl.className = 'terminal-output';
        importTermEl.innerHTML = formatTerminalOutput(result, false);
        resultEl.appendChild(importTermEl);
      } catch (e) {
        resultEl.style.display = 'block';
        resultEl.innerHTML = `<span style="color:var(--error)">Import failed: ${e.message || e}</span>`;
      }
    });
    btnRow.appendChild(submitBtn);

    // Cancel — wipe and hide
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary';
    cancelBtn.style.cssText = 'padding:6px 12px';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', () => {
      wipeInput(textarea);
      importArea.innerHTML = '';
      activeImportForm = null;
    });
    btnRow.appendChild(cancelBtn);

    wrapper.appendChild(btnRow);
    importArea.appendChild(wrapper);

    activeImportForm = {
      destroy() {
        wipeInput(textarea);
        wrapper.remove();
      },
    };
  });

  // Refresh button
  const refreshBtn = root.querySelector('#w-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      refreshBtn.textContent = 'Refreshing...';
      refreshBtn.disabled = true;
      loadWallet().finally(() => { refreshBtn.textContent = 'Refresh'; refreshBtn.disabled = false; });
    });
  }

  // WS: refresh on new block (might include new subsidy)
  unsubs.push(ws.subscribe('newBlocks', () => loadWallet()));

  // WS reconnect: refresh wallet data
  function onWsReconnect() { loadWallet(); }
  window.addEventListener('noble-ws-reconnect', onWsReconnect);
  unsubs.push(() => window.removeEventListener('noble-ws-reconnect', onWsReconnect));

  loadWallet();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
      closeWalletModal();
      destroySecureElements(mnemonicPanel);
    },
  };
}

// ── Helpers ──

function formatNoble(atomicUnits) {
  if (atomicUnits === 0) return '0.00 NOBLE';
  const noble = atomicUnits / 100_000_000;
  const full = noble.toFixed(8);
  const trimmed = full.replace(/0+$/, '').replace(/\.$/, '.00');
  const dot = trimmed.indexOf('.');
  const decimals = dot >= 0 ? trimmed.length - dot - 1 : 0;
  const display = decimals < 2 ? noble.toFixed(2) : trimmed;
  return `${display} NOBLE`;
}

function txIcon(txType) {
  switch (txType) {
    case TX_TYPES.COINBASE:          return '&#9670;';  // diamond — block reward
    case TX_TYPES.FEE_DISTRIBUTION:  return '&#9733;';  // star — fee income
    case TX_TYPES.TRANSFER:          return '&#8596;';  // left-right arrow — transfer
    case TX_TYPES.NOTARIZATION:      return '&#10003;'; // checkmark — document
    case TX_TYPES.LOCKED:            return '&#x1F512;'; // lock
    case TX_TYPES.UNLOCKING:         return '&#x1F511;'; // key
    case TX_TYPES.KEY_ROTATION:      return '&#x1F504;'; // rotation
    case TX_TYPES.BADGE_PROPOSAL:
    case TX_TYPES.BADGE_VOTE:
    case TX_TYPES.BADGE_REVOCATION:  return '&#x1F3C5;'; // medal — governance
    default: return '&#8226;';
  }
}

function txStatusHtml(status, confirmations) {
  switch (status) {
    case 'complete':
      return `<span style="color:var(--success)">Complete</span>`;
    case 'maturing':
      return `<span style="color:var(--warning)">Maturing (${confirmations || 0}/6)</span>`;
    case 'admitted':
      return `<span style="color:var(--info, #60a5fa)">Admitted</span>`;
    case 'pending':
      return `<span style="color:var(--text-muted)">Pending</span>`;
    default:
      return confirmations >= 6
        ? `<span style="color:var(--success)">${formatNumber(confirmations)}</span>`
        : confirmations > 0
          ? `<span style="color:var(--warning)">${confirmations} / 6</span>`
          : `<span style="color:var(--text-muted)">pending</span>`;
  }
}

/**
 * Build a terminal-styled HTML block showing full wallet key info.
 * @param {Object}  result       — RPC response from generateMnemonic/importMnemonic
 * @param {boolean} showMnemonic — whether to include the mnemonic words
 * @returns {string} HTML string
 */
function formatTerminalOutput(result, showMnemonic) {
  const lines = [];

  lines.push('<span class="term-warn">WARNING: The information below grants full control of this</span>');
  lines.push('<span class="term-warn">wallet. Store it securely and NEVER share it.</span>');
  lines.push('');
  lines.push('<span class="term-heading">=== Noble Wallet ===</span>');
  lines.push('');

  if (showMnemonic && result.mnemonic) {
    const words = result.mnemonic.split(/\s+/);
    lines.push(`<span class="term-label">Mnemonic (${words.length} words):</span>`);
    for (let i = 0; i < words.length; i += 4) {
      const row = words.slice(i, i + 4)
        .map((w, j) => `${String(i + j + 1).padStart(3)}. ${w.padEnd(14)}`)
        .join('');
      lines.push(`<span class="term-value">${row}</span>`);
    }
    lines.push('');
  }

  lines.push(`<span class="term-label">Derivation Path:</span> <span class="term-value">m/44'/9999'/0'/0/0</span>`);

  if (result.private_key) {
    lines.push(`<span class="term-label">Private Key:    </span> <span class="term-warn">${result.private_key}</span>`);
  }
  if (result.public_key) {
    lines.push(`<span class="term-label">Public Key:     </span> <span class="term-value">${result.public_key}</span>`);
  }
  if (result.wire_hex) {
    lines.push(`<span class="term-label">Wire Hex:       </span> <span class="term-value">${result.wire_hex}</span>`);
  }
  lines.push(`<span class="term-label">Address:        </span> <span class="term-value">${result.address}</span>`);

  if (result.bitcoin_addresses && result.bitcoin_addresses.length > 0) {
    lines.push('');
    lines.push('<span class="term-label">Bitcoin derived addresses for wallet compatibility (use is optional):</span>');
    for (const ba of result.bitcoin_addresses) {
      const label = ba.address_type === 'p2pkh' ? 'P2PKH  (1...)' :
                    ba.address_type === 'p2wpkh' ? 'P2WPKH (bc1q)' :
                    ba.address_type === 'p2tr'   ? 'P2TR   (bc1p)' :
                    ba.address_type;
      lines.push(`  <span class="term-label">${label}:</span>  <span class="term-addr">${ba.address}</span>`);
    }
  }

  return lines.join('\n');
}
