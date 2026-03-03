/**
 * NOBLE Dashboard — Wallet Inspector Page
 * Read-only view of node wallet: balance, incoming subsidies+fees, outgoing transfers.
 * Spending functionality requires a separate secure application.
 */

import { formatNumber, formatFee, formatTimestamp, timeAgo, truncateHash, bytesToHex } from '../utils.js';
import { createMnemonicGrid, startAutoClearTimer, wipeInput, destroySecureElements } from '../wallet-security.js';

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

    <!-- Reward Address -->
    <div class="panel">
      <div class="panel-header">
        <span>Reward Address</span>
        <span id="w-reward-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Your node earns block rewards and gateway fee splits. Paste your Bitcoin address from any wallet to set the reward destination.
        </p>
        <dl class="detail-grid" id="w-reward-info">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
        <div id="w-reward-edit" style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <div style="display:flex;gap:var(--gap-sm);align-items:center">
            <input id="w-reward-input" type="text" placeholder="bc1q..., 1..., bc1p..., or hex public key"
              style="flex:1;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
            <button id="w-reward-save" class="btn-sm" style="padding:6px 14px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Save</button>
          </div>
          <span id="w-reward-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);display:block;margin-top:var(--gap-xs)"></span>
        </div>
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
  const wRewardInput = root.querySelector('#w-reward-input');
  const wRewardSave = root.querySelector('#w-reward-save');
  const wRewardMsg = root.querySelector('#w-reward-msg');

  let allTransactions = [];

  // ── Load reward address ──
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
        wRewardInput.value = res.address;
      } else {
        wRewardBadge.textContent = 'Not Configured';
        wRewardBadge.className = 'badge outbound';
        // Check if wallet has a secp256k1 key we can suggest
        let suggestion = '';
        try {
          const walletKeys = await rpc.call('noble_listAddresses');
          const secpKey = (walletKeys.keys || []).find(k => k.scheme === 'secp256k1' && k.bitcoin_addresses && k.bitcoin_addresses.length > 0);
          if (secpKey) {
            const p2wpkh = secpKey.bitcoin_addresses.find(a => a.address_type === 'p2wpkh');
            if (p2wpkh) suggestion = p2wpkh.address;
          }
        } catch (_) { /* wallet may be locked */ }

        if (suggestion) {
          wRewardInfo.innerHTML = `
            <dt style="grid-column:1/-1;color:var(--text-muted)">No reward address set.</dt>
            <dt style="grid-column:1/-1">
              <button id="w-reward-use-wallet" class="btn btn-sm" style="margin-top:var(--gap-xs)">Use wallet key: <span class="mono" style="font-size:var(--font-size-xs)">${suggestion}</span></button>
            </dt>
          `;
          wRewardInput.value = '';
          const useBtn = root.querySelector('#w-reward-use-wallet');
          if (useBtn) {
            useBtn.addEventListener('click', async () => {
              useBtn.disabled = true;
              useBtn.textContent = 'Saving...';
              try {
                await rpc.call('noble_setRewardAddress', { address: suggestion });
                await loadRewardAddress();
              } catch (e) {
                wRewardMsg.style.color = 'var(--error)';
                wRewardMsg.textContent = 'Error: ' + (e.message || e);
                useBtn.disabled = false;
                useBtn.textContent = 'Retry';
              }
            });
          }
        } else {
          wRewardInfo.innerHTML = `<dt style="grid-column:1/-1;color:var(--text-muted)">No reward address set. Paste a Bitcoin address below.</dt>`;
          wRewardInput.value = '';
        }
      }
    } catch (e) {
      console.error('[wallet] load reward address:', e);
      wRewardInfo.innerHTML = `<dt style="grid-column:1/-1;color:var(--text-muted)">Could not load reward address.</dt>`;
    }
  }

  // ── Save reward address ──
  wRewardSave.addEventListener('click', async () => {
    const addr = wRewardInput.value.trim();
    if (!addr) {
      wRewardMsg.style.color = 'var(--error)';
      wRewardMsg.textContent = 'Please enter an address.';
      return;
    }
    wRewardSave.disabled = true;
    wRewardSave.textContent = 'Saving...';
    wRewardMsg.textContent = '';
    try {
      const res = await rpc.call('noble_setRewardAddress', { address: addr });
      wRewardMsg.style.color = 'var(--success)';
      wRewardMsg.textContent = `Saved: ${res.address_type} address (${res.display_address})`;
      await loadRewardAddress();
    } catch (e) {
      wRewardMsg.style.color = 'var(--error)';
      wRewardMsg.textContent = 'Error: ' + (e.message || e);
    } finally {
      wRewardSave.disabled = false;
      wRewardSave.textContent = 'Save';
    }
  });

  loadRewardAddress();

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

      // Income breakdown — 3 categories: subsidies, validator fees, gateway fees
      const subsidyTotal = txResult.transactions
        .filter(t => t.type === 'validation_subsidy')
        .reduce((s, t) => s + t.amount, 0);
      const valFeeTotal = txResult.transactions
        .filter(t => t.type === 'fee_validation')
        .reduce((s, t) => s + t.amount, 0);
      const gwFeeTotal = txResult.transactions
        .filter(t => t.type === 'fee_gateway')
        .reduce((s, t) => s + t.amount, 0);
      const outTotal = txResult.transactions
        .filter(t => t.direction === 'outgoing')
        .reduce((s, t) => s + t.amount, 0);
      const totalIncome = subsidyTotal + valFeeTotal + gwFeeTotal;

      const subsidyPct = totalIncome > 0 ? Math.round(subsidyTotal / totalIncome * 100) : 0;
      const valFeePct = totalIncome > 0 ? Math.round(valFeeTotal / totalIncome * 100) : 0;
      const gwFeePct = Math.max(0, 100 - subsidyPct - valFeePct);

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
            <span>Validator Fees</span>
            <span class="mono">${formatNoble(valFeeTotal)} (${valFeePct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${valFeePct}%;background:var(--success);border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>
        <div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;font-size:var(--font-size-sm);margin-bottom:4px">
            <span>Gateway Fees</span>
            <span class="mono">${formatNoble(gwFeeTotal)} (${gwFeePct}%)</span>
          </div>
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${gwFeePct}%;background:var(--warning);border-radius:4px;transition:width 0.3s"></div>
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
    else if (filter === 'subsidies') filtered = allTransactions.filter(t => t.type === 'validation_subsidy');
    else if (filter === 'fees') filtered = allTransactions.filter(t => t.type.startsWith('fee_'));
    else if (filter === 'transfers') filtered = allTransactions.filter(t => t.type.startsWith('payment_'));
    else if (filter === 'documents') filtered = allTransactions.filter(t => t.type === 'doc_registration');

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
        <td><span class="badge ${isIn ? 'inbound' : 'outbound'}">${typeLabel(tx.type)}</span></td>
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

  // WS: refresh on new block (might include new subsidy)
  ws.subscribe('newBlocks', () => loadWallet());
  unsubs.push(() => ws.unsubscribe('newBlocks'));

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
  const noble = atomicUnits / 1_000_000;
  if (noble >= 100) return `${noble.toFixed(2)} NOBLE`;
  if (noble >= 1) return `${noble.toFixed(4)} NOBLE`;
  if (noble >= 0.001) return `${noble.toFixed(6)} NOBLE`;
  if (atomicUnits === 0) return '0.00 NOBLE';
  return `${atomicUnits} atomic`;
}

function typeIcon(type) {
  switch (type) {
    case 'validation_subsidy': return '&#9670;';  // diamond — block reward
    case 'fee_validation':     return '&#9733;';  // star — validator fee share
    case 'fee_gateway':        return '&#9672;';  // outlined diamond — gateway fee share
    case 'payment_received':   return '&#8595;';  // down arrow — received
    case 'payment_sent':       return '&#8593;';  // up arrow — sent
    case 'doc_registration':   return '&#10003;'; // checkmark — document registration
    default: return '&#8226;';
  }
}

function typeLabel(type) {
  switch (type) {
    case 'validation_subsidy': return 'Validation Subsidy';
    case 'fee_validation':     return 'Fee (Validator)';
    case 'fee_gateway':        return 'Fee (Gateway)';
    case 'payment_received':   return 'Payment Received';
    case 'payment_sent':       return 'Payment Sent';
    case 'doc_registration':   return 'Doc Registration';
    default: return type;
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
    lines.push('<span class="term-label">Bitcoin Addresses:</span>');
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
