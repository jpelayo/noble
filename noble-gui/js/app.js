/**
 * NOBLE Dashboard — Application Entry Point
 *
 * RPC endpoint is configurable via URL parameter:
 *   ?rpc=https://localhost:8783&ws=wss://localhost:8784
 *
 * If no ?rpc parameter is provided and served over file://, the mock layer is
 * used. mock-rpc.js is never loaded on deployed nodes — it is imported
 * dynamically only in the mock branch, keeping zero interference and zero
 * parse weight on production.
 */

// Cache-bust: append ?v=<version> to all dynamic imports.
const _v = window.__noble_v || Date.now();
const _m = (path) => `${path}?v=${_v}`;

const { createStore } = await import(_m('./state.js'));
const { Router } = await import(_m('./router.js'));
const { formatNumber, formatChainLabel } = await import(_m('./utils.js'));

// ── Pages (dynamic imports with cache busting) ──
const [
  overviewPage, blocksPage, blockDetailPage, transactionsPage,
  txDetailPage, verifyPage, mempoolPage, networkPage,
  consensusPage, walletPage, healthPage, identityPage,
  tracePage, storagePage, settingsPage, setupPage,
] = await Promise.all([
  import(_m('./pages/overview.js')),
  import(_m('./pages/blocks.js')),
  import(_m('./pages/block-detail.js')),
  import(_m('./pages/transactions.js')),
  import(_m('./pages/tx-detail.js')),
  import(_m('./pages/verify.js')),
  import(_m('./pages/mempool.js')),
  import(_m('./pages/network.js')),
  import(_m('./pages/consensus.js')),
  import(_m('./pages/wallet.js')),
  import(_m('./pages/health.js')),
  import(_m('./pages/identity.js')),
  import(_m('./pages/trace.js')),
  import(_m('./pages/storage.js')),
  import(_m('./pages/settings.js')),
  import(_m('./pages/setup.js')),
]);

// ── Status change handler ──
// status: 'connecting' | 'connected' | 'disconnected'
let _wasConnected = false;
function onStatusChange(status) {
  store.state.connectionStatus = status;
  store.state.connected = status === 'connected';

  // On reconnect: refresh all global data — events were missed while disconnected.
  if (status === 'connected' && _wasConnected) {
    bootstrap();
    // Notify pages so they can refresh their own data.
    window.dispatchEvent(new CustomEvent('noble-ws-reconnect'));
  }
  if (status === 'connected') _wasConnected = true;
}

// ── Initialize RPC layer ──
const params = new URLSearchParams(window.location.search);
let rpcUrl = params.get('rpc');
let wsUrl = params.get('ws');

// Auto-detect RPC endpoint when served over HTTP(S).
// Use the same-origin /rpc proxy route (served by the GUI server on port 8785)
// so the browser never directly connects to ports 8783/8784.  This avoids the
// cross-port TLS cert trust issue where the user would need to manually accept
// the self-signed cert for each port separately from port 8785.
if (!rpcUrl && window.location.protocol.startsWith('http')) {
  rpcUrl = '/rpc';
}

// When served by the node (HTTP/HTTPS), rpcUrl is always set.
// file:// access is not a supported runtime — show a clear error.
if (!rpcUrl) {
  document.body.innerHTML = '<div style="padding:2rem;color:#f87171;font-family:monospace">'
    + 'Dashboard must be served by a Noble node (HTTPS on port 8785).<br>'
    + 'Open <code>https://127.0.0.1:8785</code> instead of opening the file directly.</div>';
  throw new Error('Dashboard requires a Noble node server — file:// access is not supported.');
}

const { RpcClient } = await import('./rpc-client.js');
const { WsManager } = await import('./ws-manager.js');
const rpc = new RpcClient(rpcUrl);

if (!wsUrl) {
  const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  wsUrl = `${wsProto}://${window.location.host}/ws`;
}
const ws = new WsManager(wsUrl, { onStatusChange });
console.info(`[app] RPC: ${rpcUrl}, WS: ${wsUrl}`);

// ── Version footer — populated from window.NOBLE_VERSION injected by the server ──
const versionEl = document.getElementById('noble-version-footer');
if (versionEl && window.NOBLE_VERSION) versionEl.textContent = 'v' + window.NOBLE_VERSION;

// ── Reactive state store ──
const { state, subscribe, getState } = createStore({
  blockHeight: 0,
  peerCount: 0,
  mempoolSize: 0,
  cyclePhase: '--',
  connected: false,
  connectionStatus: 'disconnected',
});

const store = { state, subscribe, getState };

// ── Bind status bar ──
const kpiHeight = document.getElementById('kpi-height');
const kpiPeers = document.getElementById('kpi-peers');
const kpiMempool = document.getElementById('kpi-mempool');
const kpiPhase = document.getElementById('kpi-phase');
const statusIndicator = document.getElementById('status-indicator');

subscribe('blockHeight', (val) => {
  kpiHeight.textContent = formatNumber(val);
  kpiHeight.classList.add('flash');
  setTimeout(() => kpiHeight.classList.remove('flash'), 600);
});

subscribe('peerCount', (val) => {
  kpiPeers.textContent = formatNumber(val);
});

subscribe('mempoolSize', (val) => {
  kpiMempool.textContent = formatNumber(val);
});

subscribe('cyclePhase', (val) => {
  kpiPhase.textContent = val;
});

subscribe('connectionStatus', (status) => {
  const dot = statusIndicator.querySelector('.status-dot') || document.createElement('span');
  const labels = { connecting: 'Connecting', connected: 'Connected', disconnected: 'Disconnected' };
  const classes = { connecting: 'syncing', connected: 'connected', disconnected: 'disconnected' };
  dot.className = `status-dot ${classes[status] || 'disconnected'}`;
  if (!dot.parentElement) statusIndicator.prepend(dot);
  statusIndicator.lastChild.textContent = ` ${labels[status] || 'Offline'}`;
});

// ── Theme toggle ──
const themeToggle = document.getElementById('theme-toggle');
const html = document.documentElement;

function applyTheme(theme) {
  html.setAttribute('data-theme', theme);
  localStorage.setItem('noble-theme', theme);
  themeToggle.textContent = theme === 'dark' ? 'Light' : 'Dark';
}

function initTheme() {
  const saved = localStorage.getItem('noble-theme');
  if (saved) {
    applyTheme(saved);
  } else {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(prefersDark ? 'dark' : 'light');
  }
}

themeToggle.addEventListener('click', () => {
  const current = html.getAttribute('data-theme');
  applyTheme(current === 'dark' ? 'light' : 'dark');
});

initTheme();

// ── Context shared with all pages ──
const ctx = { rpc, ws, state, subscribe, getState };

// ── Router ──
const content = document.getElementById('content');
const router = new Router(content, ctx);

// Setup guard: block all navigation except /setup when node is unconfigured.
//
// Two activation paths:
//   1. Server-injected NOBLE_SETUP_MODE (synchronous, before router.start)
//   2. RPC-based check (async, covers mock mode AND production edge cases
//      where identity.json exists from CLI setup but GUI wizard wasn't completed)

function activateSetupGuard() {
  location.hash = '#/setup';
  router.setGuard((path) => path === '/setup' ? null : '/setup');

  document.querySelectorAll('#sidebar a').forEach(a => {
    if (a.getAttribute('href') !== '#/setup') {
      a.style.opacity = '0.35';
      a.style.pointerEvents = 'none';
      a.style.cursor = 'default';
    }
  });
}

function deactivateSetupGuard() {
  router.clearGuard();

  document.querySelectorAll('#sidebar a').forEach(a => {
    if (a.getAttribute('href') !== '#/setup') {
      a.style.opacity = '';
      a.style.pointerEvents = '';
      a.style.cursor = '';
    }
  });

  // Hide setup link — it's no longer needed
  const setupNavItem = document.querySelector('a[href="#/setup"]');
  if (setupNavItem) setupNavItem.parentElement.style.display = 'none';
}

// Expose for setup.js to call after completion
ctx.deactivateSetupGuard = deactivateSetupGuard;

// Path 1: synchronous server-injected flag (production first-boot)
if (window.NOBLE_SETUP_MODE) {
  activateSetupGuard();
}

// Path 2: async RPC check (mock mode + production where identity.json exists
// but GUI wizard was never completed)
if (!window.NOBLE_SETUP_MODE) {
  rpc.call('noble_getSetupStatus').then((res) => {
    if (!res || !res.setup_complete) {
      // Setup wizard not completed — lock to setup
      activateSetupGuard();
    } else {
      // Configured — hide setup link
      const setupNavItem = document.querySelector('a[href="#/setup"]');
      if (setupNavItem) setupNavItem.parentElement.style.display = 'none';
    }
  }).catch(() => {
    // RPC unavailable — keep setup visible, don't lock
  });
}

router
  .add('/', overviewPage)
  .add('/blocks', blocksPage)
  .add('/block/:height', blockDetailPage)
  .add('/transactions', transactionsPage)
  .add('/tx/:txid', txDetailPage)
  .add('/verify', verifyPage)
  .add('/mempool', mempoolPage)
  .add('/network', networkPage)
  .add('/consensus', consensusPage)
  .add('/wallet', walletPage)
  .add('/health', healthPage)
  .add('/storage', storagePage)
  .add('/identity', identityPage)
  .add('/trace', tracePage)
  .add('/settings', settingsPage)
  .add('/setup', setupPage)
  .start();

// ── Auth prompt ──

function showAuthPrompt() {
  let overlay = document.getElementById('auth-overlay');
  if (overlay) { overlay.style.display = 'flex'; return; }

  overlay = document.createElement('div');
  overlay.id = 'auth-overlay';
  overlay.style.cssText =
    'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6)';

  const card = document.createElement('div');
  card.style.cssText =
    'background:var(--bg-primary,#1a1a2e);border:1px solid var(--border,#333);border-radius:8px;padding:2rem;min-width:320px;text-align:center';
  card.innerHTML = `
    <h3 style="margin:0 0 0.5rem;color:var(--text-primary,#e0e0e0)">Authentication Required</h3>
    <p style="margin:0 0 1rem;color:var(--text-secondary,#999);font-size:0.85rem">
      Enter your 6-digit TOTP code to access the dashboard.
    </p>
    <input id="auth-code" type="text" maxlength="6" pattern="[0-9]{6}" inputmode="numeric"
      placeholder="000000" autocomplete="one-time-code"
      style="width:100%;padding:0.6rem;text-align:center;font-size:1.4rem;letter-spacing:0.3em;
        border:1px solid var(--border,#333);border-radius:4px;background:var(--bg-secondary,#16213e);
        color:var(--text-primary,#e0e0e0);margin-bottom:1rem;box-sizing:border-box">
    <button id="auth-submit" style="width:100%;padding:0.6rem;border:none;border-radius:4px;
      background:var(--accent,#0f3460);color:#fff;font-size:0.95rem;cursor:pointer">
      Authenticate</button>
    <p id="auth-error" style="margin:0.5rem 0 0;color:#e74c3c;font-size:0.85rem;display:none"></p>
  `;
  overlay.appendChild(card);
  document.body.appendChild(overlay);

  const input = document.getElementById('auth-code');
  const submit = document.getElementById('auth-submit');
  const errEl = document.getElementById('auth-error');

  async function doAuth() {
    const code = input.value.trim();
    if (!/^\d{6}$/.test(code)) {
      errEl.textContent = 'Please enter a 6-digit code.';
      errEl.style.display = 'block';
      return;
    }
    submit.disabled = true;
    submit.textContent = 'Verifying...';
    errEl.style.display = 'none';

    await rpc.setAuthToken(code);
    // F3: propagate the same pre-computed hash to WsManager so WebSocket
    // upgrades can include ?token=<hash> for TOTP-protected nodes.
    ws.setAuthToken(rpc.getAuthToken());
    try {
      await rpc.call('noble_getBlockCount');
      overlay.style.display = 'none';
      bootstrap();
    } catch (e) {
      if (e.code === -32012) {
        errEl.textContent = 'Invalid code. Please try again.';
        errEl.style.display = 'block';
        await rpc.setAuthToken(null);
        ws.setAuthToken(null);
      } else {
        errEl.textContent = e.message;
        errEl.style.display = 'block';
      }
    } finally {
      submit.disabled = false;
      submit.textContent = 'Authenticate';
    }
  }

  submit.addEventListener('click', doAuth);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') doAuth(); });
  input.focus();
}

// ── Chain identity bar ──
function populateChainIdentity(nodeInfo) {
  const bar = document.getElementById('chain-id-bar');
  if (!bar) return;

  const label = formatChainLabel(nodeInfo);
  if (!label) { bar.style.display = 'none'; return; }

  const idHex = document.getElementById('chain-id-hex');
  idHex.textContent = label;

  bar.style.display = '';
}

// ── Fork / alignment status indicator ──
// Continuous self-assessment: "Is THIS node aligned with its peers?"
// Driven by: newBlocks, peerUpdates (including chain_tip_updated), bootstrap.
async function updateForkStatus() {
  const bar = document.getElementById('fork-status-bar');
  if (!bar) return;
  try {
    const forkData = await rpc.call('noble_getDetectedForks').catch(() => null);
    if (!forkData) { bar.style.display = 'none'; return; }

    const label = document.getElementById('fork-status-label');
    const detail = document.getElementById('fork-status-detail');
    const myHeight = forkData.local_height;
    const peerCount = forkData.peer_count || 0;
    const highestKnown = forkData.highest_known || myHeight;
    const behind = highestKnown - myHeight;

    // Check for divergence: any non-local fork that definitively disagrees
    // with our local chain (agrees_with_local === false).
    const nonLocalForks = forkData.forks.filter(f => !f.is_local);
    let diverged = false;
    for (const fork of nonLocalForks) {
      if (fork.agrees_with_local === false) {
        diverged = true;
        break;
      }
    }

    let severity, statusText, detailText;

    if (peerCount === 0) {
      // No peers reporting chain data — cannot assess alignment.
      severity = 'high';
      statusText = 'Isolated';
      detailText = `height ${myHeight} \u00b7 no peers`;
    } else if (behind > 10) {
      // Far behind — actively syncing or severely lagging.
      severity = 'syncing';
      const pct = highestKnown > 0 ? (myHeight / highestKnown * 100).toFixed(1) + '%' : '';
      statusText = `<span class="fork-sync-spinner"></span>Syncing`;
      detailText = pct
        ? `block ${myHeight} / ${highestKnown} (${pct})`
        : `${behind} blocks behind`;
    } else if (diverged) {
      // On a different chain than one or more peers (verified by block hash comparison).
      severity = 'high';
      statusText = 'Diverged';
      detailText = behind > 0
        ? `wrong fork, ${behind} block${behind !== 1 ? 's' : ''} behind`
        : 'wrong fork';
    } else if (behind === 0 && myHeight === 0) {
      // All peers also at height 0 — no chain formed yet.
      severity = 'syncing';
      statusText = 'Bootstrap';
      detailText = `forming chain \u00b7 ${peerCount} peer${peerCount !== 1 ? 's' : ''}`;
    } else if (behind === 0) {
      // We are at the highest known height.
      //
      // "Aligned" = majority of peers share the same chain, same height,
      // same chain tip.  Peers behind us are simply catching up — that is
      // their normal operation, not a problem for THIS node.
      //
      // Only show divergence when peer(s) at OUR SAME height have a
      // different tip hash — a genuine fork that may need resolution.
      const sameHeightForks = nonLocalForks.filter(f => f.height === myHeight);
      if (sameHeightForks.length > 0) {
        // Same height, different tip hash — genuine fork.
        // Check majority: if more peers agree with us, we are aligned.
        const localFork = forkData.forks.find(f => f.is_local);
        const localPeers = localFork ? localFork.peer_count : 0;
        const divergentPeers = sameHeightForks.reduce((s, f) => s + f.peer_count, 0);
        if (localPeers >= divergentPeers) {
          // Majority agrees with us — aligned despite minor fork.
          severity = 'zero';
          statusText = 'Aligned';
          detailText = `height ${myHeight}`;
        } else {
          // We are in the minority position.
          severity = 'medium';
          statusText = 'Diverged';
          detailText = `height ${myHeight} \u00b7 different tip hash`;
        }
      } else {
        // All peers either share our tip or are behind us — aligned.
        severity = 'zero';
        statusText = 'Aligned';
        detailText = `height ${myHeight}`;
      }
    } else if (behind <= 3) {
      severity = 'low';
      statusText = 'Behind';
      detailText = `${behind} block${behind !== 1 ? 's' : ''} behind`;
    } else {
      // 4-10 blocks behind.
      severity = 'medium';
      statusText = 'Drifting';
      detailText = `${behind} blocks behind`;
    }

    bar.dataset.severity = severity;
    label.innerHTML = statusText;
    detail.textContent = detailText;
    bar.style.display = '';
  } catch (e) {
    bar.style.display = 'none';
  }
}

// ── Fetch initial data ──
async function bootstrap() {
  try {
    const [blockCount, mempoolInfo, networkInfo, cycleStatus, nodeInfo] = await Promise.all([
      rpc.call('noble_getBlockCount'),
      rpc.call('noble_getMempoolInfo'),
      rpc.call('noble_getNetworkInfo'),
      rpc.call('noble_getCycleStatus'),
      rpc.call('noble_getNodeInfo'),
    ]);

    state.blockHeight = blockCount.height;
    state.peerCount = networkInfo.peer_count;
    state.mempoolSize = mempoolInfo.count;
    // null cycle_number = bootstrapping (no blocks beyond genesis).
    state.cyclePhase = cycleStatus.cycle_number == null ? 'Awaiting genesis' : cycleStatus.phase;

    // Force-render status bar values — the reactive store skips same-value
    // assignments (0→0), so initial "-- " placeholders would persist.
    kpiHeight.textContent = formatNumber(state.blockHeight);
    kpiPeers.textContent = formatNumber(state.peerCount);
    kpiMempool.textContent = formatNumber(state.mempoolSize);
    kpiPhase.textContent = state.cyclePhase;

    // Show chain identity bar if we have a chain_id.
    populateChainIdentity(nodeInfo);
    // Fork status — initial load.
    updateForkStatus();
  } catch (e) {
    if (e.code === -32012) {
      showAuthPrompt();
      return;
    }
    console.error('[app] bootstrap error:', e);
  }
}

// ── WebSocket subscriptions for global state ──
// Block notifications from backend: { height, hash, tx_count }
ws.subscribe('newBlocks', (block) => {
  const wasBootstrap = state.blockHeight === 0;
  state.blockHeight = block.height;
  // First real block committed — show chain identity bar (was hidden during bootstrap).
  if (wasBootstrap && block.height > 0) {
    rpc.call('noble_getNodeInfo').then(populateChainIdentity).catch(() => {});
  }
  // Refresh fork status on every new block.
  updateForkStatus();
});

// New-transaction notifications: { tx_id }
// Use as a trigger to refresh the mempool count via HTTP.
ws.subscribe('newTransactions', () => {
  rpc.call('noble_getMempoolInfo').then(info => {
    state.mempoolSize = info.count;
  }).catch(() => {});
});

ws.subscribe('cyclePhaseChange', (data) => {
  if (data.phase) state.cyclePhase = data.phase;
});

// ── Global connectivity log (survives page navigation) ──
const CONN_LOG_MAX = 200;
window._connLog = window._connLog || [];

// Peer count: update on peer connect/disconnect via WS (no polling needed).
ws.subscribe('peerUpdates', (data) => {
  rpc.call('noble_getNetworkInfo').then(info => {
    state.peerCount = info.peer_count;
  }).catch(() => {});
  // Accumulate connectivity events globally so they're never lost.
  // Filter out non-connectivity events (status updates belong in Protocol Activity, not here).
  const _connEvents = new Set(['disconnected', 'banned', 'rejected']);
  if (data && data.event && _connEvents.has(data.event)) {
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    window._connLog.push({ time, ...data });
    if (window._connLog.length > CONN_LOG_MAX) window._connLog.shift();
    // Notify network page if it's mounted.
    window.dispatchEvent(new CustomEvent('noble-conn-log'));
  }
  // Peer topology changed — fork picture may differ now.
  updateForkStatus();
});

// ── Network online/offline resilience ──
// When the browser regains network, force WS reconnect + data refresh.
window.addEventListener('online', () => {
  console.info('[app] network online — forcing WS reconnect');
  ws.connect();   // WsManager handles dedup if already connected
  bootstrap();
});
window.addEventListener('offline', () => {
  console.warn('[app] network offline');
});

// ── Start ──
bootstrap();
ws.connect();
