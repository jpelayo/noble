/**
 * NOBLE Dashboard — Application Entry Point
 *
 * RPC endpoint is configurable via URL parameter:
 *   ?rpc=https://localhost:8783&ws=wss://localhost:8783
 *
 * If no ?rpc parameter is provided and served over file://, the mock layer is
 * used. mock-rpc.js is never loaded on deployed nodes — it is imported
 * dynamically only in the mock branch, keeping zero interference and zero
 * parse weight on production.
 */

import { createStore } from './state.js';
import { Router } from './router.js';
import { formatNumber, formatChainLabel } from './utils.js';

// ── Pages (lazy-ish, but static imports for file:// compat) ──
import * as overviewPage from './pages/overview.js';
import * as blocksPage from './pages/blocks.js';
import * as blockDetailPage from './pages/block-detail.js';
import * as transactionsPage from './pages/transactions.js';
import * as txDetailPage from './pages/tx-detail.js';
import * as verifyPage from './pages/verify.js';
import * as mempoolPage from './pages/mempool.js';
import * as networkPage from './pages/network.js';
import * as consensusPage from './pages/consensus.js';
import * as walletPage from './pages/wallet.js';
import * as healthPage from './pages/health.js';
import * as identityPage from './pages/identity.js';
import * as tracePage from './pages/trace.js';
import * as storagePage from './pages/storage.js';
import * as settingsPage from './pages/settings.js';
import * as setupPage from './pages/setup.js';

// ── Status change handler ──
// status: 'connecting' | 'connected' | 'disconnected'
function onStatusChange(status) {
  store.state.connectionStatus = status;
  store.state.connected = status === 'connected';
}

// ── Initialize RPC layer (real or mock) ──
const params = new URLSearchParams(window.location.search);
let rpcUrl = params.get('rpc');
let wsUrl = params.get('ws');

// Auto-detect RPC endpoint when served over HTTP(S) (not file://).
// Use the same-origin /rpc proxy route (served by the GUI server on port 8785)
// so the browser never directly connects to port 8783.  This avoids the
// cross-port TLS cert trust issue where the user would need to manually accept
// the self-signed cert for port 8783 separately from port 8785.
// Pass ?mock to force mock mode over HTTP (for development).
if (!rpcUrl && window.location.protocol.startsWith('http') && !params.has('mock')) {
  rpcUrl = '/rpc';
}

let rpc, ws;
if (rpcUrl) {
  // PRODUCTION PATH — rpc-client.js and ws-manager.js only.
  // mock-rpc.js is never fetched, parsed, or held in memory.
  const { RpcClient } = await import('./rpc-client.js');
  const { WsManager } = await import('./ws-manager.js');
  rpc = new RpcClient(rpcUrl);
  // WS connects directly to the RPC port (jsonrpsee HTTP+WS on port 8783).
  // We can't proxy WS through /rpc (HTTP-only), so fall back to direct port.
  // F4: use NOBLE_RPC_PORT injected by the GUI server for non-default ports.
  if (!wsUrl) {
    const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const rpcPort = window.NOBLE_RPC_PORT || 8783;
    wsUrl = `${wsProto}://${window.location.hostname}:${rpcPort}`;
  }
  ws = new WsManager(wsUrl, { onStatusChange });
  console.info(`[app] Using RPC proxy: ${rpcUrl}, WS: ${wsUrl}`);
} else {
  // MOCK PATH (file:// dev mode only) — mock-rpc.js loaded lazily here.
  // Bugs or parse errors in mock code cannot affect the production branch.
  const { MockRpcClient, MockWsManager } = await import('./mock-rpc.js');
  rpc = new MockRpcClient();
  ws = new MockWsManager(rpc, { onStatusChange });
  console.info('[app] Using mock RPC layer');
}

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
  if (!bar || !nodeInfo.network_name) return;

  const badge = document.getElementById('chain-net-badge');
  const idHex = document.getElementById('chain-id-hex');

  const net = nodeInfo.network_name.toLowerCase();
  badge.textContent = net;
  badge.className = 'chain-net-badge net-' + net;

  idHex.textContent = formatChainLabel(nodeInfo);

  bar.style.display = '';
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

    // Only show chain identity bar once the chain is active (has blocks beyond genesis).
    if (cycleStatus.cycle_number != null) {
      populateChainIdentity(nodeInfo);
    }
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

// ── Start ──
bootstrap();
ws.connect();
