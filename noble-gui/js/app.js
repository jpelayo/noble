/**
 * NOBLE Dashboard — Application Entry Point
 *
 * To switch from mock to real API, change these imports:
 *   import { RpcClient } from './rpc-client.js';
 *   import { WsManager } from './ws-manager.js';
 *   const rpc = new RpcClient('http://localhost:9332');
 *   const ws = new WsManager('ws://localhost:9334', { onStatusChange });
 */

import { MockRpcClient, MockWsManager } from './mock-rpc.js';
import { createStore } from './state.js';
import { Router } from './router.js';
import { formatNumber } from './utils.js';

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

// ── Status change handler ──
function onStatusChange(status) {
  store.state.connected = status === 'connected';
}

// ── Initialize mock layer ──
const rpc = new MockRpcClient();
const ws = new MockWsManager(rpc, { onStatusChange });

// ── Reactive state store ──
const { state, subscribe, getState } = createStore({
  blockHeight: 0,
  peerCount: 0,
  mempoolSize: 0,
  cyclePhase: '--',
  connected: false,
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

subscribe('connected', (val) => {
  const dot = statusIndicator.querySelector('.status-dot') || document.createElement('span');
  dot.className = `status-dot ${val ? 'connected' : 'disconnected'}`;
  if (!dot.parentElement) statusIndicator.prepend(dot);
  statusIndicator.lastChild.textContent = val ? ' Connected' : ' Disconnected';
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
  .start();

// ── Fetch initial data ──
async function bootstrap() {
  try {
    const [blockCount, mempoolInfo, networkInfo, cycleStatus] = await Promise.all([
      rpc.call('noble_getBlockCount'),
      rpc.call('noble_getMempoolInfo'),
      rpc.call('noble_getNetworkInfo'),
      rpc.call('noble_getCycleStatus'),
    ]);

    state.blockHeight = blockCount.height;
    state.peerCount = networkInfo.peer_count;
    state.mempoolSize = mempoolInfo.count;
    state.cyclePhase = cycleStatus.phase;
  } catch (e) {
    console.error('[app] bootstrap error:', e);
  }
}

// ── WebSocket subscriptions for global state ──
ws.subscribe('newBlocks', (block) => {
  state.blockHeight = block.header.height;
});

ws.subscribe('mempoolStats', (info) => {
  state.mempoolSize = info.count;
});

ws.subscribe('cyclePhaseChange', (status) => {
  state.cyclePhase = status.phase;
});

// ── Start ──
bootstrap();
ws.connect();
