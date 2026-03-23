// NOBLE Document Client — Router & State Controller
import { Bridge } from './bridge.js';
import { emptyState } from './components/empty-state.js';
import { init as initHome } from './pages/home.js';
import { init as initDocuments } from './pages/documents.js';
import { init as initDrafts } from './pages/drafts.js';
import { init as initVerify } from './pages/verify.js';
import { init as initPayments } from './pages/payments.js';
import { init as initContacts } from './pages/contacts.js';
import { init as initSettings } from './pages/settings.js';
import { init as initFaucet } from './pages/faucet.js';
import { init as initTxDetail } from './pages/tx-detail.js';

const pages = {
    home:      initHome,
    documents: initDocuments,
    drafts:    initDrafts,
    verify:    initVerify,
    payments:  initPayments,
    contacts:  initContacts,
    settings:  initSettings,
    faucet:    initFaucet,
    'tx-detail': initTxDetail,
};

let currentPage = null;
let currentRoute = null;
let appState = {};
let bootComplete = false;

// Persistent page cache: each page is mounted once and hidden/shown on navigation.
// This preserves wizard state, form inputs, scroll positions across page switches.
const mountedPages = {};  // section → { root: HTMLElement, page: pageInstance }

const App = {
    /** Navigate to a section. Pages are mounted once and hidden/shown, never destroyed.
     *  Parameterized pages (like tx-detail) are always recreated with fresh params. */
    navigateTo(section, params) {
        const isParameterized = !!params;
        if (section === currentRoute && !isParameterized) return;
        const container = document.getElementById('app-content');
        if (!container) return;

        // Hide current page
        if (currentRoute && mountedPages[currentRoute]) {
            mountedPages[currentRoute].root.style.display = 'none';
        }

        currentRoute = section;

        // Parameterized pages: destroy old instance and recreate
        if (isParameterized && mountedPages[section]) {
            if (mountedPages[section].page?.destroy) mountedPages[section].page.destroy();
            mountedPages[section].root.remove();
            delete mountedPages[section];
        }

        // Reuse existing page or create new one
        if (mountedPages[section]) {
            // Show cached page
            mountedPages[section].root.style.display = '';
            currentPage = mountedPages[section].page;
            // Refresh with latest state
            if (currentPage && currentPage.refresh) {
                currentPage.refresh(appState);
            }
        } else {
            // First visit — create page root and mount
            const root = document.createElement('div');
            root.className = '';
            container.appendChild(root);

            const initFn = pages[section];
            let page = null;
            if (initFn) {
                page = initFn(root, { state: appState, Bridge, params: params || {} });
            } else {
                root.appendChild(emptyState({
                    icon: '\u{1F6A7}',
                    title: 'Coming Soon',
                    subtitle: `The ${section} section is under development.`
                }));
            }
            mountedPages[section] = { root, page };
            currentPage = page;
        }
    },

    /** Push a state patch to the current page. */
    updateState(patch) {
        const wasConnected = appState.isConnected;
        const hadWallet = appState.hasWallet;
        Object.assign(appState, patch);
        App._updateChainBar();

        // If connection or wallet state changed AFTER boot, invalidate ALL cached pages
        // so they re-mount fresh on next visit (pages check isConnected on init).
        if (bootComplete && (wasConnected !== appState.isConnected || hadWallet !== appState.hasWallet)) {
            for (const [key, entry] of Object.entries(mountedPages)) {
                if (entry.page && entry.page.destroy) entry.page.destroy();
                entry.root.remove();
            }
            for (const key of Object.keys(mountedPages)) delete mountedPages[key];
            if (currentRoute) {
                const route = currentRoute;
                currentRoute = null;
                App.navigateTo(route);
            }
            return;
        }

        if (currentPage && currentPage.refresh) {
            currentPage.refresh(appState);
        }
    },

    /** Get current app state. */
    getState() {
        return { ...appState };
    },

    /** Handle an event pushed from Swift (poll timer, state change). */
    handleEvent(type, data) {
        if (type === 'stateUpdate') {
            // During boot, ignore disconnected pushes — let boot() finish first
            if (!bootComplete && data.isConnected === false) return;
            const wasConnected = appState.isConnected;
            App.updateState(data);
            if (data.isConnected === false && wasConnected !== false) {
                appState._confirmedDisconnected = true;
                App._showDisconnectedBanner();
            } else if (data.isConnected === true) {
                appState._confirmedDisconnected = false;
                App._hideDisconnectedBanner();
            }
        }
    },

    _showDisconnectedBanner() {
        let banner = document.getElementById('disconnected-banner');
        if (banner) return;
        banner = document.createElement('div');
        banner.id = 'disconnected-banner';
        banner.setAttribute('role', 'alert');
        banner.style.cssText = 'position:fixed;top:0;left:0;right:0;padding:var(--gap-sm) var(--gap);background:var(--error);color:#fff;text-align:center;font-size:var(--font-size-sm);z-index:2000;display:flex;align-items:center;justify-content:center;gap:var(--gap-sm)';
        banner.innerHTML = '<span>Disconnected from node. Reconnecting...</span><button id="disconnected-retry" style="background:#fff3;border:1px solid #fff6;color:#fff;padding:2px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Retry Now</button>';
        document.body.appendChild(banner);
        document.getElementById('disconnected-retry').addEventListener('click', () => App._checkConnectivity());
    },

    _hideDisconnectedBanner() {
        const banner = document.getElementById('disconnected-banner');
        if (banner) banner.remove();
    },

    /** Update the persistent chain ID bar at the top. */
    _updateChainBar() {
        const bar = document.getElementById('chain-bar');
        if (!bar) return;
        if (appState.chainId) {
            bar.hidden = false;
            const dotClass = appState.isConnected ? 'chain-dot' : 'chain-dot chain-dot-offline';
            const connLabel = appState.isConnected ? 'Chain' : 'Disconnected';
            let html = `<span class="${dotClass}"></span><span class="chain-label">${connLabel}</span> ${appState.chainId}`;
            // Node alignment badge — only shown when NOT "Aligned" (the normal state).
            const ns = appState.nodeState;
            if (ns && ns !== 'Aligned' && ns !== 'Connected' && ns !== 'Unknown' && appState.isConnected) {
                const cls = 'node-state-' + ns.toLowerCase().replace(/\s+/g, '-');
                html += ` <span class="node-state-badge ${cls}">${ns}</span>`;
            }
            bar.innerHTML = html;
        } else {
            bar.hidden = true;
            bar.innerHTML = '';
        }
    },

    /** Called by bridge.js when a bridge call times out or errors. */
    onBridgeError(handler, action, error) {
        // Ignore timeouts on getState itself (heartbeat handles that)
        if (action === 'getState') return;
        // Bridge timeout is strong evidence the node is down
        if (error.message.includes('timeout') && appState.isConnected) {
            // Don't set disconnected immediately on one timeout — verify with getState
            App._checkConnectivity();
        }
    },

    /** Quick connectivity check — call getState to verify connection. */
    async _checkConnectivity() {
        try {
            const state = await Bridge.call('noble_app', 'getState');
            Object.assign(appState, state);
            App._updateChainBar();
            if (state.isConnected) {
                App._hideDisconnectedBanner();
                App._heartbeatFailures = 0;
            }
        } catch {
            // getState failed — don't panic on one failure, heartbeat will catch sustained outage
        }
    }
};

// Expose current page for cross-page calls (e.g. contacts → payments.openSendWizard)
Object.defineProperty(App, '_currentPage', { get: () => currentPage });

// Expose globally for Swift evaluateJavaScript calls
window.App = App;

// Initialize on load
async function boot() {
    // Start with NativeConfig (injected synchronously by Swift before scripts run)
    if (window.NativeConfig) {
        Object.assign(appState, window.NativeConfig);
    }

    // Then fetch full state from bridge (may have more fields like walletAddress)
    try {
        const state = await Bridge.call('noble_app', 'getState');
        Object.assign(appState, state);
    } catch {
        // Bridge not ready — use NativeConfig defaults
    }
    // NEVER start disconnected. Period.
    // Swift may report isConnected=false because its poll hasn't run yet.
    // The heartbeat will correct to offline later if the node is truly down.
    appState.isConnected = true;
    if (!appState.hasWallet) appState.hasWallet = true;

    // Show chain bar if connected
    App._updateChainBar();

    // Use NativeConfig initial route if available, otherwise default to home
    const initialRoute = appState.initialRoute || appState.selectedSection || 'home';
    App.navigateTo(initialRoute);
    bootComplete = true;

    // ── Heartbeat: 15s connectivity check ──
    // Polls getState to detect node offline/online. Does NOT invalidate pages —
    // only updates the chain bar and banner. Page invalidation only happens
    // on genuine connection/wallet state transitions via updateState.
    setInterval(async () => {
        try {
            const state = await Bridge.call('noble_app', 'getState');
            // Silently update state fields WITHOUT triggering page invalidation
            const connChanged = appState.isConnected !== state.isConnected;
            Object.assign(appState, state);
            App._updateChainBar();
            if (state.isConnected) {
                App._hideDisconnectedBanner();
                App._heartbeatFailures = 0;
                appState._confirmedDisconnected = false;
                // If we just reconnected, refresh the current page
                if (connChanged && currentPage && currentPage.refresh) {
                    currentPage.refresh(appState);
                }
            } else if (connChanged) {
                App._showDisconnectedBanner();
            }
        } catch {
            // getState bridge call failed — Swift side may be busy, don't panic
            // Only show offline after 2 consecutive heartbeat failures
            if (!App._heartbeatFailures) App._heartbeatFailures = 0;
            App._heartbeatFailures++;
            if (App._heartbeatFailures >= 3 && appState.isConnected) {
                appState.isConnected = false;
                appState._confirmedDisconnected = true;
                App._updateChainBar();
                App._showDisconnectedBanner();
            }
        }
    }, 15_000);
}

boot();

// ── iOS ghost cursor fix ──
// Hide caret on focus. Poll visualViewport geometry (height + offsetTop)
// via rAF until it stops moving. Only then show the caret.
// resize alone misses offsetTop/scroll changes from keyboard animation.
(function() {
    document.addEventListener('focusin', (e) => {
        const el = e.target;
        if (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA') return;

        el.classList.add('caret-hidden');

        const vv = window.visualViewport;
        if (!vv) {
            setTimeout(() => el.classList.remove('caret-hidden'), 350);
            return;
        }

        let lastH = vv.height;
        let lastOT = vv.offsetTop;
        let stableFrames = 0;
        let done = false;
        const STABLE_THRESHOLD = 6; // ~100ms at 60fps

        function poll() {
            if (done) return;
            const h = vv.height;
            const ot = vv.offsetTop;
            if (h === lastH && ot === lastOT) {
                stableFrames++;
            } else {
                stableFrames = 0;
                lastH = h;
                lastOT = ot;
            }
            if (stableFrames >= STABLE_THRESHOLD) {
                done = true;
                el.classList.remove('caret-hidden');
                return;
            }
            requestAnimationFrame(poll);
        }
        requestAnimationFrame(poll);

        // Ultimate safety: if rAF loop doesn't converge in 800ms, show anyway
        setTimeout(() => {
            if (!done) {
                done = true;
                el.classList.remove('caret-hidden');
            }
        }, 800);
    });
})();
