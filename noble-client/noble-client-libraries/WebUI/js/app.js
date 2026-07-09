// NOBLE Document Client — Router & State Controller
import { Bridge, Prefs } from './bridge.js';
import { isWryPlatform, setThousandsSeparator, getThousandsSeparatorId, THEME_KEY } from './utils.js';
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
import { init as initUtxoMaintenance } from './pages/utxo-maintenance.js';
import { init as initWalletSetup } from './pages/wallet-setup.js';

// ── Theme management ──
// Applies data-theme attribute on <html> for manual light/dark override.
// "system" = follow prefers-color-scheme, "light" = force light, "dark" = force dark.
window.applyTheme = function(theme) {
    const root = document.documentElement;
    if (theme === 'light') {
        root.setAttribute('data-theme', 'light');
        root.style.colorScheme = 'light';
    } else if (theme === 'dark') {
        root.setAttribute('data-theme', 'dark');
        root.style.colorScheme = 'dark';
    } else {
        root.removeAttribute('data-theme');
        root.style.colorScheme = 'light dark';
    }
};
// Restore natively-persisted preferences into localStorage BEFORE anything
// reads them — the Apple shells wipe localStorage on quit (non-persistent
// website data store), so localStorage alone reverts every preference.
await Prefs.hydrate();
// utils.js cached the separator at module init (before hydration) — re-sync.
setThousandsSeparator(getThousandsSeparatorId());

// Apply saved theme immediately (before first render)
const savedTheme = localStorage.getItem(THEME_KEY) || 'system';
window.applyTheme(savedTheme);

const pages = {
    home:       initHome,
    documents:  initDocuments,
    drafts:     initDrafts,
    verify:     initVerify,
    wallet:     initPayments,
    payments:   initPayments,
    contacts:   initContacts,
    settings:   initSettings,
    faucet:     initFaucet,
    'tx-detail': initTxDetail,
    'utxo-maintenance': initUtxoMaintenance,
    'wallet-setup': initWalletSetup,
};

/** True while a WRY platform has no wallet yet — those shells have no native
 *  onboarding, so the WebUI must run wallet setup first. */
function needsWalletSetup(state) {
    return !state.hasWallet && isWryPlatform(state.platform);
}

/** Persistent-nav sections, mirroring Mac's SidebarSection (home, documents,
 *  drafts, verify, faucet, wallet, contacts, settings). */
const NAV_ITEMS = [
    { section: 'home',      icon: '\u{1F3E0}', label: 'Home' },
    { section: 'documents', icon: '\u{1F4C4}', label: 'Documents' },
    { section: 'drafts',    icon: '\u{1F4DD}', label: 'Drafts' },
    { section: 'verify',    icon: '\u{2705}',  label: 'Verify' },
    { section: 'faucet',    icon: '\u{1F4A7}', label: 'Faucet' },
    { section: 'wallet',    icon: '\u{1F4B0}', label: 'Wallet' },
    { section: 'contacts',  icon: '\u{1F465}', label: 'Contacts' },
    { section: 'settings',  icon: '\u{2699}',  label: 'Settings' },
];

let currentPage = null;
let currentRoute = null;
let previousRoute = null;
let appState = {};
let bootComplete = false;

// Persistent page cache: each page is mounted once and hidden/shown on navigation.
// This preserves wizard state, form inputs, scroll positions across page switches.
const mountedPages = {};  // section → { root: HTMLElement, page: pageInstance }

const App = {
    /** Navigate back to previous page, or fallback to wallet. */
    navigateBack() {
        const target = previousRoute || 'wallet';
        this.navigateTo(target);
        // Keep native chrome (Mac sidebar) selection in sync — same pattern as
        // contacts/verify. On WRY this just records selected_section (no echo).
        Bridge.call('noble_app', 'navigateTo', { section: target }).catch(() => {});
    },
    /** Navigate to a section. Pages are mounted once and hidden/shown, never destroyed.
     *  Parameterized pages (like tx-detail) are always recreated with fresh params. */
    navigateTo(section, params) {
        // Wallet-setup guard (WRY platforms): until a wallet exists, every
        // route lands on the setup flow — nothing else is usable without keys.
        if (needsWalletSetup(appState)) {
            section = 'wallet-setup';
            params = undefined;
        }
        // 'wallet' and 'payments' are the same page. Canonicalize to one cache
        // key so toggling between the two route names never mounts a duplicate
        // payments instance (the nav item stays labeled 'wallet' via _updateNav).
        if (section === 'wallet') section = 'payments';
        const isParameterized = !!params;
        if (section === currentRoute && !isParameterized) return;
        const container = document.getElementById('app-content');
        if (!container) return;

        // Hide current page
        if (currentRoute && mountedPages[currentRoute]) {
            mountedPages[currentRoute].root.style.display = 'none';
        }

        previousRoute = currentRoute;
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
            // Defensive: remove any orphaned children not tracked in mountedPages
            const tracked = new Set(Object.values(mountedPages).map(e => e.root));
            for (const child of [...container.children]) {
                if (!tracked.has(child)) child.remove();
            }
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
        App._updateNav();
    },

    /** Build the persistent nav rail once (idempotent). */
    _renderNav() {
        const nav = document.getElementById('side-nav');
        if (!nav || nav.dataset.built) return;
        nav.dataset.built = '1';
        const frag = document.createDocumentFragment();
        const brand = document.createElement('div');
        brand.className = 'side-nav-brand';
        brand.textContent = 'Noble';
        frag.appendChild(brand);
        for (const item of NAV_ITEMS) {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'side-nav-item';
            btn.dataset.section = item.section;
            const icon = document.createElement('span');
            icon.className = 'side-nav-icon';
            icon.textContent = item.icon;
            const label = document.createElement('span');
            label.className = 'side-nav-label';
            label.textContent = item.label;
            btn.append(icon, label);
            btn.addEventListener('click', () => App.navigateTo(item.section));
            frag.appendChild(btn);
        }
        nav.replaceChildren(frag);
    },

    /** Show/hide the nav rail (WRY only) and highlight the active section. */
    _updateNav() {
        const nav = document.getElementById('side-nav');
        if (!nav) return;
        const show = isWryPlatform(appState.platform)
            && appState.hasWallet
            && currentRoute !== 'wallet-setup'
            && !needsWalletSetup(appState);
        document.body.classList.toggle('has-side-nav', show);
        nav.hidden = !show;
        if (!show) return;
        App._renderNav();
        // 'payments' shares the 'wallet' nav item; parameterized pages
        // (tx-detail, utxo-maintenance) leave no item highlighted.
        const active = currentRoute === 'payments' ? 'wallet' : currentRoute;
        for (const btn of nav.querySelectorAll('.side-nav-item')) {
            btn.classList.toggle('active', btn.dataset.section === active);
        }
    },

    /** Push a state patch to the current page. */
    updateState(patch) {
        const wasConnected = appState.isConnected;
        const hadWallet = appState.hasWallet;
        Object.assign(appState, patch);
        App._updateChainBar();
        App._updateNav();

        // If connection or wallet state changed AFTER boot, invalidate ALL cached pages
        // so they re-mount fresh on next visit (pages check isConnected on init).
        if (bootComplete && (wasConnected !== appState.isConnected || hadWallet !== appState.hasWallet)) {
            for (const [key, entry] of Object.entries(mountedPages)) {
                try {
                    if (entry.page && entry.page.destroy) entry.page.destroy();
                    entry.root.remove();
                } catch { /* ensure all entries are cleaned even if one throws */ }
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
                // Native says connected — any stale deliberate-disconnect flag
                // is obsolete (e.g. the user reconnected through home/settings).
                appState._userDisconnected = false;
                App._hideDisconnectedBanner();
            }
        }
    },

    _showDisconnectedBanner() {
        // A deliberate disconnect is not an outage: no banner, and definitely
        // no "Reconnecting…" claim. The status row/pill still show the state.
        if (appState._userDisconnected) return;
        let banner = document.getElementById('disconnected-banner');
        if (banner) return;
        banner = document.createElement('div');
        banner.id = 'disconnected-banner';
        banner.setAttribute('role', 'alert');
        banner.style.cssText = 'position:fixed;top:0;left:0;right:0;padding:var(--gap-sm) var(--gap);background:var(--error);color:#fff;text-align:center;font-size:var(--font-size-sm);z-index:2000;display:flex;align-items:center;justify-content:center;gap:var(--gap-sm)';
        banner.innerHTML = '<span>Disconnected from node. Reconnecting...</span><button id="disconnected-retry" style="background:#fff3;border:1px solid #fff6;color:#fff;padding:2px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Retry Now</button>';
        document.body.appendChild(banner);
        document.getElementById('disconnected-retry').addEventListener('click', () => App._retryConnect());
    },

    /** Banner "Retry Now": actually DIAL the node (connectToNode rebuilds the
     *  native client and restarts polling) — not just re-read broken state.
     *  On success the native layer pushes isConnected:true, which clears the
     *  banner through handleEvent. */
    async _retryConnect() {
        const btn = document.getElementById('disconnected-retry');
        if (btn) { btn.disabled = true; btn.textContent = 'Retrying…'; }
        appState._userDisconnected = false;
        try {
            const s = await Bridge.call('noble_app', 'getSettings').catch(() => ({}));
            const url = (s && s.nodeURL) || appState.nodeURL || '';
            if (url) {
                const res = await Bridge.call('noble_app', 'connectToNode', { url });
                if (res && res.connected === false) throw new Error('still unreachable');
            }
            await App._checkConnectivity();
        } catch { /* node still down — banner stays, button resets below */ }
        const after = document.getElementById('disconnected-retry');
        if (after) { after.disabled = false; after.textContent = 'Retry Now'; }
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
        if (error.message.includes('timeout') && appState.isConnected) {
            // Report to Swift so pollFailureCount escalates faster
            Bridge.call('noble_app', 'reportBridgeTimeout').catch(e => console.warn('[bridge] reportBridgeTimeout failed:', e.message));
            // Track JS-side consecutive timeouts
            if (!App._bridgeTimeouts) App._bridgeTimeouts = 0;
            App._bridgeTimeouts++;
            if (App._bridgeTimeouts >= 2) {
                // 2 page-level timeouts — mark disconnected from JS side
                appState.isConnected = false;
                appState._confirmedDisconnected = true;
                App._updateChainBar();
                App._showDisconnectedBanner();
            }
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
                App._bridgeTimeouts = 0;
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
    // Mac/iOS provision the wallet in native onboarding before the WebUI ever
    // loads, so a false hasWallet there is a stale-poll artifact — force it.
    // WRY platforms (linux/windows) have NO native onboarding: a false
    // hasWallet is REAL and must route to the wallet-setup flow instead.
    if (!appState.hasWallet && !needsWalletSetup(appState)) {
        appState.hasWallet = true;
    }

    // Show chain bar if connected
    App._updateChainBar();

    // Use NativeConfig initial route if available, otherwise default to home
    // (the navigateTo guard overrides to wallet-setup while no wallet exists).
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
            const walletArrived = !appState.walletAddress && state.walletAddress;
            Object.assign(appState, state);
            App._updateChainBar();
            if (state.isConnected) {
                App._hideDisconnectedBanner();
                App._heartbeatFailures = 0;
                App._bridgeTimeouts = 0;
                appState._confirmedDisconnected = false;
                // Refresh page on reconnect or when wallet address first arrives
                if ((connChanged || walletArrived) && currentPage && currentPage.refresh) {
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
