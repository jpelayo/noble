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

const pages = {
    home:      initHome,
    documents: initDocuments,
    drafts:    initDrafts,
    verify:    initVerify,
    payments:  initPayments,
    contacts:  initContacts,
    settings:  initSettings,
    faucet:    initFaucet,
};

let currentPage = null;
let currentRoute = null;
let appState = {};

const App = {
    /** Navigate to a section, destroying the current page and mounting the new one. */
    navigateTo(section) {
        if (section === currentRoute && currentPage) return;
        const root = document.getElementById('app-content');
        if (!root) return;

        // Destroy current page
        if (currentPage && currentPage.destroy) {
            currentPage.destroy();
        }
        currentPage = null;
        currentRoute = section;
        root.className = '';
        root.innerHTML = '';

        const initFn = pages[section];
        if (initFn) {
            currentPage = initFn(root, { state: appState, Bridge });
        } else {
            // Unimplemented page — coming soon
            root.appendChild(emptyState({
                icon: '\u{1F6A7}',
                title: 'Coming Soon',
                subtitle: `The ${section} section is under development.`
            }));
        }
    },

    /** Push a state patch to the current page. */
    updateState(patch) {
        const wasConnected = appState.isConnected;
        const hadWallet = appState.hasWallet;
        Object.assign(appState, patch);
        App._updateChainBar();

        // If connection or wallet state changed, re-mount the page so it re-renders
        // from scratch (pages check isConnected on init and bail early if false).
        if (wasConnected !== appState.isConnected || hadWallet !== appState.hasWallet) {
            if (currentRoute) {
                const route = currentRoute;
                currentRoute = null; // force navigateTo to re-mount
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
            const wasConnected = appState.isConnected;
            App.updateState(data);
            if (data.isConnected === false && wasConnected !== false) {
                App._showDisconnectedBanner();
            } else if (data.isConnected === true) {
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
        banner.style.cssText = 'position:fixed;top:0;left:0;right:0;padding:var(--gap-sm) var(--gap);background:var(--error);color:#fff;text-align:center;font-size:var(--font-size-sm);z-index:2000;';
        banner.textContent = 'Connection lost. Reconnecting...';
        document.body.appendChild(banner);
    },

    _hideDisconnectedBanner() {
        const banner = document.getElementById('disconnected-banner');
        if (banner) banner.remove();
    },

    /** Update the persistent chain ID bar at the top. */
    _updateChainBar() {
        const bar = document.getElementById('chain-bar');
        if (!bar) return;
        if (appState.isConnected && appState.chainId) {
            bar.hidden = false;
            bar.innerHTML = `<span class="chain-dot"></span><span class="chain-label">Chain</span> ${appState.chainId}`;
        } else {
            bar.hidden = true;
            bar.innerHTML = '';
        }
    }
};

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
        // NativeConfig already provides the basics; fill in any missing defaults
        if (appState.isConnected === undefined) appState.isConnected = false;
        if (appState.hasWallet === undefined) appState.hasWallet = false;
    }

    // Show chain bar if connected
    App._updateChainBar();

    // Use NativeConfig initial route if available, otherwise default to home
    const initialRoute = appState.initialRoute || appState.selectedSection || 'home';
    App.navigateTo(initialRoute);
}

boot();

// ── iOS ghost cursor fix (visualViewport-driven) ──
// Hide caret on focus. Show it only after visualViewport stops resizing
// (keyboard animation finished). Prevents ghost cursor at old position.
(function() {
    document.addEventListener('focusin', (e) => {
        const el = e.target;
        if (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA') return;

        el.classList.add('caret-hidden');

        if (!window.visualViewport) {
            setTimeout(() => el.classList.remove('caret-hidden'), 300);
            return;
        }

        const vv = window.visualViewport;
        const startHeight = vv.height;
        let settled = false;
        let settleTimer = null;

        const show = () => {
            if (settled) return;
            settled = true;
            el.classList.remove('caret-hidden');
            vv.removeEventListener('resize', onResize);
        };

        const onResize = () => {
            clearTimeout(settleTimer);
            settleTimer = setTimeout(show, 100);
        };

        vv.addEventListener('resize', onResize);

        // Keyboard already open (field switch): no resize → show after 50ms
        setTimeout(() => {
            if (!settled && vv.height === startHeight) show();
        }, 50);

        // Ultimate safety fallback
        setTimeout(() => { if (!settled) show(); }, 600);
    });
})();
