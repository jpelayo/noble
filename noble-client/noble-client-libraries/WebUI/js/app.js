// NOBLE Document Client — Router & State Controller
import { Bridge } from './bridge.js';
import { emptyState } from './components/empty-state.js';
import { init as initHome } from './pages/home.js';
import { init as initDocuments } from './pages/documents.js';
import { init as initVerify } from './pages/verify.js';
import { init as initPayments } from './pages/payments.js';
import { init as initContacts } from './pages/contacts.js';

const pages = {
    home:      initHome,
    documents: initDocuments,
    verify:    initVerify,
    payments:  initPayments,
    contacts:  initContacts,
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
        Object.assign(appState, patch);
        if (currentPage && currentPage.refresh) {
            currentPage.refresh(appState);
        }
    },

    /** Get current app state. */
    getState() {
        return { ...appState };
    }
};

// Expose globally for Swift evaluateJavaScript calls
window.App = App;

// Initialize on load
async function boot() {
    try {
        const state = await Bridge.call('noble_app', 'getState');
        appState = state;
    } catch {
        appState = {
            isConnected: false,
            hasWallet: false,
            walletAddress: '',
            network: '',
            blockHeight: 0,
            selectedSection: 'home'
        };
    }

    // Use NativeConfig initial route if available, otherwise default to home
    const initialRoute = (window.NativeConfig && window.NativeConfig.initialRoute) || appState.selectedSection || 'home';
    App.navigateTo(initialRoute);
}

boot();
