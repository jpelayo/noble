// NOBLE Document Client — First-run Wallet Setup
//
// Shown on WRY platforms (linux/windows) when the native shell reports
// hasWallet=false. Mac/iOS never route here — they provision the wallet in
// native SwiftUI onboarding. The flow drives the native `noble_app`
// createWallet / importWallet bridge actions (BIP-39 in Rust, keys stored in
// the OS keyring) and never handles key material beyond displaying the
// mnemonic once for backup.
import { Bridge } from '../bridge.js';
import { esc } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    root.classList.add('page-content');
    root.style.cssText = 'max-width:560px;margin:0 auto;padding-top:6vh';

    const card = document.createElement('div');
    card.className = 'noble-card';
    card.style.cssText = 'padding:2rem;text-align:center';
    root.appendChild(card);

    function finish(address) {
        const walletAddress = address || state.walletAddress;
        // Seed the "My Card" contact with the new wallet address (best effort).
        Bridge.call('noble_storage', 'ensureMyCard', {}).catch(() => {});
        if (window.App) {
            // Let updateState be the SOLE mutator of hasWallet: mutating the
            // shared state object here first would mask the false→true
            // transition its `hadWallet` snapshot watches for, silently
            // disabling the invalidate-all-pages safety net on this path.
            window.App.updateState({ hasWallet: true, walletAddress });
            window.App.navigateTo('home');
        }
    }

    function renderChoice() {
        card.innerHTML = `
            <div style="font-size:2.5rem;margin-bottom:0.5rem">&#x1F511;</div>
            <h1 style="margin:0 0 0.4rem">Set up your wallet</h1>
            <p style="color:var(--text-muted);margin:0 0 1.5rem">
                NOBLE needs a wallet to sign documents and transactions.
                Keys are stored in your system keyring and never leave this device.
            </p>
            <div style="display:flex;flex-direction:column;gap:0.75rem">
                <button id="ws-create" class="btn btn-primary" style="padding:0.8rem;font-size:1rem">Create new wallet</button>
                <button id="ws-import" class="btn" style="padding:0.8rem;font-size:1rem">Import existing wallet</button>
            </div>`;
        card.querySelector('#ws-create').addEventListener('click', doCreate);
        card.querySelector('#ws-import').addEventListener('click', renderImport);
    }

    async function doCreate() {
        card.innerHTML = '<p style="color:var(--text-muted)">Generating wallet&hellip;</p>';
        try {
            const res = await Bridge.call('noble_app', 'createWallet', {});
            if (!alive) return;
            renderMnemonic(res.mnemonic || [], res.address || '');
        } catch (e) {
            if (!alive) return;
            renderError(e, renderChoice);
        }
    }

    function renderMnemonic(words, address) {
        const grid = words.map((w, i) =>
            `<div style="display:flex;gap:0.4rem;align-items:baseline;padding:0.35rem 0.5rem;background:var(--bg-secondary,rgba(128,128,128,0.08));border-radius:6px">
                <span style="color:var(--text-muted);font-size:0.75rem;min-width:1.2em;text-align:right">${i + 1}</span>
                <span style="font-family:var(--font-mono,monospace);font-weight:600">${esc(w)}</span>
            </div>`
        ).join('');
        card.innerHTML = `
            <h1 style="margin:0 0 0.4rem">Your recovery phrase</h1>
            <p style="color:var(--error,#e5484d);font-weight:600;margin:0 0 1rem">
                Write these ${words.length} words down and store them safely.
                They are the ONLY way to recover your wallet.
            </p>
            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:0.4rem;text-align:left;margin-bottom:1rem">${grid}</div>
            <button id="ws-copy" class="btn" style="margin-bottom:1.25rem">Copy phrase</button>
            <label style="display:flex;gap:0.5rem;align-items:flex-start;text-align:left;margin-bottom:1rem;cursor:pointer">
                <input id="ws-backed" type="checkbox" style="margin-top:0.2rem">
                <span>I have written down my recovery phrase and understand it cannot be shown again.</span>
            </label>
            <button id="ws-done" class="btn btn-primary" style="width:100%;padding:0.8rem" disabled>Continue</button>`;
        const backed = card.querySelector('#ws-backed');
        const done = card.querySelector('#ws-done');
        backed.addEventListener('change', () => { done.disabled = !backed.checked; });
        card.querySelector('#ws-copy').addEventListener('click', () => {
            Bridge.call('noble_app', 'copyToClipboard', { text: words.join(' ') }).catch(() => {});
        });
        done.addEventListener('click', () => finish(address));
    }

    function renderImport() {
        card.innerHTML = `
            <h1 style="margin:0 0 0.4rem">Import wallet</h1>
            <p style="color:var(--text-muted);margin:0 0 1rem">Enter your 12&ndash;24 word recovery phrase, separated by spaces.</p>
            <textarea id="ws-phrase" rows="3" spellcheck="false" autocapitalize="off" autocorrect="off"
                style="width:100%;box-sizing:border-box;padding:0.7rem;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary,transparent);color:inherit;font-family:var(--font-mono,monospace);margin-bottom:0.5rem"></textarea>
            <div id="ws-err" style="color:var(--error,#e5484d);font-size:0.85rem;min-height:1.2em;margin-bottom:0.75rem"></div>
            <div style="display:flex;gap:0.75rem">
                <button id="ws-back" class="btn" style="flex:1">Back</button>
                <button id="ws-go" class="btn btn-primary" style="flex:2">Import</button>
            </div>`;
        card.querySelector('#ws-back').addEventListener('click', renderChoice);
        card.querySelector('#ws-go').addEventListener('click', async () => {
            const mnemonic = card.querySelector('#ws-phrase').value.trim().toLowerCase();
            const errEl = card.querySelector('#ws-err');
            const wordCount = mnemonic.split(/\s+/).filter(Boolean).length;
            if (wordCount < 12) {
                errEl.textContent = 'A recovery phrase has at least 12 words.';
                return;
            }
            errEl.textContent = '';
            try {
                const res = await Bridge.call('noble_app', 'importWallet', { mnemonic });
                if (!alive) return;
                finish(res.address || '');
            } catch (e) {
                if (!alive) return;
                errEl.textContent = (e && e.message) ? e.message : 'Invalid recovery phrase.';
            }
        });
    }

    function renderError(e, retry) {
        card.innerHTML = `
            <h1 style="margin:0 0 0.4rem">Something went wrong</h1>
            <p style="color:var(--error,#e5484d);margin:0 0 1rem">${esc((e && e.message) || String(e))}</p>
            <button id="ws-retry" class="btn btn-primary">Try again</button>`;
        card.querySelector('#ws-retry').addEventListener('click', retry);
    }

    renderChoice();

    return {
        destroy() { alive = false; },
        refresh() {},
    };
}
