// Platform-gated PKCS#12 password prompt, shared by the Identity settings and
// the contacts signing-key UI.
import { openModal } from './modal.js';
import { isWryPlatform } from '../utils.js';

/** Prompt for the .p12/.pfx password before importing.
 *
 *  On Mac/iOS the native `importPKCS12` handler prompts (via NSAlert), so this
 *  resolves to `undefined` and the caller passes no params. On WRY there is no
 *  native prompt, so we collect the password in-WebUI first.
 *
 *  Resolves to: the password string (WRY, submitted), `undefined` (Mac/iOS —
 *  defer to native), or `null` (WRY — user cancelled).
 */
export function promptP12Password(platform) {
    if (!isWryPlatform(platform)) return Promise.resolve(undefined);
    return new Promise((resolve) => {
        let settled = false;
        const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
        const { el, close } = openModal({
            title: 'PKCS#12 password',
            onClose: () => finish(null),
        });
        el.innerHTML = `
            <p style="color:var(--text-muted);margin:0 0 0.75rem">Enter the password protecting your .p12 / .pfx file. You'll choose the file next.</p>
            <input id="p12-pass" type="password" class="form-input" style="width:100%;margin-bottom:1rem" placeholder="Password" autocomplete="off">
            <div style="display:flex;gap:0.5rem">
                <button id="p12-cancel" class="btn" style="flex:1">Cancel</button>
                <button id="p12-ok" class="btn btn-primary" style="flex:1">Choose file…</button>
            </div>`;
        const input = el.querySelector('#p12-pass');
        const submit = () => { finish(input.value); close(); };
        el.querySelector('#p12-ok').addEventListener('click', submit);
        el.querySelector('#p12-cancel').addEventListener('click', () => { finish(null); close(); });
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
        setTimeout(() => input.focus(), 50);
    });
}
