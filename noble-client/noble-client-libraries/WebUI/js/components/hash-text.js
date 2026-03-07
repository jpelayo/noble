import { Bridge } from '../bridge.js';

// Truncated hash display with copy-on-click.
export function hashText(hex, opts = {}) {
    const len = opts.chars || 8;
    const full = opts.full || false;

    const el = document.createElement('span');
    el.className = 'mono';
    el.style.cursor = 'pointer';
    el.title = hex;

    if (full || hex.length <= len * 2 + 1) {
        el.textContent = hex;
    } else {
        el.textContent = hex.slice(0, len) + '\u2026' + hex.slice(-len);
    }

    el.addEventListener('click', () => {
        Bridge.call('noble_app', 'copyToClipboard', { text: hex });
        const orig = el.textContent;
        el.textContent = 'Copied!';
        setTimeout(() => { el.textContent = orig; }, 1200);
    });

    return el;
}
