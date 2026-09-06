// NOBLE Document Client — Shared Utilities
import { Prefs } from './bridge.js';

/** WRY desktop shells (Linux/Windows) — platforms with no native chrome, no
 *  native onboarding, and no native dialogs. ('desktop' is the WRY fallback
 *  platform string for non-target-OS dev builds.) Single source of truth:
 *  app.js (nav + wallet-setup gating), settings.js (reveal phrase, storage
 *  label), and p12-password.js (password modal) all import this. */
export function isWryPlatform(platform) {
    return platform === 'linux' || platform === 'windows' || platform === 'desktop';
}

export function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}

// ── Thousands separator (user preference) ──
// Default is the normal space (codebase policy: '.'/',' whose meaning flips
// between locales are never the DEFAULT). The user may override in Settings →
// Appearance; stored as a semantic ID (raw chars — especially spaces — are
// invisible/fragile in localStorage). Decimal separator is always '.'.
const THOUSANDS_SEPS = {
    space: ' ',
    narrow: '\u202F', // narrow no-break space — thinner, never line-wraps
    apostrophe: "'",
    comma: ',',
    dot: '.',
    none: '',
};
const THOUSANDS_SEP_KEY = 'noble.thousandsSep';
/** Preference keys shared across pages — single definition to prevent
 *  reader/writer typo drift. */
export const THEME_KEY = 'noble.theme';
export const AUTOSPLIT_KEY = 'noble.autoSplit';

let _sepChar = THOUSANDS_SEPS[localStorage.getItem(THOUSANDS_SEP_KEY)] ?? ' ';

/** Persist + apply a thousands-separator choice (one of THOUSANDS_SEPS' keys;
 *  unknown IDs fall back to 'space'). Takes effect on the next render. */
export function setThousandsSeparator(id) {
    if (!(id in THOUSANDS_SEPS)) id = 'space';
    Prefs.set(THOUSANDS_SEP_KEY, id); // write-through: localStorage + native store
    _sepChar = THOUSANDS_SEPS[id];
}

/** Current separator choice ID, for settings controls. */
export function getThousandsSeparatorId() {
    const stored = localStorage.getItem(THOUSANDS_SEP_KEY);
    return stored in THOUSANDS_SEPS ? stored : 'space';
}

// ── Monospace font (user preference) ──
// Faces are vendored under css/fonts/ and declared in css/noble.css, so every
// shell renders the same face instead of falling through to the OS default.
// Stored as a semantic ID; the stack is applied by overriding --font-mono on
// <html>, which every rule reading var(--font-mono) inherits.
// Iosevka Charon is quasi-proportional: digits and hex (0-9 a-f A-F) are all
// 0.5em so tables and hashes stay column-aligned, while prose letters vary.
const MONO_FONTS = {
    jetbrains: { label: 'JetBrains Mono', stack: "'JetBrains Mono', 'SF Mono', monospace" },
    plex:      { label: 'IBM Plex Mono',  stack: "'IBM Plex Mono', 'SF Mono', monospace" },
    roboto:    { label: 'Roboto Mono',    stack: "'Roboto Mono', 'SF Mono', monospace" },
    geist:     { label: 'Geist Mono',     stack: "'Geist Mono', 'SF Mono', monospace" },
    charon:    { label: 'Iosevka Charon', stack: "'Iosevka Charon', 'SF Mono', monospace" },
};
const MONO_FONT_KEY = 'noble.monoFont';
const MONO_FONT_DEFAULT = 'jetbrains';

/** Current monospace choice ID (unknown/missing IDs fall back to the default). */
export function getMonoFontId() {
    const stored = localStorage.getItem(MONO_FONT_KEY);
    return stored && stored in MONO_FONTS ? stored : MONO_FONT_DEFAULT;
}

/** [id, label] pairs, for building settings controls. */
export function monoFontOptions() {
    return Object.entries(MONO_FONTS).map(([id, f]) => [id, f.label]);
}

/** CSS stack for a choice ID (or the current choice when omitted). */
export function monoFontStack(id) {
    return (MONO_FONTS[id] || MONO_FONTS[getMonoFontId()]).stack;
}

/** Persist + apply a monospace font choice. Write-through via Prefs: the Apple
 *  shells use a non-persistent website data store and wipe localStorage on
 *  quit, so a plain localStorage write would lose the choice every restart. */
export function setMonoFont(id) {
    if (!(id in MONO_FONTS)) id = MONO_FONT_DEFAULT;
    Prefs.set(MONO_FONT_KEY, id); // write-through: localStorage + native store
    applyMonoFont(id);
}

/** Apply the stored (or given) choice to the document. Call once at boot,
 *  after Prefs.hydrate() — before hydration the stored value is not yet back. */
export function applyMonoFont(id) {
    const choice = id && id in MONO_FONTS ? id : getMonoFontId();
    document.documentElement.style.setProperty('--font-mono', MONO_FONTS[choice].stack);
}

/** Group the integer part of a number with the user's thousands separator
 *  (default: space — locale-independent). Keeps any decimal part and sign:
 *  205120 → "205 120", -1234.56 → "-1 234.56". */
export function groupThousands(value) {
    const s = String(value);
    const neg = s.startsWith('-');
    const [intPart, fracPart] = (neg ? s.slice(1) : s).split('.');
    const grouped = intPart.replace(/\B(?=(\d{3})+(?!\d))/g, _sepChar);
    return (neg ? '-' : '') + grouped + (fracPart !== undefined ? '.' + fracPart : '');
}

export function timeAgo(timestamp) {
    const diff = Math.floor(Date.now() / 1000 - timestamp);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

export function truncate(s, len) {
    if (!s || s.length <= len + len + 1) return s || '';
    return s.slice(0, len) + '\u2026' + s.slice(-len);
}

export function initials(contact) {
    const f = (contact.firstName || '')[0] || '';
    const l = (contact.lastName || '')[0] || '';
    return (f + l).toUpperCase() || '?';
}

export function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

export function formatTimestamp(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

export function escAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function showCopyFeedback(element, originalText, duration = 1200) {
    element.textContent = 'Copied!';
    setTimeout(() => { element.textContent = originalText; }, duration);
}
