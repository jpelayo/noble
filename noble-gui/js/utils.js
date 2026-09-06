/**
 * NOBLE Dashboard — Formatting Utilities
 */

/**
 * Transaction status badge with pie-chart icon.
 * @param {number|null} confirmations — null = pending (mempool)
 * @param {number} maturity — COINBASE_MATURITY (default 3)
 * @returns {string} HTML span with icon + label
 */
export function txStatusBadge(confirmations, maturity = 3) {
  if (confirmations == null || confirmations < 0) {
    // Pending — in mempool, not in any block
    return '<span title="Pending (in mempool)" style="color:var(--warning)">◔ Pending</span>';
  }
  if (confirmations === 0) {
    // Admitted — in a proposed block, not yet committed to chain
    return '<span title="Admitted (in proposed block)" style="color:var(--accent)">◑ Admitted</span>';
  }
  if (confirmations <= maturity) {
    // Maturing — 1 to maturity confirmations (1-based: being in a block = 1 confirmation)
    return `<span title="Maturing (${confirmations}/${maturity} confirmations)" style="color:var(--accent)">◕ Maturing</span>`;
  }
  // Complete — more than maturity confirmations, UTXO is spendable
  return `<span title="Complete (${confirmations} confirmations)" style="color:var(--success)">● Complete</span>`;
}

const fullDateFmt = new Intl.DateTimeFormat('en-US', {
  year: 'numeric', month: 'short', day: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
  hour12: false,
});

const DIVISIONS = [
  { amount: 60, name: 'seconds' },
  { amount: 60, name: 'minutes' },
  { amount: 24, name: 'hours' },
  { amount: 7, name: 'days' },
  { amount: 4.34524, name: 'weeks' },
  { amount: 12, name: 'months' },
  { amount: Infinity, name: 'years' },
];

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

export function formatTimestamp(unixSecs) {
  return fullDateFmt.format(new Date(unixSecs * 1000));
}

export function timeAgo(unixSecs) {
  let diff = (unixSecs - Date.now() / 1000);
  for (const division of DIVISIONS) {
    if (Math.abs(diff) < division.amount) {
      return rtf.format(Math.round(diff), division.name);
    }
    diff /= division.amount;
  }
  return formatTimestamp(unixSecs);
}

// ── Thousands separator (user preference) ──
// Default is the normal space (codebase policy: '.'/',' whose meaning flips
// between locales are never the DEFAULT). Overridable in Settings → Display;
// stored as a semantic ID (raw chars — especially spaces — are invisible/
// fragile in localStorage). Decimal separator is always '.'.
const THOUSANDS_SEPS = {
  space: ' ',
  narrow: '\u202F', // narrow no-break space — thinner, never line-wraps
  apostrophe: "'",
  comma: ',',
  dot: '.',
  none: '',
};
const THOUSANDS_SEP_KEY = 'noble-thousands-sep';

let _sepChar = THOUSANDS_SEPS[localStorage.getItem(THOUSANDS_SEP_KEY)] ?? ' ';

/** Persist + apply a thousands-separator choice (one of THOUSANDS_SEPS' keys;
 *  unknown IDs fall back to 'space'). Takes effect on the next render. */
export function setThousandsSeparator(id) {
  if (!(id in THOUSANDS_SEPS)) id = 'space';
  localStorage.setItem(THOUSANDS_SEP_KEY, id);
  _sepChar = THOUSANDS_SEPS[id];
}

/** Current separator choice ID, for settings controls. */
export function getThousandsSeparatorId() {
  const stored = localStorage.getItem(THOUSANDS_SEP_KEY);
  return stored in THOUSANDS_SEPS ? stored : 'space';
}

// ── Monospace font (user preference) ──
// Faces are vendored under vendor/fonts/ and declared in css/themes.css, so the
// dashboard renders identically everywhere instead of falling through to
// whatever mono font the OS happens to supply. Stored as a semantic ID; the
// stack is applied by overriding --font-mono on <html>, which every rule
// reading var(--font-mono) inherits.
// Iosevka Charon is quasi-proportional: digits and hex (0-9 a-f A-F) are all
// 0.5em so tables and hashes stay column-aligned, while prose letters vary.
const MONO_FONTS = {
  jetbrains: { label: 'JetBrains Mono', stack: "'JetBrains Mono', 'SF Mono', Menlo, monospace" },
  plex:      { label: 'IBM Plex Mono',  stack: "'IBM Plex Mono', 'SF Mono', Menlo, monospace" },
  roboto:    { label: 'Roboto Mono',    stack: "'Roboto Mono', 'SF Mono', Menlo, monospace" },
  geist:     { label: 'Geist Mono',     stack: "'Geist Mono', 'SF Mono', Menlo, monospace" },
  charon:    { label: 'Iosevka Charon', stack: "'Iosevka Charon', 'SF Mono', Menlo, monospace" },
  // Only family here carrying U+202F, so the `narrow` separator is actually
  // narrow in every engine under it. Cost: hex a-f are narrower than digits,
  // so hash columns lose alignment.
  aile:      { label: 'Iosevka Aile',   stack: "'Iosevka Aile', 'SF Mono', Menlo, monospace" },
};
const MONO_FONT_KEY = 'noble-mono-font';
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

/** Persist + apply a monospace font choice. Takes effect immediately. */
export function setMonoFont(id) {
  if (!(id in MONO_FONTS)) id = MONO_FONT_DEFAULT;
  localStorage.setItem(MONO_FONT_KEY, id);
  applyMonoFont(id);
}

/** Apply the stored (or given) choice to the document. Call once at boot. */
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

export function formatNumber(n) {
  return groupThousands(n);
}

export function truncateHash(hex, len = 8) {
  if (!hex || hex.length <= len * 2 + 3) return hex || '';
  return `${hex.slice(0, len)}...${hex.slice(-len)}`;
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// Amount in atomic units (groats); 1 NOBLE = 100,000,000 groats (8 decimals).
// Always show all 8 decimal places — truncation hides fees and misleads users.
export function formatFee(atomicUnits) {
  if (atomicUnits === 0) return '0 NOBLE';
  const noble = atomicUnits / 100_000_000;
  // Strip trailing zeros but keep at least 2 decimals for readability.
  const full = noble.toFixed(8);
  const trimmed = full.replace(/0+$/, '').replace(/\.$/, '.00');
  // Ensure at least 2 decimal places.
  const dot = trimmed.indexOf('.');
  const decimals = dot >= 0 ? trimmed.length - dot - 1 : 0;
  const display = decimals < 2 ? noble.toFixed(2) : trimmed;
  return `${display} NOBLE`;
}

export function formatScheme(schemeId) {
  switch (schemeId) {
    case 0x01: return 'secp256k1';
    case 0x02: return 'secp256k1';
    default: return `Unknown(0x${schemeId.toString(16).padStart(2, '0')})`;
  }
}

export function bytesToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function formatDuration(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function formatCountdown(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

export function isHex64(str) {
  return /^[0-9a-fA-F]{64}$/.test(str);
}

/** Chain identifier as hex. Empty if no blockchain exists. */
export function formatChainLabel(nodeInfo) {
  if (!nodeInfo.chain_id) return '';
  return '0x' + nodeInfo.chain_id.toString(16).toUpperCase().padStart(8, '0');
}

// Create a DOM element from HTML string
export function el(tag, attrs = {}, ...children) {
  const elem = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') elem.className = v;
    else if (k.startsWith('on')) elem.addEventListener(k.slice(2).toLowerCase(), v);
    else elem.setAttribute(k, v);
  }
  for (const child of children) {
    if (typeof child === 'string') elem.appendChild(document.createTextNode(child));
    else if (child) elem.appendChild(child);
  }
  return elem;
}
