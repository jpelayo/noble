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
    // Pending — in mempool, not yet in a block
    return '<span title="Pending (in mempool)" style="color:var(--warning)">◔ Pending</span>';
  }
  if (confirmations === 0) {
    // Admitted — in a block, 0 confirmations
    return '<span title="Admitted (in block, 0 confirmations)" style="color:var(--accent)">◑ Admitted</span>';
  }
  if (confirmations < maturity) {
    // Maturing — 1 to maturity-1 confirmations
    return `<span title="Maturing (${confirmations}/${maturity} confirmations)" style="color:var(--accent)">◕ Maturing</span>`;
  }
  // Complete — maturity+ confirmations
  return `<span title="Complete (${confirmations} confirmations)" style="color:var(--success)">● Complete</span>`;
}

const fullDateFmt = new Intl.DateTimeFormat('en-US', {
  year: 'numeric', month: 'short', day: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
  hour12: false,
});

const numFmt = new Intl.NumberFormat('en-US');

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

export function formatNumber(n) {
  return numFmt.format(n);
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
