/**
 * NOBLE Dashboard — Formatting Utilities
 */

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

// Fee is in atomic units; 1 NOBLE = 1,000,000 atomic units
export function formatFee(atomicUnits) {
  const noble = atomicUnits / 1_000_000;
  if (noble >= 1) return `${noble.toFixed(4)} NOBLE`;
  if (noble >= 0.001) return `${noble.toFixed(6)} NOBLE`;
  return `${atomicUnits} atomic`;
}

export function formatScheme(schemeId) {
  switch (schemeId) {
    case 0x00: return 'Ed25519';
    case 0x01: return 'secp256k1';
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
