// NOBLE Document Client — Shared Utilities

export function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}

export function timeAgo(timestamp) {
    const diff = Math.floor(Date.now() / 1000 - timestamp);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

export function truncate(s, len) {
    if (!s || s.length <= len * 2 + 1) return s || '';
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
