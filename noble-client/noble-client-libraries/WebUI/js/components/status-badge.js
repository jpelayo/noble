// Colored status pill.
export function statusBadge(status) {
    const el = document.createElement('span');
    const s = String(status).toLowerCase();

    let cls = 'badge-pending';
    if (s === 'confirmed' || s === 'success') cls = 'badge-confirmed';
    else if (s === 'failed' || s === 'rejected') cls = 'badge-failed';

    el.className = `badge ${cls}`;
    el.textContent = status;
    return el;
}
