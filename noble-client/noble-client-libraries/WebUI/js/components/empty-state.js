// Centered empty/placeholder state.
export function emptyState({ icon, title, subtitle, cta, onCta, disabled }) {
    const el = document.createElement('div');
    el.className = 'empty-state';
    el.innerHTML = `
        <div class="empty-icon">${icon || ''}</div>
        <div class="empty-title">${esc(title || '')}</div>
        ${subtitle ? `<div class="empty-subtitle">${esc(subtitle)}</div>` : ''}
    `;

    if (cta) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-primary btn-lg';
        btn.textContent = cta;
        btn.disabled = !!disabled;
        if (onCta) btn.addEventListener('click', onCta);
        el.appendChild(btn);
    }

    return el;
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
