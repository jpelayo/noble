// Card container with optional header.
export function nobleCard(title, contentHTML) {
    const el = document.createElement('div');
    el.className = 'panel';
    el.innerHTML = (title ? `<div class="panel-header">${esc(title)}</div>` : '')
        + `<div class="panel-body">${contentHTML}</div>`;
    return el;
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
