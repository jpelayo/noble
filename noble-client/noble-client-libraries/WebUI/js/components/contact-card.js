// Contact display card component.
import { Bridge } from '../bridge.js';
import { hashText } from './hash-text.js';

/**
 * Render a contact detail card.
 * @param {Object} contact
 * @param {Object} callbacks - { onSend, onEdit, onExport, onDelete }
 * @returns {HTMLElement}
 */
export function contactCard(contact, { onSend, onEdit, onExport, onDelete } = {}) {
    const el = document.createElement('div');
    el.className = 'panel';

    // Header
    const header = document.createElement('div');
    header.className = 'panel-header';
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.alignItems = 'center';

    const name = document.createElement('span');
    name.textContent = contact.displayName || contact.firstName || 'Unknown';
    header.appendChild(name);

    if (contact.isFavorite) {
        const star = document.createElement('span');
        star.textContent = '\u2605';
        star.style.color = 'var(--warning)';
        header.appendChild(star);
    }
    el.appendChild(header);

    // Body
    const body = document.createElement('div');
    body.className = 'panel-body';

    const grid = document.createElement('dl');
    grid.className = 'detail-grid';

    if (contact.company) addField(grid, 'Company', contact.company);
    if (contact.email) addField(grid, 'Email', contact.email);

    if (contact.noblePubkey) {
        const dt = document.createElement('dt');
        dt.textContent = 'Noble Pubkey';
        const dd = document.createElement('dd');
        dd.appendChild(hashText(contact.noblePubkey, { chars: 12 }));
        grid.appendChild(dt);
        grid.appendChild(dd);
    }

    if (contact.bitcoinKey) {
        const dt = document.createElement('dt');
        dt.textContent = 'Bitcoin Key';
        const dd = document.createElement('dd');
        dd.appendChild(hashText(contact.bitcoinKey, { chars: 12 }));
        grid.appendChild(dt);
        grid.appendChild(dd);
    }

    if (contact.notes) addField(grid, 'Notes', contact.notes);
    body.appendChild(grid);

    // Actions
    const actions = document.createElement('div');
    actions.className = 'quick-actions';
    actions.style.marginTop = 'var(--gap)';

    if (onSend && contact.noblePubkey) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-primary btn-sm';
        btn.textContent = 'Send Payment';
        btn.addEventListener('click', () => onSend(contact));
        actions.appendChild(btn);
    }

    if (onExport) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-sm';
        btn.textContent = 'Export vCard';
        btn.addEventListener('click', () => onExport(contact));
        actions.appendChild(btn);
    }

    if (onEdit) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-sm';
        btn.textContent = 'Edit';
        btn.addEventListener('click', () => onEdit(contact));
        actions.appendChild(btn);
    }

    if (onDelete) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-danger btn-sm';
        btn.textContent = 'Delete';
        btn.addEventListener('click', () => onDelete(contact));
        actions.appendChild(btn);
    }

    body.appendChild(actions);
    el.appendChild(body);

    return el;
}

function addField(grid, label, value) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    grid.appendChild(dt);
    grid.appendChild(dd);
}
