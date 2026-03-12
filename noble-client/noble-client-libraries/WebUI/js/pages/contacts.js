// NOBLE Document Client — Contacts (CRUD + VCF import/export)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { emptyState } from '../components/empty-state.js';
import { contactCard } from '../components/contact-card.js';
import { openModal, closeModal } from '../components/modal.js';
import { esc, truncate, initials } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let contacts = [];
    let searchQuery = '';
    let selectedContact = null;
    let multiSelect = false;
    let selectedIds = new Set();

    loadContacts();

    async function loadContacts() {
        try {
            const data = await Bridge.call('noble_storage', 'getContacts');
            if (!alive) return;
            contacts = data.contacts || [];
            render();
        } catch {
            if (!alive) return;
            contacts = [];
            render();
        }
    }

    function render() {
        if (!alive) return;
        root.innerHTML = '';
        root.classList.add('page-content');

        // Page header
        const header = document.createElement('div');
        header.className = 'page-header';
        header.innerHTML = '<h1>Contacts</h1><p>Manage your NOBLE address book</p>';
        root.appendChild(header);

        if (selectedContact) {
            renderDetail();
            return;
        }

        if (contacts.length === 0 && !searchQuery) {
            renderEmpty();
            return;
        }

        renderList();
    }

    // ── Empty State ──

    function renderEmpty() {
        const actions = document.createElement('div');
        actions.className = 'quick-actions';
        actions.style.justifyContent = 'center';
        actions.style.marginBottom = 'var(--gap)';

        const addBtn = document.createElement('button');
        addBtn.className = 'btn btn-primary';
        addBtn.textContent = 'Add Contact';
        addBtn.addEventListener('click', () => openEditModal(null));

        const importBtn = document.createElement('button');
        importBtn.className = 'btn';
        importBtn.textContent = 'Import VCF';
        importBtn.addEventListener('click', importVCF);

        actions.appendChild(addBtn);
        actions.appendChild(importBtn);

        root.appendChild(emptyState({
            icon: '\u{1F4D6}',
            title: 'No Contacts',
            subtitle: 'Add contacts to quickly send payments and export address books.'
        }));
        root.appendChild(actions);
    }

    // ── Contact List ──

    function renderList() {
        // Toolbar
        const toolbar = document.createElement('div');
        toolbar.style.cssText = 'display:flex; gap:var(--gap-sm); margin-bottom:var(--gap); flex-wrap:wrap; align-items:center;';

        // Search
        const searchWrap = document.createElement('div');
        searchWrap.className = 'search-bar';
        searchWrap.style.flex = '1';
        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.placeholder = 'Search contacts...';
        searchInput.setAttribute('aria-label', 'Search contacts');
        searchInput.value = searchQuery;
        searchInput.addEventListener('input', () => {
            searchQuery = searchInput.value.trim().toLowerCase();
            render();
            const newSearchEl = root.querySelector('.search-bar input');
            if (newSearchEl && searchQuery) {
                newSearchEl.focus();
                newSearchEl.setSelectionRange(newSearchEl.value.length, newSearchEl.value.length);
            }
        });
        searchWrap.appendChild(searchInput);
        toolbar.appendChild(searchWrap);

        // Buttons
        const addBtn = document.createElement('button');
        addBtn.className = 'btn btn-primary btn-sm';
        addBtn.textContent = 'Add Contact';
        addBtn.setAttribute('aria-label', 'Add new contact');
        addBtn.addEventListener('click', () => openEditModal(null));

        const importBtn = document.createElement('button');
        importBtn.className = 'btn btn-sm';
        importBtn.textContent = 'Import VCF';
        importBtn.setAttribute('aria-label', 'Import contacts from VCF file');
        importBtn.addEventListener('click', importVCF);

        const exportBtn = document.createElement('button');
        exportBtn.className = 'btn btn-sm';
        exportBtn.setAttribute('aria-label', multiSelect ? 'Export selected contacts' : 'Export all contacts');
        exportBtn.textContent = multiSelect ? 'Export Selected' : 'Export All';
        exportBtn.addEventListener('click', () => {
            if (multiSelect && selectedIds.size > 0) {
                exportSelected();
            } else if (!multiSelect) {
                multiSelect = true;
                selectedIds.clear();
                render();
            }
        });

        toolbar.appendChild(addBtn);
        toolbar.appendChild(importBtn);
        toolbar.appendChild(exportBtn);

        if (multiSelect) {
            const cancelBtn = document.createElement('button');
            cancelBtn.className = 'btn btn-secondary btn-sm';
            cancelBtn.textContent = 'Cancel';
            cancelBtn.addEventListener('click', () => { multiSelect = false; selectedIds.clear(); render(); });
            toolbar.appendChild(cancelBtn);
        }

        root.appendChild(toolbar);

        // Filter contacts
        const filtered = contacts.filter(c => {
            if (!searchQuery) return true;
            const q = searchQuery;
            return (c.displayName || '').toLowerCase().includes(q)
                || (c.firstName || '').toLowerCase().includes(q)
                || (c.lastName || '').toLowerCase().includes(q)
                || (c.company || '').toLowerCase().includes(q)
                || (c.email || '').toLowerCase().includes(q)
                || (c.noblePubkey || '').toLowerCase().startsWith(q);
        });

        if (filtered.length === 0) {
            root.appendChild(emptyState({
                icon: '\u{1F50D}',
                title: 'No Results',
                subtitle: 'No contacts match your search.'
            }));
            return;
        }

        // Favorites section
        const favorites = filtered.filter(c => c.isFavorite);
        const others = filtered.filter(c => !c.isFavorite);

        const listPanel = document.createElement('div');
        listPanel.className = 'panel';

        if (favorites.length > 0) {
            const favHeader = document.createElement('div');
            favHeader.className = 'panel-header';
            favHeader.textContent = 'Favorites';
            listPanel.appendChild(favHeader);
            for (const c of favorites) listPanel.appendChild(buildContactRow(c));
        }

        if (others.length > 0) {
            if (favorites.length > 0) {
                const otherHeader = document.createElement('div');
                otherHeader.className = 'panel-header';
                otherHeader.textContent = 'All Contacts';
                listPanel.appendChild(otherHeader);
            }
            for (const c of others) listPanel.appendChild(buildContactRow(c));
        }

        root.appendChild(listPanel);
    }

    function buildContactRow(c) {
        const row = document.createElement('div');
        row.className = 'contact-row';

        if (multiSelect) {
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = selectedIds.has(c.id);
            cb.addEventListener('change', () => {
                if (cb.checked) selectedIds.add(c.id);
                else selectedIds.delete(c.id);
            });
            row.appendChild(cb);
        }

        const avatar = document.createElement('div');
        avatar.className = 'contact-avatar';
        avatar.textContent = initials(c);

        const info = document.createElement('div');
        info.className = 'contact-info';
        const name = document.createElement('div');
        name.style.fontWeight = '500';
        name.textContent = c.displayName || c.firstName || 'Unknown';
        info.appendChild(name);

        if (c.company) {
            const comp = document.createElement('div');
            comp.style.cssText = 'font-size:var(--font-size-xs); color:var(--text-muted)';
            comp.textContent = c.company;
            info.appendChild(comp);
        }

        if (c.noblePubkey) {
            const pk = document.createElement('div');
            pk.className = 'mono';
            pk.style.cssText = 'font-size:var(--font-size-xs); color:var(--text-secondary)';
            pk.textContent = truncate(c.noblePubkey, 10);
            info.appendChild(pk);
        }

        row.appendChild(avatar);
        row.appendChild(info);

        if (c.isFavorite) {
            const star = document.createElement('span');
            star.className = 'contact-favorite';
            star.textContent = '\u2605';
            row.appendChild(star);
        }

        if (!multiSelect) {
            row.style.cursor = 'pointer';
            row.addEventListener('click', () => {
                selectedContact = c;
                render();
            });
        }

        return row;
    }

    // ── Contact Detail ──

    function renderDetail() {
        const c = selectedContact;

        // Back button
        const backBtn = document.createElement('button');
        backBtn.className = 'btn btn-secondary btn-sm';
        backBtn.textContent = '\u2190 Back';
        backBtn.setAttribute('aria-label', 'Back to contact list');
        backBtn.style.marginBottom = 'var(--gap)';
        backBtn.addEventListener('click', () => { selectedContact = null; render(); });
        root.appendChild(backBtn);

        const card = contactCard(c, {
            onSend: (contact) => {
                Bridge.call('noble_app', 'navigateTo', { section: 'payments' });
                // Defer to allow page switch
                setTimeout(() => {
                    if (window.App && window.App._currentPage && window.App._currentPage.openSendWizard) {
                        window.App._currentPage.openSendWizard(contact.noblePubkey);
                    }
                }, 300);
            },
            onExport: async (contact) => {
                try {
                    const result = await Bridge.call('noble_storage', 'exportContactsVCF', { ids: [contact.id] });
                    const filename = `${contact.displayName || 'contact'}.vcf`;
                    await Bridge.call('noble_app', 'saveFileDialog', { filename, content: result.vcf });
                } catch { /* user cancelled */ }
            },
            onEdit: () => openEditModal(c),
            onDelete: () => confirmDelete(c)
        });
        root.appendChild(card);
    }

    // ── Add/Edit Modal ──

    function openEditModal(existing) {
        const isEdit = !!existing;
        const form = {
            firstName: existing?.firstName || '',
            lastName: existing?.lastName || '',
            company: existing?.company || '',
            email: existing?.email || '',
            noblePubkey: existing?.noblePubkey || '',
            bitcoinKey: existing?.bitcoinKey || '',
            notes: existing?.notes || '',
            isFavorite: existing?.isFavorite || false,
        };

        const body = document.createElement('div');

        const fields = [
            { key: 'firstName', label: 'First Name *', type: 'text', placeholder: 'Jane' },
            { key: 'lastName', label: 'Last Name', type: 'text', placeholder: 'Doe' },
            { key: 'company', label: 'Company', type: 'text', placeholder: 'Acme Corp' },
            { key: 'email', label: 'Email', type: 'email', placeholder: 'jane@example.com' },
            { key: 'noblePubkey', label: 'Noble Pubkey', type: 'text', placeholder: '02ab3f...', mono: true },
            { key: 'bitcoinKey', label: 'Bitcoin Key', type: 'text', placeholder: 'bc1q...', mono: true },
            { key: 'notes', label: 'Notes', type: 'textarea', placeholder: 'Additional notes...' },
        ];

        for (const f of fields) {
            const group = document.createElement('div');
            group.className = 'form-group';
            const label = document.createElement('label');
            label.textContent = f.label;
            group.appendChild(label);

            let input;
            if (f.type === 'textarea') {
                input = document.createElement('textarea');
                input.rows = 3;
            } else {
                input = document.createElement('input');
                input.type = f.type;
            }
            input.className = 'form-input';
            if (f.mono) input.style.fontFamily = 'var(--font-mono)';
            input.placeholder = f.placeholder;
            input.value = form[f.key];
            input.addEventListener('input', () => { form[f.key] = input.value; });

            const error = document.createElement('div');
            error.className = 'form-error';
            error.style.display = 'none';

            // Validation on blur
            if (f.key === 'email') {
                input.addEventListener('blur', () => {
                    if (form.email && !form.email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
                        error.textContent = 'Invalid email format';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }
            if (f.key === 'noblePubkey') {
                input.addEventListener('blur', () => {
                    const pk = form.noblePubkey;
                    const isNbl1 = pk && pk.toLowerCase().startsWith('nbl1');
                    const isValidHex = pk && /^[0-9a-fA-F]+$/.test(pk) && pk.length % 2 === 0;
                    if (pk && !isNbl1 && !isValidHex) {
                        error.textContent = 'Must be a Noble address (nbl1…) or even-length hex';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }
            if (f.key === 'bitcoinKey') {
                input.addEventListener('blur', () => {
                    const bk = form.bitcoinKey;
                    if (bk && !/^(bc1q|bc1p|1|3)/.test(bk)) {
                        error.textContent = 'Must start with bc1q, bc1p, 1, or 3';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }

            group.appendChild(input);
            group.appendChild(error);
            body.appendChild(group);
        }

        // Favorite toggle
        const favGroup = document.createElement('div');
        favGroup.className = 'form-group';
        favGroup.style.display = 'flex';
        favGroup.style.alignItems = 'center';
        favGroup.style.gap = 'var(--gap-sm)';
        const favCb = document.createElement('input');
        favCb.type = 'checkbox';
        favCb.checked = form.isFavorite;
        favCb.addEventListener('change', () => { form.isFavorite = favCb.checked; });
        const favLabel = document.createElement('label');
        favLabel.textContent = 'Favorite';
        favLabel.style.margin = '0';
        favGroup.appendChild(favCb);
        favGroup.appendChild(favLabel);
        body.appendChild(favGroup);

        // Save button
        const saveBtn = document.createElement('button');
        saveBtn.className = 'btn btn-primary';
        saveBtn.textContent = isEdit ? 'Save Changes' : 'Add Contact';
        saveBtn.style.marginTop = 'var(--gap-sm)';
        saveBtn.addEventListener('click', async () => {
            if (!form.firstName.trim()) return;
            saveBtn.disabled = true;
            saveBtn.textContent = 'Saving...';
            try {
                const contact = {
                    id: existing?.id || crypto.randomUUID(),
                    ...form,
                    createdAt: existing?.createdAt || Date.now() / 1000,
                };
                await Bridge.call('noble_storage', 'saveContact', { contact });
                modal.close();
                selectedContact = null;
                await loadContacts();
            } catch (err) {
                saveBtn.disabled = false;
                saveBtn.textContent = isEdit ? 'Save Changes' : 'Add Contact';
            }
        });
        body.appendChild(saveBtn);

        const modal = openModal({ title: isEdit ? 'Edit Contact' : 'Add Contact', body });
    }

    // ── Delete Confirmation ──

    function confirmDelete(contact) {
        const body = document.createElement('div');
        body.innerHTML = `<p style="margin-bottom:var(--gap)">Delete <strong>${esc(contact.displayName || contact.firstName)}</strong>? This cannot be undone.</p>`;

        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex; gap:var(--gap-sm); justify-content:flex-end';

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.addEventListener('click', () => modal.close());

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-danger';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', async () => {
            deleteBtn.disabled = true;
            deleteBtn.textContent = 'Deleting...';
            try {
                await Bridge.call('noble_storage', 'deleteContact', { id: contact.id });
                modal.close();
                selectedContact = null;
                await loadContacts();
            } catch {}
        });

        actions.appendChild(cancelBtn);
        actions.appendChild(deleteBtn);
        body.appendChild(actions);

        const modal = openModal({ title: 'Delete Contact', body });
    }

    // ── VCF Import ──

    async function importVCF() {
        try {
            const fileResult = await Bridge.call('noble_app', 'openFileDialog', { multiple: false });
            if (!fileResult.files || fileResult.files.length === 0) return;

            const file = fileResult.files[0];
            const textResult = await Bridge.call('noble_app', 'readFileText', { filePath: file.path });
            const parsed = await Bridge.call('noble_storage', 'importContactsVCF', { vcf: textResult.text });

            if (!parsed.contacts || parsed.contacts.length === 0) {
                openModal({ title: 'Import VCF', body: 'No contacts found in file.' });
                return;
            }

            // Preview modal with checkboxes
            const body = document.createElement('div');
            const desc = document.createElement('p');
            desc.style.marginBottom = 'var(--gap)';
            desc.textContent = `Found ${parsed.contacts.length} contact(s). Select which to import:`;
            body.appendChild(desc);

            const selected = new Set(parsed.contacts.map((_, i) => i));

            for (let i = 0; i < parsed.contacts.length; i++) {
                const c = parsed.contacts[i];
                const row = document.createElement('div');
                row.style.cssText = 'display:flex; align-items:center; gap:var(--gap-sm); padding:var(--gap-xs) 0';

                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.checked = true;
                cb.addEventListener('change', () => {
                    if (cb.checked) selected.add(i);
                    else selected.delete(i);
                });

                const label = document.createElement('span');
                label.textContent = `${c.firstName || ''} ${c.lastName || ''}`.trim() || c.company || 'Unknown';

                row.appendChild(cb);
                row.appendChild(label);
                body.appendChild(row);
            }

            const importBtn = document.createElement('button');
            importBtn.className = 'btn btn-primary';
            importBtn.textContent = 'Import Selected';
            importBtn.style.marginTop = 'var(--gap)';
            importBtn.addEventListener('click', async () => {
                importBtn.disabled = true;
                importBtn.textContent = 'Importing...';
                for (const i of selected) {
                    const c = parsed.contacts[i];
                    c.id = c.id || crypto.randomUUID();
                    await Bridge.call('noble_storage', 'saveContact', { contact: c });
                }
                modal.close();
                await loadContacts();
            });
            body.appendChild(importBtn);

            const modal = openModal({ title: 'Import Contacts', body });
        } catch { /* user cancelled */ }
    }

    // ── VCF Export (batch) ──

    async function exportSelected() {
        try {
            const ids = Array.from(selectedIds);
            const result = await Bridge.call('noble_storage', 'exportContactsVCF', { ids });
            await Bridge.call('noble_app', 'saveFileDialog', { filename: 'contacts.vcf', content: result.vcf });
            multiSelect = false;
            selectedIds.clear();
            render();
        } catch { /* user cancelled */ }
    }

    return {
        destroy() { alive = false; closeModal(); },
        refresh(newState) { Object.assign(state, newState); }
    };
}

