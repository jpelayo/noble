// NOBLE Document Client — Contacts (CRUD + VCF import/export)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { emptyState } from '../components/empty-state.js';
import { contactCard } from '../components/contact-card.js';
import { openModal, closeModal } from '../components/modal.js';
import { promptP12Password } from '../components/p12-password.js';
import { esc, truncate, initials } from '../utils.js';

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let contacts = [];
    let searchQuery = '';
    let selectedContact = null;
    let multiSelect = false;
    let selectedIds = new Set();
    let loadingContacts = false;

    loadContacts();

    async function loadContacts() {
        if (loadingContacts) return;
        loadingContacts = true;
        try {
            const data = await Bridge.call('noble_storage', 'getContacts');
            if (!alive) return;
            contacts = data.contacts || [];
            // Auto-create My Card if none exists
            if (!contacts.some(c => c.isMyCard)) {
                try {
                    await Bridge.call('noble_storage', 'ensureMyCard');
                    const data2 = await Bridge.call('noble_storage', 'getContacts');
                    if (!alive) return;
                    contacts = data2.contacts || [];
                } catch (e) {
                    console.warn('[Contacts] My Card creation failed:', e.message || e);
                }
            }
            render();
        } catch {
            if (!alive) return;
            contacts = [];
            render();
        } finally {
            loadingContacts = false;
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

        // ── My Card (always at top) ──
        const myCard = contacts.find(c => c.isMyCard);
        if (myCard && !searchQuery) {
            const myCardPanel = document.createElement('div');
            myCardPanel.className = 'panel my-card-panel';
            myCardPanel.style.marginBottom = 'var(--gap)';

            const myCardHeader = document.createElement('div');
            myCardHeader.className = 'panel-header';
            myCardHeader.innerHTML = '<span class="my-card-badge">Your Identity</span>';
            myCardPanel.appendChild(myCardHeader);
            myCardPanel.appendChild(buildContactRow(myCard));
            root.appendChild(myCardPanel);
        }

        // Filter contacts (exclude My Card from main list)
        const filtered = contacts.filter(c => {
            if (c.isMyCard) return false;
            if (!searchQuery) return true;
            const q = searchQuery;
            return (c.displayName || '').toLowerCase().includes(q)
                || (c.firstName || '').toLowerCase().includes(q)
                || (c.lastName || '').toLowerCase().includes(q)
                || (c.company || '').toLowerCase().includes(q)
                || (c.email || '').toLowerCase().includes(q)
                || (c.noblePubkey || '').toLowerCase().startsWith(q)
                || (c.nobleHex || '').toLowerCase().startsWith(q)
                || (c.bitcoinP2pkh || '').toLowerCase().startsWith(q)
                || (c.bitcoinP2wpkh || '').toLowerCase().startsWith(q)
                || (c.bitcoinP2tr || '').toLowerCase().startsWith(q);
        });

        if (filtered.length === 0 && !myCard) {
            root.appendChild(emptyState({
                icon: '\u{1F50D}',
                title: 'No Results',
                subtitle: 'No contacts match your search.'
            }));
            return;
        }

        if (filtered.length === 0) return; // My Card shown, no other results

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
                // Drive the in-WebUI router directly (works on every platform);
                // the native call only keeps Mac's sidebar selection in sync and
                // is a harmless no-op on WRY, which doesn't re-drive the router.
                if (window.App) window.App.navigateTo('payments');
                Bridge.call('noble_app', 'navigateTo', { section: 'payments' });
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
            onDelete: c.isMyCard ? null : () => confirmDelete(c)
        });
        root.appendChild(card);

        // ── Signing Keys panel (My Card only) ──
        if (c.isMyCard) {
            renderSigningKeys(c);
        }
    }

    function renderSigningKeys(contact) {
        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.style.marginTop = 'var(--gap)';

        const header = document.createElement('div');
        header.className = 'panel-header';
        header.textContent = 'Signing Keys';
        panel.appendChild(header);

        const body = document.createElement('div');
        body.className = 'panel-body';

        const keys = contact.signingKeys || [];
        if (keys.length === 0) {
            const empty = document.createElement('div');
            empty.style.cssText = 'padding:var(--gap);text-align:center;color:var(--text-muted)';
            empty.textContent = 'No signing keys imported. Import a .p12 certificate to sign document metadata.';
            body.appendChild(empty);
        } else {
            for (const sk of keys) {
                const row = document.createElement('div');
                row.className = 'signing-key-row';

                const info = document.createElement('div');
                info.style.flex = '1';

                const nameRow = document.createElement('div');
                nameRow.style.cssText = 'display:flex;align-items:center;gap:var(--gap-xs)';
                const label = document.createElement('span');
                label.style.fontWeight = '500';
                label.textContent = sk.label || 'Unnamed Key';
                nameRow.appendChild(label);

                const algBadge = document.createElement('span');
                algBadge.className = 'signing-key-badge';
                algBadge.textContent = sk.algorithm === 'p256' ? 'P-256' : 'secp256k1';
                nameRow.appendChild(algBadge);
                info.appendChild(nameRow);

                if (sk.certificateSubject) {
                    const subj = document.createElement('div');
                    subj.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-secondary)';
                    subj.textContent = sk.certificateSubject;
                    info.appendChild(subj);
                }

                const pkRow = document.createElement('div');
                pkRow.className = 'mono';
                pkRow.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted)';
                pkRow.textContent = sk.publicKeyHex ? truncate(sk.publicKeyHex, 12) : '';
                info.appendChild(pkRow);

                row.appendChild(info);

                const rmBtn = document.createElement('button');
                rmBtn.className = 'btn btn-sm';
                rmBtn.textContent = 'Remove';
                rmBtn.style.cssText = 'color:var(--error);min-height:auto;padding:4px 8px';
                rmBtn.addEventListener('click', async () => {
                    rmBtn.disabled = true;
                    try {
                        await Bridge.call('noble_security', 'removeSigningKey', { keyId: sk.id });
                        await loadContacts();
                        selectedContact = contacts.find(c => c.id === contact.id) || null;
                        render();
                    } catch (err) { rmBtn.disabled = false; console.error('[Contacts] remove key failed:', err); }
                });
                row.appendChild(rmBtn);

                body.appendChild(row);
            }
        }

        panel.appendChild(body);

        // Action buttons
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:var(--gap-sm);padding:var(--gap-sm) var(--gap)';

        const importBtn = document.createElement('button');
        importBtn.className = 'btn btn-primary btn-sm';
        importBtn.textContent = 'Import .p12 Key';
        importBtn.addEventListener('click', async () => {
            // WRY collects the password in-WebUI first; Mac/iOS prompt natively.
            const password = await promptP12Password(state.platform);
            if (password === null) return; // cancelled on WRY
            try {
                const params = password === undefined ? undefined : { password };
                const result = await Bridge.call('noble_security', 'importPKCS12', params);
                if (result && !result.error) {
                    await loadContacts();
                    selectedContact = contacts.find(c => c.id === contact.id) || null;
                    render();
                }
            } catch (e) {
                // "cancelled" = user closed the file picker; anything else is a
                // real failure whose message carries actionable guidance (wrong
                // password, legacy encryption re-export command, RSA rejection).
                const msg = (e && e.message) || String(e);
                console.error('[Contacts] PKCS#12 import failed:', msg);
                if (msg !== 'cancelled') alert('PKCS#12 import failed:\n' + msg);
            }
        });
        actions.appendChild(importBtn);

        const genBtn = document.createElement('button');
        genBtn.className = 'btn btn-sm';
        genBtn.textContent = 'Generate Key';
        genBtn.addEventListener('click', async () => {
            try {
                const result = await Bridge.call('noble_security', 'generateSigningKey');
                if (result && !result.error) {
                    await loadContacts();
                    selectedContact = contacts.find(c => c.id === contact.id) || null;
                    render();
                }
            } catch (err) { console.error('[Contacts] key generation failed:', err); }
        });
        actions.appendChild(genBtn);

        panel.appendChild(actions);
        root.appendChild(panel);
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
            nobleHex: existing?.nobleHex || '',
            bitcoinP2pkh: existing?.bitcoinP2pkh || '',
            bitcoinP2wpkh: existing?.bitcoinP2wpkh || '',
            bitcoinP2tr: existing?.bitcoinP2tr || '',
            notes: existing?.notes || '',
            isFavorite: existing?.isFavorite || false,
        };

        const body = document.createElement('div');

        const fields = [
            { key: 'firstName', label: 'First Name *', type: 'text', placeholder: 'Jane' },
            { key: 'lastName', label: 'Last Name', type: 'text', placeholder: 'Doe' },
            { key: 'company', label: 'Company', type: 'text', placeholder: 'Acme Corp' },
            { key: 'email', label: 'Email', type: 'email', placeholder: 'jane@example.com' },
            { key: 'noblePubkey', label: 'Noble Address (bech32m)', type: 'text', placeholder: 'nbl1p...', mono: true },
            { key: 'nobleHex', label: 'Noble Pubkey (hex wire)', type: 'text', placeholder: '0202ab3f...', mono: true },
            { key: 'bitcoinP2pkh', label: 'Bitcoin P2PKH', type: 'text', placeholder: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', mono: true },
            { key: 'bitcoinP2wpkh', label: 'Bitcoin P2WPKH', type: 'text', placeholder: 'bc1qw508d6qejxtdg4y5r3zarv...', mono: true },
            { key: 'bitcoinP2tr', label: 'Bitcoin P2TR (Taproot)', type: 'text', placeholder: 'bc1p5cyxnuxmeuwuvkwfem96lq...', mono: true },
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
                    if (pk && !pk.toLowerCase().startsWith('nbl1')) {
                        error.textContent = 'Must be a Noble bech32m address (nbl1…)';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }
            if (f.key === 'nobleHex') {
                input.addEventListener('blur', () => {
                    const pk = form.nobleHex;
                    if (pk && !/^[0-9a-fA-F]+$/.test(pk)) {
                        error.textContent = 'Must be even-length hex (wire bytes)';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }
            if (f.key === 'bitcoinP2pkh') {
                input.addEventListener('blur', () => {
                    const bk = form.bitcoinP2pkh;
                    if (bk && !/^[13]/.test(bk)) {
                        error.textContent = 'Must start with 1 or 3';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }
            if (f.key === 'bitcoinP2wpkh') {
                input.addEventListener('blur', () => {
                    const bk = form.bitcoinP2wpkh;
                    if (bk && !bk.toLowerCase().startsWith('bc1q')) {
                        error.textContent = 'Must start with bc1q';
                        error.style.display = '';
                    } else {
                        error.style.display = 'none';
                    }
                });
            }
            if (f.key === 'bitcoinP2tr') {
                input.addEventListener('blur', () => {
                    const bk = form.bitcoinP2tr;
                    if (bk && !bk.toLowerCase().startsWith('bc1p')) {
                        error.textContent = 'Must start with bc1p';
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
            } catch (err) {
                deleteBtn.disabled = false;
                deleteBtn.textContent = 'Delete';
                console.error('[Contacts] delete failed:', err);
            }
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

