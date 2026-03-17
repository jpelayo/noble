// NOBLE Document Client — Document Registration (7-step wizard)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { formatAmount } from '../components/amount-text.js';
import { emptyState } from '../components/empty-state.js';
import { esc, formatBytes } from '../utils.js';

const STEP_NAMES = ['Files', 'Checksum', 'Metadata', 'Version', 'Fee', 'Review', 'Submit'];

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    // Wizard state
    let step = -1; // -1 = landing page
    let files = [];
    let hashes = {};       // path → hash
    let previousChecksum = '';
    let isNewVersion = false;   // Yes/No toggle for version linking
    let versionMode = 'checksum'; // checksum | file | locator
    let versionFile = null;     // selected file for version lookup
    let wantsMetadata = false;
    let metadata = [];
    let feeLevel = 'recommended';
    let feeData = null;
    let results = [];
    let editingDraftId = null;  // ID of draft being resumed
    let balanceData = null;     // cached balance { available }

    // Check if we're resuming a draft (set by drafts page)
    if (window.App && window.App._pendingDraftId) {
        resumePendingDraft(window.App._pendingDraftId);
    }

    async function resumePendingDraft(draftId) {
        window.App._pendingDraftId = null;
        try {
            const res = await Bridge.call('noble_app', 'getDrafts');
            if (!alive) return;
            const draft = (res.drafts || []).find(d => d.id === draftId);
            if (draft && draft.state) {
                editingDraftId = draft.id;
                restoreWizardState(draft.state);
                render();
            }
        } catch { /* draft not found, stay on landing */ }
    }

    function getWizardState() {
        return {
            files, hashes, previousChecksum, isNewVersion, versionMode,
            wantsMetadata, metadata, feeLevel, step
        };
    }

    function restoreWizardState(d) {
        files = d.files || [];
        hashes = d.hashes || {};
        previousChecksum = d.previousChecksum || '';
        isNewVersion = d.isNewVersion || false;
        versionMode = d.versionMode || 'checksum';
        wantsMetadata = d.wantsMetadata || false;
        metadata = d.metadata || [];
        feeLevel = d.feeLevel || 'recommended';
        step = d.step || 0;
        versionFile = null;
        feeData = null;
        results = [];
    }

    async function saveDraft(reason) {
        const draft = {
            id: editingDraftId || crypto.randomUUID(),
            name: files.length > 0 ? files[0].name : 'Untitled',
            fileCount: files.length,
            reason: reason || null,
            createdAt: Date.now() / 1000,
            state: getWizardState()
        };
        try {
            await Bridge.call('noble_app', 'saveDraft', { draft });
        } catch { /* best effort */ }
        editingDraftId = null;
        resetWizard();
        render();
    }

    function resetWizard() {
        step = -1;
        files = [];
        hashes = {};
        previousChecksum = '';
        isNewVersion = false;
        versionMode = 'checksum';
        versionFile = null;
        wantsMetadata = false;
        metadata = [];
        feeLevel = 'recommended';
        feeData = null;
        results = [];
        editingDraftId = null;
        balanceData = null;
    }

    render();

    function render() {
        if (!alive) return;
        root.innerHTML = '';

        if (step === -1) {
            renderLanding();
        } else {
            renderWizard();
        }
    }

    // ── Landing Page ──

    function renderLanding() {
        root.classList.add('page-content');

        const disabled = !state.isConnected || !state.hasWallet;

        root.appendChild(emptyState({
            icon: '\u{1F4C4}',
            title: 'Register a Document',
            subtitle: disabled
                ? 'Connect to a node and set up a wallet to register documents.'
                : 'Anchor the SHA-256 checksum of any file permanently on-chain.',
            cta: 'New Registration',
            disabled,
            onCta: () => { step = 0; render(); }
        }));
    }

    // ── Wizard Shell ──

    function renderWizard() {
        // ── Top bar: [← PrevName]  ●●●●●●●  [NextName →] ──
        const topBar = document.createElement('div');
        topBar.className = 'wizard-top-bar';

        // Left: back button with previous step name
        const backBtn = document.createElement('button');
        backBtn.className = 'wizard-top-btn wizard-top-back';
        if (step === 0) {
            backBtn.textContent = '\u2190 Cancel';
        } else {
            backBtn.textContent = `\u2190 ${STEP_NAMES[step - 1]}`;
        }
        backBtn.addEventListener('click', () => {
            if (step === 0) { resetWizard(); } else { step--; }
            render();
        });
        // Hide back on submit step
        if (step >= 6) backBtn.style.visibility = 'hidden';
        topBar.appendChild(backBtn);

        // Center: dots
        const dots = document.createElement('div');
        dots.className = 'wizard-dots';
        dots.setAttribute('role', 'progressbar');
        dots.setAttribute('aria-valuenow', step + 1);
        dots.setAttribute('aria-valuemax', String(STEP_NAMES.length));
        dots.setAttribute('aria-label', `Step ${step + 1} of ${STEP_NAMES.length}: ${STEP_NAMES[step]}`);
        for (let i = 0; i < STEP_NAMES.length; i++) {
            const dot = document.createElement('div');
            dot.className = 'step-indicator' + (i === step ? ' active' : '') + (i < step ? ' completed' : '');
            dot.title = STEP_NAMES[i];
            dots.appendChild(dot);
        }
        topBar.appendChild(dots);

        // Right: next step name hint
        const nextHint = document.createElement('span');
        nextHint.className = 'wizard-top-btn wizard-top-next';
        if (step < 6) {
            nextHint.textContent = `${STEP_NAMES[Math.min(step + 1, STEP_NAMES.length - 1)]} \u2192`;
        }
        // Invisible placeholder to keep dots centered when no next hint
        if (step >= 6) nextHint.style.visibility = 'hidden';
        topBar.appendChild(nextHint);

        root.appendChild(topBar);

        // Step title
        const title = document.createElement('h2');
        title.style.cssText = 'font-size: var(--font-size-lg); margin-bottom: var(--gap);';
        title.textContent = `Step ${step + 1}: ${STEP_NAMES[step]}`;
        root.appendChild(title);

        // Step content
        const content = document.createElement('div');
        root.appendChild(content);

        switch (step) {
            case 0: renderStepFiles(content); break;
            case 1: renderStepChecksum(content); break;
            case 2: renderStepMetadata(content); break;
            case 3: renderStepVersion(content); break;
            case 4: renderStepFee(content); break;
            case 5: renderStepReview(content); break;
            case 6: renderStepSubmit(content); break;
        }

        // Bottom navigation (except submit step)
        if (step < 6) {
            // Save Draft row
            if (files.length > 0) {
                const draftRow = document.createElement('div');
                draftRow.style.cssText = 'margin-top:var(--gap);text-align:center;';
                const draftBtn = document.createElement('button');
                draftBtn.className = 'btn btn-secondary btn-sm';
                draftBtn.textContent = 'Save Draft';
                draftBtn.addEventListener('click', () => saveDraft('Saved manually'));
                draftRow.appendChild(draftBtn);
                root.appendChild(draftRow);
            }

            const nav = document.createElement('div');
            nav.className = 'wizard-nav';

            // Left: Back button with previous step name
            const navBackBtn = document.createElement('button');
            navBackBtn.className = 'btn btn-secondary';
            if (step === 0) {
                navBackBtn.textContent = '\u2190 Cancel';
            } else {
                navBackBtn.textContent = `\u2190 ${STEP_NAMES[step - 1]}`;
            }
            navBackBtn.addEventListener('click', () => {
                if (step === 0) { resetWizard(); } else { step--; }
                render();
            });
            nav.appendChild(navBackBtn);

            // Right: Next button with next step name
            const nextBtn = document.createElement('button');
            nextBtn.className = 'btn btn-primary';
            nextBtn.textContent = step === 5 ? 'Sign & Submit' : `${STEP_NAMES[step + 1]} \u2192`;
            nextBtn.disabled = !canAdvance();
            nextBtn.addEventListener('click', () => { step++; render(); });
            nav.appendChild(nextBtn);

            root.appendChild(nav);
        }
    }

    function canAdvance() {
        if (step === 0) return files.length > 0;
        if (step === 1) return Object.keys(hashes).length === files.length;
        if (step === 2) return true; // metadata optional
        if (step === 3) return true; // version optional
        if (step === 4) return feeData !== null;
        if (step === 5) {
            // Block submit if balance is known and insufficient
            if (balanceData) {
                const total = getSelectedFee() * files.length;
                if ((balanceData.available || 0) < total) return false;
            }
            return true;
        }
        return false;
    }

    // ── Step 0: File Selection ──

    // Handle native file drops from Swift (DroppableWebView)
    window._nobleHandleFileDrop = function(droppedFiles) {
        if (step !== 0 || !alive) return;
        for (const f of droppedFiles) {
            if (files.length >= 100) break;
            if (!files.some(x => x.path === f.path)) {
                files.push(f);
            }
        }
        render();
    };

    function renderStepFiles(container) {
        const zone = document.createElement('div');
        zone.className = 'drop-zone';
        zone.setAttribute('role', 'button');
        zone.setAttribute('aria-label', 'Drag files here or click to browse');
        zone.setAttribute('tabindex', '0');
        zone.innerHTML = '<div style="font-size:2rem; margin-bottom:var(--gap-sm)">\u{1F4C1}</div><div>Drag files here or click to browse</div><div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">Up to 100 files</div>';

        // Drag-and-drop visual feedback
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            e.dataTransfer.dropEffect = 'copy';
            zone.classList.add('drag-over');
        });
        zone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove('drag-over');
        });
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove('drag-over');
            // Note: actual file handling is done via native Swift drop (window._nobleHandleFileDrop)
            // HTML5 drop does not give file paths in WKWebView
        });

        zone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); zone.click(); }
        });
        zone.addEventListener('click', async () => {
            try {
                const result = await Bridge.call('noble_app', 'openFileDialog', { multiple: true });
                if (!alive) return;
                if (result.files && result.files.length > 0) {
                    for (const f of result.files) {
                        if (files.length >= 100) break;
                        if (!files.some(x => x.path === f.path)) {
                            files.push(f);
                        }
                    }
                    render();
                }
            } catch (err) {
                // User cancelled
            }
        });
        container.appendChild(zone);

        if (files.length > 0) {
            const list = document.createElement('ul');
            list.className = 'file-list';
            list.style.marginTop = 'var(--gap)';
            for (const f of files) {
                const li = document.createElement('li');
                li.className = 'file-item';
                li.innerHTML = `
                    <span class="file-name">${esc(f.name)}</span>
                    <span class="file-size">${formatBytes(f.size)}</span>
                `;
                const rm = document.createElement('span');
                rm.className = 'file-remove';
                rm.textContent = '\u2715';
                rm.addEventListener('click', () => {
                    files = files.filter(x => x.path !== f.path);
                    delete hashes[f.path];
                    render();
                });
                li.appendChild(rm);
                list.appendChild(li);
            }
            container.appendChild(list);
        }
    }

    // ── Step 1: Checksum ──

    function renderStepChecksum(container) {
        const info = document.createElement('p');
        info.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        info.textContent = 'Computing SHA-256 checksums for each file...';
        container.appendChild(info);

        const progress = document.createElement('div');
        progress.className = 'progress-bar';
        progress.style.marginBottom = 'var(--gap)';
        const fill = document.createElement('div');
        fill.className = 'progress-fill';
        fill.style.width = `${(Object.keys(hashes).length / files.length) * 100}%`;
        progress.appendChild(fill);
        container.appendChild(progress);

        // Results table
        const list = document.createElement('ul');
        list.className = 'file-list';
        for (const f of files) {
            const li = document.createElement('li');
            li.className = 'file-item';
            const h = hashes[f.path];
            if (h) {
                li.innerHTML = `<span style="color:var(--success)">\u2713</span> <span class="file-name">${esc(f.name)}</span>`;
                const hashEl = hashText(h, { chars: 12 });
                hashEl.style.fontSize = 'var(--font-size-xs)';
                li.appendChild(hashEl);
            } else {
                li.innerHTML = `<span style="color:var(--text-muted)">\u23F3</span> <span class="file-name">${esc(f.name)}</span> <span style="font-size:var(--font-size-xs);color:var(--text-muted)">hashing...</span>`;
            }
            list.appendChild(li);
        }
        container.appendChild(list);

        // Compute hashes for files not yet hashed
        computeHashes();
    }

    async function computeHashes() {
        for (const f of files) {
            if (!alive) return;
            if (hashes[f.path]) continue;
            try {
                const result = await Bridge.call('noble_security', 'hashFile', { filePath: f.path });
                if (!alive) return;
                hashes[f.path] = result.hash;
                render();
            } catch (err) {
                if (!alive) return;
                hashes[f.path] = 'ERROR: ' + err.message;
                render();
            }
        }
    }

    // ── Step 3: Version Link ──

    function renderStepVersion(container) {
        const question = document.createElement('p');
        question.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        question.textContent = 'Is this document a new version of a previously registered document?';
        container.appendChild(question);

        // Yes / No toggle
        const toggle = document.createElement('div');
        toggle.className = 'segmented-control';
        toggle.style.marginBottom = 'var(--gap)';
        for (const opt of [{ key: false, label: 'No' }, { key: true, label: 'Yes' }]) {
            const btn = document.createElement('button');
            btn.className = isNewVersion === opt.key ? 'active' : '';
            btn.textContent = opt.label;
            btn.addEventListener('click', () => {
                isNewVersion = opt.key;
                if (!isNewVersion) { previousChecksum = ''; versionFile = null; }
                render();
            });
            toggle.appendChild(btn);
        }
        container.appendChild(toggle);

        if (!isNewVersion) return;

        // Input mode selector
        const modes = [
            { key: 'file', label: 'Select File' },
            { key: 'checksum', label: 'Paste Checksum' },
            { key: 'locator', label: 'Paste Locator' },
        ];
        const seg = document.createElement('div');
        seg.className = 'segmented-control';
        seg.style.marginBottom = 'var(--gap)';
        for (const m of modes) {
            const btn = document.createElement('button');
            btn.className = versionMode === m.key ? 'active' : '';
            btn.textContent = m.label;
            btn.addEventListener('click', () => {
                versionMode = m.key;
                render();
            });
            seg.appendChild(btn);
        }
        container.appendChild(seg);

        // Input area per mode
        const inputArea = document.createElement('div');
        container.appendChild(inputArea);

        switch (versionMode) {
            case 'file': renderVersionFile(inputArea); break;
            case 'checksum': renderVersionChecksum(inputArea); break;
            case 'locator': renderVersionLocator(inputArea); break;
        }

        // Show resolved checksum status
        if (previousChecksum.length === 64) {
            const status = document.createElement('div');
            status.style.cssText = 'margin-top:var(--gap);display:flex;align-items:center;gap:var(--gap-sm);';
            status.innerHTML = `<span style="color:var(--success)">\u2713</span><span class="mono" style="font-size:var(--font-size-xs)">${previousChecksum.slice(0, 16)}\u2026${previousChecksum.slice(-8)}</span>`;

            const verifyBtn = document.createElement('button');
            verifyBtn.className = 'btn btn-secondary btn-sm';
            verifyBtn.textContent = 'Verify on-chain';
            verifyBtn.addEventListener('click', async () => {
                verifyBtn.disabled = true;
                verifyBtn.textContent = 'Checking...';
                try {
                    const r = await Bridge.call('noble_api', 'lookupChecksum', { checksum: previousChecksum });
                    if (!alive) return;
                    verifyBtn.textContent = r.found ? '\u2713 Found on-chain' : '\u2717 Not found';
                    verifyBtn.style.color = r.found ? 'var(--success)' : 'var(--error)';
                } catch {
                    verifyBtn.textContent = 'Lookup failed';
                }
            });
            status.appendChild(verifyBtn);
            container.appendChild(status);
        }
    }

    function renderVersionFile(container) {
        if (versionFile && previousChecksum) {
            const card = document.createElement('div');
            card.className = 'panel';
            card.innerHTML = `<div class="panel-body" style="display:flex;align-items:center;gap:var(--gap-sm)">
                <span style="color:var(--success)">\u2713</span>
                <span class="file-name">${esc(versionFile.name)}</span>
            </div>`;
            const changeBtn = document.createElement('button');
            changeBtn.className = 'btn btn-secondary btn-sm';
            changeBtn.textContent = 'Change';
            changeBtn.style.marginTop = 'var(--gap-sm)';
            changeBtn.addEventListener('click', () => {
                versionFile = null;
                previousChecksum = '';
                render();
            });
            container.appendChild(card);
            container.appendChild(changeBtn);
            return;
        }

        const zone = document.createElement('div');
        zone.className = 'drop-zone';
        zone.setAttribute('role', 'button');
        zone.setAttribute('tabindex', '0');
        zone.innerHTML = '<div>Select the previous version of the document</div><div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">The file will be hashed to find its on-chain record</div>';
        zone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); zone.click(); }
        });
        zone.addEventListener('click', async () => {
            try {
                const res = await Bridge.call('noble_app', 'openFileDialog', { multiple: false });
                if (!alive || !res.files || !res.files.length) return;
                versionFile = res.files[0];
                render();
                const hashResult = await Bridge.call('noble_security', 'hashFile', { filePath: versionFile.path });
                if (!alive) return;
                previousChecksum = hashResult.hash;
                render();
            } catch {
                // cancelled
            }
        });
        container.appendChild(zone);
    }

    function renderVersionChecksum(container) {
        const group = document.createElement('div');
        group.className = 'form-group';
        group.innerHTML = `<label>SHA-256 Checksum (64 hex characters)</label>`;
        const input = document.createElement('input');
        input.className = 'form-input';
        input.type = 'text';
        input.maxLength = 64;
        input.placeholder = 'e.g. e3b0c44298fc1c149afbf4c8...';
        input.value = previousChecksum;
        input.addEventListener('input', () => {
            previousChecksum = input.value.trim().toLowerCase();
        });
        group.appendChild(input);
        container.appendChild(group);
    }

    function renderVersionLocator(container) {
        const group = document.createElement('div');
        group.className = 'form-group';
        group.innerHTML = `<label>NOBLE Document Locator</label>`;
        const input = document.createElement('input');
        input.className = 'form-input';
        input.type = 'text';
        input.placeholder = 'noble:doc:<checksum>';
        input.addEventListener('input', () => {
            const val = input.value.trim();
            const match = val.match(/^noble:doc:([0-9a-fA-F]{64})$/);
            previousChecksum = match ? match[1].toLowerCase() : '';
        });
        group.appendChild(input);
        container.appendChild(group);
    }

    // ── Step 2: Metadata ──

    // Predefined metadata fields from the client specification.
    // Each field can be toggled between plaintext and encrypted by the user.
    const METADATA_FIELDS = [
        { key: 'document_name', label: 'Document Name',  icon: '\u{1F4C4}', placeholder: 'e.g. Contract v2.1' },
        { key: 'description',   label: 'Description',    icon: '\u{1F4DD}', placeholder: 'Brief description of the document' },
        { key: 'batch_name',    label: 'Batch Name',     icon: '\u{1F4C1}', placeholder: 'e.g. Q1 2026 Invoices' },
        { key: 'uploader_name', label: 'Uploader Name',  icon: '\u{1F464}', placeholder: 'Your name or organization' },
        { key: 'url',           label: 'URL',            icon: '\u{1F517}', placeholder: 'https://...' },
        { key: 'sender_email',  label: 'Sender Email',   icon: '\u{2709}\uFE0F', placeholder: 'email@example.com', contactPicker: true },
        { key: 'sender_pubkey', label: 'Sender Public Key', icon: '\u{1F511}', placeholder: '02ab3f...' },
        { key: 'signatures',    label: 'Signatures',     icon: '\u{270D}\uFE0F', placeholder: 'Signer names or identifiers' },
        { key: 'custom',        label: 'Custom Field',   icon: '\u{2795}', placeholder: 'Value', customKey: true },
    ];

    function renderStepMetadata(container) {
        const question = document.createElement('p');
        question.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        question.textContent = 'Do you want to add metadata to this registration?';
        container.appendChild(question);

        // Yes / No toggle
        const toggle = document.createElement('div');
        toggle.className = 'segmented-control';
        toggle.style.marginBottom = 'var(--gap)';
        for (const opt of [{ key: false, label: 'No' }, { key: true, label: 'Yes' }]) {
            const btn = document.createElement('button');
            btn.className = wantsMetadata === opt.key ? 'active' : '';
            btn.textContent = opt.label;
            btn.addEventListener('click', () => {
                wantsMetadata = opt.key;
                if (!wantsMetadata) metadata = [];
                render();
            });
            toggle.appendChild(btn);
        }
        container.appendChild(toggle);

        if (!wantsMetadata) return;

        // Existing fields
        if (metadata.length > 0) {
            const list = document.createElement('div');
            list.style.cssText = 'display:flex;flex-direction:column;gap:var(--gap-sm);margin-bottom:var(--gap);';
            for (let i = 0; i < metadata.length; i++) {
                list.appendChild(buildMetadataRow(i));
            }
            container.appendChild(list);
        }

        // Add button with dropdown
        if (metadata.length < 16) {
            renderAddFieldButton(container);
        }
    }

    function buildMetadataRow(index) {
        const m = metadata[index];
        if (!m.recipients) m.recipients = [];
        const fieldDef = METADATA_FIELDS.find(f => f.key === m.fieldKey) || METADATA_FIELDS[METADATA_FIELDS.length - 1];
        const isEncrypted = m.mode === 'encrypted';

        const row = document.createElement('div');
        row.className = 'panel metadata-row';

        // Header: label + remove
        const header = document.createElement('div');
        header.className = 'metadata-row-header';

        const label = document.createElement('span');
        label.className = 'metadata-row-label';
        label.textContent = fieldDef.label;
        if (m.fieldKey === 'custom' && m.key) label.textContent = m.key;
        header.appendChild(label);

        const spacer = document.createElement('span');
        spacer.style.flex = '1';
        header.appendChild(spacer);

        const rmBtn = document.createElement('button');
        rmBtn.className = 'btn btn-sm';
        rmBtn.textContent = '\u2715';
        rmBtn.style.cssText = 'color:var(--text-muted);min-height:auto;padding:2px 6px;';
        rmBtn.addEventListener('click', () => { metadata.splice(index, 1); render(); });
        header.appendChild(rmBtn);
        row.appendChild(header);

        // Custom key input (only for "Custom Field")
        if (fieldDef.customKey) {
            const keyInput = document.createElement('input');
            keyInput.className = 'form-input';
            keyInput.placeholder = 'Field name';
            keyInput.maxLength = 64;
            keyInput.value = m.key;
            keyInput.style.marginBottom = 'var(--gap-sm)';
            keyInput.addEventListener('input', () => { m.key = keyInput.value; });
            row.appendChild(keyInput);
        }

        // Value input
        const valRow = document.createElement('div');
        valRow.style.cssText = 'display:flex;gap:var(--gap-sm);align-items:center;';

        const valInput = document.createElement('input');
        valInput.className = 'form-input';
        valInput.placeholder = fieldDef.placeholder;
        valInput.maxLength = 256;
        valInput.value = m.value;
        valInput.style.flex = '1';
        valInput.addEventListener('input', () => { m.value = valInput.value; });
        valRow.appendChild(valInput);

        // Contact picker for email fields
        if (fieldDef.contactPicker) {
            const pickBtn = document.createElement('button');
            pickBtn.className = 'btn btn-secondary btn-sm';
            pickBtn.innerHTML = '\u{1F4D6}';
            pickBtn.title = 'Pick from contacts';
            pickBtn.style.cssText = 'min-height:auto;padding:6px 10px;font-size:1.1rem;';
            pickBtn.addEventListener('click', async () => {
                try {
                    const res = await Bridge.call('noble_storage', 'getContacts');
                    if (!alive || !res.contacts || !res.contacts.length) return;
                    const withEmail = res.contacts.filter(c => c.email);
                    if (!withEmail.length) return;
                    showContactPicker(withEmail, (email) => {
                        m.value = email;
                        render();
                    });
                } catch { /* ignore */ }
            });
            valRow.appendChild(pickBtn);
        }

        row.appendChild(valRow);

        // ── Visibility toggle: Public / Encrypted (segmented) ──
        const visSection = document.createElement('div');
        visSection.className = 'metadata-visibility';

        const visLabel = document.createElement('span');
        visLabel.className = 'metadata-vis-label';
        visLabel.textContent = 'Visibility';
        visSection.appendChild(visLabel);

        const seg = document.createElement('div');
        seg.className = 'segmented-control segmented-control-sm';
        for (const opt of [
            { key: 'plaintext', label: 'Public',    icon: '\u{1F513}' },
            { key: 'encrypted', label: 'Encrypted', icon: '\u{1F512}' },
        ]) {
            const btn = document.createElement('button');
            btn.className = m.mode === opt.key ? 'active' : '';
            btn.innerHTML = `${opt.icon} ${opt.label}`;
            btn.addEventListener('click', () => {
                m.mode = opt.key;
                if (opt.key === 'plaintext') m.recipients = [];
                render();
            });
            seg.appendChild(btn);
        }
        visSection.appendChild(seg);
        row.appendChild(visSection);

        // ── Encrypted: warning + recipient picker ──
        if (isEncrypted) {
            const encBlock = document.createElement('div');
            encBlock.className = 'metadata-enc-block';

            const warn = document.createElement('div');
            warn.className = 'metadata-enc-notice';
            warn.textContent = 'Only selected recipients will be able to read this field.';
            encBlock.appendChild(warn);

            // Recipient chips
            if (m.recipients.length > 0) {
                const chips = document.createElement('div');
                chips.className = 'metadata-enc-chips';
                for (let ri = 0; ri < m.recipients.length; ri++) {
                    const r = m.recipients[ri];
                    const chip = document.createElement('span');
                    chip.className = 'metadata-enc-chip';
                    chip.innerHTML = `${esc(r.displayName || r.email)} <button class="chip-remove">\u2715</button>`;
                    chip.querySelector('.chip-remove').addEventListener('click', () => {
                        m.recipients.splice(ri, 1);
                        render();
                    });
                    chips.appendChild(chip);
                }
                encBlock.appendChild(chips);
            }

            // Add recipient button
            const addRecip = document.createElement('button');
            addRecip.className = 'btn btn-secondary btn-sm';
            addRecip.textContent = '+ Add Recipient';
            addRecip.addEventListener('click', async () => {
                try {
                    const res = await Bridge.call('noble_storage', 'getContacts');
                    if (!alive) return;
                    const contacts = (res.contacts || []).filter(c => c.email || c.publicKey);
                    if (!contacts.length) {
                        showRecipientManualEntry(m);
                        return;
                    }
                    showRecipientPicker(contacts, m);
                } catch {
                    showRecipientManualEntry(m);
                }
            });
            encBlock.appendChild(addRecip);

            row.appendChild(encBlock);
        }

        return row;
    }

    function showRecipientPicker(contacts, metaEntry) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';

        const panel = document.createElement('div');
        panel.className = 'modal-panel';

        const title = document.createElement('h3');
        title.style.cssText = 'margin-bottom:var(--gap);font-size:var(--font-size-base);';
        title.textContent = 'Select Recipient';
        panel.appendChild(title);

        for (const c of contacts) {
            const already = metaEntry.recipients.some(r => r.email === c.email || r.publicKey === c.publicKey);
            const row = document.createElement('button');
            row.className = 'modal-list-item';
            if (already) row.classList.add('modal-list-item-disabled');
            row.innerHTML = `<span style="font-weight:500;">${esc(c.displayName || c.name || 'Unknown')}</span><span style="font-size:var(--font-size-xs);color:var(--text-secondary);">${esc(c.email || c.publicKey || '')}</span>`;
            if (!already) {
                row.addEventListener('click', () => {
                    metaEntry.recipients.push({
                        displayName: c.displayName || c.name || c.email,
                        email: c.email || '',
                        publicKey: c.publicKey || ''
                    });
                    overlay.remove();
                    render();
                });
            }
            panel.appendChild(row);
        }

        // Manual entry option
        const manualBtn = document.createElement('button');
        manualBtn.className = 'btn btn-secondary';
        manualBtn.textContent = 'Enter manually...';
        manualBtn.style.cssText = 'margin-top:var(--gap);width:100%;';
        manualBtn.addEventListener('click', () => {
            overlay.remove();
            showRecipientManualEntry(metaEntry);
        });
        panel.appendChild(manualBtn);

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = 'margin-top:var(--gap-xs);width:100%;';
        cancelBtn.addEventListener('click', () => overlay.remove());
        panel.appendChild(cancelBtn);

        overlay.appendChild(panel);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
        document.body.appendChild(overlay);
    }

    function showRecipientManualEntry(metaEntry) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';

        const panel = document.createElement('div');
        panel.className = 'modal-panel';

        const title = document.createElement('h3');
        title.style.cssText = 'margin-bottom:var(--gap);font-size:var(--font-size-base);';
        title.textContent = 'Add Recipient';
        panel.appendChild(title);

        const nameGroup = document.createElement('div');
        nameGroup.className = 'form-group';
        nameGroup.innerHTML = '<label>Name (optional)</label>';
        const nameInput = document.createElement('input');
        nameInput.className = 'form-input';
        nameInput.placeholder = 'Recipient name';
        nameGroup.appendChild(nameInput);
        panel.appendChild(nameGroup);

        const keyGroup = document.createElement('div');
        keyGroup.className = 'form-group';
        keyGroup.innerHTML = '<label>Public key or email</label>';
        const keyInput = document.createElement('input');
        keyInput.className = 'form-input';
        keyInput.placeholder = 'Public key hex or email address';
        keyGroup.appendChild(keyInput);
        panel.appendChild(keyGroup);

        const addBtn = document.createElement('button');
        addBtn.className = 'btn btn-primary';
        addBtn.textContent = 'Add';
        addBtn.style.cssText = 'margin-top:var(--gap);width:100%;';
        addBtn.addEventListener('click', () => {
            const val = keyInput.value.trim();
            if (!val) return;
            const isEmail = val.includes('@');
            metaEntry.recipients.push({
                displayName: nameInput.value.trim() || val,
                email: isEmail ? val : '',
                publicKey: isEmail ? '' : val
            });
            overlay.remove();
            render();
        });
        panel.appendChild(addBtn);

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = 'margin-top:var(--gap-xs);width:100%;';
        cancelBtn.addEventListener('click', () => overlay.remove());
        panel.appendChild(cancelBtn);

        overlay.appendChild(panel);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
        document.body.appendChild(overlay);
    }

    function renderAddFieldButton(container) {
        const wrapper = document.createElement('div');
        wrapper.style.position = 'relative';

        const addBtn = document.createElement('button');
        addBtn.className = 'btn btn-secondary';
        addBtn.innerHTML = '<span style="font-size:1.4rem;line-height:1;">+</span>';
        addBtn.title = 'Add metadata field';
        addBtn.style.cssText = 'width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto;';

        let dropdownOpen = false;

        addBtn.addEventListener('click', () => {
            dropdownOpen = !dropdownOpen;
            const existing = wrapper.querySelector('.metadata-dropdown');
            if (existing) { existing.remove(); dropdownOpen = false; return; }

            const dropdown = document.createElement('div');
            dropdown.className = 'metadata-dropdown';
            dropdown.style.cssText = 'position:absolute;top:56px;left:50%;transform:translateX(-50%);background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 4px 16px rgba(0,0,0,0.2);z-index:100;min-width:260px;max-height:320px;overflow-y:auto;';

            // Filter out already-added single-use fields (allow multiple url/signatures/custom)
            const multiUse = new Set(['url', 'signatures', 'custom']);
            const usedKeys = new Set(metadata.map(m => m.fieldKey));

            for (const field of METADATA_FIELDS) {
                if (usedKeys.has(field.key) && !multiUse.has(field.key)) continue;

                const item = document.createElement('button');
                item.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm);width:100%;padding:var(--gap-sm) var(--gap);border:none;background:none;color:var(--text-primary);font-size:var(--font-size-sm);cursor:pointer;text-align:left;';
                item.addEventListener('mouseenter', () => { item.style.background = 'var(--bg-tertiary)'; });
                item.addEventListener('mouseleave', () => { item.style.background = 'none'; });

                const icon = document.createElement('span');
                icon.style.cssText = 'font-size:1rem;width:20px;text-align:center;';
                icon.textContent = field.icon;
                item.appendChild(icon);

                const text = document.createElement('span');
                text.textContent = field.label;
                item.appendChild(text);

                item.addEventListener('click', () => {
                    metadata.push({
                        fieldKey: field.key,
                        key: field.customKey ? '' : field.key,
                        value: '',
                        mode: 'plaintext'
                    });
                    dropdownOpen = false;
                    render();
                });

                dropdown.appendChild(item);
            }

            // Close on outside click
            const closeHandler = (e) => {
                if (!wrapper.contains(e.target)) {
                    dropdown.remove();
                    dropdownOpen = false;
                    document.removeEventListener('click', closeHandler, true);
                }
            };
            setTimeout(() => document.addEventListener('click', closeHandler, true), 0);

            wrapper.appendChild(dropdown);
        });

        wrapper.appendChild(addBtn);
        container.appendChild(wrapper);
    }

    function showContactPicker(contacts, onSelect) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';

        const panel = document.createElement('div');
        panel.className = 'modal-panel';

        const title = document.createElement('h3');
        title.style.cssText = 'margin-bottom:var(--gap);font-size:var(--font-size-base);';
        title.textContent = 'Select Contact';
        panel.appendChild(title);

        for (const c of contacts) {
            const row = document.createElement('button');
            row.className = 'modal-list-item';
            row.innerHTML = `<span style="font-weight:500;">${esc(c.displayName)}</span><span style="font-size:var(--font-size-xs);color:var(--text-secondary);">${esc(c.email)}</span>`;
            row.addEventListener('click', () => {
                onSelect(c.email);
                overlay.remove();
            });
            panel.appendChild(row);
        }

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = 'margin-top:var(--gap);width:100%;';
        cancelBtn.addEventListener('click', () => overlay.remove());
        panel.appendChild(cancelBtn);

        overlay.appendChild(panel);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
        document.body.appendChild(overlay);
    }

    // ── Step 4: Fee ──

    function renderStepFee(container) {
        const desc = document.createElement('p');
        desc.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        desc.textContent = 'Select a fee level for your transactions.';
        container.appendChild(desc);

        if (!feeData) {
            const loading = document.createElement('p');
            loading.textContent = 'Loading fee estimates...';
            loading.style.color = 'var(--text-muted)';
            container.appendChild(loading);
            loadFees();
            return;
        }

        const options = document.createElement('div');
        options.className = 'fee-options';

        const levels = [
            { key: 'min', label: 'Minimum', value: feeData.minFee },
            { key: 'recommended', label: 'Recommended', value: feeData.recommendedFee },
            { key: 'high', label: 'High Priority', value: feeData.highPriorityFee },
        ];

        for (const l of levels) {
            const opt = document.createElement('div');
            opt.className = 'fee-option' + (feeLevel === l.key ? ' selected' : '');
            opt.innerHTML = `
                <div class="fee-label">${l.label}</div>
                <div class="fee-amount">\u25C6 ${formatAmount(l.value)}</div>
            `;
            opt.addEventListener('click', () => {
                feeLevel = l.key;
                render();
            });
            options.appendChild(opt);
        }
        container.appendChild(options);

        // Total
        const fee = getSelectedFee();
        const total = fee * files.length;
        const totalDiv = document.createElement('div');
        totalDiv.style.cssText = 'margin-top:var(--gap);text-align:center;';
        const feeChainId = state.chainId || '';
        totalDiv.innerHTML = `
            <div style="font-size:var(--font-size-sm);color:var(--text-muted)">Total (${files.length} document${files.length > 1 ? 's' : ''})</div>
            <div class="mono" style="font-size:var(--font-size-lg);font-weight:600">\u25C6 ${formatAmount(total)}</div>
            ${feeChainId ? `<div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">Chain: ${esc(feeChainId)}</div>` : ''}
        `;
        container.appendChild(totalDiv);

        // Balance check
        if (!balanceData && state.walletAddress) {
            loadBalance();
        }
        if (balanceData) {
            const available = balanceData.available || 0;
            const sufficient = available >= total;
            const balDiv = document.createElement('div');
            balDiv.style.cssText = 'margin-top:var(--gap-sm);text-align:center;';

            if (sufficient) {
                balDiv.innerHTML = `<div style="font-size:var(--font-size-xs);color:var(--text-muted)">Available balance: \u25C6 ${formatAmount(available)}</div>`;
            } else {
                balDiv.innerHTML = `
                    <div style="font-size:var(--font-size-sm);color:var(--error);margin-bottom:var(--gap-xs)">
                        Insufficient balance: \u25C6 ${formatAmount(available)} available
                    </div>
                    <div style="font-size:var(--font-size-xs);color:var(--text-secondary)">
                        You need \u25C6 ${formatAmount(total - available)} more. You can save this as a draft and submit later.
                    </div>
                `;
                const draftBtn = document.createElement('button');
                draftBtn.className = 'btn btn-secondary btn-sm';
                draftBtn.textContent = 'Save to Drafts';
                draftBtn.style.marginTop = 'var(--gap-sm)';
                draftBtn.addEventListener('click', () => saveDraft('Insufficient balance'));
                balDiv.appendChild(draftBtn);
            }
            container.appendChild(balDiv);
        }
    }

    async function loadFees() {
        try {
            feeData = await Bridge.call('noble_api', 'estimateFee');
            if (alive) render();
        } catch {
            feeData = { minFee: 1 * 300, recommendedFee: 2 * 300, highPriorityFee: 5 * 300 };
            if (alive) render();
        }
    }

    async function loadBalance() {
        if (!state.walletAddress) return;
        try {
            balanceData = await Bridge.call('noble_api', 'getBalance', { address: state.walletAddress });
            if (alive) render();
        } catch { /* best effort */ }
    }

    function getSelectedFee() {
        if (!feeData) return 2000;
        if (feeLevel === 'min') return feeData.minFee;
        if (feeLevel === 'high') return feeData.highPriorityFee;
        return feeData.recommendedFee;
    }

    // ── Step 5: Review ──

    function renderStepReview(container) {
        const warning = document.createElement('div');
        warning.className = 'warning-box';
        warning.setAttribute('role', 'alert');
        warning.textContent = '\u26A0\uFE0F Permanent \u2014 all public information (checksums, metadata, timestamps) cannot be removed from the blockchain once registered.';
        container.appendChild(warning);

        // Files summary
        const filesSection = document.createElement('div');
        filesSection.className = 'summary-section';
        filesSection.innerHTML = `<h3>Files (${files.length})</h3>`;
        const filesList = document.createElement('ul');
        filesList.className = 'file-list';
        for (const f of files) {
            const li = document.createElement('li');
            li.className = 'file-item';
            li.innerHTML = `<span class="file-name">${esc(f.name)}</span><span class="mono" style="font-size:var(--font-size-xs);color:var(--text-secondary)">${(hashes[f.path] || '').slice(0, 16)}\u2026</span>`;
            filesList.appendChild(li);
        }
        filesSection.appendChild(filesList);
        container.appendChild(filesSection);

        // Metadata summary
        const validMeta = metadata.filter(m => m.key && m.value);
        if (validMeta.length > 0) {
            const metaSection = document.createElement('div');
            metaSection.className = 'summary-section';
            metaSection.innerHTML = `<h3>Metadata (${validMeta.length} fields)</h3>`;
            const dl = document.createElement('dl');
            dl.className = 'detail-grid';
            for (const m of validMeta) {
                const fieldDef = METADATA_FIELDS.find(f => f.key === m.fieldKey);
                const label = fieldDef ? fieldDef.label : m.key;
                const encrypted = m.mode === 'encrypted' ? ' \u{1F512}' : '';
                dl.innerHTML += `<dt>${esc(label)}${encrypted}</dt><dd>${esc(m.value)}</dd>`;
            }
            metaSection.appendChild(dl);
            container.appendChild(metaSection);
        }

        // Version link
        if (previousChecksum) {
            const versionSection = document.createElement('div');
            versionSection.className = 'summary-section';
            versionSection.innerHTML = `<h3>Version Link</h3><div class="mono" style="font-size:var(--font-size-xs);word-break:break-all">${esc(previousChecksum)}</div>`;
            container.appendChild(versionSection);
        }

        // Fee summary
        const fee = getSelectedFee();
        const total = fee * files.length;
        const feeSection = document.createElement('div');
        feeSection.className = 'summary-section';
        feeSection.innerHTML = `<h3>Fee</h3><div class="mono">\u25C6 ${formatAmount(fee)} per document \u00D7 ${files.length} = \u25C6 ${formatAmount(total)} total</div>`;
        container.appendChild(feeSection);

        // Balance warning on review
        if (balanceData && (balanceData.available || 0) < total) {
            const balWarn = document.createElement('div');
            balWarn.className = 'warning-box';
            balWarn.style.cssText = 'color:var(--error);border-color:var(--error);margin-top:var(--gap);';
            balWarn.textContent = `Insufficient balance (\u25C6 ${formatAmount(balanceData.available || 0)} available). Go back to the Fee step to save as draft, or add funds first.`;
            container.appendChild(balWarn);
        }
    }

    // ── Step 6: Submit ──

    function renderStepSubmit(container) {
        const desc = document.createElement('p');
        desc.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        desc.textContent = 'Signing and submitting transactions...';
        container.appendChild(desc);

        const progress = document.createElement('div');
        progress.className = 'progress-bar';
        progress.style.marginBottom = 'var(--gap)';
        const fill = document.createElement('div');
        fill.className = 'progress-fill';
        fill.style.width = `${(results.length / files.length) * 100}%`;
        progress.appendChild(fill);
        container.appendChild(progress);

        const resultsContainer = document.createElement('div');
        container.appendChild(resultsContainer);

        // Render existing results
        for (const r of results) {
            resultsContainer.appendChild(buildReceipt(r));
        }

        if (results.length < files.length) {
            submitNext(resultsContainer, fill);
        } else {
            // Done — show summary
            const successes = results.filter(r => r.success).length;
            const failures = results.length - successes;
            const summary = document.createElement('div');
            summary.style.cssText = 'margin-top:var(--gap);text-align:center;';

            if (failures === 0) {
                summary.innerHTML = `
                    <div style="font-size:var(--font-size-lg);font-weight:600;color:var(--success)">
                        ${successes === 1 ? 'Document Submitted' : `All ${successes} Documents Submitted`}
                    </div>
                `;
            } else if (successes === 0) {
                summary.innerHTML = `
                    <div style="font-size:var(--font-size-lg);font-weight:600;color:var(--error)">
                        Submission Failed
                    </div>
                    <div style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-top:var(--gap-xs)">
                        ${failures === 1 ? 'The transaction was rejected.' : `All ${failures} transactions were rejected.`}
                        Check your balance and try again.
                    </div>
                `;
            } else {
                summary.innerHTML = `
                    <div style="font-size:var(--font-size-lg);font-weight:600;color:var(--warning)">
                        Partially Submitted
                    </div>
                    <div style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-top:var(--gap-xs)">
                        ${successes} succeeded, ${failures} failed.
                    </div>
                `;
            }
            container.appendChild(summary);

            // Offer to save failed documents as draft
            if (failures > 0) {
                const draftBtn = document.createElement('button');
                draftBtn.className = 'btn btn-secondary';
                draftBtn.textContent = 'Save Failed as Draft';
                draftBtn.style.cssText = 'margin-top:var(--gap-sm);';
                draftBtn.addEventListener('click', () => {
                    // Keep only the failed files in state
                    const failedHashes = new Set(results.filter(r => !r.success).map(r => r.hash));
                    files = files.filter(f => failedHashes.has(hashes[f.path]));
                    const newHashes = {};
                    for (const f of files) { newHashes[f.path] = hashes[f.path]; }
                    hashes = newHashes;
                    step = 0;
                    results = [];
                    saveDraft('Submission failed');
                });
                summary.appendChild(draftBtn);
            }

            const doneBtn = document.createElement('button');
            doneBtn.className = 'btn btn-primary btn-lg';
            doneBtn.textContent = 'Done';
            doneBtn.style.marginTop = 'var(--gap)';
            doneBtn.addEventListener('click', () => {
                resetWizard();
                render();
            });
            summary.appendChild(doneBtn);
        }
    }

    async function submitNext(resultsContainer, fill) {
        const idx = results.length;
        if (idx >= files.length || !alive) return;

        const f = files[idx];
        const hash = hashes[f.path];
        if (!hash || hash.startsWith('ERROR')) {
            results.push({ file: f.name, hash, success: false, error: 'Hash computation failed' });
            if (alive) render();
            return;
        }

        try {
            const fee = getSelectedFee();
            const validMeta = metadata.filter(m => m.key && m.value);
            const signResult = await Bridge.call('noble_crypto', 'signNotarization', {
                checksum: hash,
                fee,
                metadata: validMeta,
                previousChecksum: previousChecksum || undefined
            });
            if (!alive) return;

            const submitResult = await Bridge.call('noble_api', 'submitTransaction', {
                txHex: signResult.txHex
            });
            if (!alive) return;

            results.push({
                file: f.name,
                hash,
                success: submitResult.accepted,
                txId: submitResult.txId,
                error: submitResult.accepted ? null : 'Transaction rejected'
            });
        } catch (err) {
            results.push({ file: f.name, hash, success: false, error: err.message });
        }

        if (alive) render();
    }

    function buildReceipt(r) {
        const card = document.createElement('div');
        card.className = `receipt-card ${r.success ? 'receipt-success' : 'receipt-error'}`;
        card.innerHTML = `
            <div class="receipt-title">${r.success ? '\u2713' : '\u2717'} ${esc(r.file)}</div>
            <div class="receipt-hash">${esc(r.hash)}</div>
            ${r.txId ? `<div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">TX: ${r.txId.slice(0, 16)}\u2026</div>` : ''}
            ${r.error ? `<div style="font-size:var(--font-size-xs);color:var(--error);margin-top:var(--gap-xs)">${esc(r.error)}</div>` : ''}
        `;
        return card;
    }

    return {
        destroy() { alive = false; },
        refresh(newState) { Object.assign(state, newState); }
    };
}

