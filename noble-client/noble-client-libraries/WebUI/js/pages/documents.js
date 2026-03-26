// NOBLE Document Client — Document Registration (7-step wizard)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { formatAmount } from '../components/amount-text.js';
import { emptyState } from '../components/empty-state.js';
import { esc, formatBytes } from '../utils.js';

const STEP_NAMES = ['Files', 'Metadata', 'Version', 'Locking', 'Fee', 'Review', 'Submit'];

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    // Wizard state
    let step = 0; // start directly on wizard step 0
    let files = [];
    let hashes = {};       // path → hash
    let previousChecksum = '';
    let isNewVersion = false;   // Yes/No toggle for version linking
    let versionMode = 'checksum'; // checksum | file | locator
    let versionFile = null;     // selected file for version lookup
    let wantsMetadata = false;
    let metadata = [];
    let selectedSigningKeyId = null; // default signing key for all signed fields
    let myCardKeys = [];             // signing keys from My Card
    let wantsLocking = false;
    let lockingPassword = '';
    let lockingPasswordConfirm = '';
    let feeLevel = 'recommended';
    let feeData = null;
    let feeError = null;
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
            wantsMetadata, metadata, selectedSigningKeyId, wantsLocking, feeLevel, step
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
        selectedSigningKeyId = d.selectedSigningKeyId || null;
        wantsLocking = d.wantsLocking || false;
        lockingPassword = '';
        lockingPasswordConfirm = '';
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
            editingDraftId = null;
            resetWizard();
            render();
        } catch {
            // Save failed — keep wizard state so user doesn't lose work
            alert('Could not save draft. Please try again.');
        }
    }

    function resetWizard() {
        step = 0;
        files = [];
        hashes = {};
        previousChecksum = '';
        isNewVersion = false;
        versionMode = 'checksum';
        versionFile = null;
        wantsMetadata = false;
        metadata = [];
        selectedSigningKeyId = null;
        myCardKeys = [];
        wantsLocking = false;
        lockingPassword = '';
        lockingPasswordConfirm = '';
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
            if (i <= step && i !== step) {
                dot.style.cursor = 'pointer';
                dot.addEventListener('click', () => { step = i; render(); });
            }
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

        // Page header on first step
        if (step === 0) {
            const header = document.createElement('div');
            header.className = 'page-header';
            header.innerHTML = '<h1>Register a document checksum in the blockchain</h1><p>The document itself is never uploaded to the blockchain.</p>';
            root.appendChild(header);
        }

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
            case 1: renderStepMetadata(content); break;
            case 2: renderStepVersion(content); break;
            case 3: renderStepLocking(content); break;
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
        if (step === 0) return files.length > 0 && Object.keys(hashes).length === files.length;
        if (step === 1) return true; // metadata optional
        if (step === 2) return true; // version optional
        if (step === 3) {            // locking: if enabled, passwords must match and be non-empty
            if (!wantsLocking) return true;
            return lockingPassword.length >= 8 && lockingPassword === lockingPasswordConfirm;
        }
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
                const hash = hashes[f.path];
                const hashDisplay = hash
                    ? (hash.startsWith('ERROR') ? `<span style="color:var(--error)">${esc(hash)}</span>` : `<span class="mono" style="font-size:var(--font-size-xs);color:var(--text-secondary)">\u2713 ${esc(hash)}</span>`)
                    : '<span style="color:var(--text-muted);font-size:var(--font-size-xs)">Computing...</span>';
                li.innerHTML = `
                    <div style="display:flex;align-items:center;gap:var(--gap-sm);flex:1;min-width:0">
                        <span class="file-name">${esc(f.name)}</span>
                        <span class="file-size">${formatBytes(f.size)}</span>
                    </div>
                    <div style="font-size:var(--font-size-xs);word-break:break-all">${hashDisplay}</div>
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

            // Auto-compute checksums for files that don't have one yet
            for (const f of files) {
                if (!hashes[f.path]) {
                    Bridge.call('noble_security', 'hashFile', { filePath: f.path }).then(result => {
                        if (!alive) return;
                        hashes[f.path] = result.hash;
                        render();
                    }).catch(err => {
                        if (!alive) return;
                        hashes[f.path] = 'ERROR: ' + (err.message || 'hash failed');
                        render();
                    });
                }
            }
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

    // Canonical metadata fields from metadata-types.md.
    // Each has a unique type code (T01-T13) used in the schema descriptor (slot 0).
    // Fields can be toggled between plaintext and encrypted by the user.
    // contact:* fields are forced encrypted — node rejects plaintext.
    const METADATA_FIELDS = [
        { key: 'doc:title',       code: 'T01', label: 'Document Title',    icon: '\u{1F4C4}', placeholder: 'e.g. Contract v2.1' },
        { key: 'doc:description', code: 'T02', label: 'Description',       icon: '\u{1F4DD}', placeholder: 'Brief description of the document' },
        { key: 'doc:batch',       code: 'T03', label: 'Batch Name',        icon: '\u{1F4C1}', placeholder: 'e.g. Q1 2026 Invoices' },
        { key: 'doc:url',         code: 'T04', label: 'URL',               icon: '\u{1F517}', placeholder: 'https://...' },
        { key: 'doc:bridge',      code: 'T05', label: 'Linked Document',   icon: '\u{1F4CE}', placeholder: 'Checksum, locator, or tx_id of linked document' },
        { key: 'doc:relation',    code: 'T06', label: 'Relation',          icon: '\u{1F4CB}', placeholder: 'e.g. amendment, annex, supersedes' },
        { key: 'author',          code: 'T07', label: 'Author',            icon: '\u{1F464}', placeholder: 'Document author or uploader name' },
        { key: 'publisher',       code: 'T08', label: 'Publisher',         icon: '\u{1F3E2}', placeholder: 'Distributing organization' },
        { key: 'signer:pubkey',   code: 'T09', label: 'Sender Public Key', icon: '\u{1F511}', placeholder: 'nbl1... or hex public key' },
        { key: 'contact:email',   code: 'T10', label: 'Email',             icon: '\u{2709}\uFE0F', placeholder: 'email@example.com', forceEncrypt: true },
        { key: 'contact:phone',   code: 'T11', label: 'Phone',             icon: '\u{1F4F1}', placeholder: '+1 555-0100', forceEncrypt: true },
        { key: 'custom',          code: 'T99', label: 'Custom Field',      icon: '\u{2795}', placeholder: 'Value', customKey: true },
    ];

    // Compute slot budget: schema(1) + fields + signature slots
    function computeSlotBudget() {
        const validMeta = metadata.filter(m => m.key && m.value);
        const sigCount = validMeta.filter(m => m.signed).length;
        const used = 1 + validMeta.length + sigCount; // schema + fields + sigs
        return { used, remaining: 16 - used };
    }

    // Load signing keys from My Card (cached for the session)
    async function loadMyCardKeys() {
        try {
            const res = await Bridge.call('noble_security', 'getMyCard');
            if (!alive) return;
            myCardKeys = (res.signingKeys || []).filter(k => k.hasPrivateKey);
            // Validate selectedSigningKeyId still exists (key may have been deleted)
            if (selectedSigningKeyId && !myCardKeys.some(k => k.id === selectedSigningKeyId)) {
                selectedSigningKeyId = null;
            }
            if (myCardKeys.length > 0 && !selectedSigningKeyId) {
                selectedSigningKeyId = myCardKeys[0].id;
            }
        } catch (e) {
            myCardKeys = [];
            console.warn('[Documents] signing keys unavailable:', e.message || e);
        }
    }

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
                if (wantsMetadata && myCardKeys.length === 0) loadMyCardKeys();
                render();
            });
            toggle.appendChild(btn);
        }
        container.appendChild(toggle);

        if (!wantsMetadata) return;

        // ── Signing key selector + slot budget ──
        const metaHeader = document.createElement('div');
        metaHeader.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap);flex-wrap:wrap';

        // Slot budget indicator
        const budget = computeSlotBudget();
        const budgetEl = document.createElement('span');
        budgetEl.style.cssText = 'font-size:var(--font-size-xs);padding:2px 8px;border-radius:var(--radius-sm)';
        const budgetColor = budget.remaining > 4 ? 'var(--success)' : budget.remaining > 1 ? 'var(--warning)' : 'var(--error)';
        budgetEl.style.background = `color-mix(in srgb, ${budgetColor} 12%, transparent)`;
        budgetEl.style.color = budgetColor;
        budgetEl.textContent = `${budget.used} / 16 slots`;
        metaHeader.appendChild(budgetEl);

        // Signing key dropdown (if keys available)
        if (myCardKeys.length > 0) {
            const keyLabel = document.createElement('span');
            keyLabel.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-left:auto';
            keyLabel.textContent = 'Sign with:';
            metaHeader.appendChild(keyLabel);

            const keySelect = document.createElement('select');
            keySelect.className = 'form-input';
            keySelect.style.cssText = 'width:auto;padding:2px 6px;font-size:var(--font-size-xs)';
            for (const k of myCardKeys) {
                const opt = document.createElement('option');
                opt.value = k.id;
                opt.textContent = k.label || k.certificateSubject || 'Key';
                if (k.id === selectedSigningKeyId) opt.selected = true;
                keySelect.appendChild(opt);
            }
            keySelect.addEventListener('change', () => { selectedSigningKeyId = keySelect.value; });
            metaHeader.appendChild(keySelect);
        }

        container.appendChild(metaHeader);

        // Existing fields
        if (metadata.length > 0) {
            const list = document.createElement('div');
            list.style.cssText = 'display:flex;flex-direction:column;gap:var(--gap-sm);margin-bottom:var(--gap);';
            for (let i = 0; i < metadata.length; i++) {
                list.appendChild(buildMetadataRow(i));
            }
            container.appendChild(list);
        }

        // Add button with dropdown (respect slot budget)
        const budget2 = computeSlotBudget();
        if (budget2.remaining > 1) { // need at least 1 field slot + potentially 1 sig slot
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
                } catch (e) { console.warn('[Documents] contact picker unavailable:', e.message || e); }
            });
            valRow.appendChild(pickBtn);
        }

        row.appendChild(valRow);

        // ── Visibility toggle: Public / Encrypted (segmented) ──
        // contact:* fields are forced encrypted — no public toggle allowed.
        if (fieldDef.forceEncrypt) {
            m.mode = 'encrypted';
        }

        const visSection = document.createElement('div');
        visSection.className = 'metadata-visibility';

        const visLabel = document.createElement('span');
        visLabel.className = 'metadata-vis-label';
        visLabel.textContent = 'Visibility';
        visSection.appendChild(visLabel);

        if (fieldDef.forceEncrypt) {
            const forceBadge = document.createElement('span');
            forceBadge.className = 'segmented-control segmented-control-sm';
            forceBadge.innerHTML = '<button class="active">\u{1F512} Encrypted (required)</button>';
            visSection.appendChild(forceBadge);
        } else {
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
        }
        row.appendChild(visSection);

        // ── Public warning ──
        if (!isEncrypted && !fieldDef.forceEncrypt) {
            const pubWarn = document.createElement('div');
            pubWarn.style.cssText = 'font-size:var(--font-size-xs);color:var(--warning);margin-top:var(--gap-xs);padding:4px 8px;background:color-mix(in srgb,var(--warning) 10%,transparent);border-radius:var(--radius-sm)';
            pubWarn.textContent = '\u26A0 Warning: By not encrypting this field, you are making this information public and available to anyone.';
            row.appendChild(pubWarn);
        }

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

        // ── Signing toggle: Unsigned / Signed ──
        if (!m.signed) m.signed = false;
        if (!m.signingKeyId) m.signingKeyId = selectedSigningKeyId;

        {
            const sigSection = document.createElement('div');
            sigSection.className = 'metadata-visibility';

            const sigLabel = document.createElement('span');
            sigLabel.className = 'metadata-vis-label';
            sigLabel.textContent = 'Signing';
            sigSection.appendChild(sigLabel);

            const budget = computeSlotBudget();
            const canSign = m.signed || budget.remaining >= 1;
            const hasKeys = myCardKeys.length > 0;

            const sigSeg = document.createElement('div');
            sigSeg.className = 'segmented-control segmented-control-sm';
            for (const opt of [
                { key: false, label: 'Unsigned' },
                { key: true, label: 'Signed' },
            ]) {
                const btn = document.createElement('button');
                btn.className = m.signed === opt.key ? 'active' : '';
                btn.textContent = opt.label;
                btn.addEventListener('click', () => {
                    if (opt.key === true && !hasKeys) {
                        // Show inline warning instead of silently doing nothing
                        let warn = row.querySelector('.sig-no-keys-warn');
                        if (!warn) {
                            warn = document.createElement('div');
                            warn.className = 'sig-no-keys-warn';
                            warn.style.cssText = 'font-size:var(--font-size-xs);color:var(--warning);margin-top:var(--gap-xs);padding:4px 8px;background:color-mix(in srgb,var(--warning) 10%,transparent);border-radius:var(--radius-sm)';
                            warn.textContent = 'No signing keys available. Import a .p12 certificate in Contacts \u2192 My Card first.';
                            row.appendChild(warn);
                        }
                        return;
                    }
                    if (opt.key === true && !canSign) return;
                    m.signed = opt.key;
                    if (!opt.key) m.signingKeyId = null;
                    else m.signingKeyId = selectedSigningKeyId;
                    render();
                });
                if (opt.key === true && !canSign && hasKeys) {
                    btn.disabled = true;
                    btn.title = 'No slots available for signature';
                }
                sigSeg.appendChild(btn);
            }
            sigSection.appendChild(sigSeg);
            row.appendChild(sigSection);

            if (m.signed && hasKeys) {
                const sigNote = document.createElement('div');
                sigNote.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs);padding:4px 8px';
                const keyName = myCardKeys.find(k => k.id === m.signingKeyId);
                sigNote.textContent = `CMS signature using ${keyName ? keyName.label || keyName.certificateSubject || 'key' : 'selected key'} (+1 slot)`;
                row.appendChild(sigNote);
            }
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
            const existing = document.querySelector('.metadata-dropdown');
            if (existing) { existing.remove(); dropdownOpen = false; return; }

            const dropdown = document.createElement('div');
            dropdown.className = 'metadata-dropdown';
            // Position fixed to avoid overflow clipping by parent containers
            const btnRect = addBtn.getBoundingClientRect();
            dropdown.style.position = 'fixed';
            dropdown.style.left = (btnRect.left + btnRect.width / 2) + 'px';
            dropdown.style.transform = 'translateX(-50%)';
            // Initially place below; will flip upward after measuring if it overflows
            dropdown.style.top = (btnRect.bottom + 4) + 'px';

            // All fields can be added multiple times (user may need several URLs, emails, etc.)
            for (const field of METADATA_FIELDS) {

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
                        mode: field.forceEncrypt ? 'encrypted' : 'plaintext',
                    });
                    dropdownOpen = false;
                    render();
                });

                dropdown.appendChild(item);
            }

            // Close on outside click
            const closeHandler = (e) => {
                if (!dropdown.contains(e.target) && !addBtn.contains(e.target)) {
                    dropdown.remove();
                    dropdownOpen = false;
                    document.removeEventListener('click', closeHandler, true);
                }
            };
            setTimeout(() => document.addEventListener('click', closeHandler, true), 0);

            document.body.appendChild(dropdown);

            // Position dropdown so it's fully visible and centered on the button.
            const ddRect = dropdown.getBoundingClientRect();
            const viewportH = window.innerHeight || document.documentElement.clientHeight;
            const ddHeight = ddRect.height;

            // Try below first
            if (btnRect.bottom + 4 + ddHeight <= viewportH) {
                // Fits below — keep default position
            } else if (btnRect.top - 4 - ddHeight >= 0) {
                // Fits above
                dropdown.style.top = (btnRect.top - ddHeight - 4) + 'px';
            } else {
                // Doesn't fit above or below — center vertically in viewport
                const top = Math.max(8, (viewportH - ddHeight) / 2);
                dropdown.style.top = top + 'px';
            }
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

    // ── Step 3: Locking ──

    function renderStepLocking(container) {
        const question = document.createElement('p');
        question.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        question.textContent = 'Do you want to lock (encrypt) this registration on-chain?';
        container.appendChild(question);

        const explain = document.createElement('p');
        explain.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)';
        explain.textContent = 'A locked transaction encrypts the checksum and all metadata with a password. The data remains hidden on-chain until you send an unlocking transaction with the same password. Only the original signer can unlock.';
        container.appendChild(explain);

        // Yes / No toggle
        const toggle = document.createElement('div');
        toggle.className = 'segmented-control';
        toggle.style.marginBottom = 'var(--gap)';
        for (const opt of [{ key: false, label: 'No' }, { key: true, label: 'Yes' }]) {
            const btn = document.createElement('button');
            btn.className = wantsLocking === opt.key ? 'active' : '';
            btn.textContent = opt.label;
            btn.addEventListener('click', () => {
                wantsLocking = opt.key;
                if (!wantsLocking) { lockingPassword = ''; lockingPasswordConfirm = ''; }
                render();
            });
            toggle.appendChild(btn);
        }
        container.appendChild(toggle);

        if (!wantsLocking) return;

        // Prompt to re-enter password when resuming a draft
        if (editingDraftId && !lockingPassword) {
            const notice = document.createElement('div');
            notice.style.cssText = 'padding:8px 12px;background:var(--bg-warning, #fef3c7);border:1px solid var(--border-warning, #f59e0b);border-radius:var(--radius-sm);color:var(--text-warning, #92400e);font-size:var(--font-size-xs);margin-bottom:var(--gap)';
            notice.textContent = 'Re-enter your encryption password to continue (passwords are not saved in drafts).';
            container.appendChild(notice);
        }

        // Password fields
        const pwGroup = document.createElement('div');
        pwGroup.style.cssText = 'display:flex;flex-direction:column;gap:var(--gap-sm);max-width:400px';

        const pw1Label = document.createElement('label');
        pw1Label.textContent = 'Locking password';
        pw1Label.style.cssText = 'font-size:var(--font-size-sm);font-weight:500';
        pwGroup.appendChild(pw1Label);

        function buildPasswordField(value, placeholder, onInput) {
            const wrap = document.createElement('div');
            wrap.style.cssText = 'position:relative;display:flex;align-items:center';
            const inp = document.createElement('input');
            inp.type = 'password';
            inp.className = 'form-input';
            inp.style.cssText = 'flex:1;padding-right:40px';
            inp.placeholder = placeholder;
            inp.value = value;
            inp.addEventListener('input', () => onInput(inp.value));
            wrap.appendChild(inp);
            const eye = document.createElement('button');
            eye.type = 'button';
            eye.style.cssText = 'position:absolute;right:8px;background:none;border:none;cursor:pointer;color:var(--text-muted);font-size:1.1rem;padding:2px';
            eye.textContent = '\u{1F441}';
            eye.title = 'Show password';
            eye.addEventListener('click', () => {
                const visible = inp.type === 'text';
                inp.type = visible ? 'password' : 'text';
                eye.textContent = visible ? '\u{1F441}' : '\u{1F441}\u{200D}\u{1F5E8}';
                eye.title = visible ? 'Show password' : 'Hide password';
            });
            wrap.appendChild(eye);
            return wrap;
        }

        pwGroup.appendChild(buildPasswordField(lockingPassword, 'Minimum 8 characters', v => { lockingPassword = v; render(); }));

        const pw2Label = document.createElement('label');
        pw2Label.textContent = 'Confirm password';
        pw2Label.style.cssText = 'font-size:var(--font-size-sm);font-weight:500;margin-top:var(--gap-xs)';
        pwGroup.appendChild(pw2Label);

        pwGroup.appendChild(buildPasswordField(lockingPasswordConfirm, 'Re-enter password', v => { lockingPasswordConfirm = v; render(); }));

        // Validation feedback
        if (lockingPassword.length > 0 && lockingPassword.length < 8) {
            const warn = document.createElement('div');
            warn.style.cssText = 'font-size:var(--font-size-xs);color:var(--warning)';
            warn.textContent = 'Password must be at least 8 characters.';
            pwGroup.appendChild(warn);
        } else if (lockingPassword.length >= 8 && lockingPasswordConfirm.length > 0 && lockingPassword !== lockingPasswordConfirm) {
            const warn = document.createElement('div');
            warn.style.cssText = 'font-size:var(--font-size-xs);color:var(--error)';
            warn.textContent = 'Passwords do not match.';
            pwGroup.appendChild(warn);
        } else if (lockingPassword.length >= 8 && lockingPassword === lockingPasswordConfirm) {
            const ok = document.createElement('div');
            ok.style.cssText = 'font-size:var(--font-size-xs);color:var(--success)';
            ok.textContent = '\u2713 Passwords match. This transaction will be encrypted on-chain.';
            pwGroup.appendChild(ok);
        }

        container.appendChild(pwGroup);

        // Warning box
        const warnBox = document.createElement('div');
        warnBox.className = 'warning-box';
        warnBox.style.marginTop = 'var(--gap)';
        warnBox.textContent = '\u26A0 If you lose this password, the locked data cannot be recovered. There is no password reset. Store it safely.';
        container.appendChild(warnBox);
    }

    // ── Step 4: Fee ──

    function renderStepFee(container) {
        const desc = document.createElement('p');
        desc.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        desc.textContent = 'Select a fee level for your transactions.';
        container.appendChild(desc);

        if (feeError) {
            const errEl = document.createElement('div');
            errEl.className = 'error-card';
            errEl.innerHTML = `<p>${feeError}. Please check your connection and try again.</p>`;
            container.appendChild(errEl);
            return;
        }
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

            const immature = balanceData.immature_value || 0;
            if (sufficient) {
                balDiv.innerHTML = `<div style="font-size:var(--font-size-xs);color:var(--text-muted)">Available balance: \u25C6 ${formatAmount(available)}</div>`;
            } else if (immature > 0 && (available + immature) >= total) {
                balDiv.innerHTML = `
                    <div style="font-size:var(--font-size-sm);color:var(--warning);margin-bottom:var(--gap-xs)">
                        Funds maturing: \u25C6 ${formatAmount(immature)} confirming
                    </div>
                    <div style="font-size:var(--font-size-xs);color:var(--text-secondary)">
                        Your funds will be available after ${3 - (balanceData.immature_count > 0 ? 1 : 0)} more block(s). Save as draft and submit later.
                    </div>
                `;
                const draftBtn2 = document.createElement('button');
                draftBtn2.className = 'btn btn-secondary btn-sm';
                draftBtn2.textContent = 'Save to Drafts';
                draftBtn2.style.marginTop = 'var(--gap-sm)';
                draftBtn2.addEventListener('click', () => saveDraft('Funds maturing'));
                balDiv.appendChild(draftBtn2);
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
            const f = await Bridge.call('noble_api', 'estimateFee');
            // Network-aware fee rates: always meet the highest known validator minimum.
            const netMin = f.networkMinFeeRate || f.network_min_fee_rate || 1;
            const netMedian = f.networkMedianFeeRate || f.network_median_fee_rate || 1;
            const localMin = f.localMinFeeRate || f.local_min_fee_rate || 1;
            const localLow = f.lowFeeRate || f.low_fee_rate || 1;
            const localRec = f.recommendedFeeRate || f.recommended_fee_rate || 2;
            const localHigh = f.highPriorityFeeRate || f.high_priority_fee_rate || 5;
            const minRate = Math.max(localLow, netMin, localMin);
            const recRate = Math.max(localRec, netMedian, netMin, localMin);
            const highRate = Math.max(localHigh, netMedian * 2, netMin, localMin);

            // Estimate real tx size using the C library (not hardcoded × 800)
            let txSize = 400; // fallback
            try {
                const validMeta = metadata.filter(m => m.key && m.value);
                const metaForEstimate = validMeta.map(m => ({ key: m.key, value: m.value }));
                const sizeResult = await Bridge.call('noble_crypto', 'estimateTxSize', {
                    tx_type: wantsLocking ? 'locked' : 'notarization',
                    checksum: hashes[files[0]?.path] || '00'.repeat(32),
                    metadata: metaForEstimate,
                });
                if (sizeResult && sizeResult.size) txSize = sizeResult.size;
            } catch { /* use fallback */ }

            // +2% safety margin to avoid mempool rejection from size variance
            const margin = Math.ceil(txSize * 0.02);
            const effectiveSize = txSize + margin;

            feeData = {
                minFee: minRate * effectiveSize,
                recommendedFee: recRate * effectiveSize,
                highPriorityFee: highRate * effectiveSize,
                minFeeRate: minRate,
                recommendedFeeRate: recRate,
                highPriorityFeeRate: highRate,
            };
            if (alive) render();
        } catch (err) {
            // Cannot estimate fees — do NOT proceed with hardcoded rates.
            feeError = `Could not estimate fees: ${err?.message || 'node unreachable'}`;
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

    function getSelectedFeeRate() {
        if (!feeData) return 2;
        if (feeLevel === 'min') return feeData.minFeeRate;
        if (feeLevel === 'high') return feeData.highPriorityFeeRate;
        return feeData.recommendedFeeRate;
    }

    // ── Step 5: Review ──

    function renderStepReview(container) {
        // Refresh signing keys to detect any added/removed since metadata step
        if (metadata.some(m => m.signed)) loadMyCardKeys();

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

            // ── Step 1: Sign fields BEFORE encryption (sign plaintext) ──
            // For each signed field, generate CMS detached signature over the plaintext value.
            const sigEntries = []; // { afterIndex, key, value }
            for (let i = 0; i < validMeta.length; i++) {
                const m = validMeta[i];
                if (!m.signed || !m.signingKeyId) continue;
                try {
                    const sigResult = await Bridge.call('noble_crypto', 'signMetadataField', {
                        keyId: m.signingKeyId,
                        fieldValue: m.value
                    });
                    if (!alive) return;
                    if (sigResult && sigResult.signatureHex) {
                        sigEntries.push({ afterIndex: i, sigHex: sigResult.signatureHex });
                    }
                } catch (sigErr) {
                    // CMS signing failed — abort submission for this file
                    results.push({
                        file: f.name, hash, success: false,
                        error: `CMS signing failed for field "${m.key}": ${sigErr.message}`
                    });
                    if (alive) render();
                    return;
                }
            }

            // ── Step 2: Build schema descriptor with SIG entries interleaved ──
            const schemaLines = [];
            let slotIndex = 1;
            const metaWithSigs = []; // final metadata array (fields + sig slots)
            for (let i = 0; i < validMeta.length; i++) {
                const m = validMeta[i];
                const def = METADATA_FIELDS.find(f => f.key === m.fieldKey) || { code: 'T99' };
                const vis = m.mode === 'encrypted' ? 'priv' : 'pub';
                schemaLines.push(`${slotIndex}:${def.code}:${vis}:${m.key}`);
                metaWithSigs.push(m);
                const fieldSlot = slotIndex;
                slotIndex++;

                // Insert signature slot immediately after the signed field
                const sigEntry = sigEntries.find(s => s.afterIndex === i);
                if (sigEntry) {
                    const sigKey = `sig:${fieldSlot}`;
                    schemaLines.push(`${slotIndex}:SIG:pub:${sigKey}`);
                    metaWithSigs.push({ key: sigKey, value: sigEntry.sigHex, mode: 'plaintext' });
                    slotIndex++;
                }
            }
            const schemaEntry = schemaLines.length > 0
                ? [{ key: 'schema', value: schemaLines.join('\n'), mode: 'plaintext' }]
                : [];

            // ── Step 3: Submit ──
            // NOTE: Metadata encryption (ECIES for mode:'encrypted' fields) is handled
            // by the native signNotarization handler. CMS sig slots use mode:'plaintext'
            // and are never encrypted.
            const allMeta = [...schemaEntry, ...metaWithSigs];

            // Fetch wallet UTXOs for coin selection — only use available UTXOs.
            const utxoResp = await Bridge.call('noble_api', 'getAddressUtxos', { address: state.walletAddress });
            const allUtxos = utxoResp.utxos || [];
            const utxos = allUtxos
                .filter(u => !u.status || u.status === 'available')
                .map(u => ({
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                }));

            if (utxos.length === 0 && allUtxos.length > 0) {
                const pending = allUtxos.filter(u => u.status === 'pending_spend').length;
                const immature = allUtxos.filter(u => u.status === 'immature').length;
                throw new Error(
                    `No spendable UTXOs available. ${pending ? pending + ' locked by pending transactions. ' : ''}${immature ? immature + ' immature outputs.' : ''}Wait for pending transactions to confirm.`
                );
            }

            const feeRate = getSelectedFeeRate();
            const signResult = await Bridge.call('noble_crypto', 'signNotarization', {
                checksum: hash,
                fee,
                fee_rate: feeRate,
                metadata: allMeta.map(m => ({ key: m.key, value: m.value, mode: m.mode || 'plaintext' })),
                utxos,
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

