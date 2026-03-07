// NOBLE Document Client — Document Registration (7-step wizard)
import { Bridge } from '../bridge.js';
import { nobleCard } from '../components/noble-card.js';
import { hashText } from '../components/hash-text.js';
import { formatAmount } from '../components/amount-text.js';
import { emptyState } from '../components/empty-state.js';

const STEP_NAMES = ['Files', 'Checksum', 'Version', 'Metadata', 'Fee', 'Review', 'Submit'];

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;

    // Wizard state
    let step = -1; // -1 = landing page
    let files = [];
    let hashes = {};       // path → hash
    let previousChecksum = '';
    let metadata = [{ key: 'filename', value: '' }];
    let feeLevel = 'recommended';
    let feeData = null;
    let results = [];

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
        const header = document.createElement('div');
        header.className = 'page-header';
        header.innerHTML = '<h1>Documents</h1><p>Register documents on the NOBLE blockchain</p>';
        root.appendChild(header);

        const disabled = !state.isConnected || !state.hasWallet;
        root.appendChild(emptyState({
            icon: '\u{1F4C4}',
            title: 'Register a Document',
            subtitle: disabled
                ? 'Connect to a node and set up a wallet to register documents.'
                : 'Anchor the SHA-256 checksum of any file permanently on-chain.',
            cta: 'Register Document',
            disabled,
            onCta: () => { step = 0; render(); }
        }));
    }

    // ── Wizard Shell ──

    function renderWizard() {
        // Step indicators
        const indicators = document.createElement('div');
        indicators.className = 'wizard-steps';
        for (let i = 0; i < STEP_NAMES.length; i++) {
            const dot = document.createElement('div');
            dot.className = 'step-indicator' + (i === step ? ' active' : '') + (i < step ? ' completed' : '');
            dot.title = STEP_NAMES[i];
            indicators.appendChild(dot);
        }
        root.appendChild(indicators);

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
            case 2: renderStepVersion(content); break;
            case 3: renderStepMetadata(content); break;
            case 4: renderStepFee(content); break;
            case 5: renderStepReview(content); break;
            case 6: renderStepSubmit(content); break;
        }

        // Navigation (except submit step)
        if (step < 6) {
            const nav = document.createElement('div');
            nav.className = 'wizard-nav';

            const backBtn = document.createElement('button');
            backBtn.className = 'btn btn-secondary';
            backBtn.textContent = step === 0 ? 'Cancel' : 'Back';
            backBtn.addEventListener('click', () => {
                if (step === 0) { step = -1; } else { step--; }
                render();
            });

            const nextBtn = document.createElement('button');
            nextBtn.className = 'btn btn-primary';
            nextBtn.textContent = step === 5 ? 'Sign & Submit' : 'Next';
            nextBtn.disabled = !canAdvance();
            nextBtn.addEventListener('click', () => { step++; render(); });

            nav.appendChild(backBtn);
            nav.appendChild(nextBtn);
            root.appendChild(nav);
        }
    }

    function canAdvance() {
        if (step === 0) return files.length > 0;
        if (step === 1) return Object.keys(hashes).length === files.length;
        if (step === 2) return true; // optional
        if (step === 3) return true;
        if (step === 4) return feeData !== null;
        if (step === 5) return true;
        return false;
    }

    // ── Step 0: File Selection ──

    function renderStepFiles(container) {
        const zone = document.createElement('div');
        zone.className = 'drop-zone';
        zone.innerHTML = '<div style="font-size:2rem; margin-bottom:var(--gap-sm)">\u{1F4C1}</div><div>Click to select files</div><div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">Up to 100 files</div>';
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

    // ── Step 2: Version Link ──

    function renderStepVersion(container) {
        const desc = document.createElement('p');
        desc.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        desc.textContent = 'Optional: link this registration to a previous document version.';
        container.appendChild(desc);

        const group = document.createElement('div');
        group.className = 'form-group';
        group.innerHTML = `<label>Previous Checksum (64-char hex)</label>`;
        const input = document.createElement('input');
        input.className = 'form-input';
        input.type = 'text';
        input.maxLength = 64;
        input.placeholder = 'e.g. a1b2c3d4...';
        input.value = previousChecksum;
        input.addEventListener('input', () => {
            previousChecksum = input.value.trim();
        });
        group.appendChild(input);

        const hint = document.createElement('div');
        hint.className = 'form-hint';
        hint.textContent = 'Leave empty to skip version linking.';
        group.appendChild(hint);
        container.appendChild(group);

        if (previousChecksum.length === 64) {
            const lookupBtn = document.createElement('button');
            lookupBtn.className = 'btn btn-secondary btn-sm';
            lookupBtn.textContent = 'Look up on-chain';
            lookupBtn.addEventListener('click', async () => {
                lookupBtn.disabled = true;
                lookupBtn.textContent = 'Looking up...';
                try {
                    const r = await Bridge.call('noble_api', 'lookupChecksum', { checksum: previousChecksum });
                    if (!alive) return;
                    lookupBtn.textContent = r.found ? '\u2713 Found on-chain' : '\u2717 Not found';
                    lookupBtn.style.color = r.found ? 'var(--success)' : 'var(--error)';
                } catch {
                    lookupBtn.textContent = 'Lookup failed';
                }
            });
            container.appendChild(lookupBtn);
        }
    }

    // ── Step 3: Metadata ──

    function renderStepMetadata(container) {
        const desc = document.createElement('p');
        desc.style.cssText = 'font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)';
        desc.textContent = 'Add key-value metadata pairs (max 16). Applied to all documents in this batch.';
        container.appendChild(desc);

        // Auto-populate filename if only 1 file
        if (metadata.length === 1 && metadata[0].key === 'filename' && !metadata[0].value && files.length === 1) {
            metadata[0].value = files[0].name;
        }

        const rows = document.createElement('div');
        for (let i = 0; i < metadata.length; i++) {
            const row = document.createElement('div');
            row.className = 'metadata-row';

            const keyInput = document.createElement('input');
            keyInput.className = 'form-input';
            keyInput.placeholder = 'Key';
            keyInput.maxLength = 64;
            keyInput.value = metadata[i].key;
            keyInput.addEventListener('input', () => { metadata[i].key = keyInput.value; });

            const valInput = document.createElement('input');
            valInput.className = 'form-input';
            valInput.placeholder = 'Value';
            valInput.maxLength = 256;
            valInput.value = metadata[i].value;
            valInput.addEventListener('input', () => { metadata[i].value = valInput.value; });

            const rmBtn = document.createElement('button');
            rmBtn.className = 'btn btn-sm';
            rmBtn.textContent = '\u2715';
            rmBtn.style.color = 'var(--text-muted)';
            rmBtn.addEventListener('click', () => {
                metadata.splice(i, 1);
                render();
            });

            row.appendChild(keyInput);
            row.appendChild(valInput);
            row.appendChild(rmBtn);
            rows.appendChild(row);

            // Byte counters
            const counter = document.createElement('div');
            counter.className = 'metadata-counter';
            counter.style.gridColumn = '1 / -1';
            const keyBytes = new TextEncoder().encode(metadata[i].key).length;
            const valBytes = new TextEncoder().encode(metadata[i].value).length;
            counter.textContent = `Key: ${keyBytes}/64 bytes \u2022 Value: ${valBytes}/256 bytes`;
            if (keyBytes > 64 || valBytes > 256) counter.style.color = 'var(--error)';
            rows.appendChild(counter);
        }
        container.appendChild(rows);

        if (metadata.length < 16) {
            const addBtn = document.createElement('button');
            addBtn.className = 'btn btn-secondary btn-sm';
            addBtn.textContent = '+ Add Field';
            addBtn.style.marginTop = 'var(--gap-sm)';
            addBtn.addEventListener('click', () => {
                metadata.push({ key: '', value: '' });
                render();
            });
            container.appendChild(addBtn);
        }
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
        totalDiv.innerHTML = `
            <div style="font-size:var(--font-size-sm);color:var(--text-muted)">Total (${files.length} document${files.length > 1 ? 's' : ''})</div>
            <div class="mono" style="font-size:var(--font-size-lg);font-weight:600">\u25C6 ${formatAmount(total)}</div>
        `;
        container.appendChild(totalDiv);
    }

    async function loadFees() {
        try {
            feeData = await Bridge.call('noble_api', 'estimateFee');
            if (alive) render();
        } catch {
            feeData = { minFee: 1000, recommendedFee: 2000, highPriorityFee: 5000 };
            if (alive) render();
        }
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
        warning.textContent = '\u26A0\uFE0F Permanent \u2014 checksums cannot be removed from the blockchain once registered.';
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
                dl.innerHTML += `<dt>${esc(m.key)}</dt><dd>${esc(m.value)}</dd>`;
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
            summary.innerHTML = `
                <div style="font-size:var(--font-size-lg);font-weight:600;color:${failures === 0 ? 'var(--success)' : 'var(--warning)'}">
                    ${successes}/${results.length} Submitted Successfully
                </div>
            `;
            container.appendChild(summary);

            const doneBtn = document.createElement('button');
            doneBtn.className = 'btn btn-primary btn-lg';
            doneBtn.textContent = 'Done';
            doneBtn.style.marginTop = 'var(--gap)';
            doneBtn.addEventListener('click', () => {
                step = -1;
                files = [];
                hashes = {};
                previousChecksum = '';
                metadata = [{ key: 'filename', value: '' }];
                feeLevel = 'recommended';
                feeData = null;
                results = [];
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

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
