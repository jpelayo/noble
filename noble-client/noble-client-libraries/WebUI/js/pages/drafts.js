// NOBLE Document Client — Drafts
import { Bridge } from '../bridge.js';
import { emptyState } from '../components/empty-state.js';
import { esc } from '../utils.js';

const STEP_NAMES = ['Files', 'Checksum', 'Metadata', 'Version', 'Fee', 'Review', 'Submit'];

export function init(root, ctx) {
    let alive = true;
    const state = ctx.state;
    let drafts = [];

    root.classList.add('page-content');
    loadDrafts();

    async function loadDrafts() {
        try {
            const res = await Bridge.call('noble_app', 'getDrafts');
            if (!alive) return;
            drafts = res.drafts || [];
        } catch { drafts = []; }
        render();
    }

    function render() {
        if (!alive) return;
        root.innerHTML = '';

        // Header with + New Draft button
        const header = document.createElement('div');
        header.className = 'page-header';
        header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;';

        const titleBlock = document.createElement('div');
        titleBlock.innerHTML = `<h1>Drafts</h1><p>Saved document registrations</p>`;
        header.appendChild(titleBlock);

        const addBtn = document.createElement('button');
        addBtn.className = 'btn btn-primary';
        addBtn.textContent = '+ New Draft';
        addBtn.addEventListener('click', async () => {
            const draft = {
                id: crypto.randomUUID(),
                name: 'Untitled',
                fileCount: 0,
                reason: null,
                createdAt: Date.now() / 1000,
                state: { files: [], hashes: {}, previousChecksum: '', isNewVersion: false, versionMode: 'checksum', wantsMetadata: false, metadata: [], feeLevel: 'recommended', step: 0 }
            };
            try { await Bridge.call('noble_app', 'saveDraft', { draft }); } catch {}
            await loadDrafts();
        });
        header.appendChild(addBtn);
        root.appendChild(header);

        if (drafts.length === 0) {
            root.appendChild(emptyState({
                icon: '\u{1F4DD}',
                title: 'No Drafts',
                subtitle: 'Drafts are created when you save an in-progress registration or when a submission fails.',
                cta: 'New Draft',
                onCta: () => addBtn.click()
            }));
            return;
        }

        for (const d of drafts) {
            root.appendChild(buildDraftCard(d));
        }
    }

    function buildDraftCard(d) {
        const card = document.createElement('div');
        card.className = 'panel';

        const body = document.createElement('div');
        body.className = 'panel-body';
        body.style.cssText = 'display:flex;align-items:center;gap:var(--gap);';

        // Icon
        const icon = document.createElement('span');
        icon.style.fontSize = '1.5rem';
        icon.textContent = '\u{1F4C4}';
        body.appendChild(icon);

        // Info
        const info = document.createElement('div');
        info.style.flex = '1';

        const name = document.createElement('div');
        name.style.cssText = 'font-weight:600;font-size:var(--font-size-sm);';
        name.textContent = d.name || 'Untitled';
        if (d.fileCount > 1) name.textContent += ` (+${d.fileCount - 1})`;
        info.appendChild(name);

        if (d.reason) {
            const reason = document.createElement('div');
            reason.style.cssText = 'font-size:var(--font-size-xs);color:var(--warning);margin-top:2px;';
            reason.textContent = d.reason;
            info.appendChild(reason);
        }

        const stepLabel = d.state && d.state.step >= 0 ? STEP_NAMES[d.state.step] : '';
        if (stepLabel) {
            const step = document.createElement('div');
            step.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px;';
            step.textContent = `Paused at: ${stepLabel}`;
            info.appendChild(step);
        }

        if (d.createdAt) {
            const date = document.createElement('div');
            date.style.cssText = 'font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px;';
            date.textContent = new Date(d.createdAt * 1000).toLocaleString();
            info.appendChild(date);
        }

        body.appendChild(info);

        // Action buttons
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:var(--gap-xs);align-items:center;';

        // Edit (Resume)
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-primary btn-sm';
        editBtn.textContent = 'Edit';
        editBtn.title = 'Resume editing this draft';
        editBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            Bridge.call('noble_app', 'navigateTo', { section: 'documents' });
        });
        actions.appendChild(editBtn);

        // Duplicate
        const dupBtn = document.createElement('button');
        dupBtn.className = 'btn btn-secondary btn-sm';
        dupBtn.textContent = '\u{2398}';
        dupBtn.title = 'Duplicate draft';
        dupBtn.style.cssText = 'min-height:auto;padding:4px 10px;font-size:1rem;';
        dupBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const clone = JSON.parse(JSON.stringify(d));
            clone.id = crypto.randomUUID();
            clone.name = (d.name || 'Untitled') + ' (copy)';
            clone.createdAt = Date.now() / 1000;
            clone.reason = null;
            try { await Bridge.call('noble_app', 'saveDraft', { draft: clone }); } catch {}
            await loadDrafts();
        });
        actions.appendChild(dupBtn);

        // Delete
        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-sm';
        delBtn.textContent = '\u{1F5D1}';
        delBtn.title = 'Delete draft';
        delBtn.style.cssText = 'color:var(--error);min-height:auto;padding:4px 10px;font-size:1rem;';
        delBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            try { await Bridge.call('noble_app', 'deleteDraft', { id: d.id }); } catch {}
            drafts = drafts.filter(x => x.id !== d.id);
            render();
        });
        actions.appendChild(delBtn);

        body.appendChild(actions);
        card.appendChild(body);
        return card;
    }

    return {
        destroy() { alive = false; },
        refresh(newState) { Object.assign(state, newState); }
    };
}
