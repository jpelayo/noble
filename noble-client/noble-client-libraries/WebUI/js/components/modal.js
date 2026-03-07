// Reusable modal container + wizard variant.

let _activeModal = null;

/** Open a simple modal. Returns { el, close }. */
export function openModal({ title, body, onClose }) {
    closeModal();

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';

    const panel = document.createElement('div');
    panel.className = 'modal-panel';

    // Header
    const header = document.createElement('div');
    header.className = 'modal-header';
    const h = document.createElement('span');
    h.textContent = title || '';
    const closeBtn = document.createElement('button');
    closeBtn.className = 'modal-close-btn';
    closeBtn.textContent = '\u2715';
    closeBtn.addEventListener('click', close);
    header.appendChild(h);
    header.appendChild(closeBtn);
    panel.appendChild(header);

    // Body
    const bodyEl = document.createElement('div');
    bodyEl.className = 'modal-body';
    if (typeof body === 'string') {
        bodyEl.innerHTML = body;
    } else if (body instanceof Node) {
        bodyEl.appendChild(body);
    }
    panel.appendChild(bodyEl);

    overlay.appendChild(panel);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    document.body.appendChild(overlay);

    // Trigger animation
    requestAnimationFrame(() => overlay.classList.add('visible'));

    _activeModal = { el: overlay, close };

    function close() {
        overlay.classList.remove('visible');
        setTimeout(() => { overlay.remove(); }, 200);
        if (onClose) onClose();
        if (_activeModal && _activeModal.el === overlay) _activeModal = null;
    }

    return { el: bodyEl, close };
}

/** Open a multi-step wizard modal. Returns { el, close }. */
export function openWizardModal({ title, steps, onComplete, onCancel }) {
    closeModal();
    let current = 0;

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';

    const panel = document.createElement('div');
    panel.className = 'modal-panel modal-panel-wizard';

    // Header
    const header = document.createElement('div');
    header.className = 'modal-header';
    const titleEl = document.createElement('span');
    titleEl.textContent = title || '';
    const closeBtn = document.createElement('button');
    closeBtn.className = 'modal-close-btn';
    closeBtn.textContent = '\u2715';
    closeBtn.addEventListener('click', close);
    header.appendChild(titleEl);
    header.appendChild(closeBtn);
    panel.appendChild(header);

    // Step indicators
    const indicators = document.createElement('div');
    indicators.className = 'wizard-steps';
    indicators.style.padding = 'var(--gap-sm) var(--gap)';
    panel.appendChild(indicators);

    // Body
    const bodyEl = document.createElement('div');
    bodyEl.className = 'modal-body';
    panel.appendChild(bodyEl);

    // Navigation
    const nav = document.createElement('div');
    nav.className = 'wizard-nav';
    nav.style.padding = '0 var(--gap) var(--gap)';
    panel.appendChild(nav);

    overlay.appendChild(panel);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('visible'));

    _activeModal = { el: overlay, close };

    renderStep();

    function renderStep() {
        // Indicators
        indicators.innerHTML = '';
        for (let i = 0; i < steps.length; i++) {
            const dot = document.createElement('div');
            dot.className = 'step-indicator' + (i === current ? ' active' : '') + (i < current ? ' completed' : '');
            dot.title = steps[i].label || `Step ${i + 1}`;
            indicators.appendChild(dot);
        }

        // Body
        bodyEl.innerHTML = '';
        const stepObj = steps[current];
        if (stepObj.render) stepObj.render(bodyEl);

        // Nav
        nav.innerHTML = '';
        const backBtn = document.createElement('button');
        backBtn.className = 'btn btn-secondary';
        backBtn.textContent = current === 0 ? 'Cancel' : 'Back';
        backBtn.addEventListener('click', () => {
            if (current === 0) { close(); return; }
            current--;
            renderStep();
        });

        const nextBtn = document.createElement('button');
        nextBtn.className = 'btn btn-primary';
        const isLast = current === steps.length - 1;
        nextBtn.textContent = isLast ? (stepObj.submitLabel || 'Submit') : 'Next';
        if (stepObj.canAdvance) nextBtn.disabled = !stepObj.canAdvance();

        nextBtn.addEventListener('click', async () => {
            if (stepObj.onNext) {
                nextBtn.disabled = true;
                nextBtn.textContent = 'Processing...';
                try {
                    const ok = await stepObj.onNext();
                    if (ok === false) { nextBtn.disabled = false; nextBtn.textContent = isLast ? 'Submit' : 'Next'; return; }
                } catch { nextBtn.disabled = false; nextBtn.textContent = isLast ? 'Submit' : 'Next'; return; }
            }
            if (isLast) {
                if (onComplete) onComplete();
            } else {
                current++;
                renderStep();
            }
        });

        nav.appendChild(backBtn);
        nav.appendChild(nextBtn);
    }

    function close() {
        overlay.classList.remove('visible');
        setTimeout(() => overlay.remove(), 200);
        if (onCancel) onCancel();
        if (_activeModal && _activeModal.el === overlay) _activeModal = null;
    }

    return { el: bodyEl, close, renderStep: () => renderStep() };
}

/** Close any active modal. */
export function closeModal() {
    if (_activeModal) {
        _activeModal.close();
        _activeModal = null;
    }
}
