// Reusable modal container + wizard variant.

const _modalStack = [];

function _trapFocus(container, closeFn) {
    const focusable = container.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    function handler(e) {
        if (e.key === 'Escape') { closeFn(); return; }
        if (e.key !== 'Tab') return;
        if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last?.focus(); }
        } else {
            if (document.activeElement === last) { e.preventDefault(); first?.focus(); }
        }
    }
    container.addEventListener('keydown', handler);
    first?.focus();
    return () => container.removeEventListener('keydown', handler);
}

/** Open a simple modal. Returns { el, close }. */
export function openModal({ title, body, onClose, stack = false }) {
    if (!stack) closeModal();

    const previousFocus = document.activeElement;

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';

    const panel = document.createElement('div');
    panel.className = 'modal-panel';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');

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

    const entry = { el: overlay, close, previousFocus };
    _modalStack.push(entry);

    // Focus trap
    let removeTrap = _trapFocus(panel, close);

    function close() {
        if (removeTrap) { removeTrap(); removeTrap = null; }
        overlay.classList.remove('visible');
        overlay.addEventListener('transitionend', () => overlay.remove(), { once: true });
        // Fallback in case transitionend doesn't fire
        setTimeout(() => { if (overlay.parentNode) overlay.remove(); }, 500);
        if (onClose) onClose();
        const idx = _modalStack.indexOf(entry);
        if (idx !== -1) _modalStack.splice(idx, 1);
        // Restore focus
        if (previousFocus && typeof previousFocus.focus === 'function') {
            previousFocus.focus();
        }
    }

    return { el: bodyEl, close };
}

/** Open a multi-step wizard modal. Returns { el, close }. */
export function openWizardModal({ title, steps, onComplete, onCancel, stack = false }) {
    if (!stack) closeModal();
    let current = 0;

    const previousFocus = document.activeElement;

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';

    const panel = document.createElement('div');
    panel.className = 'modal-panel modal-panel-wizard';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');

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

    const entry = { el: overlay, close, previousFocus };
    _modalStack.push(entry);

    let removeTrap = null;

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

        // Re-apply focus trap
        if (removeTrap) removeTrap();
        removeTrap = _trapFocus(panel, close);
    }

    function updateNav() {
        const stepObj = steps[current];
        const nextBtn = nav.querySelector('.btn-primary');
        if (nextBtn && stepObj.canAdvance) {
            nextBtn.disabled = !stepObj.canAdvance();
        }
    }

    function close() {
        if (removeTrap) { removeTrap(); removeTrap = null; }
        overlay.classList.remove('visible');
        overlay.addEventListener('transitionend', () => overlay.remove(), { once: true });
        setTimeout(() => { if (overlay.parentNode) overlay.remove(); }, 500);
        if (onCancel) onCancel();
        const idx = _modalStack.indexOf(entry);
        if (idx !== -1) _modalStack.splice(idx, 1);
        if (previousFocus && typeof previousFocus.focus === 'function') {
            previousFocus.focus();
        }
    }

    return { el: bodyEl, close, renderStep: () => renderStep(), updateNav: () => updateNav() };
}

/** Close any active modal (top of stack). */
export function closeModal() {
    if (_modalStack.length > 0) {
        const top = _modalStack[_modalStack.length - 1];
        top.close();
    }
}
