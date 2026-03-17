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

/** Create a slide-to-confirm element. User must drag thumb to the right to trigger onConfirm. */
function _createSlideConfirm(label, onConfirm) {
    const el = document.createElement('div');
    el.className = 'slide-confirm';

    const labelEl = document.createElement('div');
    labelEl.className = 'slide-confirm-label';
    labelEl.textContent = label;

    const thumb = document.createElement('div');
    thumb.className = 'slide-confirm-thumb';
    thumb.textContent = '\u276F'; // right-pointing angle bracket

    el.appendChild(labelEl);
    el.appendChild(thumb);

    const THUMB_SIZE = 42;
    const PAD = 3;
    let startX = 0;
    let thumbLeft = PAD;
    let confirmed = false;

    function getMaxLeft() { return el.offsetWidth - THUMB_SIZE - PAD; }

    function onPointerDown(e) {
        if (confirmed) return;
        e.preventDefault();
        startX = (e.touches ? e.touches[0].clientX : e.clientX) - thumbLeft;
        el.classList.add('dragging');
        document.addEventListener('pointermove', onPointerMove, { passive: false });
        document.addEventListener('pointerup', onPointerUp);
        document.addEventListener('touchmove', onTouchMove, { passive: false });
        document.addEventListener('touchend', onPointerUp);
    }

    function onPointerMove(e) {
        e.preventDefault();
        const x = (e.touches ? e.touches[0].clientX : e.clientX) - startX;
        const max = getMaxLeft();
        thumbLeft = Math.max(PAD, Math.min(x, max));
        thumb.style.left = thumbLeft + 'px';
        const pct = (thumbLeft - PAD) / (max - PAD);
        labelEl.style.opacity = String(1 - pct * 0.8);
    }

    function onTouchMove(e) {
        e.preventDefault();
        const x = e.touches[0].clientX - startX;
        const max = getMaxLeft();
        thumbLeft = Math.max(PAD, Math.min(x, max));
        thumb.style.left = thumbLeft + 'px';
        const pct = (thumbLeft - PAD) / (max - PAD);
        labelEl.style.opacity = String(1 - pct * 0.8);
    }

    function onPointerUp() {
        el.classList.remove('dragging');
        document.removeEventListener('pointermove', onPointerMove);
        document.removeEventListener('pointerup', onPointerUp);
        document.removeEventListener('touchmove', onTouchMove);
        document.removeEventListener('touchend', onPointerUp);

        const max = getMaxLeft();
        if (thumbLeft >= max * 0.85) {
            // Confirmed
            confirmed = true;
            thumbLeft = max;
            thumb.style.left = max + 'px';
            el.classList.add('confirmed');
            onConfirm();
        } else {
            // Snap back
            thumbLeft = PAD;
            thumb.style.left = PAD + 'px';
            labelEl.style.opacity = '1';
        }
    }

    thumb.addEventListener('pointerdown', onPointerDown);
    thumb.addEventListener('touchstart', onPointerDown, { passive: false });

    return el;
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
        backBtn.className = 'btn btn-secondary btn-sm';
        backBtn.textContent = current === 0 ? 'Cancel' : '\u2190 Back';
        backBtn.addEventListener('click', () => {
            if (current === 0) { close(); return; }
            current--;
            renderStep();
        });

        const isLast = current === steps.length - 1;

        async function advanceStep() {
            if (stepObj.onNext) {
                try {
                    const ok = await stepObj.onNext();
                    if (ok === false) return false;
                } catch { return false; }
            }
            if (isLast) {
                if (onComplete) onComplete();
            } else {
                current++;
                renderStep();
            }
            return true;
        }

        if (stepObj.slideConfirm) {
            // Slide-to-confirm button
            nav.style.flexDirection = 'column';
            nav.style.gap = 'var(--gap-sm)';

            const slider = _createSlideConfirm(
                stepObj.submitLabel || 'Slide to Confirm',
                async () => {
                    slider.classList.add('processing');
                    slider.querySelector('.slide-confirm-label').textContent = 'Processing...';
                    await advanceStep();
                }
            );
            if (stepObj.canAdvance && !stepObj.canAdvance()) {
                slider.style.opacity = '0.4';
                slider.style.pointerEvents = 'none';
            }

            const bottomRow = document.createElement('div');
            bottomRow.style.cssText = 'display:flex;justify-content:center';
            bottomRow.appendChild(backBtn);

            nav.appendChild(slider);
            nav.appendChild(bottomRow);
        } else {
            // Regular button
            nav.style.flexDirection = '';
            nav.style.gap = '';

            const nextBtn = document.createElement('button');
            nextBtn.className = 'btn btn-primary';
            nextBtn.textContent = stepObj.submitLabel || (isLast ? 'Submit' : 'Next');
            if (stepObj.canAdvance) nextBtn.disabled = !stepObj.canAdvance();

            nextBtn.addEventListener('click', async () => {
                nextBtn.disabled = true;
                const label = nextBtn.textContent;
                nextBtn.textContent = 'Processing...';
                const ok = await advanceStep();
                if (!ok) { nextBtn.disabled = false; nextBtn.textContent = label; }
            });

            nav.appendChild(backBtn);
            nav.appendChild(nextBtn);
        }

        // Re-apply focus trap
        if (removeTrap) removeTrap();
        removeTrap = _trapFocus(panel, close);
    }

    function updateNav() {
        const stepObj = steps[current];
        // Regular button
        const nextBtn = nav.querySelector('.btn-primary');
        if (nextBtn && stepObj.canAdvance) {
            nextBtn.disabled = !stepObj.canAdvance();
        }
        // Slide confirm
        const slider = nav.querySelector('.slide-confirm');
        if (slider && stepObj.canAdvance) {
            const enabled = stepObj.canAdvance();
            slider.style.opacity = enabled ? '1' : '0.4';
            slider.style.pointerEvents = enabled ? '' : 'none';
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
