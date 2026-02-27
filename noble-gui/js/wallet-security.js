/**
 * wallet-security.js — Shared security utilities for wallet and setup wizard.
 *
 * Vanilla JS ES module (no npm, no build step).
 * Exports: createPassphraseForm, createMnemonicGrid, startAutoClearTimer,
 *          createVerifyStep, wipeInput, destroySecureElements.
 */

/* ── Helpers ── */

/** Securely wipes an input element's value. */
export function wipeInput(input) {
  if (!input) return;
  input.value = 'x'.repeat(input.value.length);
  input.value = '';
}

/** Finds and wipes all sensitive elements inside a container. */
export function destroySecureElements(container) {
  if (!container) return;

  const inputs = container.querySelectorAll('input[type="password"], textarea');
  inputs.forEach((el) => wipeInput(el));

  const grids = container.querySelectorAll('.mnemonic-grid');
  grids.forEach((g) => g.remove());

  // Clear any auto-clear timers attached to the container
  if (container._securityTimers) {
    container._securityTimers.forEach((id) => clearInterval(id));
    container._securityTimers = null;
  }
}

/* ── Passphrase Form ── */

/**
 * Creates an inline passphrase entry form with strength meter.
 *
 * @param {HTMLElement} container — Parent element to append the form into.
 * @param {Object}      options
 * @param {Function}    options.onSubmit    — Called with (passphrase) on valid submit.
 * @param {string}      options.submitLabel — Button text (default "Encrypt").
 * @returns {{ el: HTMLFormElement, destroy: () => void }}
 */
export function createPassphraseForm(container, options = {}) {
  const { onSubmit, submitLabel = 'Encrypt' } = options;

  const form = document.createElement('form');
  form.autocomplete = 'off';
  form.style.cssText = 'display:flex;flex-direction:column;gap:var(--gap-sm);';

  // ── Password input ──
  const pwInput = _makeSecureInput('Min 12 characters — letters, numbers, symbols');
  form.appendChild(_label('Encryption passphrase', pwInput));

  // ── Strength meter ──
  const meterOuter = document.createElement('div');
  meterOuter.style.cssText =
    'height:4px;width:100%;background:var(--bg-tertiary);border-radius:var(--radius-sm);overflow:hidden;';
  const meterInner = document.createElement('div');
  meterInner.style.cssText =
    'height:100%;width:0%;transition:width 0.25s ease, background 0.25s ease;border-radius:var(--radius-sm);';
  meterOuter.appendChild(meterInner);
  form.appendChild(meterOuter);

  const strengthText = document.createElement('span');
  strengthText.style.cssText =
    'font-size:var(--font-size-xs);color:var(--text-muted);min-height:1.2em;';
  form.appendChild(strengthText);

  pwInput.addEventListener('input', () => {
    const len = pwInput.value.length;
    if (len === 0) {
      meterInner.style.width = '0%';
      meterInner.style.background = 'transparent';
      strengthText.textContent = '';
    } else if (len < 12) {
      meterInner.style.width = '33%';
      meterInner.style.background = 'var(--error)';
      strengthText.textContent = 'Too short (min 12 characters)';
      strengthText.style.color = 'var(--error)';
    } else if (len < 16) {
      meterInner.style.width = '66%';
      meterInner.style.background = 'var(--warning)';
      strengthText.textContent = 'Fair';
      strengthText.style.color = 'var(--warning)';
    } else {
      meterInner.style.width = '100%';
      meterInner.style.background = 'var(--success)';
      strengthText.textContent = 'Strong';
      strengthText.style.color = 'var(--success)';
    }
  });

  // ── Confirm input ──
  const confirmInput = _makeSecureInput('Confirm passphrase...');
  form.appendChild(_label('Confirm passphrase', confirmInput));

  // ── Error text ──
  const errText = document.createElement('span');
  errText.style.cssText =
    'font-size:var(--font-size-xs);color:var(--error);min-height:1.2em;';
  form.appendChild(errText);

  // ── Submit button ──
  const btn = document.createElement('button');
  btn.type = 'submit';
  btn.textContent = submitLabel;
  btn.className = 'btn';
  btn.style.cssText = 'align-self:flex-start;';
  form.appendChild(btn);

  // ── Submit handler ──
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    errText.textContent = '';

    const pw = pwInput.value;
    const confirm = confirmInput.value;

    if (pw.length < 12) {
      errText.textContent = 'Passphrase must be at least 12 characters.';
      pwInput.focus();
      return;
    }
    if (pw !== confirm) {
      errText.textContent = 'Passphrases do not match.';
      confirmInput.focus();
      return;
    }

    if (typeof onSubmit === 'function') {
      onSubmit(pw);
    }
  });

  container.appendChild(form);

  return {
    el: form,
    destroy() {
      wipeInput(pwInput);
      wipeInput(confirmInput);
      form.remove();
    },
  };
}

/* ── Mnemonic Grid ── */

/**
 * Creates a numbered 6x4 CSS grid to display 24 mnemonic words.
 *
 * @param {HTMLElement}  container — Parent element.
 * @param {string[]}     words    — Array of 24 mnemonic words.
 * @returns {HTMLElement} The grid element.
 */
export function createMnemonicGrid(container, words) {
  const grid = document.createElement('div');
  grid.classList.add('mnemonic-grid');

  words.forEach((word, i) => {
    const cell = document.createElement('div');
    cell.classList.add('mnemonic-cell');
    cell.textContent = `${i + 1}. ${word}`;
    grid.appendChild(cell);
  });

  container.appendChild(grid);
  return grid;
}

/* ── Auto-Clear Timer ── */

/**
 * Starts a countdown that auto-clears the mnemonic grid after `durationMs`.
 *
 * @param {HTMLElement} container  — Parent for the countdown text.
 * @param {HTMLElement} gridEl    — The `.mnemonic-grid` element to clear.
 * @param {number}      durationMs — Countdown duration (default 300 000 = 5 min).
 * @returns {{ stop: () => void }}
 */
export function startAutoClearTimer(container, gridEl, durationMs = 300_000) {
  const countdownEl = document.createElement('div');
  countdownEl.style.cssText =
    'font-size:var(--font-size-xs);color:var(--text-muted);font-family:var(--font-mono);margin-top:var(--gap-xs);';
  container.appendChild(countdownEl);

  const start = Date.now();
  const end = start + durationMs;

  function _format(ms) {
    const totalSec = Math.max(0, Math.ceil(ms / 1000));
    const min = Math.floor(totalSec / 60);
    const sec = totalSec % 60;
    return `${min}:${String(sec).padStart(2, '0')}`;
  }

  function _tick() {
    const remaining = end - Date.now();
    if (remaining <= 0) {
      _clear();
      return;
    }
    countdownEl.textContent = `Auto-clearing in ${_format(remaining)}`;
  }

  function _clear() {
    clearInterval(intervalId);
    // Replace each word with masked dots
    if (gridEl) {
      const cells = gridEl.querySelectorAll('.mnemonic-cell');
      cells.forEach((cell) => {
        cell.textContent = '\u2022\u2022\u2022\u2022';
      });
    }
    countdownEl.textContent = 'Cleared.';
  }

  // Initial tick + interval
  _tick();
  const intervalId = setInterval(_tick, 1000);

  // Track timer on the container for destroySecureElements cleanup
  if (!container._securityTimers) container._securityTimers = [];
  container._securityTimers.push(intervalId);

  return {
    stop() {
      clearInterval(intervalId);
      countdownEl.remove();
    },
  };
}

/* ── Verify Step ── */

/**
 * Creates a verification step that asks the user to confirm 3 random words.
 *
 * @param {HTMLElement} container — Parent element.
 * @param {string[]}    words     — The full 24-word mnemonic array.
 * @param {Function}    onSuccess — Called when all 3 words match.
 * @param {Function}    onFail    — Called when verification fails.
 * @returns {{ el: HTMLElement, destroy: () => void }}
 */
export function createVerifyStep(container, words, onSuccess, onFail) {
  const wrapper = document.createElement('div');
  wrapper.style.cssText = 'display:flex;flex-direction:column;gap:var(--gap-sm);';

  const heading = document.createElement('p');
  heading.style.cssText =
    'font-size:var(--font-size-sm);color:var(--text-secondary);font-weight:600;';
  heading.textContent = 'Verify 3 words from your recovery phrase:';
  wrapper.appendChild(heading);

  // Pick 3 unique random indices
  const indices = _pickRandom3(words.length);

  const inputs = indices.map((idx) => {
    const group = document.createElement('div');
    group.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm);';

    const label = document.createElement('span');
    label.style.cssText =
      'font-size:var(--font-size-sm);color:var(--text-muted);font-family:var(--font-mono);min-width:70px;';
    label.textContent = `Word #${idx + 1}:`;

    const input = document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.style.cssText =
      'flex:1;padding:var(--gap-xs) var(--gap-sm);background:var(--bg-primary);' +
      'border:1px solid var(--border);border-radius:var(--radius-sm);' +
      'color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm);outline:none;';

    // Block paste
    input.addEventListener('paste', (e) => e.preventDefault());

    group.appendChild(label);
    group.appendChild(input);
    wrapper.appendChild(group);

    return { idx, input };
  });

  // ── Error text ──
  const errText = document.createElement('span');
  errText.style.cssText =
    'font-size:var(--font-size-xs);color:var(--error);min-height:1.2em;';
  wrapper.appendChild(errText);

  // ── Verify button ──
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = 'Verify';
  btn.className = 'btn';
  btn.style.cssText = 'align-self:flex-start;';
  wrapper.appendChild(btn);

  btn.addEventListener('click', () => {
    errText.textContent = '';
    const allCorrect = inputs.every(
      ({ idx, input }) =>
        input.value.trim().toLowerCase() === words[idx].toLowerCase()
    );

    if (allCorrect) {
      if (typeof onSuccess === 'function') onSuccess();
    } else {
      errText.textContent = 'One or more words are incorrect. Please try again.';
      if (typeof onFail === 'function') onFail();
    }
  });

  container.appendChild(wrapper);

  return {
    el: wrapper,
    destroy() {
      inputs.forEach(({ input }) => wipeInput(input));
      wrapper.remove();
    },
  };
}

/* ── Internal Helpers ── */

function _makeSecureInput(placeholder) {
  const input = document.createElement('input');
  input.type = 'password';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.placeholder = placeholder;
  input.style.cssText =
    'width:100%;padding:var(--gap-sm);background:var(--bg-primary);' +
    'border:1px solid var(--border);border-radius:var(--radius-sm);' +
    'color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm);outline:none;';
  return input;
}

function _label(text, inputEl) {
  const wrapper = document.createElement('div');
  const lbl = document.createElement('label');
  lbl.style.cssText =
    'display:block;font-size:var(--font-size-sm);font-weight:600;' +
    'margin-bottom:var(--gap-xs);color:var(--text-secondary);';
  lbl.textContent = text;
  wrapper.appendChild(lbl);
  wrapper.appendChild(inputEl);
  return wrapper;
}

function _pickRandom3(length) {
  const indices = new Set();
  while (indices.size < 3) {
    indices.add(Math.floor(Math.random() * length));
  }
  return [...indices].sort((a, b) => a - b);
}
