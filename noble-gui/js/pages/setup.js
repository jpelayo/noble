/**
 * NOBLE Dashboard — First-Run Setup Wizard
 * Multi-step onboarding: Welcome → Role → Identity → Wallet → Review
 */

import {
  createPassphraseForm,
  createMnemonicGrid,
  startAutoClearTimer,
  createVerifyStep,
  wipeInput,
  destroySecureElements,
} from '../wallet-security.js';

const STEPS = [
  { key: 'welcome',  label: 'Welcome'  },
  { key: 'role',     label: 'Role'     },
  { key: 'identity', label: 'Identity' },
  { key: 'wallet',   label: 'Wallet'   },
  { key: 'review',   label: 'Review'   },
];


const NODE_ROLES = [
  { value: 'FullNode',       label: 'Full Node Observer',                role: 'FullNode',    validate: false, vote: false, desc: 'No consensus participation' },
  { value: 'Validator',      label: 'Full Node Validator',               role: 'Validator',   validate: true,  vote: true,  desc: 'Produces blocks and votes' },
  { value: 'BlockProducer',  label: 'Block Producer',                    role: 'Validator',   validate: true,  vote: false, desc: 'Produces blocks, no voting' },
  { value: 'VoterNode',      label: 'Voter Node',                        role: 'FullNode',    validate: false, vote: true,  desc: 'Votes on candidates only' },
  { value: 'ArchiveNode',    label: 'Archive Node',                      role: 'ArchiveNode', validate: false, vote: false, desc: 'Full history, no consensus' },
  { value: 'Gateway',        label: 'Gateway',                           role: 'Gateway',     validate: false, vote: false, desc: 'Transaction relay only' },
  { value: 'VotingGateway',  label: 'Voting Gateway',                    role: 'Gateway',     validate: false, vote: true,  desc: 'Transaction relay and votes' },
  { value: 'LightClient',    label: 'Light Client',                      role: 'LightClient', validate: false, vote: false, desc: 'Minimal, headers only' },
];

const ORG_TYPE_GROUPS = {
  individual: { label: 'Individual', types: ['Individual'] },
  private: {
    label: 'Private',
    types: ['PrivateNonProfit', 'PrivateCorporation', 'PrivateStartup', 'PrivateAcademic', 'PrivateInstitution'],
  },
  public: {
    label: 'Public',
    types: ['PublicNational', 'PublicRegional', 'PublicSupranational', 'PublicCorporation', 'PublicAcademic', 'PublicInstitution'],
  },
};

const ORG_TYPE_LABELS = {
  Individual:          'Individual',
  PrivateNonProfit:    'Fully privately funded non-profit institution or NGO',
  PrivateCorporation:  'Fully privately funded for-profit corporation',
  PrivateStartup:      'Fully privately funded for-profit startup',
  PrivateAcademic:     'Fully privately funded for-profit academic institution',
  PrivateInstitution:  'Fully privately funded for-profit institution',
  PublicNational:      'National public administration entity',
  PublicRegional:      'Regional or municipal public administration entity',
  PublicSupranational: 'Publicly funded supranational organization',
  PublicCorporation:   'Publicly funded corporation or startup',
  PublicAcademic:      'Publicly funded academic institution',
  PublicInstitution:   'Publicly funded institution or NGO',
};

function buildOrgTypeOptions(selected) {
  let html = '';
  for (const [, group] of Object.entries(ORG_TYPE_GROUPS)) {
    html += `<optgroup label="${group.label}">`;
    for (const id of group.types) {
      const sel = id === selected ? ' selected' : '';
      html += `<option value="${id}"${sel}>${ORG_TYPE_LABELS[id]}</option>`;
    }
    html += '</optgroup>';
  }
  return html;
}

export function init(root, ctx) {
  const { rpc } = ctx;
  let currentStep = 0;
  let cleanupFns = [];

  // Wizard state
  const state = {
    nodeName: '',
    roleValue: 'FullNode',
    orgType: 'Individual',
    orgName: '',
    contactEmail: '',
    website: '',
    walletPath: 'skip',  // 'create' | 'import' | 'skip'
    walletAddress: '',
    setupToken: '',  // raw setup token from node console (applied immediately for write RPCs)
  };

  // ── Shell ──
  root.innerHTML = `
    <div class="page-header">
      <h1>Node Setup</h1>
      <p>Configure your NOBLE node</p>
    </div>
    <div id="setup-progress" style="display:flex;gap:2px;margin-bottom:var(--gap-lg)"></div>
    <div class="panel">
      <div class="panel-body" id="setup-body"></div>
      <div class="panel-footer" style="display:flex;justify-content:space-between;padding:var(--gap-sm) var(--gap)">
        <button id="setup-back" class="btn btn-secondary btn-sm">Back</button>
        <button id="setup-next" class="btn btn-sm">Next</button>
      </div>
    </div>
  `;

  const progressBar = root.querySelector('#setup-progress');
  const body = root.querySelector('#setup-body');
  const backBtn = root.querySelector('#setup-back');
  const nextBtn = root.querySelector('#setup-next');

  function renderProgress() {
    progressBar.innerHTML = STEPS.map((s, i) => {
      const active = i === currentStep;
      const done = i < currentStep;
      const bg = active ? 'var(--accent)' : done ? 'var(--success)' : 'var(--bg-tertiary)';
      const color = (active || done) ? '#fff' : 'var(--text-muted)';
      return `<div style="flex:1;text-align:center;padding:var(--gap-xs);border-radius:var(--radius-sm);background:${bg};color:${color};font-size:var(--font-size-xs);font-weight:600;transition:all 0.2s">${s.label}</div>`;
    }).join('');
  }

  function goTo(step) {
    // Cleanup previous step
    cleanupFns.forEach(fn => { try { fn(); } catch {} });
    cleanupFns = [];
    destroySecureElements(body);

    currentStep = Math.max(0, Math.min(step, STEPS.length - 1));
    renderProgress();
    backBtn.style.visibility = currentStep === 0 ? 'hidden' : 'visible';

    const isLast = currentStep === STEPS.length - 1;
    nextBtn.textContent = isLast ? 'Complete Setup' : 'Next';

    body.innerHTML = '';
    const stepKey = STEPS[currentStep].key;
    switch (stepKey) {
      case 'welcome':  renderWelcome(); break;
      case 'role':     renderRole(); break;
      case 'identity': renderIdentity(); break;
      case 'wallet':   renderWallet(); break;
      case 'review':   renderReview(); break;
    }
  }

  backBtn.addEventListener('click', () => goTo(currentStep - 1));
  nextBtn.addEventListener('click', () => {
    if (currentStep === STEPS.length - 1) {
      completeSetup();
    } else {
      collectStepData();
      if (!validateCurrentStep()) return;
      goTo(currentStep + 1);
    }
  });

  function validateCurrentStep() {
    const stepKey = STEPS[currentStep].key;
    if (stepKey === 'welcome') {
      if (!state.nodeName.trim()) {
        const input = body.querySelector('#setup-node-name');
        if (input) {
          input.focus();
          input.style.borderColor = 'var(--error, #e55)';
          let err = body.querySelector('#setup-node-name-error');
          if (!err) {
            err = document.createElement('div');
            err.id = 'setup-node-name-error';
            err.style.cssText = 'font-size:var(--font-size-xs);color:var(--error,#e55);margin-top:var(--gap-xs)';
            input.parentElement.appendChild(err);
          }
          err.textContent = 'Node name is required.';
        }
        return false;
      }
    }
    return true;
  }

  function collectStepData() {
    const stepKey = STEPS[currentStep].key;
    switch (stepKey) {
      case 'welcome':
        state.nodeName = body.querySelector('#setup-node-name')?.value.trim() || '';
        state.setupToken = body.querySelector('#setup-token')?.value?.trim() || '';
        // Apply setup token immediately so wallet RPCs (write methods) in
        // Step 4 are authorized by the middleware before completeSetup().
        if (state.setupToken) rpc.setRawAuthToken(state.setupToken);
        break;
      case 'role':
        state.roleValue = body.querySelector('input[name="role"]:checked')?.value || state.roleValue;
        break;
      case 'identity': {
        const orgSel = body.querySelector('#setup-org-type');
        if (orgSel) state.orgType = orgSel.value;
        state.orgName = body.querySelector('#setup-org-name')?.value || '';
        state.contactEmail = body.querySelector('#setup-email')?.value || '';
        state.website = body.querySelector('#setup-website')?.value || '';
        break;
      }
    }
  }

  // ── Step 1: Welcome ──
  function renderWelcome() {
    // Issue 9: When NOBLE_SETUP_TOKEN was injected server-side, the token field
    // is not needed — the operator is already authorized via IP-filter + TLS.
    const tokenInjected = !!window.NOBLE_SETUP_TOKEN;
    const tokenField = tokenInjected ? '' : `
      <div class="form-group" style="margin-bottom:var(--gap-lg)">
        <label for="setup-token" style="display:flex;align-items:center;gap:var(--gap-sm)">
          Setup Token
          <span style="font-size:var(--font-size-xs);font-weight:400;color:var(--text-muted)">— required to save configuration</span>
        </label>
        <input type="text" id="setup-token" maxlength="128" placeholder="Paste token from node console output"
          value="${esc(state.setupToken)}" autocomplete="off" spellcheck="false"
          style="font-family:var(--font-mono,monospace);letter-spacing:0.03em">
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Copy the token printed in the node terminal at startup (under "SETUP MODE").
        </div>
      </div>`;
    body.innerHTML = `
      <div style="text-align:center;padding:var(--gap-lg) 0 var(--gap)">
        <h2 style="margin-bottom:var(--gap-sm)">Welcome to NOBLE</h2>
        <p style="color:var(--text-secondary)">This wizard will configure your node identity and wallet.</p>
      </div>
      ${tokenField}
      <div class="form-group">
        <label for="setup-node-name">Node Name</label>
        <input type="text" id="setup-node-name" maxlength="64" placeholder="e.g. my-noble-node"
          value="${esc(state.nodeName)}" autocomplete="off" spellcheck="false" required>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Required. A human-readable name for your node (max 64 characters).
        </div>
      </div>
    `;
  }

  // ── Step 2: Role ──
  function renderRole() {
    body.innerHTML = `
      <label style="font-size:var(--font-size-sm);font-weight:600;display:block;margin-bottom:var(--gap-sm);color:var(--text-secondary)">Node Role</label>
      <div id="setup-roles" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:var(--gap-sm)"></div>
    `;
    const rolesContainer = body.querySelector('#setup-roles');

    NODE_ROLES.forEach(r => {
      const checked = state.roleValue === r.value ? 'checked' : '';
      const card = document.createElement('label');
      card.style.cssText = 'padding:var(--gap-sm);background:var(--bg-tertiary);border:2px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;transition:border-color 0.15s;display:flex;gap:var(--gap-sm);align-items:flex-start';
      card.innerHTML = `
        <input type="radio" name="role" value="${r.value}" ${checked} style="margin-top:3px">
        <div>
          <div style="font-weight:600;font-size:var(--font-size-sm)">${r.label}</div>
          <div style="font-size:var(--font-size-xs);color:var(--text-muted)">${r.desc}</div>
        </div>
      `;
      const radio = card.querySelector('input');
      radio.addEventListener('change', () => {
        rolesContainer.querySelectorAll('label').forEach(l => l.style.borderColor = 'var(--border)');
        if (radio.checked) card.style.borderColor = 'var(--accent)';
      });
      if (checked) {
        card.style.borderColor = 'var(--accent)';
      }
      rolesContainer.appendChild(card);
    });
  }

  // ── Step 3: Identity ──
  function renderIdentity() {
    body.innerHTML = `
      <div class="form-group">
        <label for="setup-org-type">Organization Type</label>
        <select id="setup-org-type">${buildOrgTypeOptions(state.orgType)}</select>
      </div>
      <div class="form-group">
        <label for="setup-org-name">Organization Name (optional)</label>
        <input type="text" id="setup-org-name" maxlength="128" value="${esc(state.orgName)}" autocomplete="off">
      </div>
      <div class="form-group">
        <label for="setup-email">Contact Email (optional)</label>
        <input type="email" id="setup-email" value="${esc(state.contactEmail)}" autocomplete="off">
        <div class="form-hint" style="color:var(--warning)">This email will be broadcast publicly to all peers via GossipSub.</div>
      </div>
      <div class="form-group">
        <label for="setup-website">Website (optional)</label>
        <input type="url" id="setup-website" value="${esc(state.website)}" placeholder="https://..." autocomplete="off">
      </div>
    `;
  }

  // ── Step 4: Wallet ──
  function renderWallet() {
    body.innerHTML = `
      <div style="text-align:center;margin-bottom:var(--gap-lg)">
        <h3 style="margin-bottom:var(--gap-xs)">Wallet Setup</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">Create a new wallet, import an existing one, or skip for now.</p>
      </div>
      <div style="display:flex;gap:var(--gap);flex-wrap:wrap;justify-content:center;margin-bottom:var(--gap-lg)">
        <button id="setup-wallet-create" class="btn" style="padding:var(--gap-sm) var(--gap-lg)">Create New Wallet</button>
        <button id="setup-wallet-import" class="btn btn-secondary" style="padding:var(--gap-sm) var(--gap-lg)">Import Existing</button>
        <button id="setup-wallet-skip" class="btn btn-secondary" style="padding:var(--gap-sm) var(--gap-lg)">Skip</button>
      </div>
      <div id="setup-wallet-area"></div>
    `;

    const walletArea = body.querySelector('#setup-wallet-area');
    const createBtn = body.querySelector('#setup-wallet-create');
    const importBtnEl = body.querySelector('#setup-wallet-import');
    const skipBtn = body.querySelector('#setup-wallet-skip');

    skipBtn.addEventListener('click', () => {
      state.walletPath = 'skip';
      state.walletAddress = '';
      walletArea.innerHTML = '<div style="text-align:center;color:var(--text-muted);font-size:var(--font-size-sm)">Wallet setup skipped. You can set it up later from the Wallet page.</div>';
    });

    createBtn.addEventListener('click', () => {
      destroySecureElements(walletArea);
      walletArea.innerHTML = '';
      state.walletPath = 'create';

      const passContainer = document.createElement('div');
      walletArea.appendChild(passContainer);

      createPassphraseForm(passContainer, {
        submitLabel: 'Generate Mnemonic',
        onSubmit: async (passphrase) => {
          try {
            const result = await rpc.call('noble_generateMnemonic', {
              word_count: 24,
              passphrase,
            });
            destroySecureElements(walletArea);
            walletArea.innerHTML = '';

            state.walletAddress = result.address;

            // Show mnemonic
            const words = result.mnemonic.split(/\s+/);
            const header = document.createElement('div');
            header.style.cssText = 'font-weight:600;margin-bottom:var(--gap-sm);color:var(--warning)';
            header.textContent = 'Write Down Your 24-Word Recovery Phrase';
            walletArea.appendChild(header);

            const gridEl = createMnemonicGrid(walletArea, words);
            const timerHandle = startAutoClearTimer(walletArea, gridEl, 300_000);
            cleanupFns.push(() => timerHandle.stop());

            const warning = document.createElement('div');
            warning.style.cssText = 'font-size:var(--font-size-xs);color:var(--error);margin-top:var(--gap-sm)';
            warning.textContent = 'Write these words down. They CANNOT be recovered from the node.';
            walletArea.appendChild(warning);

            // "I've backed it up" button → verify step
            const continueBtn = document.createElement('button');
            continueBtn.className = 'btn';
            continueBtn.style.cssText = 'margin-top:var(--gap)';
            continueBtn.textContent = "I've backed it up \u2014 Continue to Verification";
            walletArea.appendChild(continueBtn);

            continueBtn.addEventListener('click', () => {
              walletArea.innerHTML = '';
              createVerifyStep(walletArea, words,
                () => {
                  walletArea.innerHTML = `
                    <div style="text-align:center;padding:var(--gap)">
                      <div style="font-size:2rem;color:var(--success);margin-bottom:var(--gap-sm)">&#10004;</div>
                      <h3 style="color:var(--success)">Wallet Created</h3>
                      <p class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-sm)">${result.address}</p>
                    </div>
                  `;
                },
                () => { /* fail — user retries via the verify UI */ }
              );
            });
          } catch (e) {
            walletArea.innerHTML = `<div style="color:var(--error);font-size:var(--font-size-sm)">Error: ${e.message || e}</div>`;
          }
        },
      });
    });

    importBtnEl.addEventListener('click', () => {
      destroySecureElements(walletArea);
      walletArea.innerHTML = '';
      state.walletPath = 'import';

      const textarea = document.createElement('textarea');
      textarea.rows = 3;
      textarea.autocomplete = 'off';
      textarea.spellcheck = false;
      textarea.placeholder = 'Enter your 12 or 24 word mnemonic phrase...';
      textarea.style.cssText = 'width:100%;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:var(--gap-sm);font-family:var(--font-mono);font-size:var(--font-size-sm);resize:vertical;margin-bottom:var(--gap-sm)';
      walletArea.appendChild(textarea);
      cleanupFns.push(() => wipeInput(textarea));

      const passContainer = document.createElement('div');
      walletArea.appendChild(passContainer);

      const resultEl = document.createElement('div');
      resultEl.style.cssText = 'margin-top:var(--gap-sm);font-size:var(--font-size-sm)';
      walletArea.appendChild(resultEl);

      createPassphraseForm(passContainer, {
        submitLabel: 'Import Wallet',
        onSubmit: async (passphrase) => {
          const words = textarea.value.trim();
          if (!words) { resultEl.innerHTML = '<span style="color:var(--error)">Please enter your mnemonic.</span>'; return; }
          try {
            const result = await rpc.call('noble_importMnemonic', { mnemonic: words, passphrase });
            wipeInput(textarea);
            destroySecureElements(passContainer);
            state.walletAddress = result.address;
            walletArea.innerHTML = `
              <div style="text-align:center;padding:var(--gap)">
                <div style="font-size:2rem;color:var(--success);margin-bottom:var(--gap-sm)">&#10004;</div>
                <h3 style="color:var(--success)">${result.already_exists ? 'Key Already Exists' : 'Wallet Imported'}</h3>
                <p class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-sm)">${result.address}</p>
              </div>
            `;
          } catch (e) {
            resultEl.innerHTML = `<span style="color:var(--error)">Import failed: ${e.message || e}</span>`;
          }
        },
      });
    });

    // Restore state
    if (state.walletAddress) {
      walletArea.innerHTML = `
        <div style="text-align:center;padding:var(--gap);color:var(--success)">
          <div style="font-size:2rem;margin-bottom:var(--gap-sm)">&#10004;</div>
          <h3>Wallet Configured</h3>
          <p class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-sm)">${state.walletAddress}</p>
        </div>
      `;
    }
  }

  // ── Step 5: Review ──
  function renderReview() {
    const roleObj = NODE_ROLES.find(r => r.value === state.roleValue) || NODE_ROLES[0];
    const validatorRow = roleObj.validate
      ? `<dt>Validator Key</dt><dd style="color:var(--text-muted);font-style:italic">Will be auto-generated on completion</dd>`
      : '';
    body.innerHTML = `
      <h3 style="margin-bottom:var(--gap)">Configuration Summary</h3>
      <dl class="detail-grid">
        <dt>Node Name</dt><dd>${esc(state.nodeName || '(not set)')}</dd>
        <dt>Role</dt><dd>${esc(roleObj.label)}</dd>
        <dt>Org Type</dt><dd>${esc(ORG_TYPE_LABELS[state.orgType] || state.orgType)}</dd>
        <dt>Org Name</dt><dd>${esc(state.orgName || '(not set)')}</dd>
        <dt>Contact Email</dt><dd>${esc(state.contactEmail || '(not set)')}</dd>
        <dt>Website</dt><dd>${esc(state.website || '(not set)')}</dd>
        <dt>Wallet</dt><dd>${state.walletAddress ? `<span class="mono" style="font-size:var(--font-size-xs)">${state.walletAddress.slice(0, 16)}...</span>` : '(skipped)'}</dd>
        ${validatorRow}
      </dl>
      <div style="margin-top:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);border:1px solid var(--border)">
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0">
          Network, storage, TOTP, and advanced settings can be configured in
          <code>noble.toml</code> before (re)starting the node.
        </p>
      </div>
      <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap)">
        Click a step in the progress bar above to go back and edit.
      </p>
    `;

    // Allow clicking progress steps to jump back
    const stepEls = progressBar.querySelectorAll('div');
    stepEls.forEach((el, i) => {
      if (i < currentStep) {
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => {
          collectStepData();
          goTo(i);
        });
      }
    });
  }

  // ── Complete setup ──
  async function completeSetup() {
    collectStepData();
    nextBtn.disabled = true;
    nextBtn.textContent = 'Completing...';

    try {
      const roleObj = NODE_ROLES.find(r => r.value === state.roleValue) || NODE_ROLES[0];
      const result = await rpc.call('noble_setNodeIdentity', {
        node_name: state.nodeName,
        org_type: state.orgType,
        org_name: state.orgName,
        node_role: roleObj.role,
        contact_email: state.contactEmail,
        website: state.website,
        host_address: '',
        wants_to_validate: roleObj.validate,
        wants_to_vote: roleObj.vote,
        p2p_port: 8780,
      });

      // Show validator pubkey if one was auto-generated.
      const validatorPubkey = result && result.validator_pubkey;
      const validatorSection = validatorPubkey ? `
        <div style="margin-top:var(--gap);padding:var(--gap-sm);background:color-mix(in srgb, var(--success) 10%, transparent);border:1px solid var(--success);border-radius:var(--radius-sm)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-xs)">Validator Key Generated</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-secondary);margin:0 0 var(--gap-xs)">
            Add this public key to <code>validators.txt</code> on every node in your network.
          </p>
          <div style="display:flex;align-items:center;gap:var(--gap-sm)">
            <code id="setup-vkey" style="font-size:var(--font-size-xs);word-break:break-all;flex:1">${esc(validatorPubkey)}</code>
            <button id="setup-copy-vkey" class="btn-sm" style="white-space:nowrap;padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>
          </div>
        </div>` : '';

      body.innerHTML = `
        <div style="text-align:center;padding:var(--gap-xl)">
          <div style="font-size:3rem;color:var(--success);margin-bottom:var(--gap)">&#10004;</div>
          <h2 style="color:var(--success);margin-bottom:var(--gap-sm)">Setup Complete!</h2>
          <p style="color:var(--text-secondary)">Your node identity has been saved.</p>
          ${validatorSection}
          <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);padding:var(--gap);margin-top:var(--gap);text-align:left;font-size:var(--font-size-sm)">
            <p style="margin-bottom:var(--gap-sm)"><strong>Next steps:</strong></p>
            <ol style="margin:0;padding-left:1.5em;color:var(--text-secondary)">
              <li>Edit <code>noble.toml</code> to set <code>allowed_ips</code> for persistent remote access</li>
              <li>Restart the node: <code>brew services restart noble</code></li>
            </ol>
          </div>
          <p style="color:var(--text-muted);font-size:var(--font-size-sm);margin-top:var(--gap)">Redirecting to dashboard in 5 seconds...</p>
          <a href="#/" class="btn" style="margin-top:var(--gap-lg);display:inline-block">Go to Dashboard</a>
        </div>
      `;

      // Wire copy button for validator pubkey.
      const copyVkeyBtn = body.querySelector('#setup-copy-vkey');
      if (copyVkeyBtn && validatorPubkey) {
        copyVkeyBtn.addEventListener('click', () => {
          navigator.clipboard?.writeText(validatorPubkey).catch(() => {});
          copyVkeyBtn.textContent = 'Copied!';
          setTimeout(() => { copyVkeyBtn.textContent = 'Copy'; }, 2000);
        });
      }
      backBtn.style.display = 'none';
      nextBtn.style.display = 'none';

      setTimeout(() => { location.hash = '#/'; }, 5000);
    } catch (e) {
      body.innerHTML += `<div style="color:var(--error);margin-top:var(--gap)">Setup error: ${e.message || e}</div>`;
      nextBtn.disabled = false;
      nextBtn.textContent = 'Complete Setup';
    } finally {
      // Always clear the raw setup token so it doesn't persist in memory.
      rpc.setRawAuthToken(null);
    }
  }

  // Issue 9: Auto-apply setup token when injected server-side (IP-gated + TLS).
  // If NOBLE_SETUP_TOKEN is present, the operator is already authenticated via
  // network access — no need to copy the token from the console.
  if (window.NOBLE_SETUP_TOKEN) {
    state.setupToken = window.NOBLE_SETUP_TOKEN;
    rpc.setRawAuthToken(window.NOBLE_SETUP_TOKEN);
  }

  // Start
  goTo(0);

  return {
    destroy() {
      cleanupFns.forEach(fn => { try { fn(); } catch {} });
      destroySecureElements(body);
      // Clear setup token from RPC client when navigating away from setup.
      rpc.setRawAuthToken(null);
    },
  };
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
