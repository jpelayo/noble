/**
 * NOBLE Dashboard — First-Run Setup Wizard
 * Multi-step onboarding: Welcome → Role → Identity → Rewards → Storage → Networking → Review
 */

import { createPassphraseForm, createMnemonicGrid, startAutoClearTimer, wipeInput, destroySecureElements } from '../wallet-security.js';

const STEPS = [
  { key: 'welcome',    label: 'Welcome'    },
  { key: 'role',       label: 'Role'       },
  { key: 'identity',   label: 'Identity'   },
  { key: 'rewards',    label: 'Rewards'    },
  { key: 'storage',    label: 'Storage'    },
  { key: 'networking', label: 'Network'    },
  { key: 'review',     label: 'Review'     },
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
    rewardAddress: '',     // Bitcoin or NOBLE address entered by user
    rewardAddressType: '', // e.g. 'P2WPKH', 'Ed25519'
    rewardSkipped: false,  // true when user chose to skip
    walletSkipped: false,  // true when user chose to skip wallet step
    dataDir: '',
    cacheSizeMb: 256,
    allocatedGb: 50,
    compression: true,
    p2pPort: 8780,
    seeds: '',
    maxPeers: 50,
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

    currentStep = Math.max(0, Math.min(step, STEPS.length - 1));
    renderProgress();
    backBtn.style.visibility = currentStep === 0 ? 'hidden' : 'visible';

    const isLast = currentStep === STEPS.length - 1;
    nextBtn.textContent = isLast ? 'Complete Setup' : 'Next';
    nextBtn.disabled = false;

    body.innerHTML = '';
    const stepKey = STEPS[currentStep].key;
    switch (stepKey) {
      case 'welcome':    renderWelcome(); break;
      case 'role':       renderRole(); break;
      case 'identity':   renderIdentity(); break;
      case 'rewards':    renderRewards(); break;
      case 'storage':    renderStorage(); break;
      case 'networking': renderNetworking(); break;
      case 'review':     renderReview(); break;
    }
  }

  backBtn.addEventListener('click', () => {
    goTo(currentStep - 1);
  });

  nextBtn.addEventListener('click', async () => {
    if (currentStep === STEPS.length - 1) {
      completeSetup();
    } else {
      collectStepData();
      if (!(await validateCurrentStep())) return;
      goTo(currentStep + 1);
    }
  });

  async function validateCurrentStep() {
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

    if (stepKey === 'rewards') {
      const addrInput = body.querySelector('#setup-reward-address');
      const addr = addrInput?.value?.trim() || '';

      // If the skip checkbox is checked, allow advancing without an address.
      const skipCheckbox = body.querySelector('#setup-reward-skip');
      if (skipCheckbox?.checked || state.rewardSkipped) {
        state.rewardSkipped = true;
        state.rewardAddress = '';
        return true;
      }

      if (!addr) {
        showRewardError('Please enter a Bitcoin address, or check "Skip" to configure later.');
        return false;
      }

      // Validate and save via RPC.
      nextBtn.disabled = true;
      nextBtn.textContent = 'Validating...';
      try {
        const result = await rpc.call('noble_setRewardAddress', { address: addr });
        state.rewardAddress = addr;
        state.rewardAddressType = result.address_type;
        state.rewardSkipped = false;
      } catch (e) {
        showRewardError('Invalid address: ' + (e.message || e));
        nextBtn.disabled = false;
        nextBtn.textContent = 'Next';
        return false;
      }
      nextBtn.disabled = false;
      nextBtn.textContent = 'Next';
      return true;
    }

    return true;
  }

  function showRewardError(msg) {
    let err = body.querySelector('#setup-reward-error');
    if (!err) {
      err = document.createElement('div');
      err.id = 'setup-reward-error';
      err.style.cssText =
        'color:var(--error);font-size:var(--font-size-sm);margin-top:var(--gap-sm)';
      body.appendChild(err);
    }
    err.style.display = 'block';
    err.textContent = msg;
  }

  function collectStepData() {
    const stepKey = STEPS[currentStep].key;
    switch (stepKey) {
      case 'welcome':
        state.nodeName = body.querySelector('#setup-node-name')?.value.trim() || '';
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
      case 'rewards': {
        const skipCb = body.querySelector('#setup-w-skip');
        state.walletSkipped = skipCb?.checked || false;
        break;
      }
      case 'storage': {
        state.dataDir = body.querySelector('#setup-data-dir')?.value?.trim() || '';
        const cache = parseInt(body.querySelector('#setup-cache-size')?.value, 10);
        if (!isNaN(cache) && cache > 0) state.cacheSizeMb = cache;
        const alloc = parseInt(body.querySelector('#setup-allocated-gb')?.value, 10);
        if (!isNaN(alloc) && alloc >= 0) state.allocatedGb = alloc;
        const comprCb = body.querySelector('#setup-compression');
        state.compression = comprCb ? comprCb.checked : true;
        break;
      }
      case 'networking': {
        const portSel = body.querySelector('#setup-p2p-port');
        if (portSel) state.p2pPort = parseInt(portSel.value, 10) || 8780;
        state.seeds = body.querySelector('#setup-seeds')?.value?.trim() || '';
        const maxP = parseInt(body.querySelector('#setup-max-peers')?.value, 10);
        if (!isNaN(maxP) && maxP > 0) state.maxPeers = maxP;
        break;
      }
    }
  }

  // ── Step 1: Welcome ──
  function renderWelcome() {
    // Setup token is handled transparently: the server injects
    // window.NOBLE_SETUP_TOKEN for localhost, and remote access is gated
    // by allowed_ips + TLS. No manual token field needed in the GUI.
    body.innerHTML = `
      <div style="text-align:center;padding:var(--gap-lg) 0 var(--gap)">
        <h2 style="margin-bottom:var(--gap-sm)">Welcome to NOBLE</h2>
        <p style="color:var(--text-secondary)">This wizard will configure your node identity and wallet.</p>
      </div>
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

  // ── Step 4: Rewards + Wallet ──

  let walletResult = null; // stores the last generate/import result for Review

  function renderRewards() {
    body.innerHTML = `
      <div style="text-align:center;margin-bottom:var(--gap-lg)">
        <h3 style="margin-bottom:var(--gap-xs)">Reward Address</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">
          Your node earns block rewards, the network subsidy payment to validators, and gateway fee splits.<br>
          Paste your Bitcoin address from any wallet to set the reward destination.
        </p>
      </div>

      <div class="form-group">
        <label for="setup-reward-address" style="font-weight:600">Bitcoin address or NOBLE public key</label>
        <input type="text" id="setup-reward-address" autocomplete="off" spellcheck="false"
          placeholder="bc1q..., 1..., bc1p..., or hex public key"
          value="${esc(state.rewardAddress)}"
          style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Accepts P2WPKH (bc1q...), P2PKH (1...), P2TR (bc1p...), or hex-encoded NOBLE public key.
          This address will receive 50% of transaction fees and the network subsidy payment to validators.
        </div>
      </div>

      <div id="setup-reward-result" style="display:none;margin-top:var(--gap-sm);padding:var(--gap-sm);
           background:color-mix(in srgb, var(--success) 10%, transparent);border:1px solid var(--success);
           border-radius:var(--radius-sm);font-size:var(--font-size-sm)"></div>

      <label style="display:flex;align-items:center;gap:var(--gap-sm);margin-top:var(--gap);cursor:pointer">
        <input type="checkbox" id="setup-reward-skip" ${state.rewardSkipped ? 'checked' : ''}>
        <span style="font-size:var(--font-size-sm);color:var(--text-muted)">
          Skip — configure later in Settings
        </span>
      </label>

      <div id="setup-reward-error" style="color:var(--error);font-size:var(--font-size-sm);margin-top:var(--gap-sm);display:none"></div>

      <!-- Wallet tool (ancillary) -->
      <hr style="border:none;border-top:1px solid var(--border);margin:var(--gap-lg) 0 var(--gap)">
      <div style="margin-bottom:var(--gap-sm)">
        <h4 style="margin:0 0 var(--gap-xs)">Wallet Tool</h4>
        <p style="font-size:var(--font-size-xs);color:var(--text-muted)">
          Don't have a wallet yet? Generate one here or import an existing mnemonic.
          This is an offline tool — nothing is saved to the node.
        </p>
      </div>

      <div style="display:flex;gap:var(--gap);flex-wrap:wrap;margin-bottom:var(--gap)">
        <button id="setup-w-generate" class="btn btn-primary btn-sm" style="padding:6px 14px">Generate New Wallet</button>
        <button id="setup-w-import" class="btn btn-secondary btn-sm" style="padding:6px 14px">Import from Mnemonic</button>
      </div>
      <div id="setup-w-generate-area"></div>
      <div id="setup-w-import-area"></div>
      <div id="setup-w-terminal-area"></div>

      <label style="display:flex;align-items:center;gap:var(--gap-sm);margin-top:var(--gap-sm);cursor:pointer">
        <input type="checkbox" id="setup-w-skip" ${state.walletSkipped ? 'checked' : ''}>
        <span style="font-size:var(--font-size-xs);color:var(--text-muted)">
          Skip — I already have a wallet or will set up later
        </span>
      </label>
    `;

    // ── Reward address logic ──
    const addrInput = body.querySelector('#setup-reward-address');
    const rewardSkipCb = body.querySelector('#setup-reward-skip');

    rewardSkipCb.addEventListener('change', () => {
      addrInput.disabled = rewardSkipCb.checked;
      addrInput.style.opacity = rewardSkipCb.checked ? '0.5' : '1';
      if (!rewardSkipCb.checked) addrInput.focus();
    });
    if (state.rewardSkipped) {
      addrInput.disabled = true;
      addrInput.style.opacity = '0.5';
    }

    // Prefill reward address from generated/imported wallet
    function prefillRewardAddress(result) {
      if (!result || !result.address) return;
      // Only prefill if the field is empty or still has the old value
      if (!addrInput.value.trim()) {
        addrInput.value = result.address;
        state.rewardAddress = result.address;
        // Uncheck the skip checkbox if it was checked
        if (rewardSkipCb.checked) {
          rewardSkipCb.checked = false;
          addrInput.disabled = false;
          addrInput.style.opacity = '1';
          state.rewardSkipped = false;
        }
        // Flash the input briefly to draw attention
        addrInput.style.borderColor = 'var(--success)';
        setTimeout(() => { addrInput.style.borderColor = ''; }, 2000);
      }
    }

    // ── Wallet tool logic ──
    const generateBtn = body.querySelector('#setup-w-generate');
    const importBtn = body.querySelector('#setup-w-import');
    const generateArea = body.querySelector('#setup-w-generate-area');
    const importArea = body.querySelector('#setup-w-import-area');
    const terminalArea = body.querySelector('#setup-w-terminal-area');
    let activeGenForm = null;
    let activeImpForm = null;
    let autoClear = null;

    function clearWalletAreas() {
      if (activeGenForm) { activeGenForm.destroy(); activeGenForm = null; }
      if (activeImpForm) { activeImpForm.destroy(); activeImpForm = null; }
      if (autoClear) { autoClear.stop(); autoClear = null; }
      generateArea.innerHTML = '';
      importArea.innerHTML = '';
      terminalArea.innerHTML = '';
    }

    generateBtn.addEventListener('click', () => {
      clearWalletAreas();
      activeGenForm = createPassphraseForm(generateArea, {
        submitLabel: 'Generate Wallet',
        onSubmit: async (passphrase) => {
          try {
            generateBtn.disabled = true;
            generateBtn.textContent = 'Generating...';
            const result = await rpc.call('noble_generateMnemonic', {
              word_count: 24,
              passphrase,
            });
            walletResult = result;
            if (activeGenForm) { activeGenForm.destroy(); activeGenForm = null; }
            generateArea.innerHTML = '';

            const header = document.createElement('div');
            header.style.cssText = 'font-weight:600;margin-bottom:var(--gap-sm);color:var(--warning)';
            header.textContent = 'Backup Your Mnemonic Phrase';
            generateArea.appendChild(header);

            const words = result.mnemonic.split(/\s+/);
            const gridEl = createMnemonicGrid(generateArea, words);

            const warning = document.createElement('div');
            warning.style.cssText = 'font-size:var(--font-size-xs);color:var(--error);margin-top:var(--gap-sm)';
            warning.textContent = 'Write these words down and store them securely. They cannot be recovered from the node.';
            generateArea.appendChild(warning);

            autoClear = startAutoClearTimer(generateArea, gridEl, 300_000);

            const termEl = document.createElement('div');
            termEl.className = 'terminal-output';
            termEl.innerHTML = formatSetupTerminal(result, false);
            terminalArea.innerHTML = '';
            terminalArea.appendChild(termEl);

            // Auto-fill reward address with the generated public key
            prefillRewardAddress(result);
          } catch (e) {
            const err = document.createElement('div');
            err.style.cssText = 'color:var(--error);font-size:var(--font-size-sm);margin-top:var(--gap-sm)';
            err.textContent = 'Failed to generate: ' + (e.message || e);
            generateArea.appendChild(err);
          } finally {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate New Wallet';
          }
        },
      });
    });

    importBtn.addEventListener('click', () => {
      clearWalletAreas();
      const wrapper = document.createElement('div');
      wrapper.style.cssText = 'padding:var(--gap);background:var(--bg-tertiary);border-radius:var(--radius);border:1px solid var(--border)';

      const label = document.createElement('label');
      label.style.cssText = 'font-size:var(--font-size-sm);font-weight:600;display:block;margin-bottom:var(--gap-sm)';
      label.textContent = 'Enter Mnemonic Phrase';
      wrapper.appendChild(label);

      const textarea = document.createElement('textarea');
      textarea.rows = 3;
      textarea.autocomplete = 'off';
      textarea.spellcheck = false;
      textarea.placeholder = 'Enter your 12 or 24 word mnemonic phrase...';
      textarea.style.cssText = 'width:100%;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);padding:var(--gap-sm);font-family:var(--font-mono);font-size:var(--font-size-sm);resize:vertical';
      wrapper.appendChild(textarea);

      const passArea = document.createElement('div');
      passArea.style.cssText = 'margin-top:var(--gap-sm)';
      wrapper.appendChild(passArea);

      const resultEl = document.createElement('div');
      resultEl.style.cssText = 'display:none;margin-top:var(--gap-sm);font-size:var(--font-size-sm)';
      wrapper.appendChild(resultEl);

      importArea.appendChild(wrapper);

      const passForm = createPassphraseForm(passArea, {
        submitLabel: 'Import',
        onSubmit: async (passphrase) => {
          const mWords = textarea.value.trim();
          if (!mWords) { resultEl.style.display = 'block'; resultEl.innerHTML = '<span style="color:var(--error)">Please enter your mnemonic phrase.</span>'; return; }
          try {
            const result = await rpc.call('noble_importMnemonic', { mnemonic: mWords, passphrase });
            walletResult = result;
            wipeInput(textarea);
            if (passForm) passForm.destroy();

            resultEl.style.display = 'block';
            resultEl.innerHTML = result.already_exists
              ? '<span style="color:var(--warning)">Key already exists.</span>'
              : '<span style="color:var(--success)">Key imported successfully.</span>';

            const termEl = document.createElement('div');
            termEl.className = 'terminal-output';
            termEl.innerHTML = formatSetupTerminal(result, false);
            terminalArea.innerHTML = '';
            terminalArea.appendChild(termEl);

            // Auto-fill reward address with the imported public key
            prefillRewardAddress(result);
          } catch (e) {
            resultEl.style.display = 'block';
            resultEl.innerHTML = `<span style="color:var(--error)">Import failed: ${e.message || e}</span>`;
          }
        },
      });

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn btn-secondary';
      cancelBtn.style.cssText = 'padding:6px 12px;margin-top:var(--gap-sm)';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.addEventListener('click', () => { wipeInput(textarea); clearWalletAreas(); });
      wrapper.appendChild(cancelBtn);

      activeImpForm = {
        destroy() { wipeInput(textarea); if (passForm) passForm.destroy(); wrapper.remove(); },
      };
    });

    cleanupFns.push(() => {
      clearWalletAreas();
      destroySecureElements(body);
    });
  }

  function formatSetupTerminal(result, showMnemonic) {
    const lines = [];
    lines.push('<span class="term-warn">WARNING: The information below grants full control of this</span>');
    lines.push('<span class="term-warn">wallet. Store it securely and NEVER share it.</span>');
    lines.push('');
    lines.push('<span class="term-heading">=== Noble Wallet ===</span>');
    lines.push('');

    if (showMnemonic && result.mnemonic) {
      const words = result.mnemonic.split(/\s+/);
      lines.push(`<span class="term-label">Mnemonic (${words.length} words):</span>`);
      for (let i = 0; i < words.length; i += 4) {
        const row = words.slice(i, i + 4)
          .map((w, j) => `${String(i + j + 1).padStart(3)}. ${w.padEnd(14)}`)
          .join('');
        lines.push(`<span class="term-value">${row}</span>`);
      }
      lines.push('');
    }

    lines.push(`<span class="term-label">Derivation Path:</span> <span class="term-value">m/44'/9999'/0'/0/0</span>`);
    if (result.private_key) lines.push(`<span class="term-label">Private Key:    </span> <span class="term-warn">${result.private_key}</span>`);
    if (result.public_key) lines.push(`<span class="term-label">Public Key:     </span> <span class="term-value">${result.public_key}</span>`);
    if (result.wire_hex) lines.push(`<span class="term-label">Wire Hex:       </span> <span class="term-value">${result.wire_hex}</span>`);
    lines.push(`<span class="term-label">Address:        </span> <span class="term-value">${result.address}</span>`);

    if (result.bitcoin_addresses && result.bitcoin_addresses.length > 0) {
      lines.push('');
      lines.push('<span class="term-label">Bitcoin Addresses:</span>');
      for (const ba of result.bitcoin_addresses) {
        const label = ba.address_type === 'p2pkh' ? 'P2PKH  (1...)' :
                      ba.address_type === 'p2wpkh' ? 'P2WPKH (bc1q)' :
                      ba.address_type === 'p2tr'   ? 'P2TR   (bc1p)' :
                      ba.address_type;
        lines.push(`  <span class="term-label">${label}:</span>  <span class="term-addr">${ba.address}</span>`);
      }
    }
    return lines.join('\n');
  }

  // ── Step 5: Storage ──
  function renderStorage() {
    const defaultDataDir = state.dataDir || '~/.noble/data';
    body.innerHTML = `
      <div style="text-align:center;margin-bottom:var(--gap-lg)">
        <h3 style="margin-bottom:var(--gap-xs)">Storage</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">
          Configure where the blockchain data is stored and cache settings.
        </p>
      </div>

      <div class="form-group">
        <label for="setup-data-dir" style="font-weight:600">Data Directory</label>
        <input type="text" id="setup-data-dir" autocomplete="off" spellcheck="false"
          placeholder="~/.noble/data"
          value="${esc(defaultDataDir)}"
          style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Path where blockchain data, keys, and state are stored.
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:var(--gap)">
        <div class="form-group">
          <label for="setup-allocated-gb" style="font-weight:600">Allocated Space (GB)</label>
          <input type="number" id="setup-allocated-gb" min="1" max="50000" step="1"
            value="${state.allocatedGb}"
            style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
          <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
            Max disk space for chain data. 0 = unlimited.
          </div>
        </div>
        <div class="form-group">
          <label for="setup-cache-size" style="font-weight:600">Cache Size (MB)</label>
          <input type="number" id="setup-cache-size" min="64" max="16384" step="64"
            value="${state.cacheSizeMb}"
            style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
          <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
            RocksDB block cache. More = faster reads.
          </div>
        </div>
        <div class="form-group">
          <label style="font-weight:600">&nbsp;</label>
          <label style="display:flex;align-items:center;gap:var(--gap-sm);cursor:pointer;margin-top:var(--gap-xs)">
            <input type="checkbox" id="setup-compression" ${state.compression ? 'checked' : ''}>
            <span style="font-size:var(--font-size-sm)">Enable Zstd compression</span>
          </label>
          <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
            Reduces disk usage ~40%, slight CPU overhead.
          </div>
        </div>
      </div>
    `;
  }

  // ── Step 6: Networking ──
  function renderNetworking() {
    body.innerHTML = `
      <div style="text-align:center;margin-bottom:var(--gap-lg)">
        <h3 style="margin-bottom:var(--gap-xs)">Networking</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">
          Configure P2P networking. Defaults work for most setups.
        </p>
      </div>

      <div class="form-group">
        <label for="setup-p2p-port" style="font-weight:600">P2P Port</label>
        <select id="setup-p2p-port" style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
          <option value="8780" ${state.p2pPort === 8780 ? 'selected' : ''}>8780 (default)</option>
          <option value="8781" ${state.p2pPort === 8781 ? 'selected' : ''}>8781</option>
          <option value="8782" ${state.p2pPort === 8782 ? 'selected' : ''}>8782</option>
        </select>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Open this port to the internet for peer connections.
        </div>
      </div>

      <div class="form-group">
        <label for="setup-seeds" style="font-weight:600">Seed Nodes</label>
        <input type="text" id="setup-seeds" autocomplete="off" spellcheck="false"
          placeholder="203.0.113.1, 198.51.100.2"
          value="${esc(state.seeds)}"
          style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Comma-separated IPs of seed peers. Leave empty for default bootstrap.
        </div>
      </div>

      <div class="form-group">
        <label for="setup-max-peers" style="font-weight:600">Max Peers</label>
        <input type="number" id="setup-max-peers" min="1" max="500" step="1"
          value="${state.maxPeers}"
          style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm);max-width:120px">
      </div>
    `;
  }

  // ── Step 7: Review ──
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
        <dt>Reward Address</dt><dd>${state.rewardAddress ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(state.rewardAddress)}</span>` : '(skipped)'}</dd>
        <dt>Wallet</dt><dd>${walletResult ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(walletResult.address)}</span>` : '(skipped)'}</dd>
        ${validatorRow}
        <dt>Data Dir</dt><dd><span class="mono" style="font-size:var(--font-size-xs)">${esc(state.dataDir || '~/.noble/data')}</span></dd>
        <dt>Cache</dt><dd>${state.cacheSizeMb} MB${state.compression ? ' + Zstd' : ''}</dd>
        <dt>P2P Port</dt><dd>${state.p2pPort}</dd>
        <dt>Max Peers</dt><dd>${state.maxPeers}</dd>
        <dt>Seeds</dt><dd>${state.seeds ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(state.seeds)}</span>` : '(default bootstrap)'}</dd>
      </dl>
      <div style="margin-top:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);border:1px solid var(--border)">
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0">
          TOTP and advanced settings can be configured in
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
          <p style="color:var(--text-muted);font-size:var(--font-size-sm);margin-top:var(--gap)">Click below when you are ready to continue.</p>
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
