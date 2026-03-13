/**
 * NOBLE Dashboard — First-Run Setup Wizard
 * Multi-step onboarding: Welcome → Role → Identity → Rewards → Storage → Encryption → Networking → Review
 */

import { createMnemonicGrid, startAutoClearTimer, wipeInput, destroySecureElements } from '../wallet-security.js';
import { countrySelectHtml } from '../countries.js';

const STEPS = [
  { key: 'welcome',    label: 'Welcome'    },
  { key: 'role',       label: 'Role'       },
  { key: 'identity',   label: 'Identity'   },
  { key: 'rewards',    label: 'Rewards'    },
  { key: 'storage',    label: 'Storage'    },
  { key: 'encryption', label: 'Encryption' },
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
    countryCode: '',
    rewardAddress: '',     // Bitcoin or NOBLE address entered by user
    rewardAddressType: '', // e.g. 'P2WPKH', 'Ed25519'
    rewardSkipped: false,  // true when user chose to skip
    walletSkipped: false,  // true when user chose to skip wallet step
    p2pPort: 8780,
    seeds: 'node.infinitecontext.com',
    maxPeers: 50,
    // Storage
    dataDir: '',
    allocatedGb: 50,
    cacheSizeMb: 512,
    compression: true,
    pruningMode: 'archive',
    keepBlocks: 0,
    dataDirValid: null,   // null=unchecked, true/false
    dataDirError: '',
    diskAvailable: 0,
    volumes: [],          // additional volume paths [{path: string}]
    // Encryption
    encryptionMode: 'automatic',
    encryptionPassword: '',
    encryptionConfirm: '',
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
      case 'encryption': renderEncryption(); break;
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
      const skipCheckbox = body.querySelector('#setup-skip-rewards');
      if (skipCheckbox?.checked || state.rewardSkipped) {
        state.rewardSkipped = true;
        state.walletSkipped = true;
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

    if (stepKey === 'encryption') {
      if (state.encryptionMode === 'manual') {
        const pw = body.querySelector('#setup-enc-password')?.value || '';
        const cf = body.querySelector('#setup-enc-confirm')?.value || '';
        if (pw.length < 8) {
          showStepError('setup-enc-error', 'Password must be at least 8 characters.');
          return false;
        }
        if (pw !== cf) {
          showStepError('setup-enc-error', 'Passwords do not match.');
          return false;
        }
      }
    }

    return true;
  }

  function showStepError(id, msg) {
    let err = body.querySelector('#' + id);
    if (!err) {
      err = document.createElement('div');
      err.id = id;
      err.style.cssText = 'color:var(--error);font-size:var(--font-size-sm);margin-top:var(--gap-sm)';
      body.appendChild(err);
    }
    err.style.display = 'block';
    err.textContent = msg;
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
        state.countryCode = (body.querySelector('#setup-country')?.value || '').trim().toUpperCase();
        break;
      }
      case 'rewards': {
        const skipCb = body.querySelector('#setup-skip-rewards');
        if (skipCb?.checked) {
          state.rewardSkipped = true;
          state.walletSkipped = true;
        }
        break;
      }
      case 'storage': {
        state.dataDir = body.querySelector('#setup-data-dir')?.value?.trim() || '';
        const alloc = parseInt(body.querySelector('#setup-allocated-gb')?.value, 10);
        if (!isNaN(alloc) && alloc >= 1) state.allocatedGb = alloc;
        const cache = parseInt(body.querySelector('#setup-cache-size')?.value, 10);
        if (!isNaN(cache) && cache >= 64) state.cacheSizeMb = cache;
        const compCb = body.querySelector('#setup-compression');
        if (compCb) state.compression = compCb.checked;
        const pruneEl = body.querySelector('input[name="pruning"]:checked');
        if (pruneEl) state.pruningMode = pruneEl.value;
        const keepEl = body.querySelector('#setup-keep-blocks');
        if (keepEl) {
          const kb = parseInt(keepEl.value, 10);
          if (!isNaN(kb) && kb >= 0) state.keepBlocks = kb;
        }
        break;
      }
      case 'encryption': {
        const modeEl = body.querySelector('input[name="enc-mode"]:checked');
        if (modeEl) state.encryptionMode = modeEl.value;
        if (state.encryptionMode === 'manual') {
          state.encryptionPassword = body.querySelector('#setup-enc-password')?.value || '';
          state.encryptionConfirm = body.querySelector('#setup-enc-confirm')?.value || '';
        } else {
          state.encryptionPassword = '';
          state.encryptionConfirm = '';
        }
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
      <div class="form-group">
        <label for="setup-country">Country (optional)</label>
        ${countrySelectHtml('setup-country', state.countryCode)}
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

      <div id="setup-w-buttons" style="display:flex;gap:var(--gap);flex-wrap:wrap;margin-bottom:var(--gap)">
        <button id="setup-w-generate" class="btn btn-primary btn-sm" style="padding:6px 14px">Generate New Wallet</button>
        <button id="setup-w-import" class="btn btn-secondary btn-sm" style="padding:6px 14px">Import from Mnemonic</button>
      </div>
      <div id="setup-w-generate-area"></div>
      <div id="setup-w-import-area"></div>
      <div id="setup-w-terminal-area"></div>

      <hr style="border:none;border-top:1px solid var(--border);margin:var(--gap) 0 var(--gap-sm)">
      <label style="display:flex;align-items:center;gap:var(--gap-sm);cursor:pointer">
        <input type="checkbox" id="setup-skip-rewards" ${(state.rewardSkipped && state.walletSkipped) ? 'checked' : ''}>
        <span style="font-size:var(--font-size-sm);color:var(--text-muted)">
          Skip — I'll configure rewards and wallet later
        </span>
      </label>
    `;

    // ── Reward address + skip logic ──
    const addrInput = body.querySelector('#setup-reward-address');
    const skipCb = body.querySelector('#setup-skip-rewards');
    const walletBtns = body.querySelector('#setup-w-buttons');

    function applySkipState(skipped) {
      addrInput.disabled = skipped;
      addrInput.style.opacity = skipped ? '0.5' : '1';
      if (walletBtns) walletBtns.style.opacity = skipped ? '0.5' : '1';
      const genBtn = body.querySelector('#setup-w-generate');
      const impBtn = body.querySelector('#setup-w-import');
      if (genBtn) genBtn.disabled = skipped;
      if (impBtn) impBtn.disabled = skipped;
    }

    skipCb.addEventListener('change', () => {
      state.rewardSkipped = skipCb.checked;
      state.walletSkipped = skipCb.checked;
      applySkipState(skipCb.checked);
      if (!skipCb.checked) addrInput.focus();
    });
    if (state.rewardSkipped && state.walletSkipped) {
      applySkipState(true);
    }

    // Prefill reward address from generated/imported wallet
    function prefillRewardAddress(result) {
      if (!result || !result.address) return;
      // Only prefill if the field is empty or still has the old value
      if (!addrInput.value.trim()) {
        addrInput.value = result.address;
        state.rewardAddress = result.address;
        // Uncheck the skip checkbox if it was checked
        if (skipCb.checked) {
          skipCb.checked = false;
          state.rewardSkipped = false;
          state.walletSkipped = false;
          applySkipState(false);
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

    generateBtn.addEventListener('click', async () => {
      clearWalletAreas();
      try {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Generating...';
        const result = await rpc.call('noble_generateMnemonic', {
          word_count: 24,
          passphrase: '',
        });
        walletResult = result;
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

      const resultEl = document.createElement('div');
      resultEl.style.cssText = 'display:none;margin-top:var(--gap-sm);font-size:var(--font-size-sm)';
      wrapper.appendChild(resultEl);

      const btnRow = document.createElement('div');
      btnRow.style.cssText = 'display:flex;gap:var(--gap-sm);margin-top:var(--gap-sm)';

      const submitBtn = document.createElement('button');
      submitBtn.className = 'btn';
      submitBtn.style.cssText = 'padding:6px 14px';
      submitBtn.textContent = 'Import';
      submitBtn.addEventListener('click', async () => {
        const mWords = textarea.value.trim();
        if (!mWords) { resultEl.style.display = 'block'; resultEl.innerHTML = '<span style="color:var(--error)">Please enter your mnemonic phrase.</span>'; return; }
        try {
          const result = await rpc.call('noble_importMnemonic', { mnemonic: mWords, passphrase: '' });
          walletResult = result;
          wipeInput(textarea);

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
      });
      btnRow.appendChild(submitBtn);

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn btn-secondary';
      cancelBtn.style.cssText = 'padding:6px 12px';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.addEventListener('click', () => { wipeInput(textarea); clearWalletAreas(); });
      btnRow.appendChild(cancelBtn);

      wrapper.appendChild(btnRow);
      importArea.appendChild(wrapper);

      activeImpForm = {
        destroy() { wipeInput(textarea); wrapper.remove(); },
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
      lines.push('<span class="term-label">Bitcoin derived addresses for wallet compatibility (use is optional):</span>');
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
    const pruningModes = [
      { value: 'archive',    label: 'Archive',    desc: 'Full history, no pruning (recommended for validators)' },
      { value: 'moderate',   label: 'Moderate',   desc: 'Keep recent blocks, prune old state' },
      { value: 'aggressive', label: 'Aggressive', desc: 'Minimal storage, headers + recent blocks only' },
    ];

    body.innerHTML = `
      <div style="text-align:center;margin-bottom:var(--gap-lg)">
        <h3 style="margin-bottom:var(--gap-xs)">Storage</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">
          Configure where data is stored and how much disk to use.
        </p>
      </div>

      <div class="form-group">
        <label for="setup-data-dir" style="font-weight:600">Data Directory</label>
        <div style="display:flex;gap:var(--gap-sm);align-items:center">
          <input type="text" id="setup-data-dir" autocomplete="off" spellcheck="false"
            placeholder="Leave empty for default (~/.noble)"
            value="${esc(state.dataDir)}"
            style="flex:1;font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
          <button id="setup-check-dir" class="btn btn-secondary btn-sm" style="white-space:nowrap;padding:4px 10px">Check</button>
        </div>
        <div id="setup-dir-status" style="font-size:var(--font-size-xs);margin-top:var(--gap-xs);color:var(--text-muted)">
          ${state.dataDirValid === true ? '<span style="color:var(--success)">Directory OK</span>' :
            state.dataDirValid === false ? '<span style="color:var(--error)">' + esc(state.dataDirError) + '</span>' :
            'Click "Check" to validate the path and see available disk space.'}
        </div>
        <div id="setup-disk-bar" style="display:${state.dataDirValid ? 'block' : 'none'};margin-top:var(--gap-sm)">
          <div style="height:8px;background:var(--bg-tertiary);border-radius:4px;overflow:hidden">
            <div id="setup-disk-fill" style="height:100%;background:var(--accent);width:0%;transition:width 0.3s"></div>
          </div>
          <div id="setup-disk-label" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px"></div>
        </div>
      </div>

      <div class="form-group">
        <label for="setup-allocated-gb" style="font-weight:600">Space Allocation (GB)</label>
        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
          <input type="range" id="setup-allocated-range" min="1" max="500" step="1"
            value="${state.allocatedGb}"
            style="flex:1;accent-color:var(--accent)">
          <input type="number" id="setup-allocated-gb" min="1" max="10000" step="1"
            value="${state.allocatedGb}"
            style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm);width:80px;text-align:right">
          <span style="font-size:var(--font-size-sm);color:var(--text-muted)">GB</span>
        </div>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Maximum disk space the node will use for blockchain data. Archive mode requires more space.
        </div>
      </div>

      <!-- Additional volumes -->
      <div class="form-group">
        <label style="font-weight:600;display:block;margin-bottom:var(--gap-sm)">Additional Volumes (optional)</label>
        <div id="setup-volumes-list" style="display:flex;flex-direction:column;gap:var(--gap-xs)"></div>
        <button id="setup-add-volume" class="btn btn-secondary btn-sm" style="margin-top:var(--gap-sm);padding:4px 12px">
          + Add Volume
        </button>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Spread storage across multiple disks. Each volume stores a shard of the database.
        </div>
      </div>

      <div style="display:flex;gap:var(--gap-lg);align-items:flex-start;flex-wrap:wrap">
        <div class="form-group" style="flex:0 0 auto">
          <label for="setup-cache-size" style="font-weight:600">Cache Size (MB)</label>
          <input type="number" id="setup-cache-size" min="64" max="8192" step="64"
            value="${state.cacheSizeMb}"
            style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm);width:140px">
          <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
            RocksDB block cache (64–8192 MB)
          </div>
        </div>
        <div class="form-group" style="flex:0 0 auto;padding-top:1.7em">
          <label style="display:flex;align-items:center;gap:var(--gap-sm);cursor:pointer">
            <input type="checkbox" id="setup-compression" ${state.compression ? 'checked' : ''}>
            <span style="font-size:var(--font-size-sm)">Enable LZ4 compression</span>
          </label>
        </div>
      </div>

      <div class="form-group">
        <label style="font-weight:600;display:block;margin-bottom:var(--gap-sm)">Pruning Mode</label>
        <div id="setup-pruning-modes" style="display:grid;grid-template-columns:repeat(3,1fr);gap:var(--gap-sm)"></div>
      </div>

      <div id="setup-keep-blocks-group" class="form-group" style="display:${state.pruningMode !== 'archive' ? 'block' : 'none'}">
        <label for="setup-keep-blocks" style="font-weight:600">Keep Blocks</label>
        <input type="number" id="setup-keep-blocks" min="1000" max="10000000" step="1000"
          value="${state.keepBlocks || 100000}"
          style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm);max-width:160px">
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Number of recent blocks to retain when pruning.
        </div>
      </div>
    `;

    // Pruning radio cards
    const pruningContainer = body.querySelector('#setup-pruning-modes');
    pruningModes.forEach(m => {
      const checked = state.pruningMode === m.value;
      const card = document.createElement('label');
      card.style.cssText = 'padding:var(--gap-sm);background:var(--bg-tertiary);border:2px solid ' +
        (checked ? 'var(--accent)' : 'var(--border)') +
        ';border-radius:var(--radius-sm);cursor:pointer;transition:border-color 0.15s;text-align:center';
      card.innerHTML = `
        <input type="radio" name="pruning" value="${m.value}" ${checked ? 'checked' : ''} style="display:none">
        <div style="font-weight:600;font-size:var(--font-size-sm)">${m.label}</div>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">${m.desc}</div>
      `;
      card.querySelector('input').addEventListener('change', (e) => {
        pruningContainer.querySelectorAll('label').forEach(l => l.style.borderColor = 'var(--border)');
        card.style.borderColor = 'var(--accent)';
        const keepGroup = body.querySelector('#setup-keep-blocks-group');
        if (keepGroup) keepGroup.style.display = e.target.value !== 'archive' ? 'block' : 'none';
      });
      pruningContainer.appendChild(card);
    });

    // Check directory button
    const checkBtn = body.querySelector('#setup-check-dir');
    checkBtn.addEventListener('click', async () => {
      const dir = body.querySelector('#setup-data-dir').value.trim();
      const statusEl = body.querySelector('#setup-dir-status');
      const diskBar = body.querySelector('#setup-disk-bar');
      checkBtn.disabled = true;
      checkBtn.textContent = 'Checking...';
      try {
        const result = await rpc.call('noble_checkDataDir', { path: dir || '' });
        if (result.error) {
          state.dataDirValid = false;
          state.dataDirError = result.error;
          statusEl.innerHTML = `<span style="color:var(--error)">${esc(result.error)}</span>`;
          diskBar.style.display = 'none';
        } else {
          state.dataDirValid = true;
          state.dataDirError = '';
          state.diskAvailable = result.available_bytes || 0;
          const gb = (state.diskAvailable / (1024 ** 3)).toFixed(1);
          statusEl.innerHTML = `<span style="color:var(--success)">Directory OK — ${gb} GB available</span>`;
          diskBar.style.display = 'block';
          // Simple usage bar (available vs 100GB reference)
          const pct = Math.min(100, (state.diskAvailable / (100 * 1024 ** 3)) * 100);
          const fill = diskBar.querySelector('#setup-disk-fill');
          const label = diskBar.querySelector('#setup-disk-label');
          if (fill) fill.style.width = pct + '%';
          if (label) label.textContent = `${gb} GB free`;
        }
      } catch (e) {
        state.dataDirValid = false;
        state.dataDirError = e.message || 'Check failed';
        statusEl.innerHTML = `<span style="color:var(--error)">${esc(state.dataDirError)}</span>`;
        diskBar.style.display = 'none';
      } finally {
        checkBtn.disabled = false;
        checkBtn.textContent = 'Check';
      }
    });

    // Sync range slider ↔ number input for allocation
    const allocRange = body.querySelector('#setup-allocated-range');
    const allocNum = body.querySelector('#setup-allocated-gb');
    if (allocRange && allocNum) {
      allocRange.addEventListener('input', () => {
        allocNum.value = allocRange.value;
        state.allocatedGb = parseInt(allocRange.value, 10);
      });
      allocNum.addEventListener('input', () => {
        const v = parseInt(allocNum.value, 10);
        if (!isNaN(v) && v >= 1) {
          allocRange.value = Math.min(v, 500);
          state.allocatedGb = v;
        }
      });
    }

    // Additional volumes
    const volumesList = body.querySelector('#setup-volumes-list');
    const addVolumeBtn = body.querySelector('#setup-add-volume');

    function renderVolumes() {
      volumesList.innerHTML = '';
      state.volumes.forEach((vol, i) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm)';
        row.innerHTML = `
          <input type="text" class="vol-path" data-idx="${i}" autocomplete="off" spellcheck="false"
            placeholder="/mnt/disk${i + 2}"
            value="${esc(vol.path)}"
            style="flex:1;font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
          <button class="btn btn-secondary btn-sm vol-remove" data-idx="${i}"
            style="padding:2px 8px;font-size:var(--font-size-xs);color:var(--error)">✕</button>
        `;
        volumesList.appendChild(row);
      });

      // Wire remove buttons
      volumesList.querySelectorAll('.vol-remove').forEach(btn => {
        btn.addEventListener('click', () => {
          const idx = parseInt(btn.dataset.idx, 10);
          state.volumes.splice(idx, 1);
          renderVolumes();
        });
      });

      // Wire path inputs
      volumesList.querySelectorAll('.vol-path').forEach(input => {
        input.addEventListener('input', () => {
          const idx = parseInt(input.dataset.idx, 10);
          state.volumes[idx].path = input.value.trim();
        });
      });
    }

    addVolumeBtn.addEventListener('click', () => {
      state.volumes.push({ path: '' });
      renderVolumes();
      // Focus the new input
      const inputs = volumesList.querySelectorAll('.vol-path');
      if (inputs.length) inputs[inputs.length - 1].focus();
    });

    // Render existing volumes on step load
    if (state.volumes.length > 0) renderVolumes();
  }

  // ── Step 6: Encryption ──
  function renderEncryption() {
    const modes = [
      {
        value: 'automatic',
        label: 'Automatic — less secure',
        desc: 'Key files are encrypted at rest with a machine-specific key. No password required on startup.',
        icon: '&#x1F512;',
      },
      {
        value: 'manual',
        label: 'Password Protected',
        desc: 'Key files are encrypted with a password you provide. Password is required on every startup.',
        icon: '&#x1F511;',
      },
    ];

    body.innerHTML = `
      <div style="text-align:center;margin-bottom:var(--gap-lg)">
        <h3 style="margin-bottom:var(--gap-xs)">Encryption</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">
          All private keys (validator, TLS, P2P, TOTP) are encrypted at rest.<br>
          Choose how the encryption key is managed.
        </p>
      </div>

      <div id="setup-enc-modes" style="display:grid;grid-template-columns:1fr 1fr;gap:var(--gap);margin-bottom:var(--gap)"></div>

      <div id="setup-enc-password-area" style="display:${state.encryptionMode === 'manual' ? 'block' : 'none'}">
        <div class="form-group">
          <label for="setup-enc-password" style="font-weight:600">Encryption Password</label>
          <input type="password" id="setup-enc-password" autocomplete="new-password"
            placeholder="Minimum 8 characters"
            value="${esc(state.encryptionPassword)}"
            style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
        </div>
        <div class="form-group">
          <label for="setup-enc-confirm" style="font-weight:600">Confirm Password</label>
          <input type="password" id="setup-enc-confirm" autocomplete="new-password"
            placeholder="Type password again"
            value="${esc(state.encryptionConfirm)}"
            style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
        </div>
        <div style="padding:var(--gap-sm);background:color-mix(in srgb, var(--warning) 10%, transparent);border:1px solid var(--warning);border-radius:var(--radius-sm);font-size:var(--font-size-xs);color:var(--text-secondary)">
          <strong style="color:var(--warning)">Important:</strong> This password will be required every time the node starts.
          If lost, encrypted key files cannot be recovered — you will need to regenerate all keys.
        </div>
      </div>
      <div id="setup-enc-error" style="display:none"></div>
    `;

    // Mode radio cards
    const modesContainer = body.querySelector('#setup-enc-modes');
    const pwArea = body.querySelector('#setup-enc-password-area');

    modes.forEach(m => {
      const checked = state.encryptionMode === m.value;
      const card = document.createElement('label');
      card.style.cssText = 'padding:var(--gap);background:var(--bg-tertiary);border:2px solid ' +
        (checked ? 'var(--accent)' : 'var(--border)') +
        ';border-radius:var(--radius-sm);cursor:pointer;transition:border-color 0.15s;text-align:center';
      card.innerHTML = `
        <input type="radio" name="enc-mode" value="${m.value}" ${checked ? 'checked' : ''} style="display:none">
        <div style="font-size:1.5rem;margin-bottom:var(--gap-xs)">${m.icon}</div>
        <div style="font-weight:600;font-size:var(--font-size-sm)">${m.label}</div>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">${m.desc}</div>
      `;
      card.querySelector('input').addEventListener('change', () => {
        modesContainer.querySelectorAll('label').forEach(l => l.style.borderColor = 'var(--border)');
        card.style.borderColor = 'var(--accent)';
        state.encryptionMode = m.value;
        pwArea.style.display = m.value === 'manual' ? 'block' : 'none';
      });
      modesContainer.appendChild(card);
    });
  }

  // ── Step 7: Networking ──
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
          placeholder="node.infinitecontext.com"
          value="${esc(state.seeds)}"
          style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap-xs)">
          Comma-separated hostnames or IPs of seed peers. Clear to run standalone.
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

  // ── Step 8: Review ──
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
        <dt>Country</dt><dd>${esc(state.countryCode || '(not set)')}</dd>
        <dt>Reward Address</dt><dd>${state.rewardAddress ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(state.rewardAddress)}</span>` : '(skipped)'}</dd>
        <dt>Wallet</dt><dd>${walletResult ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(walletResult.address)}</span>` : '(skipped)'}</dd>
        ${validatorRow}
        <dt>Data Directory</dt><dd>${state.dataDir ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(state.dataDir)}</span>` : '(default)'}</dd>
        <dt>Allocated</dt><dd>${state.allocatedGb} GB</dd>
        ${state.volumes.length ? `<dt>Volumes</dt><dd>${state.volumes.filter(v => v.path).map(v => esc(v.path)).join(', ') || '(none)'}</dd>` : ''}
        <dt>Cache Size</dt><dd>${state.cacheSizeMb} MB</dd>
        <dt>Compression</dt><dd>${state.compression ? 'LZ4 enabled' : 'Disabled'}</dd>
        <dt>Pruning</dt><dd>${state.pruningMode === 'archive' ? 'Archive (full history)' : state.pruningMode + ' (keep ' + state.keepBlocks + ' blocks)'}</dd>
        <dt>Encryption</dt><dd>${state.encryptionMode === 'manual' ? 'Password protected' : 'Automatic (machine key)'}</dd>
        <dt>P2P Port</dt><dd>${state.p2pPort}</dd>
        <dt>Max Peers</dt><dd>${state.maxPeers}</dd>
        <dt>Seeds</dt><dd>${state.seeds ? `<span class="mono" style="font-size:var(--font-size-xs)">${esc(state.seeds)}</span>` : '(default bootstrap)'}</dd>
      </dl>
      <div style="margin-top:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);border:1px solid var(--border)">
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0">
          ${state.seeds ? 'Seed nodes will be saved to <code>noble.toml</code> and dialed on startup.<br>' : ''}
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
      // Apply storage + encryption config values (backend expects section + key separately)
      const configCalls = [];
      if (state.dataDir) configCalls.push(rpc.call('noble_setConfigValue', { section: 'storage', key: 'data_dir', value: state.dataDir }));
      configCalls.push(rpc.call('noble_setConfigValue', { section: 'storage', key: 'cache_size_mb', value: String(state.cacheSizeMb) }));
      configCalls.push(rpc.call('noble_setConfigValue', { section: 'storage', key: 'compression', value: String(state.compression) }));
      configCalls.push(rpc.call('noble_setConfigValue', { section: 'storage', key: 'pruning_mode', value: state.pruningMode }));
      if (state.pruningMode !== 'archive') {
        configCalls.push(rpc.call('noble_setConfigValue', { section: 'storage', key: 'keep_blocks', value: String(state.keepBlocks) }));
      }
      configCalls.push(rpc.call('noble_setConfigValue', { section: 'security', key: 'encryption_mode', value: state.encryptionMode }));
      // Networking config
      configCalls.push(rpc.call('noble_setConfigValue', { section: 'network', key: 'listen_addr', value: `/ip4/0.0.0.0/tcp/${state.p2pPort}` }));
      configCalls.push(rpc.call('noble_setConfigValue', { section: 'network', key: 'max_peers', value: String(state.maxPeers) }));
      await Promise.allSettled(configCalls);

      // Persist seed nodes via addSeed RPC (also dials each immediately).
      if (state.seeds) {
        const seedAddrs = state.seeds.split(',').map(s => s.trim()).filter(Boolean);
        for (const addr of seedAddrs) {
          // Convert bare IP/hostname to multiaddr if needed.
          const multiaddr = addr.startsWith('/') ? addr
            : /[a-zA-Z]/.test(addr) ? `/dns4/${addr}/tcp/8780`
            : `/ip4/${addr}/tcp/8780`;
          try { await rpc.call('noble_addSeed', { multiaddr }); } catch { /* best effort */ }
        }
      }

      const roleObj = NODE_ROLES.find(r => r.value === state.roleValue) || NODE_ROLES[0];
      const result = await rpc.call('noble_setNodeIdentity', {
        node_name: state.nodeName,
        org_type: state.orgType,
        org_name: state.orgName,
        node_role: roleObj.role,
        contact_email: state.contactEmail,
        website: state.website,
        host_address: '',
        country_code: state.countryCode || undefined,
        wants_to_validate: roleObj.validate,
        wants_to_vote: roleObj.vote,
        p2p_port: state.p2pPort,
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

      // Unlock navigation — setup is complete
      if (typeof ctx.deactivateSetupGuard === 'function') {
        ctx.deactivateSetupGuard();
      }

    } catch (e) {
      body.innerHTML += `<div style="color:var(--error);margin-top:var(--gap)">Setup error: ${e.message || e}</div>`;
      nextBtn.disabled = false;
      nextBtn.textContent = 'Complete Setup';
    }
  }

  // Start
  goTo(0);

  return {
    destroy() {
      cleanupFns.forEach(fn => { try { fn(); } catch {} });
    },
  };
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
