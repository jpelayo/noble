/**
 * NOBLE Dashboard — First-Run Setup Wizard
 * Multi-step onboarding: Network → Role → Identity → Wallet → Security → Storage → Review
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
  { key: 'security', label: 'Security' },
  { key: 'storage',  label: 'Storage'  },
  { key: 'review',   label: 'Review'   },
];

const NETWORKS = [
  { id: 'mainnet', name: 'Mainnet', chain: '0x4E4F424C', desc: 'Production network' },
  { id: 'testnet', name: 'Testnet', chain: '0x4E4F4254', desc: 'Test network for development' },
  { id: 'regtest', name: 'Regtest', chain: '0x4E4F4252', desc: 'Local regression testing' },
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

const GOV_CLASSES = [
  { id: 'individual', label: 'Individual' },
  { id: 'private',    label: 'Private' },
  { id: 'public',     label: 'Public' },
];

const ORG_TYPES = {
  individual: [{ id: 'Individual', label: 'Individual' }],
  private: [
    { id: 'PrivateNonProfit',    label: 'Non-Profit' },
    { id: 'PrivateCorporation',  label: 'Corporation' },
    { id: 'PrivateStartup',     label: 'Startup' },
    { id: 'PrivateAcademic',    label: 'Academic Institution' },
    { id: 'PrivateInstitution', label: 'Other Institution' },
  ],
  public: [
    { id: 'PublicNational',       label: 'National Administration' },
    { id: 'PublicRegional',       label: 'Regional/Municipal' },
    { id: 'PublicSupranational',  label: 'Supranational Organization' },
    { id: 'PublicCorporation',    label: 'Public Corporation' },
    { id: 'PublicAcademic',       label: 'Academic Institution' },
    { id: 'PublicInstitution',    label: 'Other Institution' },
  ],
};

export function init(root, ctx) {
  const { rpc } = ctx;
  let currentStep = 0;
  let cleanupFns = [];

  // Wizard state
  const state = {
    network: 'mainnet',
    nodeName: '',
    p2pPort: 8780,
    roleValue: 'FullNode',
    govClass: 'individual',
    orgType: 'Individual',
    orgName: '',
    contactEmail: '',
    website: '',
    walletPath: 'skip',  // 'create' | 'import' | 'skip'
    walletAddress: '',
    totpEnabled: false,
    dataDir: 'data',
    cacheSize: 256,
    compression: true,
    setupToken: '',  // F1: raw setup token from node console (used as Bearer auth for write RPCs)
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
      case 'security': renderSecurity(); break;
      case 'storage':  renderStorage(); break;
      case 'review':   renderReview(); break;
    }
  }

  backBtn.addEventListener('click', () => goTo(currentStep - 1));
  nextBtn.addEventListener('click', () => {
    if (currentStep === STEPS.length - 1) {
      completeSetup();
    } else {
      collectStepData();
      goTo(currentStep + 1);
    }
  });

  function collectStepData() {
    const stepKey = STEPS[currentStep].key;
    switch (stepKey) {
      case 'welcome':
        state.network = body.querySelector('input[name="network"]:checked')?.value || state.network;
        state.nodeName = body.querySelector('#setup-node-name')?.value || '';
        state.p2pPort = parseInt(body.querySelector('input[name="p2pPort"]:checked')?.value || '8780', 10);
        state.setupToken = body.querySelector('#setup-token')?.value?.trim() || '';
        break;
      case 'role':
        state.roleValue = body.querySelector('input[name="role"]:checked')?.value || state.roleValue;
        break;
      case 'identity': {
        const govSel = body.querySelector('#setup-gov-class');
        const orgSel = body.querySelector('#setup-org-type');
        if (govSel) state.govClass = govSel.value;
        if (orgSel) state.orgType = orgSel.value;
        state.orgName = body.querySelector('#setup-org-name')?.value || '';
        state.contactEmail = body.querySelector('#setup-email')?.value || '';
        state.website = body.querySelector('#setup-website')?.value || '';
        break;
      }
      case 'storage':
        state.dataDir = body.querySelector('#setup-data-dir')?.value || 'data';
        state.cacheSize = parseInt(body.querySelector('#setup-cache')?.value, 10) || 256;
        state.compression = body.querySelector('#setup-compression')?.checked ?? true;
        break;
    }
  }

  // ── Step 1: Welcome ──
  function renderWelcome() {
    body.innerHTML = `
      <div style="text-align:center;padding:var(--gap-lg) 0 var(--gap)">
        <h2 style="margin-bottom:var(--gap-sm)">Welcome to NOBLE</h2>
        <p style="color:var(--text-secondary)">This wizard will guide you through the essential configuration for your node.</p>
      </div>
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
      </div>
      <div style="margin-bottom:var(--gap-lg)">
        <label style="font-size:var(--font-size-sm);font-weight:600;display:block;margin-bottom:var(--gap-sm);color:var(--text-secondary)">Target Network</label>
        <div id="setup-networks" style="display:flex;gap:var(--gap);flex-wrap:wrap"></div>
      </div>
      <div class="form-group">
        <label for="setup-node-name">Node Name (optional)</label>
        <input type="text" id="setup-node-name" maxlength="64" placeholder="e.g. my-noble-node" value="${esc(state.nodeName)}" autocomplete="off" spellcheck="false">
      </div>
      <div style="margin-top:var(--gap-lg)">
        <label style="font-size:var(--font-size-sm);font-weight:600;display:block;margin-bottom:var(--gap-sm);color:var(--text-secondary)">
          P2P Port <span style="font-weight:400;color:var(--text-muted)">(open this port to the internet)</span>
        </label>
        <div id="setup-p2p-port" style="display:flex;gap:var(--gap);flex-wrap:wrap"></div>
      </div>
    `;
    const networkContainer = body.querySelector('#setup-networks');
    NETWORKS.forEach(n => {
      const checked = state.network === n.id ? 'checked' : '';
      const card = document.createElement('label');
      card.style.cssText = 'flex:1;min-width:140px;padding:var(--gap);background:var(--bg-tertiary);border:2px solid var(--border);border-radius:var(--radius);cursor:pointer;transition:border-color 0.15s';
      card.innerHTML = `
        <input type="radio" name="network" value="${n.id}" ${checked} style="margin-right:var(--gap-sm)">
        <strong>${n.name}</strong>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">${n.desc}</div>
        <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${n.chain}</div>
      `;
      const radio = card.querySelector('input');
      radio.addEventListener('change', () => {
        networkContainer.querySelectorAll('label').forEach(l => l.style.borderColor = 'var(--border)');
        if (radio.checked) card.style.borderColor = 'var(--accent)';
      });
      if (checked) card.style.borderColor = 'var(--accent)';
      networkContainer.appendChild(card);
    });

    const portContainer = body.querySelector('#setup-p2p-port');
    [8780, 8781, 8782].forEach(p => {
      const checked = state.p2pPort === p ? 'checked' : '';
      const card = document.createElement('label');
      card.style.cssText = 'flex:1;min-width:100px;padding:var(--gap);background:var(--bg-tertiary);border:2px solid var(--border);border-radius:var(--radius);cursor:pointer;transition:border-color 0.15s';
      card.innerHTML = `
        <input type="radio" name="p2pPort" value="${p}" ${checked} style="margin-right:var(--gap-sm)">
        <strong>${p}</strong>${p === 8780 ? ' <span style="color:var(--text-muted);font-size:var(--font-size-xs)">(default)</span>' : ''}
      `;
      const radio = card.querySelector('input');
      radio.addEventListener('change', () => {
        portContainer.querySelectorAll('label').forEach(l => l.style.borderColor = 'var(--border)');
        if (radio.checked) card.style.borderColor = 'var(--accent)';
      });
      if (checked) card.style.borderColor = 'var(--accent)';
      portContainer.appendChild(card);
    });
  }

  // ── Step 2: Role ──
  function renderRole() {
    body.innerHTML = `
      <label style="font-size:var(--font-size-sm);font-weight:600;display:block;margin-bottom:var(--gap-sm);color:var(--text-secondary)">Node Role</label>
      <div id="setup-roles" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:var(--gap-sm)"></div>
      <div id="setup-role-info" style="margin-top:var(--gap);display:none;padding:var(--gap-sm);background:color-mix(in srgb, var(--warning) 10%, transparent);border-radius:var(--radius-sm);font-size:var(--font-size-sm);color:var(--warning)"></div>
    `;
    const rolesContainer = body.querySelector('#setup-roles');
    const roleInfo = body.querySelector('#setup-role-info');

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
        const sel = NODE_ROLES.find(x => x.value === radio.value);
        if (sel && sel.validate) {
          roleInfo.style.display = 'block';
          roleInfo.textContent = 'Validator key must be configured in noble.toml before starting the node.';
        } else {
          roleInfo.style.display = 'none';
        }
      });
      if (checked) {
        card.style.borderColor = 'var(--accent)';
        if (r.validate) { roleInfo.style.display = 'block'; roleInfo.textContent = 'Validator key must be configured in noble.toml before starting the node.'; }
      }
      rolesContainer.appendChild(card);
    });
  }

  // ── Step 3: Identity ──
  function renderIdentity() {
    body.innerHTML = `
      <div class="form-group">
        <label for="setup-gov-class">Governance Class</label>
        <select id="setup-gov-class"></select>
      </div>
      <div class="form-group">
        <label for="setup-org-type">Organization Type</label>
        <select id="setup-org-type"></select>
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
    const govSelect = body.querySelector('#setup-gov-class');
    const orgSelect = body.querySelector('#setup-org-type');

    GOV_CLASSES.forEach(g => {
      const opt = document.createElement('option');
      opt.value = g.id;
      opt.textContent = g.label;
      if (g.id === state.govClass) opt.selected = true;
      govSelect.appendChild(opt);
    });

    function updateOrgTypes() {
      orgSelect.innerHTML = '';
      const types = ORG_TYPES[govSelect.value] || ORG_TYPES.individual;
      types.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = t.label;
        if (t.id === state.orgType) opt.selected = true;
        orgSelect.appendChild(opt);
      });
    }

    govSelect.addEventListener('change', updateOrgTypes);
    updateOrgTypes();
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

  // ── Step 5: Security ──
  function renderSecurity() {
    body.innerHTML = `
      <div class="form-group">
        <label style="display:flex;align-items:center;gap:var(--gap-sm);cursor:pointer">
          <input type="checkbox" id="setup-totp" ${state.totpEnabled ? 'checked' : ''} style="width:18px;height:18px;accent-color:var(--accent)">
          <span style="font-weight:600">Enable TOTP Authentication</span>
        </label>
        <div class="form-hint">All RPC and dashboard access will require a 6-digit TOTP code from your authenticator app.</div>
      </div>
      <div id="setup-totp-area" style="display:${state.totpEnabled ? 'block' : 'none'}"></div>
    `;
    const checkbox = body.querySelector('#setup-totp');
    const totpArea = body.querySelector('#setup-totp-area');

    checkbox.addEventListener('change', () => {
      state.totpEnabled = checkbox.checked;
      totpArea.style.display = checkbox.checked ? 'block' : 'none';
      if (checkbox.checked && !totpArea.hasChildNodes()) {
        totpArea.innerHTML = `
          <div style="padding:var(--gap);background:var(--bg-tertiary);border-radius:var(--radius);border:1px solid var(--border)">
            <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap-sm)">
              TOTP will be configured when the node starts. The secret and otpauth URI will be shown in the node's terminal output.
              Add the URI to your authenticator app (Google Authenticator, Authy, etc.).
            </p>
            <p style="font-size:var(--font-size-xs);color:var(--text-muted)">
              Note: TOTP configuration requires the CLI setup wizard (<code>noble-node setup</code>) for secret generation and verification.
              The dashboard wizard enables the flag in configuration.
            </p>
          </div>
        `;
      }
    });

    if (state.totpEnabled) checkbox.dispatchEvent(new Event('change'));
  }

  // ── Step 6: Storage ──
  function renderStorage() {
    body.innerHTML = `
      <div class="form-group">
        <label for="setup-data-dir">Data Directory</label>
        <input type="text" id="setup-data-dir" value="${esc(state.dataDir)}" autocomplete="off">
        <div class="form-hint">Directory where blockchain data is stored.</div>
      </div>
      <div class="form-group">
        <label for="setup-cache">Cache Size (MB)</label>
        <input type="number" id="setup-cache" min="64" max="4096" value="${state.cacheSize}">
        <div class="form-hint">Recommended: 256 MB for 8+ GB RAM, 128 MB for 4 GB RAM.</div>
      </div>
      <div class="form-group">
        <label style="display:flex;align-items:center;gap:var(--gap-sm);cursor:pointer">
          <input type="checkbox" id="setup-compression" ${state.compression ? 'checked' : ''} style="width:18px;height:18px;accent-color:var(--accent)">
          <span>Enable Zstd Compression</span>
        </label>
        <div class="form-hint">Reduces disk usage by ~40%. Recommended for most setups.</div>
      </div>
    `;
  }

  // ── Step 7: Review ──
  function renderReview() {
    const roleObj = NODE_ROLES.find(r => r.value === state.roleValue) || NODE_ROLES[0];
    body.innerHTML = `
      <h3 style="margin-bottom:var(--gap)">Configuration Summary</h3>
      <dl class="detail-grid">
        <dt>Network</dt><dd>${esc(NETWORKS.find(n => n.id === state.network)?.name || state.network)}</dd>
        <dt>Node Name</dt><dd>${esc(state.nodeName || '(not set)')}</dd>
        <dt>P2P Port</dt><dd>${state.p2pPort}</dd>
        <dt>Role</dt><dd>${esc(roleObj.label)}</dd>
        <dt>Org Type</dt><dd>${esc(state.orgType)}</dd>
        <dt>Org Name</dt><dd>${esc(state.orgName || '(not set)')}</dd>
        <dt>Contact Email</dt><dd>${esc(state.contactEmail || '(not set)')}</dd>
        <dt>Website</dt><dd>${esc(state.website || '(not set)')}</dd>
        <dt>Wallet</dt><dd>${state.walletAddress ? `<span class="mono" style="font-size:var(--font-size-xs)">${state.walletAddress.slice(0, 16)}...</span>` : '(skipped)'}</dd>
        <dt>TOTP</dt><dd>${state.totpEnabled ? 'Enabled' : 'Disabled'}</dd>
        <dt>Data Dir</dt><dd class="mono">${esc(state.dataDir)}</dd>
        <dt>Cache</dt><dd>${state.cacheSize} MB</dd>
        <dt>Compression</dt><dd>${state.compression ? 'Zstd' : 'None'}</dd>
      </dl>
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

    // F1: Set setup token as raw Bearer auth for the write RPC call.
    // The node validates this token to prevent unauthorized configuration changes.
    if (state.setupToken) {
      rpc.setRawAuthToken(state.setupToken);
    }

    try {
      const roleObj = NODE_ROLES.find(r => r.value === state.roleValue) || NODE_ROLES[0];
      await rpc.call('noble_setNodeIdentity', {
        node_name: state.nodeName,
        org_type: state.orgType,
        org_name: state.orgName,
        node_role: roleObj.role,
        contact_email: state.contactEmail,
        website: state.website,
        host_address: '',
        wants_to_validate: roleObj.validate,
        wants_to_vote: roleObj.vote,
        p2p_port: state.p2pPort,
      });

      body.innerHTML = `
        <div style="text-align:center;padding:var(--gap-xl)">
          <div style="font-size:3rem;color:var(--success);margin-bottom:var(--gap)">&#10004;</div>
          <h2 style="color:var(--success);margin-bottom:var(--gap-sm)">Setup Complete!</h2>
          <p style="color:var(--text-secondary)">Your node identity has been saved.</p>
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

  // Start
  goTo(0);

  return {
    destroy() {
      cleanupFns.forEach(fn => { try { fn(); } catch {} });
      destroySecureElements(body);
    },
  };
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
