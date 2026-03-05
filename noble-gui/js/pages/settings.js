/**
 * NOBLE Dashboard — Settings Page
 * IP access control management and system configuration.
 */

import { formatChainLabel } from '../utils.js';

export function init(root, ctx) {
  const { rpc } = ctx;

  root.innerHTML = `
    <div class="page-header">
      <h1>Settings</h1>
      <p>Node access control and configuration</p>
    </div>

    <!-- IP Access Control -->
    <div class="panel">
      <div class="panel-header">
        <span>IP Access Control</span>
        <span id="s-access-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Control which remote IPs can access the RPC and dashboard. <code>127.0.0.1</code> is always allowed.
          An empty list means localhost-only access.
        </p>

        <div id="s-ip-list" style="margin-bottom:var(--gap)"></div>

        <div style="display:flex;gap:var(--gap-sm);align-items:center;margin-bottom:var(--gap)">
          <input id="s-new-ip" type="text" placeholder="e.g. 192.168.1.0/24 or 10.0.0.5"
            style="flex:1;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
          <button id="s-add-ip" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm);white-space:nowrap">Add</button>
        </div>

        <div id="s-ip-error" style="color:var(--error);font-size:var(--font-size-xs);margin-bottom:var(--gap);display:none"></div>

        <div style="display:flex;gap:var(--gap-sm);align-items:center">
          <button id="s-save-ips" class="btn-sm" style="padding:6px 14px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Save Changes</button>
          <span id="s-save-msg" style="font-size:var(--font-size-xs);color:var(--text-muted)"></span>
        </div>

        <div style="margin-top:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);font-size:var(--font-size-xs);color:var(--text-muted)">
          <strong>Note:</strong> Switching between localhost-only (empty list) and remote access (non-empty list)
          requires a node restart because the bind address changes between <code>127.0.0.1</code> and <code>0.0.0.0</code>.
          Updating entries within an existing non-empty list takes effect immediately.
        </div>
      </div>
    </div>

    <!-- Authentication Status -->
    <div class="panel">
      <div class="panel-header">Authentication</div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-auth-info">
          <dt>TOTP Status</dt>
          <dd id="s-totp-status">--</dd>
          <dt>Auth Mode</dt>
          <dd id="s-auth-mode">--</dd>
        </dl>
        <!-- Enable TOTP (shown only when TOTP is NOT active) -->
        <div id="s-totp-enable-section" style="display:none;margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)"></div>
        <!-- TOTP Rotation (shown only when TOTP is active) -->
        <div id="s-totp-rotate-section" style="display:none;margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Rotate TOTP Secret</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0 0 var(--gap-sm)">
            Enter your current 6-digit TOTP code to rotate the shared secret.
            The new secret will be displayed once — store it immediately.
          </p>
          <div style="display:flex;gap:var(--gap-sm);align-items:center;margin-bottom:var(--gap-sm)">
            <input id="s-totp-code" type="text" maxlength="6" placeholder="6-digit code"
              style="width:120px;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm);text-align:center">
            <button id="s-totp-rotate-btn" class="btn-sm" style="padding:6px 14px;background:var(--warning,#f0a500);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Rotate Secret</button>
          </div>
          <div id="s-totp-rotate-result" style="display:none;padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);font-size:var(--font-size-xs)"></div>
          <div id="s-totp-rotate-error" style="color:var(--error);font-size:var(--font-size-xs);display:none"></div>
        </div>
      </div>
    </div>

    <!-- Validator Key -->
    <div class="panel">
      <div class="panel-header">
        <span>Validator Key</span>
        <span id="s-vkey-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-vkey-details">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
      </div>
    </div>

    <!-- P2P Identity -->
    <div class="panel">
      <div class="panel-header">P2P Identity</div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-p2p-details">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>
      </div>
    </div>

    <!-- Wallet -->
    <div class="panel">
      <div class="panel-header">
        <span>Wallet</span>
        <span id="s-wk-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Your wallet key is used as the gateway key and derives the reward address. Back up your mnemonic before replacing it.
        </p>

        <!-- Key info -->
        <div id="s-wk-list" style="margin-bottom:var(--gap)"></div>
        <div id="s-wk-error" style="color:var(--error);font-size:var(--font-size-xs);display:none"></div>
        <div id="s-wk-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);display:none"></div>

        <!-- Reward address -->
        <div style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Reward Address</p>
          <dl class="detail-grid" id="s-reward-info">
            <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
          </dl>
          <div style="margin-top:var(--gap-sm)">
            <div style="display:flex;gap:var(--gap-sm);align-items:center">
              <input id="s-reward-input" type="text" placeholder="bc1q..., 1..., bc1p..., or hex public key"
                style="flex:1;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
              <button id="s-reward-save" class="btn-sm" style="padding:6px 14px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Save</button>
            </div>
            <span id="s-reward-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);display:block;margin-top:var(--gap-xs)"></span>
          </div>
        </div>
      </div>
    </div>
    <div id="s-wk-modal"></div>

    <!-- Seed Nodes -->
    <div class="panel">
      <div class="panel-header">
        <span>Seed Nodes</span>
        <span id="s-seed-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap)">
          Seed nodes are dialed on startup and used for initial peer discovery.
          Changes are persisted to <code>noble.toml</code>.
        </p>

        <div id="s-seed-list" style="margin-bottom:var(--gap)"></div>

        <div style="display:flex;gap:var(--gap-sm);align-items:center;margin-bottom:var(--gap)">
          <input id="s-new-seed" type="text" placeholder="e.g. 192.168.5.20 or /ip4/1.2.3.4/tcp/8780"
            style="flex:1;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
          <button id="s-add-seed" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm);white-space:nowrap">Add Seed</button>
        </div>
        <div id="s-seed-error" style="color:var(--error);font-size:var(--font-size-xs);display:none"></div>
        <div id="s-seed-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);display:none"></div>
      </div>
    </div>

    <!-- Node Ports -->
    <div class="panel">
      <div class="panel-header">Port Configuration</div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-ports">
        </dl>
      </div>
    </div>

    <!-- At-Rest Encryption -->
    <div class="panel">
      <div class="panel-header">
        <span>At-Rest Encryption</span>
        <span id="s-enc-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-enc-details">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>

        <div style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Switch Encryption Mode</p>
          <div style="display:grid;gap:var(--gap-sm);max-width:400px">
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">New Mode</label>
              <select id="s-enc-mode-select" style="width:100%;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-size:var(--font-size-sm)">
                <option value="automatic">Automatic — less secure (no startup password)</option>
                <option value="manual">Manual (password on every startup)</option>
              </select>
            </div>
            <div id="s-enc-current-pw-row" style="display:none">
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Current Password</label>
              <input id="s-enc-current-pw" type="text" placeholder="Current encryption password"
                style="width:100%;box-sizing:border-box;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
            </div>
            <div id="s-enc-new-pw-row" style="display:none">
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">New Password</label>
              <input id="s-enc-new-pw" type="text" placeholder="New encryption password"
                style="width:100%;box-sizing:border-box;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
            </div>
            <div id="s-enc-confirm-pw-row" style="display:none">
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Confirm Password</label>
              <input id="s-enc-confirm-pw" type="text" placeholder="Confirm password"
                style="width:100%;box-sizing:border-box;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
            </div>
            <div style="display:flex;align-items:center;gap:var(--gap-sm)">
              <button id="s-enc-switch-btn" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Switch Mode</button>
              <span id="s-enc-switch-msg" style="font-size:var(--font-size-xs);color:var(--text-muted)"></span>
            </div>
          </div>
          <div id="s-enc-error" style="color:var(--error);font-size:var(--font-size-xs);margin-top:var(--gap-sm);display:none"></div>
        </div>

        <div style="margin-top:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);font-size:var(--font-size-xs);color:var(--text-muted)">
          <strong>Warning:</strong> If you set manual mode and lose the password, all key material is unrecoverable.
          A node restart is required after switching modes.
        </div>
      </div>
    </div>

    <!-- TLS Certificate -->
    <div class="panel">
      <div class="panel-header">
        <span>TLS Certificate</span>
        <span id="s-tls-badge" class="badge"></span>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-tls-details"></dl>

        <div style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Regenerate Self-Signed Certificate</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0 0 var(--gap-sm)">
            Writes new certificate files to disk. <strong>Restart the node</strong> for the new cert to load.
          </p>
          <button id="s-tls-regen-btn" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Regenerate Certificate</button>
          <span id="s-tls-regen-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-sm)"></span>
        </div>

        <div style="margin-top:var(--gap);border-top:1px solid var(--border);padding-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Upload CA-Signed Certificate</p>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin:0 0 var(--gap-sm)">
            Replace the self-signed cert with a certificate from a trusted CA. Key must match the certificate.
            <strong>Restart the node</strong> after upload.
          </p>
          <div style="display:grid;gap:var(--gap-sm)">
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Certificate PEM (required)</label>
              <textarea id="s-tls-cert-pem" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;..."
                style="width:100%;box-sizing:border-box;padding:6px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"></textarea>
            </div>
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Private Key PEM (required)</label>
              <textarea id="s-tls-key-pem" rows="4" placeholder="-----BEGIN PRIVATE KEY-----&#10;..."
                style="width:100%;box-sizing:border-box;padding:6px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"></textarea>
            </div>
            <div>
              <label style="font-size:var(--font-size-xs);color:var(--text-secondary);display:block;margin-bottom:2px">Intermediate Chain PEM (optional)</label>
              <textarea id="s-tls-chain-pem" rows="3" placeholder="-----BEGIN CERTIFICATE-----&#10;... (optional intermediate/chain)"
                style="width:100%;box-sizing:border-box;padding:6px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"></textarea>
            </div>
            <div style="display:flex;align-items:center;gap:var(--gap-sm)">
              <button id="s-tls-upload-btn" class="btn-sm" style="padding:6px 14px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Upload &amp; Replace</button>
              <span id="s-tls-upload-msg" style="font-size:var(--font-size-xs);color:var(--text-muted)"></span>
            </div>
          </div>
          <div id="s-tls-upload-error" style="color:var(--error);font-size:var(--font-size-xs);margin-top:var(--gap-sm);display:none"></div>
        </div>
      </div>
    </div>

    <!-- Chain Management -->
    <div class="panel">
      <div class="panel-header">
        <span>Chain Management</span>
        <button id="s-chain-gear" title="Chain reset options" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 8px;cursor:pointer;color:var(--text-muted);font-size:1rem;line-height:1">&#9881;</button>
      </div>
      <div class="panel-body">
        <dl class="detail-grid" id="s-chain-info">
          <dt style="grid-column:1/-1;color:var(--text-muted)">Loading...</dt>
        </dl>

        <div style="margin-top:var(--gap)">
          <p style="font-size:var(--font-size-sm);font-weight:600;margin:0 0 var(--gap-sm)">Detected Forks</p>
          <div id="s-fork-table-wrap" style="overflow-x:auto">
            <p style="font-size:var(--font-size-xs);color:var(--text-muted)">Loading...</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Chain Management Modal -->
    <div id="s-chain-modal" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);align-items:center;justify-content:center">
      <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:700px;width:92%;max-height:85vh;overflow-y:auto;padding:var(--gap-lg);position:relative">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap)">
          <h3 style="margin:0">Chain Reset &amp; Re-sync</h3>
          <button id="s-chain-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.5rem;cursor:pointer;padding:0 4px;line-height:1" title="Close">&times;</button>
        </div>
        <p style="font-size:var(--font-size-sm);color:var(--text-muted);margin:0 0 var(--gap)">
          Reset the local chain to genesis and re-sync from network peers. Use when this node is stuck on a wrong fork.
        </p>
        <div id="s-chain-modal-forks" style="margin-bottom:var(--gap)"></div>
        <div id="s-chain-modal-datadir" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm)"></div>
        <p style="font-size:var(--font-size-xs);color:var(--warning);margin:0 0 var(--gap)">
          &#9888; This will erase all blocks above genesis. Back up your data directory manually before proceeding if needed.
        </p>
        <div style="display:flex;gap:var(--gap-sm);justify-content:flex-end">
          <button id="s-chain-modal-cancel" class="btn-sm" style="padding:6px 14px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Cancel</button>
          <button id="s-chain-modal-backup" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Backup Data</button>
          <button id="s-chain-modal-reset" class="btn-sm" style="padding:6px 14px;background:var(--error);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Reset &amp; Re-sync</button>
        </div>
        <div id="s-chain-modal-msg" style="font-size:var(--font-size-xs);margin-top:var(--gap-sm);text-align:right"></div>
      </div>
    </div>
  `;

  // DOM refs
  const accessBadge = root.querySelector('#s-access-badge');
  const ipListEl = root.querySelector('#s-ip-list');
  const newIpInput = root.querySelector('#s-new-ip');
  const addBtn = root.querySelector('#s-add-ip');
  const errorEl = root.querySelector('#s-ip-error');
  const saveBtn = root.querySelector('#s-save-ips');
  const saveMsg = root.querySelector('#s-save-msg');
  const totpStatus = root.querySelector('#s-totp-status');
  const authMode = root.querySelector('#s-auth-mode');
  const portsEl = root.querySelector('#s-ports');
  // TOTP rotation refs
  const totpRotateSection = root.querySelector('#s-totp-rotate-section');
  const totpCodeInput = root.querySelector('#s-totp-code');
  const totpRotateBtn = root.querySelector('#s-totp-rotate-btn');
  const totpRotateResult = root.querySelector('#s-totp-rotate-result');
  const totpRotateError = root.querySelector('#s-totp-rotate-error');
  // Validator key refs
  const vkeyBadge = root.querySelector('#s-vkey-badge');
  const vkeyDetails = root.querySelector('#s-vkey-details');
  // P2P identity refs
  const p2pDetails = root.querySelector('#s-p2p-details');
  // TLS cert refs
  const tlsBadge = root.querySelector('#s-tls-badge');
  const tlsDetails = root.querySelector('#s-tls-details');
  const tlsRegenBtn = root.querySelector('#s-tls-regen-btn');
  const tlsRegenMsg = root.querySelector('#s-tls-regen-msg');
  const tlsCertPem = root.querySelector('#s-tls-cert-pem');
  const tlsKeyPem = root.querySelector('#s-tls-key-pem');
  const tlsChainPem = root.querySelector('#s-tls-chain-pem');
  const tlsUploadBtn = root.querySelector('#s-tls-upload-btn');
  const tlsUploadMsg = root.querySelector('#s-tls-upload-msg');
  const tlsUploadError = root.querySelector('#s-tls-upload-error');
  // Encryption refs
  const encBadge = root.querySelector('#s-enc-badge');
  const encDetails = root.querySelector('#s-enc-details');
  const encModeSelect = root.querySelector('#s-enc-mode-select');
  const encCurrentPwRow = root.querySelector('#s-enc-current-pw-row');
  const encCurrentPw = root.querySelector('#s-enc-current-pw');
  const encNewPwRow = root.querySelector('#s-enc-new-pw-row');
  const encNewPw = root.querySelector('#s-enc-new-pw');
  const encConfirmPwRow = root.querySelector('#s-enc-confirm-pw-row');
  const encConfirmPw = root.querySelector('#s-enc-confirm-pw');
  const encSwitchBtn = root.querySelector('#s-enc-switch-btn');
  const encSwitchMsg = root.querySelector('#s-enc-switch-msg');
  const encError = root.querySelector('#s-enc-error');

  // Reward address refs
  const rewardInfo = root.querySelector('#s-reward-info');
  const rewardInput = root.querySelector('#s-reward-input');
  const rewardSave = root.querySelector('#s-reward-save');
  const rewardMsg = root.querySelector('#s-reward-msg');

  // Wallet key refs
  const wkBadge = root.querySelector('#s-wk-badge');
  const wkListEl = root.querySelector('#s-wk-list');
  const wkError = root.querySelector('#s-wk-error');
  const wkMsg = root.querySelector('#s-wk-msg');
  const wkModal = root.querySelector('#s-wk-modal');

  // Seed node refs
  const seedBadge = root.querySelector('#s-seed-badge');
  const seedListEl = root.querySelector('#s-seed-list');
  const newSeedInput = root.querySelector('#s-new-seed');
  const addSeedBtn = root.querySelector('#s-add-seed');
  const seedError = root.querySelector('#s-seed-error');
  const seedMsg = root.querySelector('#s-seed-msg');

  let allowedIps = [];
  let currentEncMode = 'automatic';

  // Validate an IP or CIDR string
  function isValidIpOrCidr(str) {
    const trimmed = str.trim();
    if (!trimmed) return false;
    // Simple IPv4 pattern
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    // IPv4 with CIDR
    const ipv4Cidr = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    // IPv6 pattern (simplified)
    const ipv6 = /^[0-9a-fA-F:]+$/;
    // IPv6 with CIDR
    const ipv6Cidr = /^[0-9a-fA-F:]+\/\d{1,3}$/;
    return ipv4.test(trimmed) || ipv4Cidr.test(trimmed) || ipv6.test(trimmed) || ipv6Cidr.test(trimmed);
  }

  // Render the IP list
  function renderIpList() {
    if (allowedIps.length === 0) {
      ipListEl.innerHTML = `<div style="color:var(--text-muted);font-size:var(--font-size-sm);font-style:italic">No remote IPs configured (localhost-only access)</div>`;
      return;
    }
    ipListEl.innerHTML = allowedIps.map((ip, i) => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 8px;margin-bottom:2px;background:var(--bg-tertiary);border-radius:var(--radius-sm)">
        <code style="font-size:var(--font-size-sm)">${ip}</code>
        <button class="ip-remove" data-index="${i}" style="background:none;border:none;color:var(--error);cursor:pointer;font-size:var(--font-size-sm);padding:2px 6px" title="Remove">&times;</button>
      </div>
    `).join('');

    // Remove handlers
    ipListEl.querySelectorAll('.ip-remove').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.index);
        allowedIps.splice(idx, 1);
        renderIpList();
      });
    });
  }

  // Add new IP
  addBtn.addEventListener('click', () => {
    const value = newIpInput.value.trim();
    if (!value) return;
    if (!isValidIpOrCidr(value)) {
      errorEl.textContent = `Invalid IP or CIDR: "${value}"`;
      errorEl.style.display = 'block';
      return;
    }
    if (allowedIps.includes(value)) {
      errorEl.textContent = `"${value}" is already in the list`;
      errorEl.style.display = 'block';
      return;
    }
    errorEl.style.display = 'none';
    allowedIps.push(value);
    newIpInput.value = '';
    renderIpList();
  });

  newIpInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addBtn.click();
  });

  // Save
  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    saveMsg.textContent = 'Saving...';
    errorEl.style.display = 'none';
    try {
      const result = await rpc.call('noble_setAllowedIps', { allowed_ips: allowedIps });
      saveMsg.textContent = result.message || 'Saved';
      saveMsg.style.color = 'var(--success)';
      updateBadge();
    } catch (e) {
      errorEl.textContent = e.message || 'Failed to save';
      errorEl.style.display = 'block';
      saveMsg.textContent = '';
    } finally {
      saveBtn.disabled = false;
      setTimeout(() => { saveMsg.textContent = ''; }, 5000);
    }
  });

  function updateBadge() {
    if (allowedIps.length > 0) {
      accessBadge.textContent = 'Remote Access Enabled';
      accessBadge.className = 'badge inbound';
    } else {
      accessBadge.textContent = 'Localhost Only';
      accessBadge.className = 'badge outbound';
    }
  }

  // --- TLS cert helpers ---
  function renderTlsCert(info) {
    if (!info || !info.enabled) {
      tlsBadge.textContent = 'TLS Disabled';
      tlsBadge.className = 'badge';
      tlsBadge.style.background = 'var(--text-muted)';
      tlsDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">TLS is not enabled on this node.</dt>';
      tlsRegenBtn.disabled = true;
      tlsUploadBtn.disabled = true;
      return;
    }
    tlsRegenBtn.disabled = false;
    tlsUploadBtn.disabled = false;

    if (info.plaintext_mode) {
      tlsBadge.textContent = 'Plaintext Fallback';
      tlsBadge.className = 'badge';
      tlsBadge.style.background = 'var(--error)';
    } else if (info.auto_generated) {
      tlsBadge.textContent = 'Self-Signed';
      tlsBadge.className = 'badge outbound';
      tlsBadge.style.background = '';
    } else {
      tlsBadge.textContent = 'CA-Signed';
      tlsBadge.className = 'badge inbound';
      tlsBadge.style.background = '';
    }

    // Expiry badge color
    let expiryHtml = '--';
    if (info.expires_at) {
      const days = info.days_remaining;
      let color = 'var(--success)';
      if (days !== null && days !== undefined) {
        if (days <= 0) color = 'var(--error)';
        else if (days <= 30) color = 'var(--error)';
        else if (days <= 90) color = 'var(--warning, #f0a500)';
        const label = days <= 0 ? 'EXPIRED' : `${days} days`;
        const dateStr = info.expires_at.replace('T', ' ').replace('Z', ' UTC').slice(0, 20);
        expiryHtml = `${dateStr} <span style="color:${color};font-weight:600">(${label})</span>`;
      } else {
        expiryHtml = info.expires_at;
      }
    }

    const fp = info.fingerprint || '';
    const fpDisplay = fp.length > 16 ? fp.slice(0, 8) + '…' + fp.slice(-8) : fp;
    const sanList = (info.sans || []).join(', ') || '--';

    tlsDetails.innerHTML = `
      <dt>Fingerprint (SHA-256)</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${fpDisplay}</code>
        ${fp ? `<button class="btn-copy-fp btn-sm" data-fp="${fp}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>` : ''}
      </dd>
      <dt>Expires</dt><dd>${expiryHtml}</dd>
      <dt>SANs</dt><dd style="font-size:var(--font-size-xs);word-break:break-all">${sanList}</dd>
    `;

    tlsDetails.querySelector('.btn-copy-fp')?.addEventListener('click', (e) => {
      const full = e.currentTarget.dataset.fp;
      navigator.clipboard?.writeText(full).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }

  tlsRegenBtn.addEventListener('click', async () => {
    tlsRegenBtn.disabled = true;
    tlsRegenMsg.style.color = 'var(--text-muted)';
    tlsRegenMsg.textContent = 'Regenerating...';
    try {
      const result = await rpc.call('noble_regenerateTlsCert', { extra_sans: [] });
      tlsRegenMsg.style.color = 'var(--success)';
      tlsRegenMsg.innerHTML = `Done — new fingerprint: ${result.fingerprint.slice(0, 16)}… Restart node to apply.`;
      // Refresh the cert panel to show updated info.
      loadTlsCert();
    } catch (e) {
      tlsRegenMsg.style.color = 'var(--error)';
      tlsRegenMsg.textContent = e.message || 'Regeneration failed';
    } finally {
      tlsRegenBtn.disabled = false;
    }
  });

  tlsUploadBtn.addEventListener('click', async () => {
    tlsUploadError.style.display = 'none';
    tlsUploadMsg.textContent = '';
    const certPem = tlsCertPem.value.trim();
    const keyPem = tlsKeyPem.value.trim();
    const chainPem = tlsChainPem.value.trim() || null;
    if (!certPem || !keyPem) {
      tlsUploadError.textContent = 'Certificate PEM and Private Key PEM are required.';
      tlsUploadError.style.display = 'block';
      return;
    }
    tlsUploadBtn.disabled = true;
    tlsUploadMsg.style.color = 'var(--text-muted)';
    tlsUploadMsg.textContent = 'Uploading...';
    try {
      const result = await rpc.call('noble_uploadTlsCert', { cert_pem: certPem, key_pem: keyPem, chain_pem: chainPem });
      tlsUploadMsg.style.color = 'var(--success)';
      tlsUploadMsg.innerHTML = `Uploaded — SHA-256: ${result.fingerprint.slice(0, 16)}… Restart node to apply.`;
      tlsCertPem.value = '';
      tlsKeyPem.value = '';
      tlsChainPem.value = '';
      loadTlsCert();
    } catch (e) {
      tlsUploadError.textContent = e.message || 'Upload failed';
      tlsUploadError.style.display = 'block';
      tlsUploadMsg.textContent = '';
    } finally {
      tlsUploadBtn.disabled = false;
    }
  });

  async function loadTlsCert() {
    try {
      const info = await rpc.call('noble_getTlsCertInfo');
      renderTlsCert(info);
    } catch {
      tlsDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Unable to load TLS certificate info.</dt>';
    }
  }

  // --- TOTP Rotation ---
  totpRotateBtn.addEventListener('click', async () => {
    totpRotateError.style.display = 'none';
    totpRotateResult.style.display = 'none';
    const code = totpCodeInput.value.trim();
    if (code.length !== 6 || !/^\d{6}$/.test(code)) {
      totpRotateError.textContent = 'Enter a valid 6-digit TOTP code.';
      totpRotateError.style.display = 'block';
      return;
    }
    totpRotateBtn.disabled = true;
    try {
      // Hash the 6-digit code with SHA-256 (matching the middleware expectation).
      const encoder = new TextEncoder();
      const codeBytes = encoder.encode(code);
      const hashBuf = await crypto.subtle.digest('SHA-256', codeBytes);
      const hashHex = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      const result = await rpc.call('noble_rotateTotpSecret', { current_code_hash: hashHex });

      // Show new secret with auto-clear timer.
      let countdown = 60;
      let timerHandle;
      function showSecret() {
        totpRotateResult.style.display = 'block';
        totpRotateResult.style.color = 'var(--success)';
        totpRotateResult.innerHTML = `
          <p style="margin:0 0 var(--gap-xs);font-weight:600">New TOTP Secret (clears in <span id="s-totp-countdown">${countdown}s</span>)</p>
          <p style="margin:0 0 var(--gap-xs)"><strong>Base32:</strong> <code>${result.secret_base32}</code></p>
          <p style="margin:0;word-break:break-all"><strong>otpauth:</strong> <code style="font-size:10px">${result.otpauth_uri}</code></p>
        `;
        timerHandle = setInterval(() => {
          countdown--;
          const countEl = totpRotateResult.querySelector('#s-totp-countdown');
          if (countEl) countEl.textContent = countdown + 's';
          if (countdown <= 0) {
            clearInterval(timerHandle);
            totpRotateResult.style.display = 'none';
            totpRotateResult.innerHTML = '';
          }
        }, 1000);
      }
      showSecret();
      totpCodeInput.value = '';
    } catch (e) {
      totpRotateError.textContent = e.message || 'Rotation failed';
      totpRotateError.style.display = 'block';
    } finally {
      totpRotateBtn.disabled = false;
    }
  });

  // --- Validator Key card ---
  function renderValidatorKey(info) {
    if (!info || !info.enabled) {
      vkeyBadge.textContent = 'Observer Mode';
      vkeyBadge.className = 'badge';
      vkeyBadge.style.background = 'var(--text-muted)';
      vkeyDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Node is running in observer mode — no validator key configured.</dt>';
      return;
    }
    vkeyBadge.textContent = 'Active';
    vkeyBadge.className = 'badge inbound';
    vkeyBadge.style.background = '';

    const pk = info.pubkey_hex || '';
    const pkDisplay = pk.length > 16 ? pk.slice(0, 8) + '…' + pk.slice(-8) : pk;

    vkeyDetails.innerHTML = `
      <dt>Public Key</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${pkDisplay}</code>
        ${pk ? `<button class="btn-copy-vkey btn-sm" data-pk="${pk}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>` : ''}
      </dd>
      <dt>Scheme</dt><dd>${info.scheme || '--'}</dd>
      <dt>Key Path</dt><dd style="font-size:var(--font-size-xs);word-break:break-all">${info.key_path || '--'}</dd>
    `;
    vkeyDetails.querySelector('.btn-copy-vkey')?.addEventListener('click', (e) => {
      const full = e.currentTarget.dataset.pk;
      navigator.clipboard?.writeText(full).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }

  // --- P2P Identity card ---
  function renderP2pIdentity(nodeInfo) {
    const peerId = (nodeInfo && nodeInfo.peer_id) || '';
    if (!peerId) {
      p2pDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Peer ID not available.</dt>';
      return;
    }
    const peerIdDisplay = peerId.length > 20 ? peerId.slice(0, 12) + '…' + peerId.slice(-8) : peerId;
    p2pDetails.innerHTML = `
      <dt>Peer ID</dt>
      <dd style="display:flex;align-items:center;gap:var(--gap-sm)">
        <code style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${peerIdDisplay}</code>
        <button class="btn-copy-peerid btn-sm" data-pid="${peerId}" style="padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Copy</button>
      </dd>
    `;
    p2pDetails.querySelector('.btn-copy-peerid')?.addEventListener('click', (e) => {
      navigator.clipboard?.writeText(e.currentTarget.dataset.pid).catch(() => {});
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => { e.currentTarget.textContent = 'Copy'; }, 2000);
    });
  }


  // --- Encryption helpers ---
  function updateEncPasswordFields() {
    const target = encModeSelect.value;
    // Show current password when switching FROM manual
    encCurrentPwRow.style.display = (currentEncMode === 'manual' && target !== 'manual') ? '' : 'none';
    // Show new/confirm password when switching TO manual
    const toManual = (target === 'manual' && currentEncMode !== 'manual');
    encNewPwRow.style.display = toManual ? '' : 'none';
    encConfirmPwRow.style.display = toManual ? '' : 'none';
  }

  encModeSelect.addEventListener('change', updateEncPasswordFields);

  async function loadEncryptionStatus() {
    try {
      const info = await rpc.call('noble_getEncryptionStatus');
      currentEncMode = info.mode || 'automatic';
      encModeSelect.value = currentEncMode;
      updateEncPasswordFields();

      encBadge.textContent = currentEncMode === 'manual' ? 'Manual' : 'Automatic';
      encBadge.className = 'badge ' + (currentEncMode === 'manual' ? 'inbound' : 'outbound');
      encBadge.style.background = '';

      const modeLabel = currentEncMode === 'manual'
        ? 'Manual (password required on every startup)'
        : 'Automatic — less secure (no startup password)';
      const formatLabel = info.is_locked ? 'NBLK (password-locked)' : 'raw 32-byte entropy';

      encDetails.innerHTML = `
        <dt>Mode</dt><dd>${modeLabel}</dd>
        <dt>Chain Meta</dt><dd>${info.chain_meta_exists ? 'exists' : 'not created'}, ${formatLabel}</dd>
      `;
    } catch {
      encDetails.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">Unable to load encryption status.</dt>';
    }
  }

  encSwitchBtn.addEventListener('click', async () => {
    encError.style.display = 'none';
    encSwitchMsg.textContent = '';
    const target = encModeSelect.value;

    if (target === currentEncMode) {
      encSwitchMsg.textContent = 'Already in this mode.';
      return;
    }

    // Validate passwords
    if (target === 'manual') {
      const pw = encNewPw.value;
      if (!pw) {
        encError.textContent = 'New password is required for manual mode.';
        encError.style.display = 'block';
        return;
      }
      if (pw !== encConfirmPw.value) {
        encError.textContent = 'Passwords do not match.';
        encError.style.display = 'block';
        return;
      }
    }
    if (currentEncMode === 'manual' && target === 'automatic') {
      if (!encCurrentPw.value) {
        encError.textContent = 'Current password is required to switch from manual mode.';
        encError.style.display = 'block';
        return;
      }
    }

    encSwitchBtn.disabled = true;
    encSwitchMsg.textContent = 'Switching...';
    try {
      const rpcParams = { mode: target };
      if (currentEncMode === 'manual') rpcParams.current_password = encCurrentPw.value;
      if (target === 'manual') rpcParams.new_password = encNewPw.value;

      const result = await rpc.call('noble_setEncryptionMode', rpcParams);
      encSwitchMsg.style.color = 'var(--success)';
      encSwitchMsg.textContent = result.message || 'Mode switched. Restart node to apply.';
      encCurrentPw.value = '';
      encNewPw.value = '';
      encConfirmPw.value = '';
      loadEncryptionStatus();
    } catch (e) {
      encError.textContent = e.message || 'Mode switch failed';
      encError.style.display = 'block';
      encSwitchMsg.textContent = '';
    } finally {
      encSwitchBtn.disabled = false;
    }
  });

  // --- Seed node management ---
  function renderSeedList(seeds) {
    if (!seeds || seeds.length === 0) {
      seedListEl.innerHTML = `<div style="color:var(--text-muted);font-size:var(--font-size-sm);font-style:italic">No seed nodes configured (using default bootstrap)</div>`;
      seedBadge.textContent = '0 seeds';
      seedBadge.className = 'badge';
      seedBadge.style.background = 'var(--text-muted)';
      return;
    }
    seedBadge.textContent = `${seeds.length} seed${seeds.length > 1 ? 's' : ''}`;
    seedBadge.className = 'badge inbound';
    seedBadge.style.background = '';
    seedListEl.innerHTML = seeds.map((s, i) => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:4px 8px;margin-bottom:2px;background:var(--bg-tertiary);border-radius:var(--radius-sm)">
        <code style="font-size:var(--font-size-sm)">${s}</code>
        <button class="seed-remove" data-addr="${s}" style="background:none;border:none;color:var(--error);cursor:pointer;font-size:var(--font-size-sm);padding:2px 6px" title="Remove">&times;</button>
      </div>
    `).join('');
    seedListEl.querySelectorAll('.seed-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        const addr = btn.dataset.addr;
        try {
          const result = await rpc.call('noble_removeSeed', { multiaddr: addr });
          renderSeedList(result.seeds);
        } catch (e) {
          seedError.textContent = e.message || 'Remove failed';
          seedError.style.display = 'block';
        }
      });
    });
  }

  addSeedBtn.addEventListener('click', async () => {
    const value = newSeedInput.value.trim();
    if (!value) return;
    seedError.style.display = 'none';
    addSeedBtn.disabled = true;
    seedMsg.style.display = 'block';
    seedMsg.textContent = 'Adding...';
    try {
      const result = await rpc.call('noble_addSeed', { multiaddr: value });
      renderSeedList(result.seeds);
      newSeedInput.value = '';
      seedMsg.style.color = 'var(--success)';
      seedMsg.textContent = 'Seed added and dial initiated';
      setTimeout(() => { seedMsg.style.display = 'none'; }, 3000);
    } catch (e) {
      seedError.textContent = e.message || 'Failed to add seed';
      seedError.style.display = 'block';
      seedMsg.style.display = 'none';
    } finally {
      addSeedBtn.disabled = false;
    }
  });
  newSeedInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addSeedBtn.click();
  });

  async function loadSeeds() {
    try {
      const result = await rpc.call('noble_getSeeds');
      renderSeedList(result.seeds);
    } catch {
      seedListEl.innerHTML = '<div style="color:var(--text-muted);font-size:var(--font-size-sm)">Unable to load seeds.</div>';
    }
  }

  function showKeyManageModal(pubkey, scheme) {
    const short = pubkey.slice(0, 8) + '...' + pubkey.slice(-8);
    wkModal.innerHTML = `
      <div class="modal-overlay" id="s-wk-overlay" style="position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center">
        <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:520px;width:92%;max-height:85vh;overflow-y:auto">
          <div style="display:flex;justify-content:space-between;align-items:center;padding:var(--gap);border-bottom:1px solid var(--border)">
            <span style="font-weight:700">Manage Wallet Key</span>
            <button id="s-wk-modal-close" style="background:none;border:none;cursor:pointer;font-size:1.2em;color:var(--text-muted)">&times;</button>
          </div>
          <div style="padding:var(--gap)">
            <div style="margin-bottom:var(--gap);padding:8px 12px;background:var(--bg-tertiary);border-radius:var(--radius-sm)">
              <div style="font-size:var(--font-size-xs);color:var(--text-muted)">Current Key</div>
              <code style="font-size:var(--font-size-sm)">${short}</code>
              <span class="badge" style="font-size:10px;padding:1px 6px;margin-left:6px">${scheme}</span>
            </div>

            <div style="display:flex;flex-direction:column;gap:var(--gap)">
              <!-- Regenerate -->
              <div style="padding:var(--gap);border:1px solid var(--border);border-radius:var(--radius-sm)">
                <div style="font-weight:600;margin-bottom:var(--gap-xs)">Regenerate Key</div>
                <p style="font-size:var(--font-size-xs);color:var(--text-secondary);margin:0 0 var(--gap-sm)">
                  Generate a new random key, replacing the current one. The old key is permanently deleted.
                  <strong style="color:var(--error)">Any balance on the old address will become inaccessible.</strong>
                </p>
                <button id="s-wk-regenerate" class="btn btn-sm" style="background:var(--warning);color:#000;border:none">Regenerate New Key</button>
              </div>

              <!-- Replace via mnemonic -->
              <div style="padding:var(--gap);border:1px solid var(--border);border-radius:var(--radius-sm)">
                <div style="font-weight:600;margin-bottom:var(--gap-xs)">Replace from Mnemonic</div>
                <p style="font-size:var(--font-size-xs);color:var(--text-secondary);margin:0 0 var(--gap-sm)">
                  Import a mnemonic seed phrase (BIP-39) to replace the current key. Use this to restore a backup.
                </p>
                <div style="margin-bottom:var(--gap-sm)">
                  <textarea id="s-wk-mnemonic" rows="2" placeholder="Enter 12 or 24 mnemonic words separated by spaces"
                    style="width:100%;padding:6px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);resize:vertical"
                    spellcheck="false" autocomplete="off"></textarea>
                </div>
                <button id="s-wk-import" class="btn btn-sm">Replace with Mnemonic</button>
              </div>
            </div>

            <div id="s-wk-modal-msg" style="margin-top:var(--gap);font-size:var(--font-size-xs);display:none"></div>
          </div>
        </div>
      </div>
    `;

    const overlay = wkModal.querySelector('#s-wk-overlay');
    const modalMsg = wkModal.querySelector('#s-wk-modal-msg');
    function closeModal() { wkModal.innerHTML = ''; }
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
    wkModal.querySelector('#s-wk-modal-close').addEventListener('click', closeModal);

    function showMsg(text, color) {
      modalMsg.textContent = text;
      modalMsg.style.color = color;
      modalMsg.style.display = 'block';
    }

    // Regenerate: delete old key, generate new one
    wkModal.querySelector('#s-wk-regenerate').addEventListener('click', async () => {
      const btn = wkModal.querySelector('#s-wk-regenerate');
      if (!btn.dataset.confirmed) {
        btn.textContent = 'Are you sure? Click again to confirm';
        btn.style.background = 'var(--error)';
        btn.style.color = '#fff';
        btn.dataset.confirmed = '1';
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Regenerating...';
      try {
        // Delete old key first
        await rpc.call('noble_deleteAddress', { pubkey_hex: pubkey });
        // Generate new mnemonic key
        const result = await rpc.call('noble_generateMnemonic', { scheme: 'secp256k1' });
        showMsg('New key generated. SAVE YOUR MNEMONIC: ' + result.mnemonic, 'var(--success)');
        // Keep modal open so user can copy the mnemonic
        btn.textContent = 'Done';
        loadWalletKeys();
      } catch (e) {
        showMsg('Error: ' + (e.message || e), 'var(--error)');
        btn.disabled = false;
        btn.textContent = 'Regenerate New Key';
        delete btn.dataset.confirmed;
        btn.style.background = 'var(--warning)';
        btn.style.color = '#000';
      }
    });

    // Import mnemonic: delete old key, import from mnemonic
    wkModal.querySelector('#s-wk-import').addEventListener('click', async () => {
      const btn = wkModal.querySelector('#s-wk-import');
      const mnemonic = wkModal.querySelector('#s-wk-mnemonic').value.trim();
      if (!mnemonic) {
        showMsg('Enter a mnemonic phrase.', 'var(--error)');
        return;
      }
      const words = mnemonic.split(/\s+/);
      if (words.length !== 12 && words.length !== 24) {
        showMsg('Mnemonic must be 12 or 24 words.', 'var(--error)');
        return;
      }
      if (!btn.dataset.confirmed) {
        btn.textContent = 'This will replace the current key. Click again.';
        btn.style.background = 'var(--warning)';
        btn.style.color = '#000';
        btn.dataset.confirmed = '1';
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Replacing...';
      try {
        await rpc.call('noble_deleteAddress', { pubkey_hex: pubkey });
        const result = await rpc.call('noble_importMnemonic', { mnemonic, scheme: 'secp256k1' });
        showMsg('Key replaced successfully. New address: ' + result.address, 'var(--success)');
        btn.textContent = 'Done';
        loadWalletKeys();
      } catch (e) {
        showMsg('Error: ' + (e.message || e), 'var(--error)');
        btn.disabled = false;
        btn.textContent = 'Replace with Mnemonic';
        delete btn.dataset.confirmed;
        btn.style.background = '';
        btn.style.color = '';
      }
    });
  }

  // Load data
  async function loadWalletKeys() {
    try {
      const result = await rpc.call('noble_listAddresses');
      const keys = result.keys || [];
      wkBadge.textContent = `${keys.length} key${keys.length !== 1 ? 's' : ''}`;
      wkBadge.style.background = keys.length > 0 ? 'var(--success)' : 'var(--text-muted)';
      wkError.style.display = 'none';

      if (keys.length === 0) {
        wkListEl.innerHTML = `<div style="color:var(--text-muted);font-size:var(--font-size-sm);font-style:italic">No wallet keys. Generate one from the Identity page.</div>`;
        return;
      }

      wkListEl.innerHTML = keys.map(k => {
        const short = k.pubkey_hex.length > 16 ? k.pubkey_hex.slice(0, 8) + '...' + k.pubkey_hex.slice(-8) : k.pubkey_hex;
        const btcAddr = (k.bitcoin_addresses && k.bitcoin_addresses.length > 0)
          ? k.bitcoin_addresses.find(a => a.address_type === 'p2wpkh')
          : null;
        return `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;margin-bottom:4px;background:var(--bg-tertiary);border-radius:var(--radius-sm)">
            <div style="flex:1;min-width:0">
              <span class="badge" style="font-size:10px;padding:1px 6px;margin-right:6px">${k.scheme}</span>
              <code style="font-size:var(--font-size-xs)" title="${k.pubkey_hex}">${short}</code>
              ${btcAddr ? `<div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">${btcAddr.address}</div>` : ''}
            </div>
            <button class="wk-manage" data-pubkey="${k.pubkey_hex}" data-scheme="${k.scheme}" style="background:none;border:1px solid var(--border);color:var(--text-primary);cursor:pointer;font-size:var(--font-size-xs);padding:2px 8px;border-radius:var(--radius-sm);white-space:nowrap" title="Manage key">Manage</button>
          </div>`;
      }).join('');

      wkListEl.querySelectorAll('.wk-manage').forEach(btn => {
        btn.addEventListener('click', () => {
          const pubkey = btn.dataset.pubkey;
          const scheme = btn.dataset.scheme;
          showKeyManageModal(pubkey, scheme);
        });
      });
    } catch (e) {
      wkBadge.textContent = '?';
      wkListEl.innerHTML = `<div style="color:var(--text-muted);font-size:var(--font-size-sm)">Could not load wallet keys.</div>`;
    }
  }

  // ── Reward address ──
  async function loadRewardAddress() {
    try {
      const res = await rpc.call('noble_getRewardAddress');
      if (res.configured) {
        rewardInfo.innerHTML = `
          <dt>Address</dt><dd class="mono">${res.address}</dd>
          <dt>Type</dt><dd>${res.address_type || 'Unknown'}</dd>
        `;
        rewardInput.value = res.address;
      } else {
        rewardInfo.innerHTML = `<dt style="grid-column:1/-1;color:var(--text-muted)">No reward address configured.</dt>`;
        rewardInput.value = '';
        // Auto-suggest wallet key
        try {
          const walletKeys = await rpc.call('noble_listAddresses');
          const secpKey = (walletKeys.keys || []).find(k => k.scheme === 'secp256k1' && k.bitcoin_addresses && k.bitcoin_addresses.length > 0);
          if (secpKey) {
            const p2wpkh = secpKey.bitcoin_addresses.find(a => a.address_type === 'p2wpkh');
            if (p2wpkh) rewardInput.value = p2wpkh.address;
          }
        } catch (_) { /* wallet may be locked */ }
      }
    } catch (e) {
      console.error('[settings] load reward address:', e);
      rewardInfo.innerHTML = `<dt style="grid-column:1/-1;color:var(--text-muted)">Could not load reward address.</dt>`;
    }
  }

  rewardSave.addEventListener('click', async () => {
    const addr = rewardInput.value.trim();
    if (!addr) {
      rewardMsg.style.color = 'var(--error)';
      rewardMsg.textContent = 'Please enter an address.';
      return;
    }
    rewardSave.disabled = true;
    rewardSave.textContent = 'Saving...';
    rewardMsg.textContent = '';
    try {
      const res = await rpc.call('noble_setRewardAddress', { address: addr });
      rewardMsg.style.color = 'var(--success)';
      rewardMsg.textContent = `Saved: ${res.address_type} address (${res.display_address})`;
      await loadRewardAddress();
    } catch (e) {
      rewardMsg.style.color = 'var(--error)';
      rewardMsg.textContent = 'Error: ' + (e.message || e);
    } finally {
      rewardSave.disabled = false;
      rewardSave.textContent = 'Save';
    }
  });

  async function loadSettings() {
    // Load TLS cert, encryption status, seeds, wallet keys, and reward address in parallel.
    loadTlsCert();
    loadEncryptionStatus();
    loadSeeds();
    loadWalletKeys();
    loadRewardAddress();

    try {
      const [ipResult, nodeInfo, vkeyInfo] = await Promise.all([
        rpc.call('noble_getAllowedIps'),
        rpc.call('noble_getNodeInfo'),
        rpc.call('noble_getValidatorKeyInfo').catch(() => null),
      ]);

      // IP Access Control
      allowedIps = ipResult.allowed_ips || [];
      renderIpList();
      updateBadge();

      // Auth status using getTotpStatus RPC
      try {
        const totpInfo = await rpc.call('noble_getTotpStatus');
        totpStatus.textContent = totpInfo.enabled ? 'Enabled' : 'Not configured';
        totpStatus.style.color = totpInfo.enabled ? 'var(--success)' : 'var(--text-muted)';
        authMode.textContent = totpInfo.enabled ? `TOTP (scope: ${totpInfo.scope})` : 'None';
        const totpEnableSection = root.querySelector('#s-totp-enable-section');
        if (totpInfo.enabled) {
          totpRotateSection.style.display = 'block';
          totpEnableSection.style.display = 'none';
          totpEnableSection.innerHTML = '';
        } else {
          totpRotateSection.style.display = 'none';
          // Populate the stable enable container (cleared first to avoid duplicates)
          totpEnableSection.innerHTML = `
            <button id="s-enable-totp-btn" class="btn-sm" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-sm)">Enable TOTP</button>
            <span id="s-enable-totp-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-sm)"></span>
            <div id="s-enable-totp-result" style="display:none;margin-top:var(--gap-sm);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);font-size:var(--font-size-xs)"></div>
          `;
          totpEnableSection.style.display = 'block';
          totpEnableSection.querySelector('#s-enable-totp-btn').addEventListener('click', async function() {
            this.disabled = true;
            const msg = totpEnableSection.querySelector('#s-enable-totp-msg');
            const result = totpEnableSection.querySelector('#s-enable-totp-result');
            msg.textContent = 'Enabling...';
            try {
              const resp = await rpc.call('noble_enableTotp');
              result.style.display = 'block';
              result.style.color = 'var(--success)';
              result.innerHTML = `
                <p style="margin:0 0 var(--gap-xs);font-weight:600">TOTP Enabled — save this secret now:</p>
                <p style="margin:0 0 var(--gap-xs)"><strong>Base32:</strong> <code>${resp.secret_base32}</code></p>
                <p style="margin:0;word-break:break-all"><strong>otpauth:</strong> <code style="font-size:10px">${resp.otpauth_uri}</code></p>
              `;
              msg.textContent = '';
              this.style.display = 'none';
              totpStatus.textContent = 'Enabled';
              totpStatus.style.color = 'var(--success)';
              authMode.textContent = 'TOTP (scope: all)';
            } catch (e) {
              msg.textContent = e.message || 'Failed';
              msg.style.color = 'var(--error)';
              this.disabled = false;
            }
          });
        }
      } catch {
        const hasAuth = rpc.hasAuthToken ? rpc.hasAuthToken() : false;
        totpStatus.textContent = hasAuth ? 'Active' : 'Not configured';
        authMode.textContent = hasAuth ? 'TOTP' : 'None';
        if (hasAuth) totpRotateSection.style.display = 'block';
      }

      // Ports with inline P2P edit
      portsEl.innerHTML = `
        <dt>RPC (JSON-RPC)</dt><dd>${nodeInfo.rpc_port}</dd>
        <dt>WebSocket</dt><dd>${nodeInfo.ws_port}</dd>
        <dt>P2P</dt>
        <dd id="s-p2p-port-dd">
          <span id="s-p2p-port-val">${nodeInfo.p2p_port}</span>
          <button id="s-p2p-edit-btn" class="btn-sm" style="margin-left:var(--gap-sm);padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Edit</button>
          <span id="s-p2p-edit-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-sm)"></span>
        </dd>
        <dt>Dashboard (GUI)</dt><dd>8785</dd>
      `;
      const p2pEditBtn = root.querySelector('#s-p2p-edit-btn');
      const p2pPortVal = root.querySelector('#s-p2p-port-val');
      const p2pEditMsg = root.querySelector('#s-p2p-edit-msg');
      const p2pPortDd = root.querySelector('#s-p2p-port-dd');
      if (p2pEditBtn) {
        p2pEditBtn.addEventListener('click', () => {
          const currentPort = p2pPortVal.textContent.trim();
          p2pPortDd.innerHTML = `
            <select id="s-p2p-port-input"
              style="padding:4px 8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-sm)">
              <option value="8780"${currentPort === '8780' ? ' selected' : ''}>8780</option>
              <option value="8781"${currentPort === '8781' ? ' selected' : ''}>8781</option>
              <option value="8782"${currentPort === '8782' ? ' selected' : ''}>8782</option>
            </select>
            <button id="s-p2p-save" class="btn-sm" style="margin-left:var(--gap-sm);padding:4px 10px;background:var(--success);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Save</button>
            <button id="s-p2p-cancel" class="btn-sm" style="margin-left:var(--gap-xs);padding:4px 10px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:var(--font-size-xs)">Cancel</button>
            <span id="s-p2p-save-msg" style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-sm)"></span>
          `;
          root.querySelector('#s-p2p-cancel').addEventListener('click', () => loadSettings());
          root.querySelector('#s-p2p-save').addEventListener('click', async () => {
            const port = root.querySelector('#s-p2p-port-input').value;
            const msg = root.querySelector('#s-p2p-save-msg');
            try {
              const result = await rpc.call('noble_setConfigValue', { section: 'network', key: 'listen_addr', value: `/ip4/0.0.0.0/tcp/${port}` });
              msg.style.color = 'var(--success)';
              msg.innerHTML = result.restart_required ? 'Saved — run <code>brew services restart noble</code>' : 'Saved';
              setTimeout(() => loadSettings(), 2000);
            } catch (e) {
              msg.style.color = 'var(--error)';
              msg.textContent = e.message || 'Save failed';
            }
          });
        });
      }

      // New key/identity cards
      renderValidatorKey(vkeyInfo);
      renderP2pIdentity(nodeInfo);
    } catch (e) {
      console.error('[settings] load:', e);
    }
  }

  loadSettings();

  // --- Chain Management ---
  let cachedNodeInfo = null;
  // Pre-fetch nodeInfo for chain label (also fetched inside loadSettings, but we
  // need it accessible in the chain management scope).
  rpc.call('noble_getNodeInfo').then(ni => { cachedNodeInfo = ni; }).catch(() => {});

  const chainInfoEl = root.querySelector('#s-chain-info');
  const forkWrap = root.querySelector('#s-fork-table-wrap');
  const chainGear = root.querySelector('#s-chain-gear');
  const chainModal = root.querySelector('#s-chain-modal');
  const chainModalClose = root.querySelector('#s-chain-modal-close');
  const chainModalCancel = root.querySelector('#s-chain-modal-cancel');
  const chainModalReset = root.querySelector('#s-chain-modal-reset');
  const chainModalForks = root.querySelector('#s-chain-modal-forks');
  const chainModalDatadir = root.querySelector('#s-chain-modal-datadir');
  const chainModalMsg = root.querySelector('#s-chain-modal-msg');
  const chainModalBackup = root.querySelector('#s-chain-modal-backup');

  let latestForkData = null;

  function renderForkTable(data, container, withRadio) {
    if (!data.forks || data.forks.length === 0) {
      container.innerHTML = '<p style="font-size:var(--font-size-xs);color:var(--text-muted)">No peer data available</p>';
      return;
    }
    if (data.forks.length <= 1 && !withRadio) {
      container.innerHTML = '<p style="font-size:var(--font-size-xs);color:var(--text-muted)">No forks detected — all peers on same chain</p>';
      return;
    }

    const chainLabel = cachedNodeInfo ? formatChainLabel(cachedNodeInfo) : '';

    let rows = data.forks.map((f, i) => {
      const label = f.is_local
        ? '<span style="color:var(--success)">\u25CF Our chain</span>'
        : (f.height > data.local_height ? '<span style="color:var(--warning)">\u26A0 Longer fork</span>' : 'Alternative');
      const radioCol = withRadio
        ? `<td><input type="radio" name="s-fork-select" value="${i}" ${!f.is_local ? '' : 'disabled'} style="accent-color:var(--accent)"></td>`
        : '';
      return `<tr style="${f.is_local ? 'background:rgba(var(--success-rgb,52,211,153),0.08)' : ''}">
        ${radioCol}
        <td style="font-family:var(--font-mono);font-size:var(--font-size-xs)">${chainLabel}</td>
        <td>${f.height}</td>
        <td>${f.peers}</td>
        <td>${label}</td>
      </tr>`;
    }).join('');

    const radioHeader = withRadio ? '<th style="width:30px"></th>' : '';
    container.innerHTML = `<table class="mini-table" style="width:100%;font-size:var(--font-size-sm)">
      <thead><tr>${radioHeader}<th>Chain</th><th>Height</th><th>Peers</th><th>Status</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  }

  async function loadForks() {
    try {
      const data = await rpc.call('noble_getDetectedForks');
      latestForkData = data;
      // No blocks committed — show clear "waiting" state
      if (data.local_height === 0) {
        chainInfoEl.innerHTML = '<dt style="grid-column:1/-1;color:var(--text-muted)">No blocks committed \u2014 waiting for genesis</dt>';
        forkWrap.innerHTML = '';
        return;
      }
      // Render chain info
      const chainLabel = cachedNodeInfo ? formatChainLabel(cachedNodeInfo) : '';
      chainInfoEl.innerHTML = `
        <dt>Chain</dt><dd>${chainLabel || '\u2014'}</dd>
        <dt>Height</dt><dd>${data.local_height}</dd>
      `;
      renderForkTable(data, forkWrap, false);
    } catch (e) {
      forkWrap.innerHTML = '<p style="font-size:var(--font-size-xs);color:var(--text-muted)">Fork detection unavailable</p>';
    }
  }

  loadForks();
  const forkTimer = setInterval(loadForks, 30000);

  // Modal open/close
  function openChainModal() {
    chainModalMsg.textContent = '';
    // Refresh forks for the modal
    if (latestForkData) {
      renderForkTable(latestForkData, chainModalForks, true);
    }
    // Show data directory path
    rpc.call('noble_getNodeInfo').then(info => {
      chainModalDatadir.innerHTML = info.data_dir
        ? `<strong>Data directory:</strong> <code>${info.data_dir}</code>`
        : 'Data directory path not available.';
    }).catch(() => {
      chainModalDatadir.textContent = 'Data directory path not available.';
    });
    chainModal.style.display = 'flex';
  }
  function closeChainModal() { chainModal.style.display = 'none'; }

  chainGear.addEventListener('click', openChainModal);
  chainModalClose.addEventListener('click', closeChainModal);
  chainModalCancel.addEventListener('click', closeChainModal);
  chainModal.addEventListener('click', (e) => { if (e.target === chainModal) closeChainModal(); });

  chainModalBackup.addEventListener('click', async () => {
    chainModalMsg.textContent = 'Creating backup...';
    chainModalMsg.style.color = 'var(--text-muted)';
    chainModalBackup.disabled = true;
    try {
      const result = await rpc.call('noble_backupChain');
      const sizeMb = (result.size_bytes / (1024 * 1024)).toFixed(1);
      chainModalMsg.style.color = 'var(--success)';
      chainModalMsg.innerHTML = `Backup saved: <code style="font-size:var(--font-size-xs)">${result.path}</code> (${sizeMb} MB)`;
    } catch (e) {
      chainModalMsg.style.color = 'var(--error)';
      chainModalMsg.textContent = e.message || 'Backup failed';
    } finally {
      chainModalBackup.disabled = false;
    }
  });

  chainModalReset.addEventListener('click', async () => {
    chainModalMsg.textContent = 'Resetting...';
    chainModalMsg.style.color = 'var(--text-muted)';
    chainModalReset.disabled = true;
    try {
      const result = await rpc.call('noble_resetChain');
      chainModalMsg.style.color = 'var(--success)';
      chainModalMsg.textContent = `Reset complete (was height ${result.previous_height}). Re-syncing from peers...`;
      setTimeout(() => { loadForks(); closeChainModal(); }, 2000);
    } catch (e) {
      chainModalMsg.style.color = 'var(--error)';
      chainModalMsg.textContent = e.message || 'Reset failed';
    } finally {
      chainModalReset.disabled = false;
    }
  });

  return {
    destroy() {
      clearInterval(forkTimer);
      closeChainModal();
    },
  };
}
