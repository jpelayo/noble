/**
 * NOBLE Dashboard — Consensus Page
 * PoR cycle superposition timeline + Accepted Validator Registry
 */

import { formatNumber, formatCountdown, bytesToHex, truncateHash, timeAgo, formatTimestamp, formatChainLabel } from '../utils.js';

function extractIpFromMultiaddr(ma) {
  if (!ma) return '--';
  const m = ma.match(/\/ip[46]\/([^/]+)/);
  return m ? m[1] : '--';
}

/** Escape HTML-special characters to prevent XSS via peer-supplied names. */
function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Phase & status colors ──
const PHASE_COLORS = {
  'Block Proposal':  { bg: '#3b82f6', fg: '#fff' },
  'Voting':          { bg: '#8b5cf6', fg: '#fff' },
  'Reflection':      { bg: '#10b981', fg: '#fff' },
  'Propagation':     { bg: '#f59e0b', fg: '#fff' },
};

const STATE_STYLES = {
  complete: 'opacity:1',
  active:   'opacity:1;box-shadow:0 0 0 2px var(--accent)',
  pending:  'opacity:0.3',
  skipped:  'opacity:0.2',
};

export function init(root, ctx) {
  const { rpc, ws, getState } = ctx;
  const unsubs = [];
  let countdownInterval = null;

  // Helper: extract hex key from ValidatorEntry.public_key
  // Live API returns a hex string; mock returns { Ed25519: [u8] } or { Secp256k1: [u8] }.
  function valKeyHex(pk) {
    if (typeof pk === 'string') return pk;
    const k = pk.Ed25519 || pk.Secp256k1 || [];
    return k.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── Validator name lookup map (pubkey hex → friendly name) ──
  const validatorNameMap = new Map();
  function getValidatorDisplayName(pubkeyHex, maxLen) {
    if (!pubkeyHex) return '—';
    const name = validatorNameMap.get(pubkeyHex);
    if (name) return escapeHtml(name);
    return truncateHash(pubkeyHex, maxLen || 6);
  }

  // ── Peer ID → friendly name cache (populated from announce events) ──
  const peerIdToName = new Map();
  // ── Deferred peer_connected events: hold until name is known (max 3s) ──
  const deferredPeerEvents = new Map(); // peer_id → { data, timer }
  function getPeerDisplayName(peerId) {
    if (!peerId) return '—';
    const name = peerIdToName.get(peerId);
    if (name) return name;
    return truncateHash(peerId, 6);
  }

  root.innerHTML = `
    <div class="page-header" style="display:flex;align-items:baseline;gap:var(--gap-sm)">
      <div style="flex:1"><h1 style="display:inline">Consensus</h1><p>Proof of Reputation cycle status, accepted validator registry, and network candidate discovery</p></div>
      <button id="cs-badge-gear" title="Badge Governance" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1;flex-shrink:0;align-self:flex-start">&#9881;</button>
    </div>

    <!-- Superposition Timeline -->
    <div class="panel">
      <div class="panel-header">
        <span>Cycle Superposition Timeline</span>
        <span id="cs-chain-badge" style="font-weight:500;font-size:var(--font-size-xs);padding:2px 8px;border-radius:9999px;background:var(--bg-tertiary);color:var(--text-secondary)"></span>
        <span style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted);margin-left:auto">Last 3 cycles</span>
      </div>
      <div class="panel-body">
        <!-- Phase pipeline -->
        <div style="display:flex;align-items:center;gap:0;margin-bottom:var(--gap-lg);flex-wrap:wrap">
          <div style="font-weight:700;font-size:var(--font-size-sm);color:var(--text-muted);margin-right:var(--gap-sm)">CYCLE: <span id="cs-cycle-info">#--</span></div>
          <div id="cs-phase-pipeline" style="display:flex;align-items:center;gap:0;flex:1;min-width:0;flex-wrap:wrap"></div>
        </div>

        <!-- Timeline rows (filled by JS) -->
        <div id="cs-timeline"></div>

        <!-- Validator activity summary -->
        <div id="cs-activity-summary" style="margin-top:var(--gap-lg);padding-top:var(--gap);border-top:1px solid var(--border)"></div>
      </div>
    </div>

    <!-- Cycle detail grid (kept compact) -->
    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Current Cycle Details</div>
        <div class="panel-body">
          <dl class="detail-grid">
            <dt>Cycle Number</dt><dd id="cs-cycle-num">--</dd>
            <dt>Phase</dt><dd id="cs-phase-name">--</dd>
            <dt>Phase Remaining</dt><dd id="cs-phase-remaining">--</dd>
            <dt>Cycle Remaining</dt><dd id="cs-cycle-remaining">--</dd>
            <dt>Current Validator</dt><dd id="cs-validator" class="mono">--</dd>
          </dl>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <span>Protocol Activity</span>
          <button id="cs-activity-clear" title="Clear log" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:2px 8px;cursor:pointer;color:var(--text-muted);font-size:var(--font-size-xs);line-height:1.4">Clear</button>
        </div>
        <div class="panel-body" id="cs-activity-log" style="max-height:220px;overflow-y:auto;font-family:var(--font-mono);font-size:var(--font-size-xs);line-height:1.6;padding:var(--gap-xs)">
          <div style="color:var(--text-muted)">Waiting for events...</div>
        </div>
      </div>
    </div>

    <!-- Voting Strategy Configuration -->
    <div class="panel">
      <div class="panel-header">
        <span>Voting Strategy</span>
        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
          <span style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)">Per-round strategy configuration</span>
          <button id="cs-strategy-help" title="Strategy reference" style="background:none;border:1px solid var(--border);border-radius:50%;width:22px;height:22px;cursor:pointer;color:var(--text-muted);font-size:12px;line-height:1;display:flex;align-items:center;justify-content:center;padding:0">?</button>
        </div>
      </div>
      <div class="panel-body">
        <div class="split-layout">
          <div>
            <div class="kpi-label" style="margin-bottom:var(--gap-xs)">ROUND 1 — REFLECTION</div>
            <select id="cs-r1-strategy" class="form-select" style="width:100%;margin-bottom:var(--gap-sm)">
              <option value="first_valid">First Valid</option>
              <option value="fixed_validator">Fixed Validator</option>
              <option value="round_robin">Round Robin</option>
              <option value="subset_rotation">Subset Rotation</option>
              <option value="random">Random</option>
              <option value="weighted_reputation">Weighted Reputation</option>
              <option value="weighted_probability">Weighted Probability</option>
              <option value="follow_majority">Follow Majority</option>
              <option value="manual">Manual</option>
            </select>
            <div id="cs-r1-params" style="display:none;margin-bottom:var(--gap-sm)">
              <input id="cs-r1-validator-key" type="text" placeholder="Validator pubkey (hex)" style="width:100%" spellcheck="false">
              <div id="cs-r1-subset-area" style="display:none;margin-top:var(--gap-sm)">
                <textarea id="cs-r1-subset-keys" rows="4"
                  placeholder="One validator pubkey (hex) per line"
                  style="width:100%;font-family:var(--font-mono);font-size:var(--font-size-xs)"
                  spellcheck="false"></textarea>
                <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">
                  One hex pubkey per line. Rotation follows list order.
                </div>
              </div>
            </div>
            <div id="cs-r1-desc" style="font-size:var(--font-size-xs);color:var(--text-muted)"></div>
          </div>
          <div>
            <div class="kpi-label" style="margin-bottom:var(--gap-xs)">ROUND 2 — CONFIRMATION</div>
            <select id="cs-r2-strategy" class="form-select" style="width:100%;margin-bottom:var(--gap-sm)">
              <option value="first_valid">First Valid</option>
              <option value="fixed_validator">Fixed Validator</option>
              <option value="round_robin">Round Robin</option>
              <option value="subset_rotation">Subset Rotation</option>
              <option value="random">Random</option>
              <option value="weighted_reputation">Weighted Reputation</option>
              <option value="weighted_probability">Weighted Probability</option>
              <option value="follow_majority">Follow Majority</option>
              <option value="manual">Manual</option>
            </select>
            <div id="cs-r2-params" style="display:none;margin-bottom:var(--gap-sm)">
              <input id="cs-r2-validator-key" type="text" placeholder="Validator pubkey (hex)" style="width:100%" spellcheck="false">
              <div id="cs-r2-subset-area" style="display:none;margin-top:var(--gap-sm)">
                <textarea id="cs-r2-subset-keys" rows="4"
                  placeholder="One validator pubkey (hex) per line"
                  style="width:100%;font-family:var(--font-mono);font-size:var(--font-size-xs)"
                  spellcheck="false"></textarea>
                <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">
                  One hex pubkey per line. Rotation follows list order.
                </div>
              </div>
            </div>
            <div id="cs-r2-desc" style="font-size:var(--font-size-xs);color:var(--text-muted)"></div>
          </div>
        </div>
        <div style="margin-top:var(--gap);display:flex;align-items:center;gap:var(--gap-sm)">
          <button class="btn btn-sm" id="cs-save-strategy">Save Strategies</button>
          <span id="cs-strategy-status" style="font-size:var(--font-size-xs);color:var(--success)"></span>
        </div>
      </div>
    </div>

    <!-- Voting Strategy Help Modal -->
    <div id="cs-strategy-modal" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);align-items:center;justify-content:center">
      <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:720px;width:92%;max-height:85vh;overflow-y:auto;padding:var(--gap-lg);position:relative">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap)">
          <h3 style="margin:0">Voting Strategy Reference</h3>
          <button id="cs-strategy-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.5rem;cursor:pointer;padding:0 4px;line-height:1" title="Close">&times;</button>
        </div>
        <table class="mini-table" style="width:100%;font-size:var(--font-size-sm)">
          <thead><tr><th>Strategy</th><th>Behaviour</th></tr></thead>
          <tbody>
            <tr><td style="white-space:nowrap;font-weight:600">First Valid</td><td>Accept the first candidate block that passes validation. Fast, no preference.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Fixed Validator</td><td>Always vote for a specific validator (pubkey). Useful for delegating trust to a known operator.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Round Robin</td><td>Rotate votes across validators in priority order (drag to reorder in the validator list). Ensures fair block production over time.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Subset Rotation</td><td>Rotate votes across a manually-defined subset of validators. Gives control over the rotation pool.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Random</td><td>Vote for a random valid candidate each cycle. Simple, unpredictable.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Weighted Reputation</td><td>Always vote for the candidate with the highest reputation score. Rewards good behaviour.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Weighted Probability</td><td>Probabilistic voting weighted by priority order position. Higher in the list = more likely but not guaranteed.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Follow Majority</td><td>Wait for tally data and vote with the current plurality. Converges quickly, avoids splits.</td></tr>
            <tr><td style="white-space:nowrap;font-weight:600">Manual</td><td>No automatic vote. Use the <em>Cast Manual Vote</em> panel below to vote by hand each cycle.</td></tr>
          </tbody>
        </table>
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:var(--gap)">
          <strong>Round 1</strong> selects the candidate block. <strong>Round 2</strong> ratifies the R1 winner —
          if R2 disagrees, its vote overrides R1. Strategies persist to <code>noble.toml</code>.
        </p>
      </div>
    </div>

    <!-- Vote Tallies -->
    <div class="panel">
      <div class="panel-header">
        <span>Live Vote Tallies</span>
        <span id="cs-tally-meta" style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)"></span>
      </div>
      <div class="panel-body" id="cs-tallies-body">
        <div class="empty-state">No votes recorded for the current cycle.</div>
      </div>
    </div>

    <!-- Manual Vote Casting -->
    <div class="panel" id="cs-manual-vote-panel" style="display:none">
      <div class="panel-header">
        <span>Cast Manual Vote</span>
        <span id="cs-manual-phase" style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)"></span>
      </div>
      <div class="panel-body">
        <div class="form-group">
          <label>Candidate Block</label>
          <select id="cs-manual-candidate" class="form-select" style="width:100%">
            <option value="">— No candidates yet —</option>
          </select>
          <div class="form-hint">Candidates from the current cycle's vote tallies.</div>
        </div>
        <div style="display:flex;gap:var(--gap-sm);align-items:center;margin-top:var(--gap-sm)">
          <button class="btn btn-sm" id="cs-cast-vote-btn">Cast Vote</button>
          <span id="cs-cast-status" style="font-size:var(--font-size-xs)"></span>
        </div>
      </div>
    </div>

    <!-- Accepted Validator Registry -->
    <div class="panel">
      <div class="panel-header">
        <span>Accepted Validator Registry</span>
        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
          <span id="cs-policy" style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)"></span>
          <button class="btn btn-sm" id="cs-add-validator">+ Add Validator</button>
        </div>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
          You maintain this list sovereignly. Add validators by pasting their Node ID (public key), received out-of-band.
        </p>
        <div class="kpi-grid" style="margin-bottom:var(--gap)">
          <div class="kpi-card"><div class="kpi-label">Total Validators</div><div class="kpi-value" id="cs-val-total">--</div></div>
          <div class="kpi-card"><div class="kpi-label">Online</div><div class="kpi-value" id="cs-val-online" style="color:var(--success)">--</div></div>
          <div class="kpi-card"><div class="kpi-label">Offline</div><div class="kpi-value" id="cs-val-offline" style="color:var(--text-muted)">--</div></div>
          <div class="kpi-card"><div class="kpi-label">Avg Reputation</div><div class="kpi-value" id="cs-val-avg-rep">--</div></div>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th style="width:32px" title="Drag to set priority order">&#9776;</th><th>#</th><th>Validator</th><th>IP</th><th>Country</th><th>Status</th><th>Reputation</th><th title="Block acceptance rate (weight 0.4)">Acceptance</th><th title="Uptime ratio (weight 0.3)">Uptime</th><th title="Trust score (weight 0.3)">Trust</th><th>Blocks</th><th title="Validators listing this peer">Listers</th><th>Last Active</th><th></th></tr></thead>
          <tbody id="cs-validators"></tbody>
        </table>
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:4px">Drag rows to set priority order &mdash; used by Round Robin and Weighted Probability strategies.</p>
      </div>
    </div>

    <!-- Network Candidates — Discovered Peers -->
    <div class="panel">
      <div class="panel-header">
        <span>Network Candidates &mdash; Discovered Peers</span>
        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
          <span id="cs-candidate-count" style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)"></span>
          <button class="btn btn-secondary btn-sm" id="cs-prune-stale">Prune Stale</button>
        </div>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
          Peers discovered via GossipSub that want to participate in consensus. Add them to your accepted validator list after out-of-band verification.
        </p>
      </div>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead><tr><th>Node Name</th><th>IP</th><th>Country</th><th>Org Type</th><th>Role</th><th>Last Seen</th><th>First Seen</th><th>Connections</th><th></th></tr></thead>
          <tbody id="cs-candidates"></tbody>
        </table>
      </div>
      <div id="cs-candidates-empty" class="empty-state" style="display:none;padding:var(--gap-lg)">No candidate peers discovered yet.</div>
    </div>

    <div id="cs-detail-panel"></div>
    <div id="cs-modal-container"></div>

    <!-- Badge Governance Modal -->
    <div id="cs-badge-modal" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);align-items:center;justify-content:center">
      <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:900px;width:95%;max-height:80vh;overflow-y:auto;padding:var(--gap-lg)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap)">
          <h2 style="margin:0;font-size:1.2rem">Badge Governance</h2>
          <button id="badge-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.5rem;cursor:pointer;padding:0 4px;line-height:1" title="Close">&times;</button>
        </div>
        <div style="display:flex;gap:var(--gap-sm);margin-bottom:var(--gap);border-bottom:1px solid var(--border);padding-bottom:var(--gap-sm)">
          <button class="badge-tab-btn" data-tab="holders" data-active="true" style="padding:4px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;background:var(--accent);color:#fff;font-size:var(--font-size-sm)">Badge Holders</button>
          <button class="badge-tab-btn" data-tab="proposals" style="padding:4px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;background:var(--bg-tertiary);color:var(--text);font-size:var(--font-size-sm)">Active Proposals</button>
          <button class="badge-tab-btn" data-tab="propose" style="padding:4px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;background:var(--bg-tertiary);color:var(--text);font-size:var(--font-size-sm)">Propose</button>
          <button class="badge-tab-btn" data-tab="history" style="padding:4px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;background:var(--bg-tertiary);color:var(--text);font-size:var(--font-size-sm)">History</button>
        </div>

        <!-- Tab: Badge Holders -->
        <div id="badge-tab-holders" class="badge-tab-content">
          <table style="width:100%;border-collapse:collapse;font-size:var(--font-size-sm)">
            <thead><tr style="border-bottom:1px solid var(--border)">
              <th style="text-align:left;padding:6px 8px">Pubkey</th>
              <th style="text-align:left;padding:6px 8px">Name</th>
              <th style="text-align:left;padding:6px 8px">Status</th>
              <th style="text-align:right;padding:6px 8px">Granted At</th>
              <th style="text-align:right;padding:6px 8px">Last Seen</th>
              <th style="text-align:center;padding:6px 8px">Action</th>
            </tr></thead>
            <tbody id="badge-holders-body"></tbody>
          </table>
          <div id="badge-holders-empty" style="text-align:center;color:var(--text-muted);padding:var(--gap-lg);display:none">No badge holders yet.</div>
        </div>

        <!-- Tab: Active Proposals -->
        <div id="badge-tab-proposals" class="badge-tab-content" style="display:none">
          <div id="badge-proposals-list"></div>
          <div id="badge-proposals-empty" style="text-align:center;color:var(--text-muted);padding:var(--gap-lg);display:none">No active proposals.</div>
        </div>

        <!-- Tab: Propose -->
        <div id="badge-tab-propose" class="badge-tab-content" style="display:none">
          <div style="max-width:500px">
            <label style="display:block;margin-bottom:var(--gap-xs);font-weight:600;font-size:var(--font-size-sm)">Target Pubkey (hex)</label>
            <input id="badge-propose-target" type="text" placeholder="33-byte wire pubkey hex" style="width:100%;margin-bottom:var(--gap-sm);font-family:var(--font-mono);font-size:var(--font-size-xs)" spellcheck="false">

            <label style="display:block;margin-bottom:var(--gap-xs);font-weight:600;font-size:var(--font-size-sm)">Proposal Type</label>
            <select id="badge-propose-type" class="form-select" style="width:100%;margin-bottom:var(--gap-sm)">
              <option value="grant">Grant Badge</option>
              <option value="revoke">Revoke Badge</option>
            </select>

            <div id="badge-propose-reason-wrap" style="display:none">
              <label style="display:block;margin-bottom:var(--gap-xs);font-weight:600;font-size:var(--font-size-sm)">Revocation Reason</label>
              <select id="badge-propose-reason" class="form-select" style="width:100%;margin-bottom:var(--gap-sm)">
                <option value="DuplicateProposal">Duplicate Proposal</option>
                <option value="ProtocolAbuse">Protocol Abuse</option>
                <option value="ExtendedAbsence">Extended Absence</option>
                <option value="Misrepresentation">Misrepresentation</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <button id="badge-propose-submit" class="btn btn-primary" style="margin-top:var(--gap-sm)">Submit Proposal</button>
            <div id="badge-propose-status" style="margin-top:var(--gap-sm);font-size:var(--font-size-xs)"></div>
          </div>
        </div>

        <!-- Tab: History -->
        <div id="badge-tab-history" class="badge-tab-content" style="display:none">
          <table style="width:100%;border-collapse:collapse;font-size:var(--font-size-sm)">
            <thead><tr style="border-bottom:1px solid var(--border)">
              <th style="text-align:left;padding:6px 8px">Type</th>
              <th style="text-align:left;padding:6px 8px">Target</th>
              <th style="text-align:left;padding:6px 8px">Reason</th>
              <th style="text-align:right;padding:6px 8px">Votes For</th>
              <th style="text-align:right;padding:6px 8px">Votes Against</th>
              <th style="text-align:left;padding:6px 8px">Result</th>
              <th style="text-align:right;padding:6px 8px">Cycle</th>
            </tr></thead>
            <tbody id="badge-history-body"></tbody>
          </table>
          <div id="badge-history-empty" style="text-align:center;color:var(--text-muted);padding:var(--gap-lg);display:none">No proposal history.</div>
        </div>
      </div>
    </div>
  `;

  // ── DOM refs ──
  const csPipeline = root.querySelector('#cs-phase-pipeline');
  const csCycleInfo = root.querySelector('#cs-cycle-info');
  const csCycleNum = root.querySelector('#cs-cycle-num');
  const csPhaseName = root.querySelector('#cs-phase-name');
  const csPhaseRemaining = root.querySelector('#cs-phase-remaining');
  const csCycleRemaining = root.querySelector('#cs-cycle-remaining');
  const csValidator = root.querySelector('#cs-validator');
  const csActivityLog = root.querySelector('#cs-activity-log');
  const csActivityClear = root.querySelector('#cs-activity-clear');
  const csTimeline = root.querySelector('#cs-timeline');
  const csActivitySummary = root.querySelector('#cs-activity-summary');
  const csPolicy = root.querySelector('#cs-policy');
  const csValTotal = root.querySelector('#cs-val-total');
  const csValOnline = root.querySelector('#cs-val-online');
  const csValOffline = root.querySelector('#cs-val-offline');
  const csValAvgRep = root.querySelector('#cs-val-avg-rep');
  const modalContainer = root.querySelector('#cs-modal-container');
  const validatorsTbody = root.querySelector('#cs-validators');
  const detailPanel = root.querySelector('#cs-detail-panel');
  const candidatesTbody = root.querySelector('#cs-candidates');
  const csCandidateCount = root.querySelector('#cs-candidate-count');
  const candidatesEmpty = root.querySelector('#cs-candidates-empty');

  // Voting strategy DOM refs
  const r1Select = root.querySelector('#cs-r1-strategy');
  const r2Select = root.querySelector('#cs-r2-strategy');
  const r1Params = root.querySelector('#cs-r1-params');
  const r2Params = root.querySelector('#cs-r2-params');
  const r1Desc = root.querySelector('#cs-r1-desc');
  const r2Desc = root.querySelector('#cs-r2-desc');
  const saveStrategyBtn = root.querySelector('#cs-save-strategy');
  const strategyStatus = root.querySelector('#cs-strategy-status');
  const strategyHelpBtn = root.querySelector('#cs-strategy-help');
  const strategyModal = root.querySelector('#cs-strategy-modal');
  const strategyModalClose = root.querySelector('#cs-strategy-modal-close');
  const tallyMeta = root.querySelector('#cs-tally-meta');
  const talliesBody = root.querySelector('#cs-tallies-body');

  const STRATEGY_DESCRIPTIONS = {
    first_valid: 'Vote for the first valid block received. Fast but biased toward low-latency validators.',
    fixed_validator: 'Always vote for a specific validator. Falls back to first valid if they don\'t propose.',
    round_robin: 'Rotate through validators in priority order each cycle (drag rows to reorder).',
    subset_rotation: 'Rotate through a user-defined subset of preferred validators.',
    random: 'Randomly select among valid candidates (deterministic per cycle).',
    weighted_reputation: 'Vote for the candidate from the highest-weight validator.',
    weighted_probability: 'Probabilistic vote weighted by priority order — higher in the list = more likely.',
    follow_majority: 'Wait for tallies, then vote for the leading candidate.',
    manual: 'Do not auto-vote. Requires manual vote via RPC or GUI each cycle.',
  };

  // ── Protocol Activity Log ──
  // ── Debounced reload scheduler ──
  // Merges multiple rapid WS events into a single batch of RPC calls.
  let _pendingReloads = new Set();
  let _reloadTimer = null;
  function scheduleReload(...fns) {
    for (const f of fns) _pendingReloads.add(f);
    if (!_reloadTimer) {
      _reloadTimer = setTimeout(() => {
        _reloadTimer = null;
        const batch = [..._pendingReloads];
        _pendingReloads.clear();
        batch.forEach(f => f());
      }, 150);
    }
  }

  const ACTIVITY_MAX_ENTRIES = 100;
  const activityEntries = []; // circular buffer (oldest at 0)

  const ACTIVITY_ICONS = {
    block_committed:    '\u2713',  // checkmark
    block_proposed:     '\u25b6',  // right triangle
    block_received:     '\u25bc',  // down triangle
    block_announced:    '\u25b7',  // right triangle outline
    block_requested:    '\u2190',  // left arrow
    vote_broadcast:     '\u2191',  // up arrow
    vote_received:      '\u2193',  // down arrow
    peer_connected:     '\u2192',  // right arrow
    peer_disconnected:  '\u00d7',  // multiplication sign
    peer_banned:        '\u2298',  // circled division
    peer_status:        '\u2022',  // bullet
    announce_received:  '\u2022',  // bullet
    announce_published: '\u2022',  // bullet
    tx_announced:       '\u2022',  // bullet
    sync_complete:      '\u21bb',  // clockwise arrow
    sync_requested:     '\u21bb',  // clockwise arrow
    reconnect_attempt:  '\u21ba',  // counter-clockwise arrow
    evidence_received:  '\u26a0',  // warning triangle
    evidence_published: '\u26a0',  // warning triangle
    blockchain_discovered: '\u2728', // sparkles
    consensus_log:      '\u2022',  // bullet
    warning:            '\u26a0',  // warning triangle
    phase_change:       '\u25cf',  // filled circle
    heartbeat:          '\u25cf',  // filled circle
  };

  function activityColor(evt) {
    switch (evt) {
      case 'block_committed': return 'var(--success, #22c55e)';
      case 'sync_complete': return 'var(--success, #22c55e)';
      case 'warning':
      case 'peer_banned':
      case 'evidence_received':
      case 'evidence_published': return 'var(--danger, #ef4444)';
      case 'vote_broadcast':
      case 'vote_received': return 'var(--accent, #3b82f6)';
      case 'phase_change': return '#f59e0b';
      case 'block_proposed':
      case 'block_received':
      case 'block_announced': return '#a78bfa';
      case 'peer_connected': return '#34d399';
      case 'peer_disconnected': return '#f87171';
      case 'announce_received':
      case 'announce_published': return '#60a5fa';
      case 'reconnect_attempt': return '#fbbf24';
      case 'peer_wrong_chain': return 'var(--danger, #ef4444)';
      case 'blockchain_discovered': return '#c084fc';
      case 'sync_requested': return '#94a3b8';
      case 'heartbeat': return '#6ee7b7';
      default: return 'var(--text-muted)';
    }
  }

  function formatActivityMessage(data) {
    // Enriched events carry a pre-formatted message.
    if (data.message && (data.event === 'block_proposed' || data.event === 'vote_broadcast')) return data.message;
    const vName = (id) => getValidatorDisplayName(id, 8);
    const pName = (id) => truncateHash(id || '', 6);
    switch (data.event) {
      case 'block_committed': {
        const who = data.proposer_name || vName(data.proposer) || '';
        return `Block #${data.height} committed${who ? ` by ${who}` : ''} (${truncateHash(data.hash || '')}, ${data.tx_count} tx)`;
      }
      case 'block_proposed':
        return `Proposed block #${data.height}`;
      case 'block_received': {
        const from = data.proposer_name || vName(data.proposer) || pName(data.peer_id);
        return `Block #${data.height} received from ${from}`;
      }
      case 'block_announced':
        return `Block #${data.height} announced by ${peerIdToName.get(data.peer_id) || pName(data.peer_id)}`;
      case 'block_requested':
        return `Requested block ${truncateHash(data.hash || '')}`;
      case 'vote_broadcast':
        return `Vote broadcast R${data.round} \u2192 ${truncateHash(data.block_hash || '')}`;
      case 'vote_received': {
        const voter = data.voter_name || vName(data.voter_id);
        const candidate = data.candidate_name || truncateHash(data.candidate_hash || '', 6);
        return `Vote R${data.round} received from ${voter} \u2192 ${candidate}`;
      }
      case 'peer_connected':
        return `Peer connected: ${data.node_name || peerIdToName.get(data.peer_id) || pName(data.peer_id)} (${data.direction || ''})`;
      case 'peer_disconnected':
        return `Peer disconnected: ${data.node_name || peerIdToName.get(data.peer_id) || pName(data.peer_id)}`;
      case 'peer_banned':
        return `Peer banned: ${peerIdToName.get(data.peer_id) || pName(data.peer_id)} \u2014 ${data.reason}`;
      case 'peer_status':
        return `Peer ${peerIdToName.get(data.peer_id) || pName(data.peer_id)} at height ${data.height}`;
      case 'announce_received':
        return `${data.node_name || pName(data.identity)} v${data.software_version || '?'}${data.wants_to_validate ? ' \u2022 validator' : ''}${data.wants_to_vote ? ' \u2022 voter' : ''} \u2014 ${data.connected ? 'connected' : 'via gossip'}`;
      case 'tx_announced':
        return `Tx ${truncateHash(data.tx_id || '')} from ${peerIdToName.get(data.peer_id) || pName(data.peer_id)}`;
      case 'sync_complete':
        return `Sync complete \u2192 height ${data.height}`;
      case 'evidence_received': {
        const etype = data.type === 'vote_equivocation' ? 'Vote equivocation' : 'Double-proposal';
        return `${etype} evidence from ${peerIdToName.get(data.peer_id) || pName(data.peer_id)}`;
      }
      case 'evidence_published': {
        const etype = data.type === 'vote_equivocation' ? 'Vote equivocation' : 'Double-proposal';
        return `${etype} evidence published (${truncateHash(data.evidence_hash || '')})`;
      }
      case 'peer_wrong_chain':
        return `Kicked ${data.peer_name || pName(data.peer_id)} \u2014 wrong chain (${data.their_chain_id})`;
      case 'blockchain_discovered':
        return `Blockchain discovered: ${data.chain_id} from ${data.peer_name || 'unknown peer'}`;
      case 'consensus_log':
        return data.message;
      case 'warning':
        return data.message;
      case 'phase_change':
        return `Phase \u2192 ${data.phase}${data.cycle != null ? ` (cycle #${data.cycle})` : ''}`;
      case 'announce_published':
        return `NodeAnnounce published${data.node_name ? ` (${data.node_name})` : ''}`;
      case 'reconnect_attempt':
        return `Reconnect: dialing ${data.addresses} address(es) (${data.current_peers} peers)`;
      case 'sync_requested':
        return 'Sync requested \u2014 polling peer chain tips';
      case 'heartbeat':
        return data.message;
      default:
        return JSON.stringify(data);
    }
  }

  function pushActivity(data) {
    const now = new Date();
    const ts = String(now.getHours()).padStart(2, '0') + ':' +
               String(now.getMinutes()).padStart(2, '0') + ':' +
               String(now.getSeconds()).padStart(2, '0');
    activityEntries.push({ ts, data });
    // Cap at max — drop oldest
    if (activityEntries.length > ACTIVITY_MAX_ENTRIES) {
      activityEntries.splice(0, activityEntries.length - ACTIVITY_MAX_ENTRIES);
    }
    renderActivityLog();
  }

  function renderActivityLog() {
    if (!activityEntries.length) {
      csActivityLog.innerHTML = '<div style="color:var(--text-muted)">Waiting for events...</div>';
      return;
    }
    // Render newest first, reuse innerHTML (fast for <100 entries)
    let html = '';
    for (let i = activityEntries.length - 1; i >= 0; i--) {
      const { ts, data } = activityEntries[i];
      const icon = ACTIVITY_ICONS[data.event] || '\u2022';
      const color = activityColor(data.event);
      const msg = formatActivityMessage(data);
      html += `<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span style="color:var(--text-muted)">${ts}</span> <span style="color:${color}">${icon}</span> ${escapeHtml(msg)}</div>`;
    }
    csActivityLog.innerHTML = html;
  }

  // Clear button
  csActivityClear.addEventListener('click', () => {
    activityEntries.length = 0;
    renderActivityLog();
  });

  // Push peer_connected with deferred name resolution: if no name is known yet,
  // hold the event for up to 3 s waiting for the announce_received that carries
  // the friendly name.  If the announce arrives in time, emit with name.
  // If timeout, emit with whatever is available (hash as last resort).
  function pushPeerEvent(data) {
    const pid = data.peer_id;
    const name = data.node_name || peerIdToName.get(pid);
    if (name) {
      data.node_name = name;
      pushActivity(data);
      return;
    }
    // No name yet — defer up to 3 s.
    const timer = setTimeout(() => {
      deferredPeerEvents.delete(pid);
      data.node_name = peerIdToName.get(pid) || '';
      pushActivity(data);
    }, 3000);
    deferredPeerEvents.set(pid, { data, timer });
  }

  function flushDeferredPeer(peerId, name) {
    const entry = deferredPeerEvents.get(peerId);
    if (!entry) return;
    clearTimeout(entry.timer);
    deferredPeerEvents.delete(peerId);
    entry.data.node_name = name;
    pushActivity(entry.data);
  }

  // Subscribe to cyclePhaseChange + peerUpdates WS topics for the activity feed.
  // Both streams are normalized into a single scrolling list.
  if (ws && ws.subscribe) {
    unsubs.push(ws.subscribe('cyclePhaseChange', (data) => {
      // Cache peer names from announce events for display resolution.
      if (data.event === 'announce_received' && data.node_name) {
        if (data.peer_id) {
          peerIdToName.set(data.peer_id, data.node_name);
          // Flush any deferred peer_connected event now that we have the name.
          flushDeferredPeer(data.peer_id, data.node_name);
        }
        // Also populate validatorNameMap (identity_key → name) so vote/block
        // events can resolve names immediately without waiting for refreshList().
        if (data.identity) validatorNameMap.set(data.identity, data.node_name);
      }
      // Events with enriched follow-up messages: push the enriched version only
      // (skip the raw event to avoid duplicate log lines).
      if (data.event === 'block_proposed' && data.hash) {
        pushActivity({ event: 'block_proposed', message: `This node proposed block #${data.height || '?'} (${truncateHash(data.hash)})` });
      } else if (data.event === 'vote_broadcast') {
        const target = data.candidate_name || truncateHash(data.block_hash || '', 6);
        pushActivity({ event: 'vote_broadcast', message: `This node voted for ${target} (R${data.round || 1})` });
      } else if (data.event === 'peer_connected') {
        pushPeerEvent(data);
      } else {
        pushActivity(data);
      }
      // Push follow-up context for enriched phase transitions.
      if (data.event === 'phase_change') {
        if (data.phase === 'Reflection' && data.total_votes != null) {
          const leader = data.leader_name || truncateHash(data.leader_hash || '', 6);
          pushActivity({ event: 'consensus_log', message: `Voting results favor ${leader} with ${data.leader_pct}% of votes (${data.total_votes} total)` });
        }
        if (data.phase === 'Propagation' && (data.winner_name || data.winner_hash)) {
          const winner = data.winner_name || truncateHash(data.winner_hash || '', 6);
          pushActivity({ event: 'consensus_log', message: `Winning proposer: ${winner}` });
        }
      }
      // Refresh data panels on significant events
      if (data.event === 'block_committed') {
        scheduleReload(loadCycle, loadTimeline, loadVoteTallies, loadValidators);
      }
      // Refresh tallies on vote events (live updates)
      if (data.event === 'vote_received' || data.event === 'vote_broadcast') {
        scheduleReload(loadVoteTallies);
      }
      // Refresh cycle display on phase changes
      if (data.event === 'phase_change') {
        scheduleReload(loadCycle, loadVoteTallies);
      }
    }));
    unsubs.push(ws.subscribe('peerUpdates', (data) => {
      // Normalize peerUpdates event names to match activity log conventions.
      const normalized = { ...data };
      if (data.event === 'connected') normalized.event = 'peer_connected';
      else if (data.event === 'disconnected') normalized.event = 'peer_disconnected';
      // Defer peer_connected until name is known (max 3s wait for announce).
      if (normalized.event === 'peer_connected') {
        pushPeerEvent(normalized);
      } else {
        pushActivity(normalized);
      }
    }));
  }


  // Seed activity log on page load: current phase + already-connected peers.
  // Phase is seeded once; peers are retried a few times to catch late reconnections.
  let seededPeerIds = new Set();

  function seedPhase() {
    rpc.call('noble_getCycleStatus').then(status => {
      if (status && status.phase) {
        pushActivity({ event: 'phase_change', phase: status.phase, cycle: status.cycle_number });
      }
    }).catch(() => {});
  }

  function seedPeers() {
    // Pre-populate peer names from peer memory BEFORE seeding connections.
    // Must chain: getPeerInfo needs peerIdToName populated by getPeerMemory.
    rpc.call('noble_getPeerMemory').then(records => {
      if (Array.isArray(records)) {
        for (const r of records) {
          if (r.peer_id && r.node_name) peerIdToName.set(r.peer_id, r.node_name);
        }
      }
      // Now that names are populated, seed peer connections.
      return rpc.call('noble_getPeerInfo');
    }).then(peers => {
      if (Array.isArray(peers)) {
        for (const p of peers) {
          if (p.status === 'connected' && !seededPeerIds.has(p.peer_id)) {
            seededPeerIds.add(p.peer_id);
            pushPeerEvent({ event: 'peer_connected', peer_id: p.peer_id || '', addr: p.addr || '', direction: p.direction || '', node_name: peerIdToName.get(p.peer_id) || '' });
          }
        }
      }
    }).catch(() => {});
  }

  // ── Startup seed: lightweight "node is alive" snapshot ──
  function seedNodeStatus() {
    rpc.call('noble_getNodeInfo').then(info => {
      if (info) {
        pushActivity({ event: 'heartbeat', message: `Node v${info.version}` });
      }
    }).catch(() => {});
  }

  function seedReconnectStatus() {
    rpc.call('noble_getPeerInfo').then(peers => {
      const connected = Array.isArray(peers) ? peers.filter(p => p.status === 'connected') : [];
      pushActivity({ event: 'heartbeat', message: `${connected.length} peer(s) connected \u2014 reconnect loop armed` });
    }).catch(() => {});
  }

  seedNodeStatus();
  seedPhase();
  seedPeers();
  seedReconnectStatus();
  // Retry peer seeding at 3s, 8s, 15s to catch late reconnections after node restart
  const seedTimers = [3000, 8000, 15000].map(delay =>
    setTimeout(() => seedPeers(), delay)
  );
  unsubs.push(() => seedTimers.forEach(t => clearTimeout(t)));

  // ── WS reconnect recovery: refresh all panels after reconnection ──
  // Events were missed during the disconnect window — re-fetch everything.
  function onWsReconnect() {
    pushActivity({ event: 'heartbeat', message: 'WebSocket reconnected — refreshing data' });
    scheduleReload(loadCycle, loadTimeline, loadVoteTallies, loadValidators);
    seedPeers();
  }
  window.addEventListener('noble-ws-reconnect', onWsReconnect);
  unsubs.push(() => window.removeEventListener('noble-ws-reconnect', onWsReconnect));

  function updateManualVoteVisibility() {
    const panel = root.querySelector('#cs-manual-vote-panel');
    const isManual = r1Select.value === 'manual' || r2Select.value === 'manual';
    panel.style.display = isManual ? '' : 'none';
  }

  function updateStrategyUI(select, paramsEl, descEl, prefix) {
    const strategy = select.value;
    descEl.textContent = STRATEGY_DESCRIPTIONS[strategy] || '';
    const validatorInput = root.querySelector(`#${prefix}-validator-key`);
    const subsetArea = root.querySelector(`#${prefix}-subset-area`);
    validatorInput.style.display = (strategy === 'fixed_validator') ? '' : 'none';
    subsetArea.style.display = (strategy === 'subset_rotation') ? '' : 'none';
    paramsEl.style.display = (strategy === 'fixed_validator' || strategy === 'subset_rotation') ? '' : 'none';
    updateManualVoteVisibility();
  }

  r1Select.addEventListener('change', () => updateStrategyUI(r1Select, r1Params, r1Desc, 'cs-r1'));
  r2Select.addEventListener('change', () => updateStrategyUI(r2Select, r2Params, r2Desc, 'cs-r2'));

  // Help modal
  strategyHelpBtn.addEventListener('click', () => { strategyModal.style.display = 'flex'; });
  strategyModalClose.addEventListener('click', () => { strategyModal.style.display = 'none'; });
  strategyModal.addEventListener('click', (e) => { if (e.target === strategyModal) strategyModal.style.display = 'none'; });

  async function loadVotingStrategy() {
    try {
      const result = await rpc.call('noble_getVotingStrategy');
      r1Select.value = result.round1_strategy;
      r2Select.value = result.round2_strategy;
      if (result.round1_params && result.round1_params.validator_key) {
        root.querySelector('#cs-r1-validator-key').value = result.round1_params.validator_key;
      }
      if (result.round2_params && result.round2_params.validator_key) {
        root.querySelector('#cs-r2-validator-key').value = result.round2_params.validator_key;
      }
      if (result.round1_params?.validators) {
        root.querySelector('#cs-r1-subset-keys').value = result.round1_params.validators.join('\n');
      }
      if (result.round2_params?.validators) {
        root.querySelector('#cs-r2-subset-keys').value = result.round2_params.validators.join('\n');
      }
      updateStrategyUI(r1Select, r1Params, r1Desc, 'cs-r1');
      updateStrategyUI(r2Select, r2Params, r2Desc, 'cs-r2');
    } catch (e) {
      console.error('[consensus] load voting strategy:', e);
    }
  }

  saveStrategyBtn.addEventListener('click', async () => {
    try {
      saveStrategyBtn.disabled = true;
      strategyStatus.textContent = '';

      // Save Round 1
      const r1Name = r1Select.value;
      let r1p = null;
      if (r1Name === 'fixed_validator') {
        r1p = { validator_key: root.querySelector('#cs-r1-validator-key').value.trim() };
      } else if (r1Name === 'subset_rotation') {
        r1p = { validators: root.querySelector('#cs-r1-subset-keys').value
          .split('\n').map(s => s.trim()).filter(Boolean) };
      }
      await rpc.call('noble_setVotingStrategy', { round: 1, strategy: r1Name, params: r1p });

      // Save Round 2
      const r2Name = r2Select.value;
      let r2p = null;
      if (r2Name === 'fixed_validator') {
        r2p = { validator_key: root.querySelector('#cs-r2-validator-key').value.trim() };
      } else if (r2Name === 'subset_rotation') {
        r2p = { validators: root.querySelector('#cs-r2-subset-keys').value
          .split('\n').map(s => s.trim()).filter(Boolean) };
      }
      await rpc.call('noble_setVotingStrategy', { round: 2, strategy: r2Name, params: r2p });

      strategyStatus.textContent = 'Saved';
      setTimeout(() => { strategyStatus.textContent = ''; }, 3000);
    } catch (e) {
      strategyStatus.style.color = 'var(--error)';
      strategyStatus.textContent = e.message || 'Failed';
      setTimeout(() => { strategyStatus.textContent = ''; strategyStatus.style.color = 'var(--success)'; }, 5000);
    } finally {
      saveStrategyBtn.disabled = false;
    }
  });

  // ── Manual vote cast handler ──
  root.querySelector('#cs-cast-vote-btn').addEventListener('click', async () => {
    const hash = root.querySelector('#cs-manual-candidate').value;
    if (!hash) return;
    const btn = root.querySelector('#cs-cast-vote-btn');
    const status = root.querySelector('#cs-cast-status');
    try {
      btn.disabled = true;
      await rpc.call('noble_castVote', { block_hash: hash });
      status.textContent = 'Vote cast';
      status.style.color = 'var(--success)';
    } catch (e) {
      status.textContent = e.message || 'Failed';
      status.style.color = 'var(--error)';
    } finally {
      btn.disabled = false;
      setTimeout(() => { status.textContent = ''; }, 5000);
    }
  });

  async function loadVoteTallies() {
    try {
      const result = await rpc.call('noble_getVoteTallies');
      tallyMeta.textContent = `Cycle #${formatNumber(result.cycle ?? 0)} — ${result.phase || '--'}`;

      // Update manual vote phase indicator
      const manualPhase = root.querySelector('#cs-manual-phase');
      manualPhase.textContent = `Cycle #${formatNumber(result.cycle)} — ${result.phase}`;

      if (!result.tallies || result.tallies.length === 0) {
        talliesBody.innerHTML = '<div class="empty-state">No votes recorded for the current cycle.</div>';
        // Clear manual candidate dropdown
        const candidateSelect = root.querySelector('#cs-manual-candidate');
        candidateSelect.innerHTML = '<option value="">— No candidates yet —</option>';
        return;
      }
      const total = result.tallies.reduce((s, t) => s + t.vote_count, 0);
      talliesBody.innerHTML = result.tallies.map(t => {
        const pct = total > 0 ? Math.round(t.vote_count / total * 100) : 0;
        const name = t.validator || truncateHash(t.block_hash, 8);
        return `<div style="display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap-sm)">
          <span style="font-weight:600;font-size:var(--font-size-xs);min-width:90px;flex-shrink:0">${name}</span>
          <div style="flex:1;min-width:40px;height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${pct}%;background:var(--accent);border-radius:4px;transition:width 0.3s"></div>
          </div>
          <span style="font-weight:600;flex-shrink:0;text-align:right">${t.vote_count} (${pct}%)</span>
        </div>`;
      }).join('');

      // Populate manual vote candidate dropdown
      const candidateSelect = root.querySelector('#cs-manual-candidate');
      candidateSelect.innerHTML = '<option value="">— Select candidate —</option>' +
        result.tallies.map(t => {
          const name = t.validator ? `${t.validator} — ` : '';
          return `<option value="${t.block_hash}">${name}${t.block_hash.slice(0,16)}... (${t.vote_count} votes)</option>`;
        }).join('');
    } catch (e) {
      console.error('[consensus] load tallies:', e);
    }
  }

  const PHASES = ['Block Proposal', 'Voting', 'Reflection', 'Propagation'];
  const PHASE_DURATION = 300; // 5:00 per phase

  // ══════════════════════════════════════════════
  // SUPERPOSITION TIMELINE
  // ══════════════════════════════════════════════

  /** Transform flat API entry into the phase-based format renderTimeline expects. */
  function apiEntryToCycle(entry, isCurrent) {
    // If already has phases (mock data), pass through.
    if (entry.phases) return entry;
    const hasWinner = !!entry.winner;
    const indeterminate = entry.status === 'indeterminate' || (!hasWinner && !isCurrent);
    // Sort proposals by validator key for deterministic display across nodes
    const sortedProposals = [...(entry.proposals || [])].sort((a, b) => a.validator.localeCompare(b.validator));

    return {
      cycle_number: entry.cycle_number,
      is_current: isCurrent,
      indeterminate,
      disambiguation: entry.disambiguation,
      winner: entry.winner,
      winning_hash: entry.winning_hash,
      phases: [
        {
          name: 'Block Proposal',
          state: isCurrent && !hasWinner ? 'active' : 'complete',
          proposals: sortedProposals,
        },
        {
          name: 'Voting',
          state: isCurrent && !hasWinner ? 'active' : 'complete',
          votes: entry.votes || [],
          total_voters: (entry.votes || []).reduce((s, v) => s + v.vote_count, 0),
        },
        {
          name: 'Reflection',
          state: indeterminate ? 'skipped' : hasWinner ? 'complete' : isCurrent ? 'pending' : 'complete',
          winner: entry.winner,
          winning_hash: entry.winning_hash,
          disambiguation: entry.disambiguation,
        },
        {
          name: 'Propagation',
          state: indeterminate ? 'skipped' : hasWinner ? 'complete' : isCurrent ? 'pending' : 'complete',
          finalized: hasWinner,
          block_hash: entry.winning_hash,
        },
      ],
    };
  }

  const TIMELINE_LIMIT = 4;

  async function loadTimeline() {
    try {
      // Request more than needed so we can filter out empty indeterminate cycles.
      const history = await rpc.call('noble_getCycleHistory', [TIMELINE_LIMIT * 5]);
      let allEntries = (history.entries || history.cycles || [])
        .filter(e => e.status !== 'indeterminate' || (e.proposals && e.proposals.length > 0) || (e.votes && e.votes.length > 0));

      // Filter stale entries from previous chains: entries arrive newest-first.
      // If a gap > 20 appears between consecutive entries, the older group is the
      // current chain and the isolated high-numbered entry is from a previous chain.
      // Keep only the largest contiguous group.
      if (allEntries.length >= 2) {
        for (let i = 1; i < allEntries.length; i++) {
          const gap = allEntries[i - 1].cycle_number - allEntries[i].cycle_number;
          if (gap > 20) {
            // Entries [0..i-1] are isolated outliers, [i..] is the real chain
            // unless the outlier group is larger (unlikely after reset).
            if (i <= allEntries.length - i) {
              allEntries = allEntries.slice(i); // drop high outliers, keep low contiguous
            } else {
              allEntries = allEntries.slice(0, i); // keep high group
            }
            break;
          }
        }
      }

      const raw = allEntries.slice(0, TIMELINE_LIMIT);
      if (raw.length === 0) {
        csTimeline.innerHTML = '<div class="empty-state">No consensus cycles yet</div>';
        return;
      }
      const cycles = raw.map((e, i) =>
        apiEntryToCycle(e, i === 0 && (e.status === 'active' || !e.finalized_at))
      );

      // Fetch per-block vote witnesses for recent blocks.
      // These survive ClearCycleHistory and carry individual voter names.
      try {
        const tipInfo = await rpc.call('noble_getSyncStatus', []);
        const tipHeight = tipInfo ? tipInfo.current_height : 0;
        const votePromises = [];
        for (let h = tipHeight; h >= Math.max(1, tipHeight - TIMELINE_LIMIT); h--) {
          votePromises.push(rpc.call('noble_getBlockVotes', [h]).catch(() => null));
        }
        const voteResults = await Promise.all(votePromises);
        for (const bv of voteResults) {
          if (!bv) continue;
          const match = cycles.find(c => c.cycle_number === bv.cycle_number);
          if (match) match._blockVotes = bv;
        }
      } catch (_) { /* getSyncStatus or getBlockVotes not available */ }

      // Fetch finality status for per-block finality badges.
      let finalityStatus = null;
      try {
        finalityStatus = await rpc.call('noble_getFinalityStatus', []);
      } catch (_) { /* getFinalityStatus not available */ }

      renderTimeline(cycles, finalityStatus);
    } catch (e) {
      console.error('[consensus] load timeline:', e);
      csTimeline.innerHTML = '<div class="empty-state">Failed to load cycle history</div>';
    }
  }

  function renderTimeline(cycles, finalityStatus) {
    csTimeline.innerHTML = '';

    // Track all validators that participated
    const participantMap = new Map(); // validator_name → { role[], cycles[] }

    for (const cycle of cycles) {
      const row = document.createElement('div');
      row.style.cssText = 'margin-bottom:var(--gap-lg)';

      // ── Cycle header ──
      const statusLabel = cycle.is_current ? 'ACTIVE' : cycle.indeterminate ? 'NO CONSENSUS' : 'FINALIZED';
      const statusColor = cycle.is_current ? 'var(--accent)' : cycle.indeterminate ? 'var(--text-muted)' : 'var(--success)';
      let disambigBadge = '';
      if (!cycle.indeterminate) {
        disambigBadge = cycle.disambiguation
          ? `<span style="margin-left:var(--gap-sm);padding:1px 6px;border-radius:9999px;font-size:var(--font-size-xs);background:color-mix(in srgb, var(--warning) 15%, transparent);color:var(--warning)">disambiguation</span>`
          : `<span style="margin-left:var(--gap-sm);padding:1px 6px;border-radius:9999px;font-size:var(--font-size-xs);background:color-mix(in srgb, var(--success) 15%, transparent);color:var(--success)">clean</span>`;
      }

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap-xs)';
      header.innerHTML = `
        <span style="font-weight:700;font-size:var(--font-size-sm)">Cycle #${formatNumber(cycle.cycle_number)}</span>
        <span style="font-size:var(--font-size-xs);color:${statusColor};font-weight:600">${statusLabel}</span>
        ${disambigBadge}
        ${cycle.winner ? `<span style="margin-left:auto;font-size:var(--font-size-xs);color:var(--text-secondary)">Winner: <strong title="${cycle.winner}">${getValidatorDisplayName(cycle.winner, 10)}</strong></span>` : ''}
      `;
      row.appendChild(header);

      // ── Phase bar (4 segments) ──
      const bar = document.createElement('div');
      bar.style.cssText = 'display:flex;border-radius:var(--radius-sm);overflow:hidden;height:42px;border:1px solid var(--border)';

      for (let pi = 0; pi < 4; pi++) {
        const phase = cycle.phases[pi];
        const color = PHASE_COLORS[phase.name];
        const stateStyle = STATE_STYLES[phase.state];
        const isActive = phase.state === 'active';

        const seg = document.createElement('div');
        seg.style.cssText = `flex:1;display:flex;flex-direction:column;justify-content:center;align-items:center;background:${color.bg};color:${color.fg};font-size:var(--font-size-xs);${stateStyle};position:relative;padding:2px 4px;transition:opacity 0.3s`;

        if (isActive) {
          seg.style.animation = 'pulse 2s infinite';
        }

        // Phase label
        let label = `<div style="font-weight:700;font-size:0.6rem;letter-spacing:0.03em">${phase.name.toUpperCase()}</div>`;

        // Phase-specific content
        if (pi === 0) {
          // Block Proposal
          if (phase.proposals && phase.proposals.length > 0) {
            const names = phase.proposals.map(p => {
              const name = p.validator.replace('noble-', '');
              return name.length > 12 ? name.slice(0, 6) + '…' : name;
            }).join(', ');
            label += `<div style="font-size:0.55rem;opacity:0.85">${phase.proposals.length} prop.</div>`;
          } else {
            label += `<div style="font-size:0.55rem;opacity:0.5">—</div>`;
          }

          // Track participants
          for (const p of (phase.proposals || [])) {
            if (!participantMap.has(p.validator)) participantMap.set(p.validator, { roles: [], cycles: [] });
            const entry = participantMap.get(p.validator);
            entry.roles.push('proposed');
            entry.cycles.push(cycle.cycle_number);
          }
        } else if (pi === 1) {
          // Voting (R1)
          if (phase.votes && phase.votes.length > 0) {
            label += `<div style="font-size:0.55rem;opacity:0.85">${phase.total_voters || 0} voter${(phase.total_voters || 0) !== 1 ? 's' : ''}</div>`;
          } else {
            label += `<div style="font-size:0.55rem;opacity:0.5">—</div>`;
          }
        } else if (pi === 2) {
          // Reflection (R2 / winner)
          if (phase.winner) {
            const icon = phase.disambiguation ? '&#9878;' : '&#10003;';
            label += `<div style="font-size:0.55rem;opacity:0.85">${icon} ${getValidatorDisplayName(phase.winner, 5)}</div>`;

            if (!participantMap.has(phase.winner)) participantMap.set(phase.winner, { roles: [], cycles: [] });
            participantMap.get(phase.winner).roles.push('won');
          } else if (phase.state === 'skipped') {
            label += `<div style="font-size:0.55rem;opacity:0.5">—</div>`;
          } else {
            label += `<div style="font-size:0.55rem;opacity:0.5">pending</div>`;
          }
        } else {
          // Propagation — show finality status badge
          if (phase.finalized) {
            let badge = '&#10003; sealed';
            let badgeColor = 'opacity:0.85';
            if (finalityStatus && finalityStatus.finalized_height > 0) {
              // Estimate block depth from cycle position within the displayed list.
              // Cycles are ordered newest-first; cycleIdx counts from 0 (most recent).
              const cycleIdx = cycles.indexOf(cycle);
              const tipH = finalityStatus.latest_height;
              const depth = cycleIdx; // approximate: each cycle = 1 block deeper
              const blockH = tipH - depth;
              if (blockH > 0 && blockH <= finalityStatus.finalized_height) {
                badge = '&#9989; finalized';
                badgeColor = 'color:var(--accent-green,#4caf50)';
              } else if (blockH > 0) {
                const threshold = finalityStatus.confirmation_threshold;
                const confs = Math.min(Math.max(tipH - blockH, 0), threshold);
                if (confs > 0 && confs < threshold) {
                  badge = `&#9679; ${confs}/${threshold}`;
                  badgeColor = 'color:var(--accent-blue,#2196f3)';
                }
              }
            }
            label += `<div style="font-size:0.55rem;${badgeColor}">${badge}</div>`;
          } else if (phase.state === 'skipped') {
            label += `<div style="font-size:0.55rem;opacity:0.5">—</div>`;
          } else {
            label += `<div style="font-size:0.55rem;opacity:0.5">waiting</div>`;
          }
        }

        seg.innerHTML = label;
        bar.appendChild(seg);
      }

      row.appendChild(bar);

      // ── Proposal detail strip (below bar) ──
      if (cycle.phases[0].proposals && cycle.phases[0].proposals.length > 0) {
        const strip = document.createElement('div');
        strip.style.cssText = 'display:flex;gap:var(--gap);margin-top:var(--gap-xs);flex-wrap:wrap';

        for (const p of cycle.phases[0].proposals) {
          const isWinner = cycle.winner === p.validator;
          const borderColor = isWinner ? 'var(--success)' : cycle.disambiguation ? 'var(--error)' : 'var(--border)';
          const icon = isWinner ? '<span style="color:var(--success)">&#10003;</span>' : cycle.disambiguation ? '<span style="color:var(--error)">&#10007;</span>' : '';

          const card = document.createElement('div');
          card.style.cssText = `flex:1;min-width:180px;padding:var(--gap-sm);border:1px solid ${borderColor};border-radius:var(--radius-sm);background:var(--bg-secondary);font-size:var(--font-size-xs)`;
          const vName = getValidatorDisplayName(p.validator, 6);
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px">
              <strong>${vName}</strong>
              ${icon}
            </div>
            <div style="color:var(--text-muted)">
              ${p.tx_count} txs &middot; <span class="mono">${truncateHash(p.block_hash, 4)}</span>
            </div>
          `;

          // Show vote count from voting phase (index 1)
          const votingPhase = cycle.phases[1];
          if (votingPhase.votes && votingPhase.votes.length > 0) {
            const voteEntry = votingPhase.votes.find(v => v.block_hash === p.block_hash);
            if (voteEntry) {
              const r1 = voteEntry.vote_count;
              const r2 = voteEntry.r2_vote_count || 0;
              const displayVotes = r2 > 0 ? r2 : r1;
              const pct = votingPhase.total_voters > 0 ? Math.min(100, Math.round(displayVotes / votingPhase.total_voters * 100)) : 0;
              const roundLabel = r2 > 0
                ? ` <span style="color:var(--text-muted);font-weight:400">(R1:${r1} R2:${r2})</span>`
                : '';
              card.innerHTML += `
                <div style="margin-top:4px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:2px">
                    <span style="color:var(--text-secondary)">Votes</span>
                    <span style="font-weight:600">${displayVotes}/${votingPhase.total_voters}${roundLabel}</span>
                  </div>
                  <div style="height:4px;background:var(--bg-tertiary);border-radius:2px">
                    <div style="height:100%;width:${pct}%;background:${isWinner ? 'var(--success)' : 'var(--error)'};border-radius:2px"></div>
                  </div>
                </div>
              `;
            }
          }

          strip.appendChild(card);
        }

        // Per-block vote witness strip (below proposal cards)
        if (cycle._blockVotes) {
          const bv = cycle._blockVotes;
          const witnessDiv = document.createElement('div');
          witnessDiv.style.cssText = 'margin-top:var(--gap-xs);padding:var(--gap-sm);border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg-secondary);font-size:var(--font-size-xs)';
          const allVoters = new Map();
          for (const v of bv.r1_voters || []) allVoters.set(v.validator_key, { name: v.name || v.validator_key.slice(0, 8), r1: true, r2: false });
          for (const v of bv.r2_voters || []) {
            const existing = allVoters.get(v.validator_key);
            if (existing) { existing.r2 = true; }
            else allVoters.set(v.validator_key, { name: v.name || v.validator_key.slice(0, 8), r1: false, r2: true });
          }
          const voterList = [...allVoters.values()].map(v => {
            const rounds = [v.r1 ? 'R1' : '', v.r2 ? 'R2' : ''].filter(Boolean).join('+');
            return `<span style="display:inline-flex;align-items:center;gap:2px;padding:1px 6px;border-radius:9999px;background:color-mix(in srgb, var(--success) 12%, transparent);color:var(--success)">&#10003; ${v.name} <span style="opacity:0.7;font-size:0.5rem">${rounds}</span></span>`;
          }).join(' ');
          const dualBadge = bv.dual_witness_required
            ? `<span style="padding:1px 6px;border-radius:9999px;font-size:0.55rem;background:color-mix(in srgb, ${bv.dual_witness_met ? 'var(--success)' : 'var(--error)'} 15%, transparent);color:${bv.dual_witness_met ? 'var(--success)' : 'var(--error)'}">Dual-Witness: ${bv.dual_witness_met ? 'PASS' : 'FAIL'}</span>`
            : '';
          witnessDiv.innerHTML = `
            <div style="display:flex;align-items:center;gap:var(--gap-xs);margin-bottom:4px;flex-wrap:wrap">
              <span style="font-weight:600;color:var(--text-secondary)">Witnesses (${bv.unique_witness_count}/${bv.voter_count})</span>
              <span style="color:var(--text-muted)">${bv.strength}</span>
              ${dualBadge}
            </div>
            <div style="display:flex;gap:var(--gap-xs);flex-wrap:wrap">${voterList}</div>
          `;
          strip.appendChild(witnessDiv);
        }

        row.appendChild(strip);
      }

      csTimeline.appendChild(row);
    }

    // ── Validator activity summary ──
    if (participantMap.size > 0) {
      const entries = [...participantMap.entries()].sort((a, b) => b[1].roles.length - a[1].roles.length);
      csActivitySummary.innerHTML = `
        <div style="font-weight:600;font-size:var(--font-size-sm);margin-bottom:var(--gap-sm)">Validator Activity (3-cycle window)</div>
        <div style="display:flex;flex-wrap:wrap;gap:var(--gap-sm)">
          ${entries.map(([pubkey, data]) => {
            const won = data.roles.filter(r => r === 'won').length;
            const proposed = data.roles.filter(r => r === 'proposed').length;
            const lost = proposed - won;
            const dotColor = won > 0 ? 'var(--success)' : 'var(--warning)';
            const displayName = getValidatorDisplayName(pubkey, 8);
            return `<div style="display:flex;align-items:center;gap:var(--gap-xs);padding:3px 8px;background:var(--bg-secondary);border-radius:var(--radius-sm);font-size:var(--font-size-xs)" title="${pubkey}">
              <span style="width:6px;height:6px;border-radius:50%;background:${dotColor}"></span>
              <strong>${displayName}</strong>
              <span style="color:var(--text-muted)">${proposed}P</span>
              ${won > 0 ? `<span style="color:var(--success)">${won}W</span>` : ''}
              ${lost > 0 ? `<span style="color:var(--error)">${lost}L</span>` : ''}
            </div>`;
          }).join('')}
        </div>
      `;
    }
  }

  // ══════════════════════════════════════════════
  // CYCLE STATUS (countdown, phase progression)
  // ══════════════════════════════════════════════

  function renderPipeline(activeIdx, remaining) {
    const arrow = '<span style="color:var(--text-muted);font-size:var(--font-size-sm);margin:0 2px">\u2192</span>';
    return PHASES.map((p, i) => {
      const color = PHASE_COLORS[p];
      const done = i < activeIdx;
      const active = i === activeIdx;
      const pending = i > activeIdx;
      const time = active ? formatCountdown(remaining) : done ? '0:00' : formatCountdown(PHASE_DURATION);
      const opacity = pending ? '0.4' : '1';
      const border = active ? `2px solid ${color.bg}` : '2px solid transparent';
      const bg = active ? color.bg + '22' : 'transparent';
      return (i > 0 ? arrow : '') +
        `<span style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:var(--radius-sm);border:${border};background:${bg};opacity:${opacity};white-space:nowrap">` +
          `<span style="width:8px;height:8px;border-radius:2px;background:${color.bg};flex-shrink:0"></span>` +
          `<span style="font-size:var(--font-size-xs);font-weight:${active ? '700' : '400'};color:${active ? color.bg : done ? 'var(--text-muted)' : 'var(--text-secondary)'}">${p}</span>` +
          `<span id="cs-phase-time-${i}" style="font-family:var(--font-mono);font-size:var(--font-size-sm);font-weight:700;color:${active ? color.bg : done ? 'var(--text-muted)' : 'var(--text-secondary)'}">${time}</span>` +
        '</span>';
    }).join('');
  }

  let lastPhaseKey = null; // track phase changes for activity log
  function updateCycleDisplay(status) {
    // null cycle_number = bootstrapping (no genesis block yet).
    const sane = status.cycle_number != null;
    csCycleNum.textContent = sane ? formatNumber(status.cycle_number) : '—';
    csPhaseName.textContent = status.phase || 'Bootstrapping';
    csCycleInfo.textContent = sane ? `#${formatNumber(status.cycle_number)}` : 'Forming chain';

    // Track phase key for UI updates (phase_change activity comes from WS only).
    lastPhaseKey = `${status.cycle_number || 'boot'}:${status.phase_index}`;

    if (!sane) {
      // Bootstrap: the engine IS running full consensus (proposals, votes, phases).
      // Derive phase from cycle_remaining_secs so the pipeline looks alive.
      const cycleDur = PHASE_DURATION * 4; // 1200s
      let cycleRemaining = status.cycle_remaining_secs || 0;
      const elapsed = cycleDur - cycleRemaining;
      // 4 phases of PHASE_DURATION each
      const activeIdx = Math.min(3, Math.floor(elapsed / PHASE_DURATION));
      const phaseElapsed = elapsed - (activeIdx * PHASE_DURATION);
      let phaseRemaining = Math.max(0, PHASE_DURATION - phaseElapsed);

      csPhaseName.textContent = PHASES[activeIdx];
      csPhaseRemaining.textContent = formatCountdown(phaseRemaining);
      csCycleRemaining.textContent = formatCountdown(cycleRemaining);
      csValidator.textContent = '—';

      // (Phase Progression replaced by Protocol Activity log panel)

      // Pipeline header
      csPipeline.innerHTML = renderPipeline(activeIdx, phaseRemaining);

      // Countdown ticker
      clearInterval(countdownInterval);
      countdownInterval = setInterval(() => {
        phaseRemaining = Math.max(0, phaseRemaining - 1);
        cycleRemaining = Math.max(0, cycleRemaining - 1);
        csPhaseRemaining.textContent = formatCountdown(phaseRemaining);
        csCycleRemaining.textContent = formatCountdown(cycleRemaining);
        const activeTimer = root.querySelector(`#cs-phase-time-${activeIdx}`);
        if (activeTimer) activeTimer.textContent = formatCountdown(phaseRemaining);
        if ((phaseRemaining <= 0 || cycleRemaining <= 0) && countdownInterval) { clearInterval(countdownInterval); countdownInterval = null; loadCycle(); loadTimeline(); loadVoteTallies(); }
      }, 1000);
      return;
    }

    // CycleStatusResponse doesn't carry current_validator — show '—'.
    csValidator.textContent = '—';

    const activeIdx = status.phase_index;

    // (Phase Progression replaced by Protocol Activity log panel)

    // Pipeline header
    csPipeline.innerHTML = renderPipeline(activeIdx, status.phase_remaining_secs);

    // Countdown ticker
    let remaining = status.phase_remaining_secs;
    let cycleRemaining = status.cycle_remaining_secs;
    clearInterval(countdownInterval);
    countdownInterval = setInterval(() => {
      remaining = Math.max(0, remaining - 1);
      cycleRemaining = Math.max(0, cycleRemaining - 1);
      csPhaseRemaining.textContent = formatCountdown(remaining);
      csCycleRemaining.textContent = formatCountdown(cycleRemaining);
      // Update active timer in pipeline
      const activeTimer = root.querySelector(`#cs-phase-time-${activeIdx}`);
      if (activeTimer) activeTimer.textContent = formatCountdown(remaining);
      if (remaining <= 0 && countdownInterval) { clearInterval(countdownInterval); countdownInterval = null; loadCycle(); loadTimeline(); loadVoteTallies(); }
    }, 1000);
    csPhaseRemaining.textContent = formatCountdown(remaining);
    csCycleRemaining.textContent = formatCountdown(cycleRemaining);
  }

  async function loadCycle() {
    try {
      const status = await rpc.call('noble_getCycleStatus');
      updateCycleDisplay(status);
    } catch (e) {
      console.error('[consensus] load cycle:', e);
    }
  }

  // ══════════════════════════════════════════════
  // VALIDATOR REGISTRY
  // ══════════════════════════════════════════════

  // Track current display order for drag-and-drop
  let currentDisplayOrder = [];

  async function loadValidators() {
    try {
      const [result, nodeInfo, peerMemory, identity] = await Promise.all([
        rpc.call('noble_getValidatorList'),
        rpc.call('noble_getNodeInfo'),
        rpc.call('noble_getPeerMemory').catch(() => []),
        rpc.call('noble_getNodeIdentity').catch(() => ({})),
      ]);
      const selfKey = nodeInfo.validator_pubkey || null;
      const validators = result?.validators || [];
      const priorityOrder = result.priority_order || [];
      csPolicy.textContent = `Selection: ${result.selection_policy.replace('_', ' ')}`;

      // Populate validator name lookup for use by timeline and other panels.
      // Layer 1: peer memory (identity_key → node_name from NodeAnnounce).
      if (Array.isArray(peerMemory)) {
        for (const r of peerMemory) {
          if (r.identity_key && r.node_name) validatorNameMap.set(r.identity_key, r.node_name);
        }
      }
      // Layer 2: self identity (overrides peer memory for own key).
      if (selfKey && identity.node_name) {
        validatorNameMap.set(selfKey, identity.node_name);
      }
      // Layer 3: validator list names (highest priority — operator-set).
      for (const v of validators) {
        const keyHex = valKeyHex(v.public_key);
        const name = v.name || (selfKey && keyHex === selfKey ? (identity.node_name || 'This Node') : null);
        if (name) validatorNameMap.set(keyHex, name);
      }

      // Display chain identity in timeline header (only when blockchain exists)
      const chainBadge = root.querySelector('#cs-chain-badge');
      if (chainBadge) {
        chainBadge.textContent = getState().blockHeight > 0 ? formatChainLabel(nodeInfo) : '';
      }

      const online = validators.filter(v => v.status === 'alive').length;
      const offline = validators.length - online;
      const avgRep = validators.length > 0
        ? validators.reduce((s, v) => s + v.reputation_score, 0) / validators.length
        : 0;
      csValTotal.textContent = validators.length;
      csValOnline.textContent = online;
      csValOffline.textContent = offline;
      csValAvgRep.textContent = avgRep.toFixed(3);

      // Order by priority_order from server, unlisted validators appended
      const byKey = new Map(validators.map(v => [valKeyHex(v.public_key), v]));
      const ordered = [];
      for (const key of priorityOrder) {
        if (byKey.has(key)) ordered.push(byKey.get(key));
      }
      for (const v of validators) {
        if (!priorityOrder.includes(valKeyHex(v.public_key))) ordered.push(v);
      }
      currentDisplayOrder = ordered.map(v => valKeyHex(v.public_key));

      validatorsTbody.innerHTML = '';
      let dragSrcIdx = null;

      ordered.forEach((v, i) => {
        const keyHex = valKeyHex(v.public_key);
        const br = v.reputation_breakdown;
        const statusClass = v.status === 'alive' ? 'inbound' : 'pending';
        const isSelf = selfKey && keyHex === selfKey;
        const youBadge = isSelf
          ? ' <span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:var(--accent);color:#fff;vertical-align:middle;margin-left:4px">YOU</span>'
          : '';
        const removeCell = `<td><button class="btn btn-danger btn-sm cs-remove-btn" data-pubkey="${keyHex}" title="Remove from your accepted list">&#10005;</button></td>`;
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.draggable = true;
        tr.dataset.idx = i;
        tr.dataset.key = keyHex;
        tr.innerHTML = `
          <td style="cursor:grab;color:var(--text-secondary);font-size:1.3em;text-align:center;user-select:none;padding:0 6px;letter-spacing:2px;opacity:0.7;transition:opacity 0.15s,color 0.15s" class="cs-drag-handle" title="Drag to set priority order"
              onmouseenter="this.style.opacity='1';this.style.color='var(--accent)'"
              onmouseleave="this.style.opacity='0.7';this.style.color='var(--text-secondary)'">&#8942;&#8942;</td>
          <td>${i + 1}</td>
          <td>
            <div style="font-weight:600;font-size:var(--font-size-sm)">${escapeHtml(v.name) || (isSelf ? 'This Node' : 'Unknown')}${youBadge}</div>
            <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${truncateHash(keyHex, 6)} <button class="btn-copy" data-copy="${keyHex}" title="Copy public key">&#128203;</button></div>
          </td>
          <td class="mono" style="font-size:var(--font-size-xs)">${extractIpFromMultiaddr(v.host_address)}${v.host_address ? ` <button class="btn-copy" data-copy="${extractIpFromMultiaddr(v.host_address)}" title="Copy IP">&#128203;</button>` : ''}</td>
          <td style="font-size:var(--font-size-xs)">${v.country_code || '--'}</td>
          <td><span class="badge ${statusClass}">${v.status}</span></td>
          <td>
            <div style="display:flex;align-items:center;gap:var(--gap-sm)">
              <div style="flex:1;height:6px;background:var(--bg-tertiary);border-radius:3px;min-width:60px">
                <div style="height:100%;width:${Math.min(100, v.reputation_score * 100)}%;background:${repColor(v.reputation_score)};border-radius:3px"></div>
              </div>
              <span class="mono" style="font-size:var(--font-size-xs)">${v.reputation_score.toFixed(3)}</span>
            </div>
          </td>
          <td class="mono" style="font-size:var(--font-size-xs)">${(br.block_acceptance_rate * 100).toFixed(1)}%</td>
          <td class="mono" style="font-size:var(--font-size-xs)">${(br.uptime * 100).toFixed(1)}%</td>
          <td class="mono" style="font-size:var(--font-size-xs)">${br.trust_score.toFixed(3)}</td>
          <td>${formatNumber(v.blocks_produced)}</td>
          <td>${v.listers_count ?? 0}</td>
          <td style="font-size:var(--font-size-xs)">${v.last_active ? (v.status === 'alive' ? timeAgo(v.last_active) : formatTimestamp(v.last_active)) : '--'}</td>
          ${removeCell}
        `;

        // Drag-and-drop handlers
        tr.addEventListener('dragstart', (e) => {
          dragSrcIdx = i;
          e.dataTransfer.effectAllowed = 'move';
          tr.style.opacity = '0.5';
        });
        tr.addEventListener('dragend', () => { tr.style.opacity = ''; });
        tr.addEventListener('dragover', (e) => {
          e.preventDefault();
          e.dataTransfer.dropEffect = 'move';
          tr.style.background = 'var(--bg-tertiary)';
        });
        tr.addEventListener('dragleave', () => { tr.style.background = ''; });
        tr.addEventListener('drop', async (e) => {
          e.preventDefault();
          tr.style.background = '';
          const destIdx = parseInt(tr.dataset.idx, 10);
          if (dragSrcIdx === null || dragSrcIdx === destIdx) return;
          // Reorder currentDisplayOrder
          const newOrder = [...currentDisplayOrder];
          const [moved] = newOrder.splice(dragSrcIdx, 1);
          newOrder.splice(destIdx, 0, moved);
          currentDisplayOrder = newOrder;
          try {
            await rpc.call('noble_setValidatorOrder', { order: newOrder });
            loadValidators();
          } catch (err) {
            console.error('[consensus] set validator order:', err);
            loadValidators(); // refresh to revert visual
          }
        });

        tr.addEventListener('click', (e) => {
          if (e.target.closest('.cs-remove-btn') || e.target.closest('.cs-drag-handle')) return;
          showValidatorDetail(v);
        });
        validatorsTbody.appendChild(tr);
      });

      // Attach remove handlers
      validatorsTbody.querySelectorAll('.cs-remove-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const pubkey = btn.dataset.pubkey;
          const name = ordered.find(v => valKeyHex(v.public_key) === pubkey)?.name || pubkey.slice(0, 16);
          showRemoveConfirmation(pubkey, name, selfKey);
        });
      });
    } catch (e) {
      console.error('[consensus] load validators:', e);
    }
  }

  function showValidatorDetail(v) {
    const keyHex = valKeyHex(v.public_key);
    const scheme = typeof v.public_key === 'string'
      ? (v.public_key.startsWith('00') ? 'Ed25519' : 'secp256k1')
      : (v.public_key.Ed25519 ? 'Ed25519' : 'secp256k1');
    const br = v.reputation_breakdown;

    detailPanel.innerHTML = `
      <div class="panel" style="border-color:var(--accent)">
        <div class="panel-header">
          <span>${v.name || 'Validator'} — Detail</span>
          <button class="btn btn-secondary" id="cs-close-detail" style="padding:2px 8px;font-size:var(--font-size-xs)">Close</button>
        </div>
        <div class="panel-body">
          <div class="split-layout">
            <dl class="detail-grid">
              <dt>Name</dt><dd>${escapeHtml(v.name) || '—'}</dd>
              <dt>Public Key</dt><dd class="mono">${keyHex}</dd>
              <dt>Scheme</dt><dd>${scheme}</dd>
              <dt>Host Address</dt><dd class="mono">${v.host_address || 'N/A'}</dd>
              <dt>Country</dt><dd>${v.country_code || 'N/A'}</dd>
              <dt>Status</dt><dd><span class="badge ${v.status === 'alive' ? 'inbound' : 'pending'}">${v.status}</span></dd>
              <dt>Last Active</dt><dd>${formatTimestamp(v.last_active)}</dd>
              <dt>Proposed This Cycle</dt><dd>${v.proposed_this_cycle ? 'Yes' : 'No'}</dd>
              <dt>Nodes Listing</dt><dd>${v.listers_count ?? 0} peers trust this validator</dd>

            </dl>
            <div>
              <h4 style="margin-bottom:var(--gap);font-size:var(--font-size-sm)">Reputation Breakdown</h4>
              <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)">
                R(V) = 0.4 &times; B(V) + 0.3 &times; U(V) + 0.3 &times; T(V)
              </p>
              ${repBar('Block Acceptance B(V)', br.block_acceptance_rate, `${v.blocks_accepted} / ${v.cycles_active} cycles`, 0.4)}
              ${repBar('Uptime U(V)', br.uptime, `${v.cycles_reachable} / ${v.total_cycles} cycles reachable`, 0.3)}
              ${repBar('Trust Score T(V)', br.trust_score, `${v.listers_count ?? 0} peers listing`, 0.3)}
              <div style="margin-top:var(--gap);padding-top:var(--gap);border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
                <span style="font-weight:700">Combined Reputation</span>
                <span class="mono" style="font-size:var(--font-size-lg);font-weight:700;color:${repColor(v.reputation_score)}">${v.reputation_score.toFixed(4)}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    detailPanel.querySelector('#cs-close-detail').addEventListener('click', () => {
      detailPanel.innerHTML = '';
    });
    detailPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ══════════════════════════════════════════════
  // VALIDATOR MANAGEMENT (add / remove)
  // ══════════════════════════════════════════════

  function showAddValidatorModal() {
    modalContainer.innerHTML = `
      <div class="modal-overlay" id="cs-modal-overlay">
        <div class="modal">
          <div class="modal-header">
            <span>Add Validator to Your Accepted List</span>
            <button class="btn btn-secondary btn-sm" id="cs-modal-close">&#10005;</button>
          </div>
          <div class="modal-body">
            <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap)">
              Paste the Node ID (public key) you received from the validator operator.
              As a sovereign node maintainer, you control which validators your node trusts.
            </p>
            <div class="form-group">
              <label for="cs-add-key">Node ID (Public Key)</label>
              <input id="cs-add-key" type="text" placeholder="64-character hex string (Ed25519)" maxlength="64" spellcheck="false" autocomplete="off">
              <div class="form-hint">Ed25519 public key, 64 hex characters. Example: a1b2c3d4e5...64 chars</div>
              <div class="form-error" id="cs-add-error"></div>
            </div>
            <div class="form-group">
              <label for="cs-add-name">Friendly Name (optional)</label>
              <input id="cs-add-name" type="text" placeholder="e.g. alice-node, company-validator" maxlength="40" spellcheck="false">
              <div class="form-hint">A label to identify this validator in your list</div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" id="cs-modal-cancel">Cancel</button>
            <button class="btn" id="cs-modal-submit">Add Validator</button>
          </div>
        </div>
      </div>
    `;

    const overlay = modalContainer.querySelector('#cs-modal-overlay');
    const keyInput = modalContainer.querySelector('#cs-add-key');
    const nameInput = modalContainer.querySelector('#cs-add-name');
    const errorEl = modalContainer.querySelector('#cs-add-error');
    const submitBtn = modalContainer.querySelector('#cs-modal-submit');

    function closeModal() { modalContainer.innerHTML = ''; }

    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
    modalContainer.querySelector('#cs-modal-close').addEventListener('click', closeModal);
    modalContainer.querySelector('#cs-modal-cancel').addEventListener('click', closeModal);

    submitBtn.addEventListener('click', async () => {
      errorEl.textContent = '';
      const hexKey = keyInput.value.trim().toLowerCase();
      const name = nameInput.value.trim();

      if (hexKey.length !== 64 || !/^[0-9a-f]{64}$/.test(hexKey)) {
        errorEl.textContent = 'Invalid key: must be exactly 64 hexadecimal characters.';
        return;
      }

      try {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Adding...';
        await rpc.call('noble_addValidator', { public_key: hexKey, name: name || undefined });
        closeModal();
        loadValidators();
      } catch (e) {
        errorEl.textContent = e.message || 'Failed to add validator.';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Add Validator';
      }
    });

    keyInput.focus();
  }

  function showRemoveConfirmation(pubkey, name, selfKey) {
    const isSelf = selfKey && pubkey === selfKey;
    const title = isSelf ? 'Removing Your Own Node' : 'Remove Validator';
    const bodyHtml = isSelf
      ? `<p style="font-size:var(--font-size-sm);margin-bottom:var(--gap)">
              You are removing this node from its own validator list.
            </p>
            <p style="font-size:var(--font-size-sm);margin-bottom:var(--gap)">
              On the next restart, your node will re-add itself automatically
              unless you change your node type.
            </p>
            <p style="font-size:var(--font-size-xs);color:var(--text-muted)">
              To stop producing blocks permanently:<br>
              Go to <strong>Settings &rarr; Node Identity</strong> and set
              <strong>"Wants to Validate"</strong> to <strong>No</strong>.
            </p>`
      : `<p style="font-size:var(--font-size-sm);margin-bottom:var(--gap)">
              Remove <strong>${name}</strong> from your accepted validator list?
            </p>
            <p style="font-size:var(--font-size-xs);color:var(--text-muted)">
              This only affects your node's list. The validator can be re-added at any time with the same Node ID.
            </p>`;
    const confirmLabel = isSelf ? 'Remove Anyway' : 'Remove';

    modalContainer.innerHTML = `
      <div class="modal-overlay" id="cs-modal-overlay">
        <div class="modal" style="max-width:400px">
          <div class="modal-header">
            <span>${isSelf ? '&#9888; ' : ''}${title}</span>
          </div>
          <div class="modal-body">
            ${bodyHtml}
            <div class="form-error" id="cs-remove-error" style="margin-top:var(--gap-sm)"></div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" id="cs-modal-cancel">Cancel</button>
            <button class="btn btn-danger" id="cs-modal-confirm">${confirmLabel}</button>
          </div>
        </div>
      </div>
    `;

    const overlay = modalContainer.querySelector('#cs-modal-overlay');
    const errorEl = modalContainer.querySelector('#cs-remove-error');
    const confirmBtn = modalContainer.querySelector('#cs-modal-confirm');

    function closeModal() { modalContainer.innerHTML = ''; }

    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
    modalContainer.querySelector('#cs-modal-cancel').addEventListener('click', closeModal);

    confirmBtn.addEventListener('click', async () => {
      try {
        confirmBtn.disabled = true;
        confirmBtn.textContent = 'Removing...';
        await rpc.call('noble_removeValidator', { public_key: pubkey });
        closeModal();
        detailPanel.innerHTML = '';
        loadValidators();
      } catch (e) {
        errorEl.textContent = e.message || 'Failed to remove validator.';
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Remove';
      }
    });
  }

  // ══════════════════════════════════════════════
  // NETWORK CANDIDATES
  // ══════════════════════════════════════════════

  function candidateParticipation(wantsValidate, wantsVote) {
    if (wantsValidate && wantsVote) return { label: 'Full Validator', color: 'var(--success)' };
    if (wantsValidate) return { label: 'Block Producer', color: 'var(--warning)' };
    if (wantsVote) return { label: 'Voter Only', color: 'var(--info, #3b82f6)' };
    return { label: 'Watcher', color: 'var(--text-muted)' };
  }

  function candidateLiveness(lastSeen) {
    const age = Math.floor(Date.now() / 1000) - lastSeen;
    if (age <= 5400) return { label: 'alive', color: 'var(--success)' };
    if (age <= 21600) return { label: 'stale', color: 'var(--warning)' };
    return { label: 'unreachable', color: 'var(--error)' };
  }

  async function loadCandidates() {
    try {
      const [peers, valResult, nodeInfo, identity] = await Promise.all([
        rpc.call('noble_getPeerMemory'),
        rpc.call('noble_getValidatorList'),
        rpc.call('noble_getNodeInfo'),
        rpc.call('noble_getNodeIdentity'),
      ]);

      // Build set of validator identity keys for exclusion
      const validatorKeys = new Set(
        valResult.validators.map(v => valKeyHex(v.public_key))
      );

      // Filter: wants to participate AND not already a validator
      const candidates = peers.filter(p =>
        (p.wants_to_validate || p.wants_to_vote) && !validatorKeys.has(p.identity_key)
      );

      // Inject SELF if this node is a validator candidate but not yet accepted
      const selfKey = nodeInfo.validator_pubkey;
      if (selfKey && !validatorKeys.has(selfKey)) {
        const now = Math.floor(Date.now() / 1000);
        candidates.unshift({
          identity_key: selfKey,
          node_name: identity.node_name || 'This Node',
          org_type: identity.org_type || null,
          node_role: identity.node_role || null,
          wants_to_validate: identity.wants_to_validate ?? true,
          wants_to_vote: identity.wants_to_vote ?? true,
          first_seen: now,
          last_seen: now,
          connection_count: null,
          _isSelf: true,
        });
      }

      csCandidateCount.textContent = `${candidates.length} candidate${candidates.length !== 1 ? 's' : ''}`;

      if (candidates.length === 0) {
        candidatesTbody.innerHTML = '';
        candidatesEmpty.style.display = '';
        return;
      }
      candidatesEmpty.style.display = 'none';

      // Sort: alive first, then by last_seen descending
      candidates.sort((a, b) => b.last_seen - a.last_seen);

      candidatesTbody.innerHTML = '';
      for (const peer of candidates) {
        const part = candidateParticipation(peer.wants_to_validate, peer.wants_to_vote);
        const live = candidateLiveness(peer.last_seen);
        const isStale = live.label !== 'alive';

        const tr = document.createElement('tr');
        if (isStale && !peer._isSelf) tr.style.opacity = '0.6';
        const youBadge = peer._isSelf
          ? ' <span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:var(--accent);color:#fff;vertical-align:middle;margin-left:4px">YOU</span>'
          : '';
        const connCount = peer.connection_count != null ? peer.connection_count : '—';
        const removeBtn = peer._isSelf
          ? ''
          : `<button class="btn btn-danger btn-sm cs-remove-candidate" data-key="${peer.identity_key}" title="Remove from peer memory">&#10005;</button>`;
        tr.innerHTML = `
          <td>
            <div style="font-weight:600;font-size:var(--font-size-sm)">${escapeHtml(peer.node_name) || 'Unknown'}${youBadge}</div>
            <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${peer.identity_key.slice(0, 12)}...${peer.identity_key.slice(-8)} <button class="btn-copy" data-copy="${peer.identity_key}" title="Copy public key">&#128203;</button></div>
          </td>
          <td class="mono" style="font-size:var(--font-size-xs)">${extractIpFromMultiaddr(peer.last_addr || peer.host_address)}${(peer.last_addr || peer.host_address) ? ` <button class="btn-copy" data-copy="${extractIpFromMultiaddr(peer.last_addr || peer.host_address)}" title="Copy IP">&#128203;</button>` : ''}</td>
          <td style="font-size:var(--font-size-xs)">${peer.country_code || '--'}</td>
          <td style="font-size:var(--font-size-xs)">${peer.org_type || '—'}</td>
          <td>
            <span style="display:inline-block;padding:2px 8px;border-radius:9999px;font-size:var(--font-size-xs);font-weight:600;border:1px solid ${part.color};color:${part.color}">${part.label}</span>
          </td>
          <td style="font-size:var(--font-size-xs)">
            <span style="color:${live.color};font-weight:600">${live.label}</span>
            <div style="color:var(--text-muted)">${timeAgo(peer.last_seen)}</div>
          </td>
          <td style="font-size:var(--font-size-xs);color:var(--text-muted)">${timeAgo(peer.first_seen)}</td>
          <td style="font-size:var(--font-size-xs);text-align:center">${connCount}</td>
          <td>
            <div style="display:flex;gap:var(--gap-xs)">
              <button class="btn btn-sm cs-add-candidate" data-key="${peer.identity_key}" data-name="${peer.node_name || ''}" title="Add to validator list">+</button>
              ${removeBtn}
            </div>
          </td>
        `;
        candidatesTbody.appendChild(tr);
      }

      // Action handlers: Add to validator list
      candidatesTbody.querySelectorAll('.cs-add-candidate').forEach(btn => {
        btn.addEventListener('click', async () => {
          const key = btn.dataset.key;
          const name = btn.dataset.name;
          try {
            btn.disabled = true;
            btn.textContent = '...';
            await rpc.call('noble_addValidator', { public_key: key, name: name || undefined });
            loadValidators();
            loadCandidates();
          } catch (e) {
            console.error('[consensus] add candidate:', e);
            btn.disabled = false;
            btn.textContent = '+';
          }
        });
      });

      // Action handlers: Remove from memory
      candidatesTbody.querySelectorAll('.cs-remove-candidate').forEach(btn => {
        btn.addEventListener('click', async () => {
          const key = btn.dataset.key;
          try {
            btn.disabled = true;
            await rpc.call('noble_removePeerRecord', { identity_key: key });
            loadCandidates();
          } catch (e) {
            console.error('[consensus] remove peer:', e);
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      console.error('[consensus] load candidates:', e);
    }
  }

  // Prune stale peers (7 days default)
  root.querySelector('#cs-prune-stale').addEventListener('click', async () => {
    try {
      const result = await rpc.call('noble_pruneStalePeers', { max_age_secs: 604800 });
      console.log('[consensus] pruned', result.pruned, 'stale peers');
      loadCandidates();
    } catch (e) {
      console.error('[consensus] prune stale:', e);
    }
  });

  // Wire up "Add Validator" button
  root.querySelector('#cs-add-validator').addEventListener('click', showAddValidatorModal);

  // ── WS subscriptions ──
  // (cyclePhaseChange events are handled by the Protocol Activity log above)

  // ── Copy-to-clipboard delegation (named for cleanup) ──
  function handleRootCopyClick(e) {
    const btn = e.target.closest('.btn-copy');
    if (btn) {
      e.stopPropagation();
      navigator.clipboard?.writeText(btn.dataset.copy).catch(() => {});
      btn.textContent = '\u2713';
      setTimeout(() => { btn.textContent = '\u{1F4CB}'; }, 1200);
    }
  }
  root.addEventListener('click', handleRootCopyClick);
  unsubs.push(() => root.removeEventListener('click', handleRootCopyClick));

  // ── Badge Governance Modal ──
  const badgeGear = root.querySelector('#cs-badge-gear');
  const badgeModal = root.querySelector('#cs-badge-modal');
  const badgeModalClose = root.querySelector('#badge-modal-close');
  let badgePollInterval = null;

  function openBadgeModal() {
    badgeModal.style.display = 'flex';
    loadBadgeHolders();
    loadActiveProposals();
    badgePollInterval = setInterval(() => {
      const active = root.querySelector('.badge-tab-btn[data-active="true"]');
      if (active) {
        const tab = active.dataset.tab;
        if (tab === 'holders') loadBadgeHolders();
        else if (tab === 'proposals') loadActiveProposals();
      }
    }, 10000);
  }
  function closeBadgeModal() {
    badgeModal.style.display = 'none';
    if (badgePollInterval) { clearInterval(badgePollInterval); badgePollInterval = null; }
  }
  badgeGear.addEventListener('click', openBadgeModal);
  badgeModalClose.addEventListener('click', closeBadgeModal);
  badgeModal.addEventListener('click', (e) => { if (e.target === badgeModal) closeBadgeModal(); });

  // Tab switching
  root.querySelectorAll('.badge-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      root.querySelectorAll('.badge-tab-btn').forEach(b => {
        b.style.background = 'var(--bg-tertiary)'; b.style.color = 'var(--text)';
        b.dataset.active = '';
      });
      btn.style.background = 'var(--accent)'; btn.style.color = '#fff';
      btn.dataset.active = 'true';
      root.querySelectorAll('.badge-tab-content').forEach(c => c.style.display = 'none');
      root.querySelector('#badge-tab-' + btn.dataset.tab).style.display = '';
      if (btn.dataset.tab === 'holders') loadBadgeHolders();
      else if (btn.dataset.tab === 'proposals') loadActiveProposals();
      else if (btn.dataset.tab === 'history') loadBadgeHistory();
    });
  });

  // Show/hide reason dropdown for revoke proposals
  const propType = root.querySelector('#badge-propose-type');
  const reasonWrap = root.querySelector('#badge-propose-reason-wrap');
  propType.addEventListener('change', () => {
    reasonWrap.style.display = propType.value === 'revoke' ? '' : 'none';
  });

  // Load badge holders
  async function loadBadgeHolders() {
    try {
      const holders = await rpc.call('noble_getBadgeHolders');
      const tbody = root.querySelector('#badge-holders-body');
      const empty = root.querySelector('#badge-holders-empty');
      if (!holders || holders.length === 0) {
        tbody.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      tbody.innerHTML = holders.map(h => `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:6px 8px" class="mono">${truncateHash(h.pubkey, 10)}</td>
        <td style="padding:6px 8px">${escapeHtml(h.node_name) || '--'}</td>
        <td style="padding:6px 8px"><span style="padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--font-size-xs);background:${h.status==='active'?'var(--success)':h.status==='suspended'?'var(--warning)':'var(--error)'};color:#fff">${h.status}</span></td>
        <td style="padding:6px 8px;text-align:right">${formatNumber(h.granted_at_height)}</td>
        <td style="padding:6px 8px;text-align:right">${h.last_seen ? timeAgo(h.last_seen) : '--'}</td>
        <td style="padding:6px 8px;text-align:center">${h.status==='active'?`<button class="badge-revoke-btn" data-pubkey="${h.pubkey}" style="padding:2px 8px;border:1px solid var(--error);border-radius:var(--radius-sm);background:none;color:var(--error);cursor:pointer;font-size:var(--font-size-xs)">Propose Revoke</button>`:''}</td>
      </tr>`).join('');
    } catch (e) {
      console.error('loadBadgeHolders:', e);
    }
  }

  // Load active proposals
  async function loadActiveProposals() {
    try {
      const proposals = await rpc.call('noble_getActiveProposals');
      const list = root.querySelector('#badge-proposals-list');
      const empty = root.querySelector('#badge-proposals-empty');
      if (!proposals || proposals.length === 0) {
        list.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      list.innerHTML = proposals.map(p => `
        <div style="border:1px solid var(--border);border-radius:var(--radius);padding:var(--gap);margin-bottom:var(--gap-sm)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap-xs)">
            <span style="font-weight:700;text-transform:uppercase;font-size:var(--font-size-xs);padding:2px 8px;border-radius:var(--radius-sm);background:${p.proposal_type==='grant'?'var(--success)':'var(--error)'};color:#fff">${p.proposal_type}</span>
            <span style="font-size:var(--font-size-xs);color:var(--text-muted)">Expires cycle ${p.expires_at_cycle}</span>
          </div>
          <div style="font-size:var(--font-size-sm);margin-bottom:var(--gap-xs)">
            <strong>Target:</strong> <span class="mono">${truncateHash(p.target_pubkey, 10)}</span>
            ${p.reason ? `<br><strong>Reason:</strong> ${p.reason}` : ''}
          </div>
          <div style="display:flex;align-items:center;gap:var(--gap);margin-bottom:var(--gap-xs)">
            <span style="font-size:var(--font-size-xs)">For: <strong>${p.votes_for}</strong></span>
            <span style="font-size:var(--font-size-xs)">Against: <strong>${p.votes_against}</strong></span>
            <span style="font-size:var(--font-size-xs);color:var(--text-muted)">of ${p.total_eligible_voters} eligible</span>
          </div>
          <div style="display:flex;gap:var(--gap-sm)">
            <button class="badge-vote-btn" data-hash="${p.proposal_hash}" data-vote="true" style="padding:4px 12px;border:1px solid var(--success);border-radius:var(--radius-sm);background:none;color:var(--success);cursor:pointer;font-size:var(--font-size-xs)">Vote For</button>
            <button class="badge-vote-btn" data-hash="${p.proposal_hash}" data-vote="false" style="padding:4px 12px;border:1px solid var(--error);border-radius:var(--radius-sm);background:none;color:var(--error);cursor:pointer;font-size:var(--font-size-xs)">Vote Against</button>
          </div>
        </div>
      `).join('');
    } catch (e) {
      console.error('loadActiveProposals:', e);
    }
  }

  // Load proposal history
  async function loadBadgeHistory() {
    try {
      const history = await rpc.call('noble_getProposalHistory', { limit: 50 });
      const tbody = root.querySelector('#badge-history-body');
      const empty = root.querySelector('#badge-history-empty');
      if (!history || history.length === 0) {
        tbody.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      tbody.innerHTML = history.map(h => `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:6px 8px;text-transform:uppercase;font-size:var(--font-size-xs)">${h.proposal_type}</td>
        <td style="padding:6px 8px" class="mono">${truncateHash(h.target_pubkey, 10)}</td>
        <td style="padding:6px 8px">${h.reason || '--'}</td>
        <td style="padding:6px 8px;text-align:right">${h.votes_for}</td>
        <td style="padding:6px 8px;text-align:right">${h.votes_against}</td>
        <td style="padding:6px 8px"><span style="padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--font-size-xs);background:${h.status==='passed'?'var(--success)':'var(--text-muted)'};color:#fff">${h.status}</span></td>
        <td style="padding:6px 8px;text-align:right">${h.created_at_cycle}</td>
      </tr>`).join('');
    } catch (e) {
      console.error('loadBadgeHistory:', e);
    }
  }

  // Event delegation for vote & revoke buttons (named for cleanup)
  async function handleRootBadgeClick(e) {
    const voteBtn = e.target.closest('.badge-vote-btn');
    if (voteBtn) {
      const hash = voteBtn.dataset.hash;
      const vote = voteBtn.dataset.vote === 'true';
      try {
        voteBtn.disabled = true;
        await rpc.call('noble_voteBadgeProposal', { proposal_hash: hash, vote });
        loadActiveProposals();
      } catch (err) {
        voteBtn.style.color = 'var(--error)';
        voteBtn.textContent = err.message || 'Failed';
        setTimeout(() => loadActiveProposals(), 3000);
      }
      return;
    }
    const revokeBtn = e.target.closest('.badge-revoke-btn');
    if (revokeBtn) {
      const pubkey = revokeBtn.dataset.pubkey;
      root.querySelector('#badge-propose-target').value = pubkey;
      propType.value = 'revoke';
      reasonWrap.style.display = '';
      // Switch to Propose tab
      root.querySelectorAll('.badge-tab-btn').forEach(b => {
        b.style.background = 'var(--bg-tertiary)'; b.style.color = 'var(--text)';
        b.dataset.active = '';
      });
      const proposeTab = root.querySelector('.badge-tab-btn[data-tab="propose"]');
      proposeTab.style.background = 'var(--accent)';
      proposeTab.style.color = '#fff';
      proposeTab.dataset.active = 'true';
      root.querySelectorAll('.badge-tab-content').forEach(c => c.style.display = 'none');
      root.querySelector('#badge-tab-propose').style.display = '';
    }
  }
  root.addEventListener('click', handleRootBadgeClick);
  unsubs.push(() => root.removeEventListener('click', handleRootBadgeClick));

  // Submit proposal
  root.querySelector('#badge-propose-submit').addEventListener('click', async () => {
    const target = root.querySelector('#badge-propose-target').value.trim();
    const ptype = root.querySelector('#badge-propose-type').value;
    const reason = ptype === 'revoke' ? root.querySelector('#badge-propose-reason').value : null;
    const status = root.querySelector('#badge-propose-status');
    if (!target) { status.textContent = 'Target pubkey required'; return; }
    try {
      const result = await rpc.call('noble_proposeBadge', {
        target_pubkey: target, proposal_type: ptype, reason
      });
      status.innerHTML = `<span style="color:var(--success)">Proposal submitted: ${result.tx_hash ? truncateHash(result.tx_hash, 12) : 'ok'}</span>`;
      root.querySelector('#badge-propose-target').value = '';
    } catch (err) {
      status.innerHTML = `<span style="color:var(--error)">${err.message || err}</span>`;
    }
  });

  // ── Bootstrap ──
  // Load validators first to populate name lookup, then timeline and tallies use friendly names
  loadValidators().then(() => { loadTimeline(); loadVoteTallies(); });
  loadCycle();
  loadCandidates();
  loadVotingStrategy();

  return {
    destroy() {
      clearInterval(countdownInterval);
      if (badgePollInterval) clearInterval(badgePollInterval);
      if (_reloadTimer) clearTimeout(_reloadTimer);
      for (const entry of deferredPeerEvents.values()) clearTimeout(entry.timer);
      deferredPeerEvents.clear();
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}

// ── Helpers ──

function repColor(score) {
  if (score >= 0.7) return 'var(--success)';
  if (score >= 0.4) return 'var(--warning)';
  return 'var(--error)';
}

function repBar(label, value, detail, weight) {
  const pct = Math.min(100, value * 100);
  return `
    <div style="margin-bottom:var(--gap)">
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:2px">
        <span style="font-size:var(--font-size-sm);font-weight:600">${label} <span style="color:var(--text-muted);font-weight:400">(weight: ${(weight * 100).toFixed(0)}%)</span></span>
        <span class="mono" style="font-size:var(--font-size-sm)">${value.toFixed(4)}</span>
      </div>
      <div style="height:8px;background:var(--bg-tertiary);border-radius:4px">
        <div style="height:100%;width:${pct}%;background:${repColor(value)};border-radius:4px;transition:width 0.3s"></div>
      </div>
      <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">${detail}</div>
    </div>
  `;
}
