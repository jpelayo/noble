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
  active:   'opacity:1',
  pending:  'opacity:0.3',
  skipped:  'opacity:0.2',
};

export function init(root, ctx) {
  const { rpc, ws, getState } = ctx;
  const unsubs = [];
  let tickFn = null;

  // Helper: extract display key from ValidatorEntry.public_key
  // Both live API and mock return nbl1… bech32 strings. Legacy object format handled for safety.
  function valKey(pk) {
    if (typeof pk === 'string') return pk;
    const k = pk.Secp256k1 || [];
    return k.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── Name display helpers (names pre-resolved by backend) ──
  // No client-side name maps — all names come from RPC/WS `node_name`/`validator`/`name` fields.
  function displayName(name, key, maxLen) {
    if (name) return escapeHtml(name);
    if (!key) return '—';
    return truncateHash(key, maxLen || 6);
  }

  root.innerHTML = `
    <div class="page-header" style="display:flex;align-items:baseline;gap:var(--gap-sm)">
      <div style="flex:1"><h1 style="display:inline">Consensus</h1><p>Proof of Reputation cycle status, accepted validator registry, and network candidate discovery</p></div>
      <a href="#/governance" title="Governance" style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;color:var(--text-muted);font-size:1.1rem;line-height:1;flex-shrink:0;align-self:flex-start;text-decoration:none">&#9745;</a>
    </div>
    <div id="cs-sync-banner" style="display:none;padding:10px 16px;margin-bottom:var(--gap);border-radius:var(--radius-sm);background:var(--bg-warning, #fef3c7);border:1px solid var(--border-warning, #f59e0b);color:var(--text-warning, #92400e);font-size:var(--font-size-sm);font-weight:500"></div>

    <!-- Superposition Timeline -->
    <div class="panel">
      <div class="panel-header">
        <span>Cycle Superposition Timeline</span>
        <span id="cs-chain-badge" style="font-weight:500;font-size:var(--font-size-xs);padding:2px 8px;border-radius:9999px;background:var(--bg-tertiary);color:var(--text-secondary);margin-left:var(--gap-sm)"></span>
        <span style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted);margin-left:auto">Recent cycles</span>
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
            <div class="kpi-label" style="margin-bottom:var(--gap-xs)">ROUND 1 — VOTING</div>
            <select id="cs-r1-strategy" class="form-select" style="width:100%;margin-bottom:var(--gap-sm)">
              <option value="first_valid">First Valid</option>
              <option value="fixed_validator">Fixed Validator</option>
              <option value="round_robin">Round Robin</option>
              <option value="subset_rotation">Subset Rotation</option>
              <option value="random">Random</option>
              <option value="weighted_reputation">Weighted Reputation</option>
              <option value="weighted_probability">Weighted Probability</option>
              <option value="manual">Manual</option>
            </select>
            <div id="cs-r1-desc" style="font-size:var(--font-size-xs);color:var(--text-muted)"></div>
          </div>
          <div>
            <div class="kpi-label" style="margin-bottom:var(--gap-xs)">ROUND 2 — REFLECTION</div>
            <select id="cs-r2-strategy" class="form-select" style="width:100%;margin-bottom:var(--gap-sm)">
              <option value="first_valid">First Valid</option>
              <option value="fixed_validator">Fixed Validator</option>
              <option value="round_robin">Round Robin</option>
              <option value="subset_rotation">Subset Rotation</option>
              <option value="random">Random</option>
              <option value="weighted_reputation">Weighted Reputation</option>
              <option value="weighted_probability">Weighted Probability</option>
              <option value="follow_majority">Follow Round 1 Majority</option>
              <option value="manual">Manual</option>
            </select>
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
            <tr><td style="white-space:nowrap;font-weight:600">Manual</td><td>No automatic vote. Use the inline <em>Vote</em> buttons in the Live Vote Tallies panel each cycle.</td></tr>
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
      <div style="display:flex;gap:0;border-bottom:1px solid var(--border);padding:0 var(--gap)">
        <button class="cs-tally-tab" data-round="r1" style="background:none;border:none;border-bottom:2px solid var(--accent);padding:6px 16px;cursor:pointer;font-size:var(--font-size-sm);font-weight:700;color:var(--text-primary)">Round 1</button>
        <button class="cs-tally-tab" data-round="r2" style="background:none;border:none;border-bottom:2px solid transparent;padding:6px 16px;cursor:pointer;font-size:var(--font-size-sm);font-weight:400;color:var(--text-muted)">Round 2</button>
      </div>
      <div class="panel-body" id="cs-tallies-body" style="max-height:400px;overflow-y:auto">
        <div class="empty-state">No votes recorded for the current cycle.</div>
      </div>
    </div>

    <!-- Accepted Validator Registry -->
    <div class="panel">
      <div class="panel-header">
        <span>Accepted Validator Registry</span>
        <div style="display:flex;align-items:center;gap:var(--gap-sm)">
          <span id="cs-policy" style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)"></span>
          <button class="btn btn-secondary btn-sm" id="cs-refresh-validators" style="padding:2px 10px;font-size:var(--font-size-xs)">Refresh</button>
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
      <div style="overflow-x:auto;max-height:500px;overflow-y:auto">
        <table class="data-table">
          <thead style="position:sticky;top:0;z-index:1;background:var(--bg-secondary)"><tr><th style="width:32px" title="Drag to set priority order">&#9776;</th><th>#</th><th id="cs-strategy-col-header" style="width:52px"></th><th>Validator</th><th>IP</th><th>Country</th><th>Status</th><th>Reputation</th><th title="Minimum fee rate (groats/byte)">Min Fee</th><th title="Uptime ratio (weight 0.3)">Uptime</th><th title="Trust score (weight 0.3)">Trust</th><th>Blocks</th><th title="Validators listing this peer">Listers</th><th>Last Active</th><th title="Connection stability: stability (reconnections), uptime, and latency">Connectivity</th><th></th></tr></thead>
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
          <button class="btn btn-secondary btn-sm" id="cs-refresh-candidates" style="padding:2px 10px;font-size:var(--font-size-xs)">Refresh</button>
          <button class="btn btn-secondary btn-sm" id="cs-prune-stale">Prune Stale</button>
        </div>
      </div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
          Peers discovered via GossipSub that want to participate in consensus. Add them to your accepted validator list after out-of-band verification.
        </p>
      </div>
      <div style="overflow-x:auto;max-height:500px;overflow-y:auto">
        <table class="data-table">
          <thead style="position:sticky;top:0;z-index:1;background:var(--bg-secondary)"><tr><th>Node Name</th><th>IP</th><th>Country</th><th>Min Fee</th><th>Org Type</th><th>Role</th><th>Last Seen</th><th>First Seen</th><th>Connections</th><th></th></tr></thead>
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
            <label style="display:block;margin-bottom:var(--gap-xs);font-weight:600;font-size:var(--font-size-sm)">Target Validator</label>
            <input id="badge-propose-target" type="text" placeholder="nbl1p... address or hex wire bytes" style="width:100%;margin-bottom:var(--gap-sm);font-family:var(--font-mono);font-size:var(--font-size-xs)" spellcheck="false">

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
  const r1Desc = root.querySelector('#cs-r1-desc');
  const r2Desc = root.querySelector('#cs-r2-desc');
  const saveStrategyBtn = root.querySelector('#cs-save-strategy');
  const strategyStatus = root.querySelector('#cs-strategy-status');
  const strategyHelpBtn = root.querySelector('#cs-strategy-help');
  const strategyModal = root.querySelector('#cs-strategy-modal');
  const strategyModalClose = root.querySelector('#cs-strategy-modal-close');
  const tallyMeta = root.querySelector('#cs-tally-meta');
  const talliesBody = root.querySelector('#cs-tallies-body');
  let tallyRound = 'r1';
  let lastTallyResult = null;

  // Tab switching for vote tallies
  root.querySelectorAll('.cs-tally-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      tallyRound = tab.dataset.round;
      root.querySelectorAll('.cs-tally-tab').forEach(t => {
        t.style.borderBottom = t === tab ? '2px solid var(--accent)' : '2px solid transparent';
        t.style.fontWeight = t === tab ? '700' : '400';
        t.style.color = t === tab ? 'var(--text-primary)' : 'var(--text-muted)';
      });
      renderTallies();
    });
  });

  // Strategy state: current params loaded from RPC (for checkbox/radio initial state)
  let currentStrategyParams = { r1: null, r2: null };

  const STRATEGY_DESCRIPTIONS = {
    first_valid: 'Vote for the first valid block received. Fast but biased toward low-latency validators.',
    fixed_validator: 'Always vote for a specific validator (select with radio button below). Fallback: follow majority \u2192 random.',
    round_robin: 'Rotate through validators in priority order each cycle (drag rows to reorder).',
    subset_rotation: 'Rotate through selected validators (check boxes below). Fallback: follow majority \u2192 random.',
    random: 'Randomly select among valid candidates (deterministic per cycle).',
    weighted_reputation: 'Vote for the candidate from the highest-weight validator.',
    weighted_probability: 'Probabilistic vote weighted by priority order — higher in the list = more likely.',
    follow_majority: 'Confirm the Round 1 leader. Fallback: random if no tallies yet.',
    manual: 'Do not auto-vote. Use inline Vote buttons in the tally panel each cycle.',
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
  const deferredPeerEvents = new Map(); // peer_id → { data, timer }

  // ── Rate-limiting: coalesce rapid repeated events ──
  // Key = event type + peer/node identifier → last entry index + timestamp.
  // If the same key fires again within DEDUP_WINDOW_MS, increment a counter
  // on the existing entry instead of appending a new one.
  const DEDUP_WINDOW_MS = 5000;
  const _lastEntryByKey = new Map(); // key → { idx, ts }

  function dedupKey(data) {
    const e = data.event;
    // Group by event type + peer/node identity
    if (e === 'peer_connected' || e === 'peer_disconnected')
      return `${e}:${data.peer_id || data.node_name || ''}`;
    if (e === 'announce_published' || e === 'announce_received')
      return `${e}:${data.node_name || data.identity || ''}`;
    if (e === 'reconnect_attempt')
      return `${e}:${data.addresses || ''}`;
    if (e === 'peer_status')
      return `${e}:${data.peer_id || ''}`;
    if (e === 'sync_requested' || e === 'sync_started' || e === 'sync_progress')
      return e;
    if (e === 'chain_tip_updated') return `${e}:${data.peer_id || ''}`;
    if (e === 'score_updated') return `${e}:${data.peer_id || ''}`;
    if (e === 'alignment_changed') return e;
    if (e === 'fork_alignment_pending') return e;
    if (e === 'fork_detected') return e;
    if (e === 'fork_divergence') return e;
    // All other events: no dedup (they carry unique data)
    return null;
  }

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
    sync_started:       '\u21bb',  // clockwise arrow
    sync_progress:      '\u21bb',  // clockwise arrow
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
    startup_info:       '\u25cf',  // filled circle
    chain_tip_updated:      '\u2195',  // up-down arrow (alignment)
    fork_detected:          '\u26a0',  // warning triangle
    fork_aligned:           '\u2713',  // checkmark
    fork_divergence:        '\u2195',  // up-down arrow
    fork_auto_resolved:     '\u21c4',  // right-left arrows
    fork_alignment_pending: '\u21c4',  // right-left arrows
    fork_alignment_clear:   '\u2713',  // checkmark
    alignment_changed:      '\u25c9',  // fisheye (alignment state)
    chain_adoption_started: '\u21c4',  // right-left arrows
    healing_clue:           '\u2764',  // heart (healing)
    healing_action:         '\u2764',  // heart (healing)
    fork_disagreement:      '\u26a0',  // warning triangle
    checkpoints_activated:  '\u2713',  // checkmark
    rejected:               '\u00d7',  // multiplication sign
    score_updated:          '\u26a0',  // warning triangle
  };

  function activityColor(evt) {
    switch (evt) {
      case 'block_committed': return 'var(--success, #22c55e)';
      case 'sync_started':
      case 'sync_progress': return '#60a5fa';
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
      case 'startup_info': return '#6ee7b7';
      case 'chain_tip_updated': return '#94a3b8';
      case 'fork_detected': return '#f59e0b';
      case 'fork_aligned': return 'var(--success, #22c55e)';
      case 'fork_divergence': return '#f59e0b';
      case 'fork_auto_resolved': return 'var(--danger, #ef4444)';
      case 'fork_alignment_pending': return '#f59e0b';
      case 'fork_alignment_clear': return 'var(--success, #22c55e)';
      case 'alignment_changed': return '#60a5fa';
      case 'chain_adoption_started': return 'var(--danger, #ef4444)';
      case 'checkpoints_activated': return 'var(--success, #22c55e)';
      case 'rejected': return '#f87171';
      case 'score_updated': return '#fbbf24';
      case 'healing_clue': return '#c084fc';
      case 'healing_action': return '#f43f5e';
      case 'fork_disagreement': return '#f59e0b';
      default: return 'var(--text-muted)';
    }
  }

  // Wrap a raw hash in {} to denote it's a non-friendly identifier.
  function hashLabel(id, len = 6) { return `{${truncateHash(id || '', len)}}`; }

  function formatActivityMessage(data) {
    // Enriched events carry a pre-formatted message.
    if (data.message && (data.event === 'block_proposed' || data.event === 'vote_broadcast')) return data.message;
    const vName = (name, id) => displayName(name, id, 8);
    const pName = (id) => truncateHash(id || '', 6);
    switch (data.event) {
      case 'block_committed': {
        const who = data.proposer_name || truncateHash(data.proposer, 8) || '';
        return `Block #${data.height} committed${who ? ` by ${who}` : ''} {${truncateHash(data.hash || '')}} (${data.tx_count} tx)`;
      }
      case 'block_proposed':
        return `Proposed block #${data.height}`;
      case 'block_received': {
        const from = data.proposer_name || truncateHash(data.proposer, 8) || hashLabel(data.peer_id);
        return `Block #${data.height} received from ${from}`;
      }
      case 'block_announced':
        return `Block #${data.height} announced by ${data.node_name || hashLabel(data.peer_id)}`;
      case 'block_requested':
        return `Requested block {${truncateHash(data.hash || '')}}`;
      case 'vote_broadcast':
        return `Vote broadcast R${data.round} \u2192 ${data.candidate_name || hashLabel(data.block_hash)}`;
      case 'vote_received': {
        const voter = data.voter_name || truncateHash(data.voter_id, 8) || hashLabel(data.voter_id);
        const candidate = data.candidate_name || hashLabel(data.candidate_hash);
        return `Vote R${data.round} received from ${voter} \u2192 ${candidate}`;
      }
      case 'peer_connected':
        return `Peer connected: ${data.node_name || data.node_name || hashLabel(data.peer_id)} (${data.direction || ''})`;
      case 'peer_disconnected':
        return `Peer disconnected: ${data.node_name || data.node_name || hashLabel(data.peer_id)}`;
      case 'peer_banned':
        return `Peer banned: ${data.node_name || hashLabel(data.peer_id)} \u2014 ${data.reason}`;
      case 'peer_status':
        return null; // Suppressed — only sync_started/sync_complete are meaningful
      case 'announce_received':
        return `${data.node_name || hashLabel(data.identity)} v${data.software_version || '?'}${data.wants_to_validate ? ' \u2022 validator' : ''}${data.wants_to_vote ? ' \u2022 voter' : ''} \u2014 ${data.connected ? 'connected' : 'via gossip'}`;
      case 'tx_announced':
        return `Tx {${truncateHash(data.tx_id || '')}} from ${data.node_name || hashLabel(data.peer_id)}`;
      case 'sync_started':
        return `Behind by ${data.blocks_behind} block${data.blocks_behind > 1 ? 's' : ''} (height ${data.our_height} \u2192 ${data.peer_height}) \u2014 syncing`;
      case 'sync_progress':
        return data.target
          ? `Syncing \u2014 block ${data.height} of ${data.target} (${data.progress}%)`
          : `Sync-imported block #${data.height}`;
      case 'sync_complete':
        return `Sync complete \u2192 height ${data.height}`;
      case 'evidence_received': {
        const etypes = { vote_equivocation: 'Vote equivocation', double_proposal: 'Double-proposal', invalid_block: 'Invalid block', announce_equivocation: 'Announce equivocation' };
        const etype = etypes[data.type] || data.type;
        return `${etype} evidence from ${data.node_name || hashLabel(data.peer_id)}`;
      }
      case 'evidence_published': {
        const etypes = { vote_equivocation: 'Vote equivocation', double_proposal: 'Double-proposal', invalid_block: 'Invalid block', announce_equivocation: 'Announce equivocation' };
        const etype = etypes[data.type] || data.type;
        return `${etype} evidence published {${truncateHash(data.evidence_hash || '')}}`;
      }
      case 'peer_wrong_chain':
        return `Kicked ${data.peer_name || hashLabel(data.peer_id)} \u2014 wrong chain (${data.their_chain_id})`;
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
      case 'startup_info':
        return data.message;
      case 'chain_tip_updated':
        return `Peer ${data.node_name || hashLabel(data.peer_id)} at height ${data.height}`;
      case 'healing_clue':
        return `Healing clue: ${data.clue} [${data.phase}]`;
      case 'healing_action':
        return `Healing: ${data.action.toUpperCase()} \u2014 ${data.reason} (${data.clue_count} clue${data.clue_count !== 1 ? 's' : ''})`;
      case 'fork_disagreement':
        return `Fork disagreement: peer block at height ${data.block_height} rejected (${data.reason})`;
      case 'fork_detected':
      case 'fork_aligned':
      case 'fork_divergence':
        // Transient fork detection — suppress from activity log.
        // Only healing manager decisions (alignment_pending, auto_resolved) are actionable.
        return null;
      case 'alignment_changed':
        return `${data.state}${data.previous_state ? ` (was ${data.previous_state})` : ''}`;
      case 'fork_alignment_pending':
        return `Fork alignment: ${data.cycles_remaining} cycle(s) to resolution`;
      case 'fork_alignment_clear':
        return `Fork alignment cleared \u2014 no dominant fork`;
      case 'fork_auto_resolved':
        return `Fork auto-resolved \u2192 rollback to height ${data.rollback_height ?? 0}, target ${data.target_height} (${data.reason})`;
      case 'chain_adoption_started':
        return `Chain adoption \u2192 ${data.target_chain_id} (${data.reason})`;
      case 'checkpoints_activated':
        return `Checkpoints activated at heights ${(data.heights || []).join(', ')}`;
      case 'rejected':
        return `Connection rejected: ${data.node_name || hashLabel(data.peer_id)} \u2014 ${data.reason}`;
      case 'score_updated':
        return `Ban score: ${data.node_name || hashLabel(data.peer_id)} \u2192 ${data.ban_score}`;
      default:
        return JSON.stringify(data);
    }
  }

  function pushActivity(data) {
    const now = Date.now();
    const d = new Date(now);
    const ts = String(d.getHours()).padStart(2, '0') + ':' +
               String(d.getMinutes()).padStart(2, '0') + ':' +
               String(d.getSeconds()).padStart(2, '0');

    // Rate-limit: coalesce rapid repeated events
    const key = dedupKey(data);
    if (key) {
      const prev = _lastEntryByKey.get(key);
      if (prev && (now - prev.ts) < DEDUP_WINDOW_MS && prev.idx < activityEntries.length) {
        const entry = activityEntries[prev.idx];
        entry.count = (entry.count || 1) + 1;
        entry.ts = ts; // update timestamp to latest occurrence
        prev.ts = now;
        renderActivityLog();
        return;
      }
    }

    const entry = { ts, data, count: 1 };
    activityEntries.push(entry);
    if (key) _lastEntryByKey.set(key, { idx: activityEntries.length - 1, ts: now });

    // Cap at max — drop oldest and reindex dedup map
    if (activityEntries.length > ACTIVITY_MAX_ENTRIES) {
      const removed = activityEntries.length - ACTIVITY_MAX_ENTRIES;
      activityEntries.splice(0, removed);
      // Reindex: shift all tracked indices down
      for (const [k, v] of _lastEntryByKey) {
        v.idx -= removed;
        if (v.idx < 0) _lastEntryByKey.delete(k);
      }
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
      const { ts, data, count } = activityEntries[i];
      const icon = ACTIVITY_ICONS[data.event] || '\u2022';
      const color = activityColor(data.event);
      const msg = formatActivityMessage(data);
      if (!msg) continue;
      const badge = count > 1 ? ` <span style="font-size:0.75em;color:var(--text-muted);background:var(--bg-tertiary);padding:0 4px;border-radius:3px">\u00d7${count}</span>` : '';
      html += `<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span style="color:var(--text-muted)">${ts}</span> <span style="color:${color}">${icon}</span> ${escapeHtml(msg)}${badge}</div>`;
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
    const name = data.node_name || data.node_name;
    if (name) {
      data.node_name = name;
      pushActivity(data);
      return;
    }
    // No name yet — defer up to 3 s.
    const timer = setTimeout(() => {
      deferredPeerEvents.delete(pid);
      data.node_name = data.node_name || '';
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
  // Suppress repeated announce_received events — only show first per identity.
  const seenAnnounceIdentities = new Set();
  if (ws && ws.subscribe) {
    unsubs.push(ws.subscribe('cyclePhaseChange', (data) => {
      // Cache peer names from announce events for display resolution.
      if (data.event === 'announce_received' && data.node_name) {
        if (data.peer_id) {
          // Name already in data.node_name from backend — no client-side map needed.
          // Flush any deferred peer_connected event now that we have the name.
          flushDeferredPeer(data.peer_id, data.node_name);
        }
        // Name already in data.node_name from backend.
        // events can resolve names immediately without waiting for refreshList().
        // (identity → name mapping handled by backend)
      }
      // Events with enriched follow-up messages: push the enriched version only
      // (skip the raw event to avoid duplicate log lines).
      if (data.event === 'block_proposed' && data.hash) {
        pushActivity({ event: 'block_proposed', message: `This node proposed block #${data.height || '?'} {${truncateHash(data.hash)}}` });
      } else if (data.event === 'vote_broadcast') {
        const target = data.candidate_name || hashLabel(data.block_hash || '');
        pushActivity({ event: 'vote_broadcast', message: `This node voted for ${target} (R${data.round || 1})` });
      } else if (data.event === 'peer_connected') {
        pushPeerEvent(data);
      } else if (data.event === 'announce_received') {
        // Suppress repeated announces — only log the first one per identity.
        // Name cache update above still runs for every announce.
        const id = data.identity || data.peer_id;
        if (id && seenAnnounceIdentities.has(id)) return;
        if (id) seenAnnounceIdentities.add(id);
        pushActivity(data);
        // Refresh panels so friendly names replace raw hex keys immediately
        // and new candidates appear in the candidates list.
        scheduleReload(loadValidators, loadVoteTallies, loadTimeline, loadCandidates);
      } else {
        pushActivity(data);
      }
      // Push follow-up context for enriched phase transitions.
      if (data.event === 'phase_change') {
        if (data.phase === 'Reflection' && data.total_votes != null) {
          const leader = data.leader_name || (data.leader_key ? truncateHash(data.leader_key, 8) : hashLabel(data.leader_hash));
          pushActivity({ event: 'consensus_log', message: `Voting results favor ${leader} with ${data.leader_pct ?? 0}% of votes (${data.total_votes} total)` });
        }
        if (data.phase === 'Propagation' && (data.winner_name || data.winner_hash)) {
          const winner = data.winner_name || (data.winner_key ? truncateHash(data.winner_key, 8) : hashLabel(data.winner_hash));
          pushActivity({ event: 'consensus_log', message: `Winning proposer: ${winner}` });
        }
      }
      // Refresh data panels on significant events
      if (data.event === 'block_committed') {
        scheduleReload(loadCycle, loadTimeline, loadVoteTallies, loadValidators);
      }
      // Refresh tallies on vote events and block arrivals (live updates).
      if (data.event === 'vote_received' || data.event === 'vote_broadcast' || data.event === 'block_received') {
        scheduleReload(loadVoteTallies);
      }
      // Block proposed — update timeline to show the new candidate.
      if (data.event === 'block_proposed') {
        scheduleReload(loadTimeline, loadVoteTallies);
      }
      // Phase change — refresh cycle display AND timeline (phase highlights).
      if (data.event === 'phase_change') {
        scheduleReload(loadCycle, loadTimeline, loadVoteTallies);
      }
      // Sync banner: show on sync_started, update on sync_progress, hide on sync_complete
      if (data.event === 'sync_started') {
        updateSyncBanner(true, data.peer_height);
      } else if (data.event === 'sync_progress' && data.target) {
        updateSyncBanner(true, data.target, data.height, data.progress);
      } else if (data.event === 'sync_complete') {
        updateSyncBanner(false);
        // After sync finishes, all panels need a full refresh — the timeline,
        // cycle display, vote tallies, and validator list are all stale.
        scheduleReload(loadCycle, loadTimeline, loadVoteTallies, loadValidators);
      }
    }));

    // Block commits via sync import may not emit block_committed on cyclePhaseChange.
    // Subscribe to newBlocks as a reliable fallback: any new block → refresh timeline.
    unsubs.push(ws.subscribe('newBlocks', () => {
      scheduleReload(loadCycle, loadTimeline, loadVoteTallies);
    }));

    unsubs.push(ws.subscribe('peerUpdates', (data) => {
      // Normalize peerUpdates event names to match activity log conventions.
      const normalized = { ...data };
      if (data.event === 'connected') normalized.event = 'peer_connected';
      else if (data.event === 'disconnected') normalized.event = 'peer_disconnected';
      else if (data.event === 'banned') normalized.event = 'peer_banned';
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
    // Must chain: getPeerInfo needs peer memory loaded first for name display.
    rpc.call('noble_getPeerMemory').then(records => {
      if (Array.isArray(records)) {
        for (const r of records) {
          // Names from peer memory are now resolved by the backend — no client map.
        }
      }
      // Now that names are populated, seed peer connections.
      return rpc.call('noble_getPeerInfo');
    }).then(peers => {
      if (Array.isArray(peers)) {
        for (const p of peers) {
          if (p.status === 'connected' && !seededPeerIds.has(p.peer_id)) {
            seededPeerIds.add(p.peer_id);
            pushPeerEvent({ event: 'peer_connected', peer_id: p.peer_id || '', addr: p.addr || '', direction: p.direction || '', node_name: p.node_name || '' });
          }
        }
      }
    }).catch(() => {});
  }

  // ── Sync banner management ──
  const syncBanner = root.querySelector('#cs-sync-banner');

  function updateSyncBanner(syncing, targetHeight, currentHeight, progressPct) {
    if (!syncBanner) return;
    if (syncing) {
      syncBanner.style.display = 'block';
      if (currentHeight && targetHeight) {
        syncBanner.textContent = `Syncing \u2014 block ${formatNumber(currentHeight)} of ${formatNumber(targetHeight)} (${progressPct || 0}%)`;
      } else if (targetHeight) {
        syncBanner.textContent = `Syncing \u2014 catching up to height ${formatNumber(targetHeight)}\u2026`;
      } else {
        syncBanner.textContent = 'Syncing \u2014 catching up to peer chain\u2026';
      }
    } else {
      syncBanner.style.display = 'none';
    }
  }

  // ── Startup seed: lightweight "node is alive" snapshot ──
  function seedNodeStatus() {
    rpc.call('noble_getNodeInfo').then(info => {
      if (info) {
        pushActivity({ event: 'heartbeat', message: `Node v${info.version}` });
        // Show sync banner immediately from RPC state (no WS event needed).
        updateSyncBanner(info.sync_behind, info.sync_target_height, info.sync_current_height, info.sync_progress_pct);
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

  function updateStrategyUI(select, descEl) {
    const strategy = select.value;
    descEl.textContent = STRATEGY_DESCRIPTIONS[strategy] || '';
  }

  r1Select.addEventListener('change', () => { updateStrategyUI(r1Select, r1Desc); loadValidators(); });
  r2Select.addEventListener('change', () => { updateStrategyUI(r2Select, r2Desc); loadValidators(); });

  // Help modal
  strategyHelpBtn.addEventListener('click', () => { strategyModal.style.display = 'flex'; });
  strategyModalClose.addEventListener('click', () => { strategyModal.style.display = 'none'; });
  strategyModal.addEventListener('click', (e) => { if (e.target === strategyModal) strategyModal.style.display = 'none'; });

  async function loadVotingStrategy() {
    try {
      const result = await rpc.call('noble_getVotingStrategy');
      r1Select.value = result.round1_strategy;
      r2Select.value = result.round2_strategy;
      currentStrategyParams.r1 = result.round1_params || null;
      currentStrategyParams.r2 = result.round2_params || null;
      updateStrategyUI(r1Select, r1Desc);
      updateStrategyUI(r2Select, r2Desc);
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
      await rpc.call('noble_setVotingStrategy', { round: 1, strategy: r1Name, params: currentStrategyParams.r1 });

      // Save Round 2
      const r2Name = r2Select.value;
      await rpc.call('noble_setVotingStrategy', { round: 2, strategy: r2Name, params: currentStrategyParams.r2 });

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

  async function loadVoteTallies() {
    try {
      lastTallyResult = await rpc.call('noble_getVoteTallies');
      tallyMeta.textContent = `Cycle #${formatNumber(lastTallyResult.cycle ?? 0)} — ${lastTallyResult.phase || '--'}`;
      renderTallies();
    } catch (e) {
      console.error('[consensus] load tallies:', e);
    }
  }

  function renderTallies() {
    const result = lastTallyResult;
    if (!result || !result.tallies || result.tallies.length === 0) {
      talliesBody.innerHTML = '<div class="empty-state">No votes recorded for the current cycle.</div>';
      return;
    }

    const isR2 = tallyRound === 'r2';
    const entries = result.tallies
      .map(t => ({
        ...t,
        count: isR2 ? (t.r2_vote_count || 0) : t.vote_count,
      }))
      .sort((a, b) => b.count - a.count);

    const total = entries.reduce((s, t) => s + t.count, 0);
    const isManual = !isR2 && (r1Select.value === 'manual' || r2Select.value === 'manual');

    talliesBody.innerHTML = entries.map(t => {
      const pct = total > 0 ? Math.round(t.count / total * 100) : 0;
      const name = t.validator || truncateHash(t.validator_key || t.block_hash, 8);
      const voteBtn = isManual
        ? `<button class="btn btn-sm cs-inline-vote-btn" data-hash="${t.block_hash}" style="flex-shrink:0;padding:2px 8px;font-size:11px">Vote</button>`
        : '';
      return `<div style="display:flex;align-items:center;gap:var(--gap-sm);padding:4px 0">
        <span style="font-weight:600;font-size:var(--font-size-xs);width:${isManual ? '30%' : '38%'};flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${t.block_hash}">${escapeHtml(name)}</span>
        <div style="flex:1;min-width:40px;height:8px;background:var(--bg-tertiary);border-radius:4px">
          <div style="height:100%;width:${pct}%;background:${isR2 ? 'var(--success)' : 'var(--accent)'};border-radius:4px;transition:width 0.3s"></div>
        </div>
        <span style="font-weight:600;flex-shrink:0;text-align:right;min-width:60px;font-size:var(--font-size-xs)">${t.count} (${pct}%)</span>
        ${voteBtn}
      </div>`;
    }).join('');

    if (isManual) {
      talliesBody.querySelectorAll('.cs-inline-vote-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
          const hash = btn.dataset.hash;
          btn.disabled = true;
          btn.textContent = '...';
          try {
            await rpc.call('noble_castVote', [hash]);
            btn.textContent = 'Voted';
            btn.style.background = 'var(--success)';
            btn.style.color = '#fff';
            setTimeout(() => loadVoteTallies(), 2000);
          } catch {
            btn.textContent = 'Error';
            btn.style.background = 'var(--error)';
            btn.style.color = '#fff';
            setTimeout(() => { btn.textContent = 'Vote'; btn.disabled = false; btn.style.background = ''; btn.style.color = ''; }, 3000);
          }
        });
      });
    }
  }

  const PHASES = ['Block Proposal', 'Voting', 'Reflection', 'Propagation'];
  const PHASE_DURATION = 300; // 5:00 per phase

  // ══════════════════════════════════════════════
  // SUPERPOSITION TIMELINE
  // ══════════════════════════════════════════════

  /** Transform flat API entry into the phase-based format renderTimeline expects. */
  function apiEntryToCycle(entry, isCurrent) {
    // Gap placeholder — no proposals, no votes, just an empty marker.
    if (entry._gap) return entry;
    // If already has phases (mock data), pass through.
    if (entry.phases) return entry;
    const hasWinner = !!entry.winner;
    const hasProposals = (entry.proposals || []).length > 0;
    const hasVotes = (entry.votes || []).length > 0;
    const indeterminate = entry.status === 'indeterminate' || (!hasWinner && !isCurrent);

    // Empty active cycle: no proposals, no votes — show as gray collapsed row.
    if (isCurrent && !hasProposals && !hasVotes && !hasWinner) {
      return {
        cycle_number: entry.cycle_number,
        is_current: true,
        _empty: true,
      };
    }

    // Sort proposals by validator key for deterministic display across nodes
    const sortedProposals = [...(entry.proposals || [])].sort((a, b) => (a.validator || '').localeCompare(b.validator || ''));

    return {
      cycle_number: entry.cycle_number,
      is_current: isCurrent,
      indeterminate,
      disambiguation: entry.disambiguation,
      winner: entry.winner,
      winning_hash: entry.winning_hash,
      finalized_at: entry.finalized_at || null,
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
          state: hasWinner ? 'complete' : isCurrent ? 'pending' : 'complete',
          winner: entry.winner,
          winning_hash: entry.winning_hash,
          disambiguation: entry.disambiguation,
        },
        {
          name: 'Propagation',
          state: hasWinner ? 'complete' : isCurrent ? 'pending' : 'complete',
          finalized: hasWinner,
          block_hash: entry.winning_hash,
        },
      ],
    };
  }

  const TIMELINE_LIMIT = 2; // 2 finalized + 1 active = 3 visible

  /**
   * Verify and correct winner information in timeline entries against
   * committed block data (the second source of truth).
   *
   * Block data from noble_getBlockRange is chain truth — identical on
   * every synced node. Local cycle history (noble_getCycleHistory) records
   * this node's ENGINE view, which may differ when the node voted for a
   * candidate that lost.
   *
   * For each entry that has a committed block, the block's validator
   * replaces whatever the cycle history recorded as winner.
   *
   * @param {Array} entries - Timeline entries (mutated in place)
   * @param {Map} cycleBlockMap - cycle_number → block from noble_getBlockRange
   */
  function verifyWinnersAgainstBlocks(entries, cycleBlockMap) {
    for (const entry of entries) {
      if (entry.status === 'active' || entry._gap) continue;
      const block = cycleBlockMap.get(entry.cycle_number);
      if (!block) continue;

      const blockValidator = block.validator_name || block.validator_id || '';
      if (!blockValidator) continue;

      // Chain truth overrides local history unconditionally.
      if (entry.winner && entry.winner !== blockValidator) {
        tracing_debug(
          `[consensus] Winner corrected for cycle ${entry.cycle_number}: ` +
          `history="${entry.winner}" → chain="${blockValidator}"`
        );
      }
      entry.winner = blockValidator;
      entry.winning_hash = block.hash || entry.winning_hash || '';
      entry.status = 'finalized';
    }
  }

  /** Debug logger — only in dev mode (console available). */
  function tracing_debug(msg) {
    if (typeof console !== 'undefined' && console.debug) console.debug(msg);
  }

  async function loadTimeline() {
    try {
      // ── Build timeline from CHAIN DATA (committed blocks), not local history ──
      // try_sync_import does NOT write cycle history, so nodes that synced from
      // peers have no local history for those cycles.  Committed blocks ARE
      // chain data — identical on every synced node.  We use blocks as the
      // backbone and overlay local cycle history for enrichment (proposals,
      // votes, disambiguation).
      const [blockCount, cycleStatus, tallies, history] = await Promise.all([
        rpc.call('noble_getBlockCount').catch(e => { console.warn('[consensus] getBlockCount failed:', e.message); return { height: 0 }; }),
        rpc.call('noble_getCycleStatus').catch(e => { console.warn('[consensus] getCycleStatus failed:', e.message); return null; }),
        rpc.call('noble_getVoteTallies').catch(e => { console.warn('[consensus] getVoteTallies failed:', e.message); return null; }),
        rpc.call('noble_getCycleHistory', [TIMELINE_LIMIT * 5]).catch(e => { console.warn('[consensus] getCycleHistory failed:', e.message); return { entries: [] }; }),
      ]);

      const tipHeight = blockCount.height || 0;
      const creating = cycleStatus && cycleStatus.cycle_number === 0 && tipHeight >= 1;
      if ((tipHeight === 0 && !cycleStatus) || creating) {
        csTimeline.innerHTML = creating
          ? '<div class="empty-state">Chain created — waiting for first consensus cycle</div>'
          : '<div class="empty-state">No consensus cycles yet</div>';
        return false;
      }

      // Fetch recent blocks from the chain — enough to fill TIMELINE_LIMIT cycles.
      // Each block carries its cycle number; this is chain truth.
      const fetchCount = Math.min(tipHeight, TIMELINE_LIMIT * 3);
      let recentBlocks = [];
      if (fetchCount > 0) {
        const startH = Math.max(1, tipHeight - fetchCount + 1);
        recentBlocks = await rpc.call('noble_getBlockRange', [startH, tipHeight - startH + 1])
          .catch(e => { console.warn('[consensus] getBlockRange failed:', e.message); return []; });
      }

      // Build cycle→block mapping from committed blocks (newest first).
      // Each cycle produces at most one committed block.
      const cycleBlockMap = new Map(); // cycle_number → block info
      for (let i = recentBlocks.length - 1; i >= 0; i--) {
        const b = recentBlocks[i];
        if (b.cycle != null && !cycleBlockMap.has(b.cycle)) {
          cycleBlockMap.set(b.cycle, b);
        }
      }

      // Build local cycle history lookup for enrichment.
      const historyEntries = (history.entries || history.cycles || []);
      const historyMap = new Map(); // cycle_number → history entry
      for (const e of historyEntries) {
        historyMap.set(e.cycle_number, e);
      }

      // Determine the cycle range for the timeline.
      let highestCycle = 0;
      if (cycleStatus && cycleStatus.cycle_number != null) {
        highestCycle = cycleStatus.cycle_number;
      }
      for (const [c] of cycleBlockMap) {
        if (c > highestCycle) highestCycle = c;
      }

      // Collect finalized cycle numbers from blocks (newest first).
      const blockCycles = [...cycleBlockMap.keys()].sort((a, b) => b - a);

      // Build timeline entries: active cycle + recent finalized + gaps.
      const allEntries = [];

      // 1) Active cycle (live state — same on all nodes since it's time-derived).
      if (cycleStatus && cycleStatus.cycle_number != null) {
        const liveCycle = cycleStatus.cycle_number;
        const liveProposals = (tallies?.tallies || []).map(t => ({
          validator: t.validator || t.block_hash,
          block_hash: t.block_hash,
          tx_count: t.tx_count || 0,
        }));
        const liveVotes = (tallies?.tallies || []).filter(t => t.vote_count > 0).map(t => ({
          block_hash: t.block_hash,
          validator: t.validator || '',
          vote_count: t.vote_count || 0,
          r2_vote_count: t.r2_vote_count || 0,
        }));
        allEntries.push({
          cycle_number: liveCycle,
          status: 'active',
          proposals: liveProposals,
          votes: liveVotes,
          winner: null,
          winning_hash: null,
          disambiguation: null,
          finalized_at: null,
        });
      }

      // 2) Past cycles: walk down from highestCycle-1, collect up to TIMELINE_LIMIT
      //    finalized cycles (from blocks) with gap rows in between.
      //    Cap the scan range to avoid iterating hundreds of empty cycles
      //    (e.g. when bootstrap cycle inflation produced a high cycle number).
      let collected = 0;
      const lowestBlockCycle = blockCycles.length > 0 ? blockCycles[blockCycles.length - 1] : highestCycle;
      const startCycle = allEntries.length > 0 ? allEntries[0].cycle_number - 1 : highestCycle;
      const MAX_SCAN_GAP = TIMELINE_LIMIT * 10;
      const scanFloor = Math.max(lowestBlockCycle, startCycle - MAX_SCAN_GAP);

      for (let c = startCycle; c >= scanFloor && collected < TIMELINE_LIMIT; c--) {
        const block = cycleBlockMap.get(c);
        if (block) {
          // Committed block exists — this cycle is FINALIZED (chain truth).
          // Enrich with local history if available, but chain truth wins:
          // if history says indeterminate but chain has a committed block,
          // force winner/winning_hash from the block.
          const hist = historyMap.get(c);
          if (hist) {
            // Chain truth: block's validator is the real winner.
            // Local cycle history may record a different winner if this
            // node's engine voted for a different candidate.
            hist.winner = block.validator_name || block.validator_id || hist.winner || '';
            hist.winning_hash = block.hash || hist.winning_hash || '';
            hist.status = 'finalized';
            hist.finalized_at = hist.finalized_at || block.timestamp || null;
            allEntries.push(hist);
          } else {
            // No local history — synthesize minimal entry from block data.
            allEntries.push({
              cycle_number: c,
              status: 'finalized',
              proposals: [{
                validator: block.validator_name || block.validator_id || '',
                block_hash: block.hash || '',
                tx_count: block.tx_count || 0,
              }],
              votes: [],
              winner: block.validator_name || block.validator_id || '',
              winning_hash: block.hash || '',
              disambiguation: null,
              finalized_at: block.timestamp || null,
            });
          }
          collected++;
        } else {
          // No committed block for this cycle — gap row ("no block").
          // This is chain truth: no block exists at this cycle on any synced node.
        }
      }

      if (allEntries.length === 0) {
        csTimeline.innerHTML = '<div class="empty-state">No consensus cycles yet</div>';
        return;
      }

      // ── Verify winners against block data (chain truth) ──
      // Corrects any cycle where local engine history recorded a different
      // winner than the actual committed block validator.
      verifyWinnersAgainstBlocks(allEntries, cycleBlockMap);

      // Insert gap placeholders between consecutive entries (newest-first).
      const filled = [];
      for (let i = 0; i < allEntries.length; i++) {
        filled.push(allEntries[i]);
        if (i < allEntries.length - 1) {
          const hi = allEntries[i].cycle_number;
          const lo = allEntries[i + 1].cycle_number;
          if (hi - lo <= 1) continue;
          // Collapse all empty cycles into a single summary line.
          const gapSize = hi - lo - 1;
          filled.push({
            cycle_number: null,
            status: 'gap_summary',
            _gapCount: gapSize,
            _gapFrom: lo + 1,
            _gapTo: hi - 1,
            proposals: [],
            votes: [],
            _gap: true,
          });
        }
      }

      const cycles = filled.map((e, i) =>
        apiEntryToCycle(e, i === 0 && (e.status === 'active' || !e.finalized_at))
      );

      // Fetch per-block vote witnesses for recent blocks.
      // These survive ClearCycleHistory and carry individual voter names.
      // Uses tipHeight from noble_getBlockCount (already fetched above).
      try {
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
      } catch (_) { /* getBlockVotes not available */ }

      // Enrich empty voting phases from blockVotes witness data.
      // Synced nodes and genesis blocks may lack local vote tallies,
      // but noble_getBlockVotes always has the committed witness data.
      for (const cycle of cycles) {
        if (!cycle._blockVotes || !cycle.phases) continue;
        const votingPhase = cycle.phases[1];
        if (votingPhase.votes && votingPhase.votes.length > 0) continue;

        const bv = cycle._blockVotes;
        const winningHash = cycle.winning_hash || (cycle.phases[2] && cycle.phases[2].winning_hash);
        if (winningHash) {
          votingPhase.votes = [{
            block_hash: winningHash,
            validator: cycle.winner || '',
            vote_count: bv.r1_voters.length,
            r2_vote_count: bv.r2_voters.length,
          }];
          votingPhase.total_voters = bv.voter_count;
        }
      }

      // Fetch finality status for per-block finality badges.
      let finalityStatus = null;
      try {
        finalityStatus = await rpc.call('noble_getFinalityStatus', []);
      } catch (_) { /* getFinalityStatus not available */ }

      // Fetch checkpoint data for timeline markers.
      let checkpointData = null;
      try {
        checkpointData = await rpc.call('noble_getCheckpoints', [50]);
      } catch (_) { /* getCheckpoints not available */ }

      renderTimeline(cycles, finalityStatus, checkpointData);
      return true;
    } catch (e) {
      console.error('[consensus] load timeline:', e);
      csTimeline.innerHTML = '<div class="empty-state">Failed to load cycle history</div>';
      return false;
    }
  }

  function renderTimeline(cycles, finalityStatus, checkpointData) {
    csTimeline.innerHTML = '';

    // Track all validators that participated
    const participantMap = new Map(); // validator_name → { role[], cycles[] }

    for (const cycle of cycles) {
      // ── Gap placeholder (empty cycle) ──
      if (cycle._gap) {
        const row = document.createElement('div');
        row.style.cssText = 'margin-bottom:var(--gap-xs);opacity:0.4;padding:4px 0';
        if (cycle.status === 'gap_summary') {
          row.innerHTML = `<span style="font-size:var(--font-size-xs);color:var(--text-muted);font-style:italic">… ${cycle._gapCount} empty cycles (#${formatNumber(cycle._gapFrom)}–#${formatNumber(cycle._gapTo)}) …</span>`;
        } else {
          // Gap rows are derived from chain data: no committed block exists for
          // this cycle.  Always "no block" — identical on all synced nodes.
          const label = 'no block';
          const color = 'var(--text-muted)';
          row.innerHTML = `<span style="font-weight:700;font-size:var(--font-size-sm)">Cycle #${formatNumber(cycle.cycle_number)}</span> <span style="font-size:var(--font-size-xs);color:${color};font-weight:600">${label}</span>`;
        }
        csTimeline.appendChild(row);
        continue;
      }

      // ── Empty active cycle (no proposals, no votes) ──
      if (cycle._empty) {
        const row = document.createElement('div');
        row.style.cssText = 'margin-bottom:var(--gap-xs);padding:6px 0;opacity:0.5';
        row.innerHTML = `
          <span style="font-weight:700;font-size:var(--font-size-sm)">Cycle #${formatNumber(cycle.cycle_number)}</span>
          <span style="font-size:var(--font-size-xs);color:var(--text-muted);font-weight:600">WAITING</span>
          <span style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:var(--gap-sm)">no proposals yet</span>
        `;
        csTimeline.appendChild(row);
        continue;
      }

      const row = document.createElement('div');
      row.style.cssText = 'margin-bottom:var(--gap-lg)';

      // ── Cycle header ──
      // Distinguish "no consensus" (proposals existed, votes tied) from
      // "no proposals" (truly empty cycle — nobody proposed a block).
      const hadProposals = cycle.phases[0] && cycle.phases[0].proposals && cycle.phases[0].proposals.length > 0;
      const statusLabel = cycle.is_current ? 'ACTIVE'
        : cycle.indeterminate ? (hadProposals ? 'NO CONSENSUS' : 'NO PROPOSALS')
        : 'FINALIZED';
      const statusColor = cycle.is_current ? 'var(--accent)'
        : cycle.indeterminate ? (hadProposals ? 'var(--warning, #e8a435)' : 'var(--text-muted)')
        : 'var(--success)';
      let disambigBadge = '';
      if (!cycle.indeterminate) {
        disambigBadge = cycle.disambiguation
          ? `<span style="margin-left:var(--gap-sm);padding:1px 6px;border-radius:9999px;font-size:var(--font-size-xs);background:color-mix(in srgb, var(--warning) 15%, transparent);color:var(--warning)">disambiguation</span>`
          : `<span style="margin-left:var(--gap-sm);padding:1px 6px;border-radius:9999px;font-size:var(--font-size-xs);background:color-mix(in srgb, var(--success) 15%, transparent);color:var(--success)">clean</span>`;
      }

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap-xs)';
      const timeLabel = cycle.finalized_at ? new Date(cycle.finalized_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      header.innerHTML = `
        <span style="font-weight:700;font-size:var(--font-size-sm)">Cycle #${formatNumber(cycle.cycle_number)}</span>
        <span style="font-size:var(--font-size-xs);color:${statusColor};font-weight:600">${statusLabel}</span>
        ${disambigBadge}
        ${(() => {
          const proposals = cycle.phases[0]?.proposals || [];
          if (proposals.length === 0) return '';
          const counts = proposals.map(p => p.tx_count || 0);
          const txMin = Math.min(...counts);
          const txMax = Math.max(...counts);
          let txLabel;
          if (cycle.winner) {
            const wp = proposals.find(p => p.validator === cycle.winner);
            txLabel = `${wp ? wp.tx_count : '?'} transactions`;
          } else {
            txLabel = txMin === txMax ? `${txMin} transactions` : `${txMin} to ${txMax} transactions`;
          }
          return `<span style="font-size:var(--font-size-xs);color:var(--text-muted)">${txLabel}</span>`;
        })()}
        ${cycle.winner ? `<span style="margin-left:auto;font-size:var(--font-size-xs);color:var(--text-secondary)">Winner: <strong title="${cycle.winner}">${escapeHtml(cycle.winner)}</strong></span>` : ''}
        ${timeLabel ? `<span style="${cycle.winner ? '' : 'margin-left:auto;'}font-size:var(--font-size-xs);color:var(--text-muted)">${timeLabel}</span>` : ''}
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
          seg.style.opacity = '0.85';
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
          } else if (cycle._blockVotes) {
            // Fallback: use per-block witness data when cycle history lacks tallies
            const bv = cycle._blockVotes;
            label += `<div style="font-size:0.55rem;opacity:0.85">${bv.unique_witness_count} witness${bv.unique_witness_count !== 1 ? 'es' : ''}</div>`;
          } else {
            label += `<div style="font-size:0.55rem;opacity:0.5">—</div>`;
          }
        } else if (pi === 2) {
          // Reflection (R2 / winner)
          if (phase.winner) {
            const icon = phase.disambiguation ? '&#9878;' : '&#10003;';
            label += `<div style="font-size:0.55rem;opacity:0.85">${icon} ${escapeHtml(phase.winner || '')}</div>`;

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
            let blockH = 0;
            if (finalityStatus && finalityStatus.finalized_height > 0) {
              const cycleIdx = cycles.indexOf(cycle);
              const tipH = finalityStatus.latest_height;
              const depth = cycleIdx;
              blockH = tipH - depth;
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
            if (checkpointData && checkpointData.checkpoints && blockH > 0) {
              const cp = checkpointData.checkpoints.find(c => c.height === blockH);
              if (cp) {
                const cpStyle = cp.active
                  ? 'color:var(--accent-green,#4caf50)'
                  : 'color:var(--accent-yellow,#ffc107);opacity:0.8';
                const cpLabel = cp.active ? '&#9875; CP' : '&#9875; CP (pending)';
                label += `<div style="font-size:0.5rem;${cpStyle}">${cpLabel}</div>`;
              }
            }
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
        const proposals = cycle.phases[0].proposals;
        const useCoverflow = proposals.length > 2;
        const strip = document.createElement('div');

        // Build card HTML for each proposal
        function buildProposalCard(p) {
          const isWinner = cycle.winner === p.validator;
          const borderColor = isWinner ? 'var(--success)' : cycle.disambiguation ? 'var(--error)' : 'var(--border)';
          const icon = isWinner ? '<span style="color:var(--success)">&#10003;</span>' : cycle.disambiguation ? '<span style="color:var(--error)">&#10007;</span>' : '';
          const vName = escapeHtml(p.validator || truncateHash(p.block_hash, 6));
          let html = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px">
              <strong>${vName}</strong>
              ${icon}
            </div>
            <div style="color:var(--text-muted)">
              ${p.tx_count} txs &middot; <span class="mono">${truncateHash(p.block_hash, 4)}</span>
            </div>
          `;
          const votingPhase = cycle.phases[1];
          if (votingPhase.votes && votingPhase.votes.length > 0) {
            const voteEntry = votingPhase.votes.find(v => v.block_hash === p.block_hash);
            if (voteEntry) {
              const r1 = voteEntry.vote_count;
              const r2 = voteEntry.r2_vote_count || 0;
              const displayVotes = r2 > 0 ? r2 : r1;
              const pct = votingPhase.total_voters > 0 ? Math.min(100, Math.round(displayVotes / votingPhase.total_voters * 100)) : 0;
              const roundLabel = (r2 > 0 && r2 !== r1)
                ? ` <span style="color:var(--text-muted);font-weight:400">(R1:${r1} R2:${r2})</span>`
                : '';
              html += `
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
          return { html, borderColor, isWinner };
        }

        if (useCoverflow) {
          // ── Coverflow layout for ≥3 proposals ──
          strip.className = 'coverflow-container';
          const track = document.createElement('div');
          track.className = 'coverflow-track';

          // Auto-focus winner, or first proposal
          let focusIdx = proposals.findIndex(p => p.validator === cycle.winner);
          if (focusIdx < 0) focusIdx = 0;

          const cards = proposals.map((p, i) => {
            const { html, borderColor } = buildProposalCard(p);
            const card = document.createElement('div');
            card.className = 'coverflow-card';
            card.style.border = `1px solid ${borderColor}`;
            card.innerHTML = html;
            card.addEventListener('click', () => {
              focusIdx = i;
              updatePositions();
            });
            track.appendChild(card);
            return card;
          });

          function updatePositions() {
            cards.forEach((card, i) => {
              const pos = i - focusIdx;
              if (Math.abs(pos) > 2) card.setAttribute('data-pos', 'hidden');
              else card.setAttribute('data-pos', String(pos));
            });
          }

          // Navigation arrows
          const leftNav = document.createElement('button');
          leftNav.className = 'coverflow-nav coverflow-nav--left';
          leftNav.innerHTML = '&#x276E;';
          leftNav.addEventListener('click', (e) => {
            e.stopPropagation();
            if (focusIdx > 0) { focusIdx--; updatePositions(); }
          });

          const rightNav = document.createElement('button');
          rightNav.className = 'coverflow-nav coverflow-nav--right';
          rightNav.innerHTML = '&#x276F;';
          rightNav.addEventListener('click', (e) => {
            e.stopPropagation();
            if (focusIdx < proposals.length - 1) { focusIdx++; updatePositions(); }
          });

          strip.appendChild(track);
          strip.appendChild(leftNav);
          strip.appendChild(rightNav);
          updatePositions();

          // Mouse/touch drag with natural inertia + mouse wheel
          let dragStartX = 0, lastMoveX = 0, lastMoveTime = 0;
          let dragging = false, accumulated = 0, inertiaId = null;

          function stopInertia() { if (inertiaId) { cancelAnimationFrame(inertiaId); inertiaId = null; } }

          function startDrag(x) {
            stopInertia();
            dragStartX = x; lastMoveX = x; lastMoveTime = Date.now();
            accumulated = 0; dragging = true;
          }

          function moveDrag(x) {
            if (!dragging) return;
            accumulated += x - lastMoveX;
            lastMoveX = x;
            // Step every 60px of accumulated movement
            while (accumulated > 60) { accumulated -= 60; if (focusIdx > 0) { focusIdx--; updatePositions(); } }
            while (accumulated < -60) { accumulated += 60; if (focusIdx < proposals.length - 1) { focusIdx++; updatePositions(); } }
          }

          function endDrag() {
            if (!dragging) return;
            dragging = false;
            const dt = Math.max(1, Date.now() - lastMoveTime);
            let velocity = accumulated / dt; // px/ms
            // Natural inertia via requestAnimationFrame with exponential decay
            function inertiaStep() {
              velocity *= 0.92;
              accumulated += velocity * 16;
              let stepped = false;
              while (accumulated > 60) { accumulated -= 60; if (focusIdx > 0) { focusIdx--; updatePositions(); stepped = true; } }
              while (accumulated < -60) { accumulated += 60; if (focusIdx < proposals.length - 1) { focusIdx++; updatePositions(); stepped = true; } }
              if (Math.abs(velocity) > 0.05) inertiaId = requestAnimationFrame(inertiaStep);
              else inertiaId = null;
            }
            if (Math.abs(velocity) > 0.1) inertiaId = requestAnimationFrame(inertiaStep);
          }

          strip.addEventListener('mousedown', (e) => { e.preventDefault(); startDrag(e.clientX); });
          strip.addEventListener('mousemove', (e) => moveDrag(e.clientX));
          strip.addEventListener('mouseup', endDrag);
          strip.addEventListener('mouseleave', endDrag);
          strip.addEventListener('touchstart', (e) => startDrag(e.touches[0].clientX), { passive: true });
          strip.addEventListener('touchmove', (e) => moveDrag(e.touches[0].clientX), { passive: true });
          strip.addEventListener('touchend', endDrag);

          // Mouse wheel: scroll through cards
          strip.addEventListener('wheel', (e) => {
            e.preventDefault();
            if (e.deltaX > 20 || e.deltaY > 20) { if (focusIdx < proposals.length - 1) { focusIdx++; updatePositions(); } }
            else if (e.deltaX < -20 || e.deltaY < -20) { if (focusIdx > 0) { focusIdx--; updatePositions(); } }
          }, { passive: false });
        } else {
          // ── Simple flex layout for 1-2 proposals ──
          strip.style.cssText = 'display:flex;gap:var(--gap);margin-top:var(--gap-xs);flex-wrap:wrap';
          for (const p of proposals) {
            const { html, borderColor } = buildProposalCard(p);
            const card = document.createElement('div');
            card.style.cssText = `flex:1;min-width:180px;padding:var(--gap-sm);border:1px solid ${borderColor};border-radius:var(--radius-sm);background:var(--bg-secondary);font-size:var(--font-size-xs)`;
            card.innerHTML = html;
            strip.appendChild(card);
          }
        }

        // Per-block vote witness strip (below proposal cards)
        if (cycle._blockVotes) {
          const bv = cycle._blockVotes;
          const witnessDiv = document.createElement('div');
          witnessDiv.style.cssText = 'margin-top:var(--gap-xs);padding:var(--gap-sm);border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg-secondary);font-size:var(--font-size-xs)';
          const allVoters = new Map();
          for (const v of bv.r1_voters || []) allVoters.set(v.validator_key, { name: v.name || truncateHash(v.validator_key, 8), r1: true, r2: false });
          for (const v of bv.r2_voters || []) {
            const existing = allVoters.get(v.validator_key);
            if (existing) { existing.r2 = true; }
            else allVoters.set(v.validator_key, { name: v.name || truncateHash(v.validator_key, 8), r1: false, r2: true });
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
            const dn = escapeHtml(pubkey);
            return `<div style="display:flex;align-items:center;gap:var(--gap-xs);padding:3px 8px;background:var(--bg-secondary);border-radius:var(--radius-sm);font-size:var(--font-size-xs)" title="${pubkey}">
              <span style="width:6px;height:6px;border-radius:50%;background:${dotColor}"></span>
              <strong>${dn}</strong>
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
    // cycle_number == 0 with blocks committed = post-genesis re-alignment ("Creating").
    const blockHeight = window.state?.blockHeight || 0;
    const creating = status.cycle_number === 0 && blockHeight >= 1;
    const sane = status.cycle_number != null && !creating;
    csCycleNum.textContent = creating ? '—' : (sane ? formatNumber(status.cycle_number) : '—');
    csPhaseName.textContent = creating ? 'Creating' : (status.phase || 'Bootstrapping');
    csCycleInfo.textContent = creating ? 'Forming consensus' : (sane ? `#${formatNumber(status.cycle_number)}` : 'Forming chain');

    // Track phase key for UI updates (phase_change activity comes from WS only).
    lastPhaseKey = `${status.cycle_number || 'boot'}:${status.phase_index}`;

    if (creating) {
      // Post-genesis re-alignment: block 1 committed, engine resetting epoch.
      // Hide cycle details and pipeline — show "Creating" status only.
      csPhaseName.textContent = 'Creating';
      csPhaseRemaining.textContent = formatCountdown(status.cycle_remaining_secs || 0);
      csCycleRemaining.textContent = formatCountdown(status.cycle_remaining_secs || 0);
      csValidator.textContent = '—';
      csPipeline.innerHTML = `<div style="text-align:center;padding:var(--gap);color:var(--text-muted);font-size:var(--font-size-sm)">Chain created — waiting for first consensus cycle</div>`;
      if (tickFn) window._nobleTick.remove(tickFn);
      const creatingEnd = Date.now() + (status.cycle_remaining_secs || 0) * 1000;
      tickFn = () => {
        const left = Math.max(0, Math.round((creatingEnd - Date.now()) / 1000));
        csPhaseRemaining.textContent = formatCountdown(left);
        csCycleRemaining.textContent = formatCountdown(left);
        if (left <= 0) {
          window._nobleTick.remove(tickFn); tickFn = null;
          loadCycle(); loadTimeline(); loadVoteTallies();
          setTimeout(() => { loadCycle(); loadTimeline(); loadVoteTallies(); }, 3000);
        }
      };
      window._nobleTick.add(tickFn);
      return;
    }

    if (!sane) {
      // Bootstrap: no genesis yet. Derive phase from timers.
      const cycleDur = PHASE_DURATION * 4;
      let cycleRemaining = status.cycle_remaining_secs || 0;
      const elapsed = cycleDur - cycleRemaining;
      const activeIdx = Math.min(3, Math.floor(elapsed / PHASE_DURATION));
      const phaseElapsed = elapsed - (activeIdx * PHASE_DURATION);
      let phaseRemaining = Math.max(0, PHASE_DURATION - phaseElapsed);

      csPhaseName.textContent = PHASES[activeIdx];
      csPhaseRemaining.textContent = formatCountdown(phaseRemaining);
      csCycleRemaining.textContent = formatCountdown(cycleRemaining);
      csValidator.textContent = '—';

      csPipeline.innerHTML = renderPipeline(activeIdx, phaseRemaining);

      if (tickFn) window._nobleTick.remove(tickFn);
      const bootPhaseEnd = Date.now() + phaseRemaining * 1000;
      const bootCycleEnd = Date.now() + cycleRemaining * 1000;
      tickFn = () => {
        const t = Date.now();
        const pLeft = Math.max(0, Math.round((bootPhaseEnd - t) / 1000));
        const cLeft = Math.max(0, Math.round((bootCycleEnd - t) / 1000));
        csPhaseRemaining.textContent = formatCountdown(pLeft);
        csCycleRemaining.textContent = formatCountdown(cLeft);
        const activeTimer = root.querySelector(`#cs-phase-time-${activeIdx}`);
        if (activeTimer) activeTimer.textContent = formatCountdown(pLeft);
        if (pLeft <= 0 || cLeft <= 0) {
          window._nobleTick.remove(tickFn); tickFn = null;
          loadCycle(); loadTimeline(); loadVoteTallies();
          setTimeout(() => { loadCycle(); loadTimeline(); loadVoteTallies(); }, 3000);
        }
      };
      window._nobleTick.add(tickFn);
      return;
    }

    // CycleStatusResponse doesn't carry current_validator — show '—'.
    csValidator.textContent = '—';

    const activeIdx = status.phase_index;

    // (Phase Progression replaced by Protocol Activity log panel)

    // Pipeline header
    csPipeline.innerHTML = renderPipeline(activeIdx, status.phase_remaining_secs);

    // Countdown — wall-clock based via global tick
    if (tickFn) window._nobleTick.remove(tickFn);
    const phaseEnd = Date.now() + status.phase_remaining_secs * 1000;
    const cycleEnd = Date.now() + status.cycle_remaining_secs * 1000;
    tickFn = () => {
      const t = Date.now();
      const phaseLeft = Math.max(0, Math.round((phaseEnd - t) / 1000));
      const cycleLeft = Math.max(0, Math.round((cycleEnd - t) / 1000));
      csPhaseRemaining.textContent = formatCountdown(phaseLeft);
      csCycleRemaining.textContent = formatCountdown(cycleLeft);
      const activeTimer = root.querySelector(`#cs-phase-time-${activeIdx}`);
      if (activeTimer) activeTimer.textContent = formatCountdown(phaseLeft);
      if (phaseLeft <= 0) {
        window._nobleTick.remove(tickFn); tickFn = null;
        loadCycle(); loadTimeline(); loadVoteTallies();
        setTimeout(() => { loadCycle(); loadTimeline(); loadVoteTallies(); }, 3000);
      }
    };
    window._nobleTick.add(tickFn);
    csPhaseRemaining.textContent = formatCountdown(status.phase_remaining_secs);
    csCycleRemaining.textContent = formatCountdown(status.cycle_remaining_secs);
  }

  async function loadCycle() {
    try {
      const status = await rpc.call('noble_getCycleStatus');
      updateCycleDisplay(status);
      return true;
    } catch (e) {
      console.error('[consensus] load cycle:', e);
      return false;
    }
  }

  // ══════════════════════════════════════════════
  // VALIDATOR REGISTRY
  // ══════════════════════════════════════════════

  // Track current display order for drag-and-drop
  let currentDisplayOrder = [];
  let _isDragging = false; // suppress table rebuilds while drag is in progress

  async function loadValidators() {
    if (_isDragging) return; // don't rebuild table mid-drag
    try {
      const [result, nodeInfo, peerMemory, identity, peerInfo] = await Promise.all([
        rpc.call('noble_getValidatorList'),
        rpc.call('noble_getNodeInfo'),
        rpc.call('noble_getPeerMemory').catch(() => []),
        rpc.call('noble_getNodeIdentity').catch(() => ({})),
        rpc.call('noble_getPeerInfo').catch(() => []),
      ]);
      const selfKey = nodeInfo.validator_pubkey_display || nodeInfo.validator_pubkey || null;
      const validators = result?.validators || [];
      const priorityOrder = result.priority_order || [];
      csPolicy.textContent = `Selection: ${result.selection_policy.replace('_', ' ')}`;

      // Populate validator name lookup for use by timeline and other panels.
      // Keys are stored in BOTH bech32 (nbl1…) and hex formats because:
      // - Validator list & peer memory return bech32 keys
      // - Cycle history proposals/votes store hex keys
      // Both must resolve to the same friendly name.

      // Name resolution is now handled entirely by the backend.
      // No client-side name maps needed.

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
      const byKey = new Map(validators.map(v => [valKey(v.public_key), v]));
      const ordered = [];
      for (const key of priorityOrder) {
        if (byKey.has(key)) ordered.push(byKey.get(key));
      }
      for (const v of validators) {
        if (!priorityOrder.includes(valKey(v.public_key))) ordered.push(v);
      }
      currentDisplayOrder = ordered.map(v => valKey(v.public_key));

      // ── Connectivity score lookups ──
      // Map identity_key → peer memory record (connection_count, first_seen, last_seen).
      const memByKey = new Map();
      if (Array.isArray(peerMemory)) {
        for (const r of peerMemory) {
          if (r.identity_key) memByKey.set(r.identity_key, r);
        }
      }
      // Map identity_key → live peer info (latency_ms, connected_at) via peer_id cross-ref.
      const peerIdToIdentity = new Map();
      if (Array.isArray(peerMemory)) {
        for (const r of peerMemory) {
          if (r.peer_id && r.identity_key) peerIdToIdentity.set(r.peer_id, r.identity_key);
        }
      }
      const liveByKey = new Map();
      if (Array.isArray(peerInfo)) {
        for (const p of peerInfo) {
          const ik = peerIdToIdentity.get(p.peer_id);
          if (ik) liveByKey.set(ik, p);
        }
      }

      /**
       * Compute a synthetic Connectivity score (0–100) from available data.
       *
       *  Stability (40%): Fewer reconnections per unit time = better.
       *    score = max(0, 1 - (reconnections / 10))
       *
       *  Uptime (30%): Directly from reputation breakdown.
       *
       *  Latency (30%): Lower is better. Perfect ≤50ms, degrades to 0 at ≥2000ms.
       *    If latency unavailable, use freshness (alive=1, stale=0.5, unreachable=0).
       */
      function connectivityScore(v, keyHex) {
        const isSelfNode = selfKey && keyHex === selfKey;
        if (isSelfNode) return { score: 100, bars: 5, label: 'Local', latencyMs: null };

        const mem = memByKey.get(keyHex);
        const live = liveByKey.get(keyHex);
        const br = v.reputation_breakdown;

        // Stability: penalize reconnections (connection_count includes initial = 1)
        const reconnections = mem ? Math.max(0, (mem.connection_count || 1) - 1) : 0;
        const stability = Math.max(0, 1 - reconnections / 10);

        // Uptime: from reputation breakdown
        const uptime = br ? br.uptime : 0;

        // Latency or freshness fallback
        let latencyComponent;
        const latencyMs = live?.latency_ms;
        if (latencyMs != null) {
          // 0ms→1.0, 50ms→1.0, 500ms→0.75, 2000ms→0
          latencyComponent = Math.max(0, 1 - Math.max(0, latencyMs - 50) / 1950);
        } else {
          // Freshness fallback based on liveness status
          latencyComponent = v.status === 'alive' ? 1 : v.status === 'stale' ? 0.5 : 0;
        }

        const score = Math.round((stability * 0.4 + uptime * 0.3 + latencyComponent * 0.3) * 100);
        const bars = score >= 80 ? 5 : score >= 60 ? 4 : score >= 40 ? 3 : score >= 20 ? 2 : score > 0 ? 1 : 0;
        const label = latencyMs != null ? `${latencyMs}ms` : null;
        return { score, bars, label, latencyMs };
      }

      /** Render signal-strength bars (1–5). */
      function signalBars(bars, score) {
        const barColor = score >= 70 ? 'var(--success)' : score >= 40 ? 'var(--warning, #e6a817)' : 'var(--error)';
        let html = '<span style="display:inline-flex;align-items:flex-end;gap:1px;height:14px" title="Connectivity: ' + score + '/100">';
        for (let i = 1; i <= 5; i++) {
          const h = 3 + i * 2; // heights: 5,7,9,11,13 px
          const active = i <= bars;
          html += `<span style="display:inline-block;width:3px;height:${h}px;border-radius:1px;background:${active ? barColor : 'var(--bg-tertiary)'}"></span>`;
        }
        html += '</span>';
        return html;
      }

      // ── Strategy column helpers ──
      const r1Strat = r1Select.value;
      const r2Strat = r2Select.value;

      // Determine which interactive controls are needed (can have multiple)
      const needProbability = r1Strat === 'weighted_probability' || r2Strat === 'weighted_probability';
      const needCheckbox = r1Strat === 'subset_rotation' || r2Strat === 'subset_rotation';
      const needRadio = r1Strat === 'fixed_validator' || r2Strat === 'fixed_validator';
      const hasStratCol = needProbability || needCheckbox || needRadio;

      // Update column header dynamically based on active strategy
      const colHeader = root.querySelector('#cs-strategy-col-header');
      if (colHeader) {
        if (needProbability && !needCheckbox && !needRadio) colHeader.textContent = 'Probability';
        else if (needCheckbox && !needProbability && !needRadio) colHeader.textContent = 'Subset';
        else if (needRadio && !needProbability && !needCheckbox) colHeader.textContent = 'Target';
        else if (hasStratCol) colHeader.textContent = 'Strategy';
        else colHeader.textContent = '';
      }

      // Compute probability weights for WeightedProbability strategy
      const n = ordered.length;
      const totalWeight = n * (n + 1) / 2;

      // Determine currently-selected keys for checkbox from strategy params
      const subsetKeys = new Set();
      if (needCheckbox) {
        // Merge from whichever round(s) use subset_rotation
        if (r1Strat === 'subset_rotation') {
          for (const k of ((currentStrategyParams.r1 || {}).validators || [])) subsetKeys.add(k);
        }
        if (r2Strat === 'subset_rotation') {
          for (const k of ((currentStrategyParams.r2 || {}).validators || [])) subsetKeys.add(k);
        }
      }

      // Determine currently-selected key for radio from strategy params
      let fixedKey = '';
      if (needRadio) {
        if (r1Strat === 'fixed_validator') {
          fixedKey = (currentStrategyParams.r1 || {}).validator_key || '';
        } else if (r2Strat === 'fixed_validator') {
          fixedKey = (currentStrategyParams.r2 || {}).validator_key || '';
        }
      }

      function strategyCell(keyHex, idx) {
        const parts = [];
        if (needProbability) {
          const weight = n - idx;
          const pct = totalWeight > 0 ? (weight / totalWeight * 100).toFixed(1) : '0.0';
          parts.push(`<span style="display:inline-block;padding:1px 6px;border-radius:9999px;font-size:10px;font-weight:600;background:color-mix(in srgb, var(--accent) 15%, transparent);color:var(--accent)">${pct}%</span>`);
        }
        if (needCheckbox) {
          const checked = subsetKeys.has(keyHex) ? ' checked' : '';
          parts.push(`<input type="checkbox" class="cs-subset-chk" data-key="${keyHex}"${checked} style="cursor:pointer;width:16px;height:16px" title="Subset Rotation">`);
        }
        if (needRadio) {
          const checked = fixedKey === keyHex ? ' checked' : '';
          parts.push(`<input type="radio" name="cs-fixed-validator" class="cs-fixed-radio" data-key="${keyHex}"${checked} style="cursor:pointer;width:16px;height:16px" title="Fixed Validator">`);
        }
        if (!hasStratCol) return '<td></td>';
        return `<td style="text-align:center;white-space:nowrap">${parts.join(' ')}</td>`;
      }

      validatorsTbody.innerHTML = '';
      let dragSrcIdx = null;

      ordered.forEach((v, i) => {
        const keyHex = valKey(v.public_key);
        const br = v.reputation_breakdown;
        const statusClass = v.status === 'alive' ? 'inbound' : 'pending';
        const isSelf = selfKey && keyHex === selfKey;
        const youBadge = isSelf
          ? ' <span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;background:var(--accent);color:#fff;vertical-align:middle;margin-left:4px">YOU</span>'
          : '';
        const removeCell = `<td><button class="btn btn-danger btn-sm cs-remove-btn" data-pubkey="${keyHex}" title="Remove from your accepted list">&#10005;</button></td>`;
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.draggable = false; // only enabled when grabbing the handle
        tr.dataset.idx = i;
        tr.dataset.key = keyHex;
        tr.innerHTML = `
          <td class="cs-drag-handle" title="Drag to reorder, or use arrows" style="cursor:grab;text-align:center;user-select:none;padding:0 4px;position:relative;min-width:38px">
            <span class="cs-grip" style="font-size:1.3em;letter-spacing:2px;color:var(--text-secondary);opacity:0.7;transition:opacity 0.15s">&#8942;&#8942;</span>
            <span class="cs-move-arrows" style="display:none;flex-direction:column;gap:0;position:absolute;inset:0;align-items:center;justify-content:center">
              <button class="cs-move-up" data-dir="up" style="background:none;border:none;cursor:pointer;color:var(--accent);font-size:14px;line-height:1;padding:0 4px;opacity:${i === 0 ? '0.25' : '1'}" ${i === 0 ? 'disabled' : ''} title="Move up">&#9650;</button>
              <button class="cs-move-down" data-dir="down" style="background:none;border:none;cursor:pointer;color:var(--accent);font-size:14px;line-height:1;padding:0 4px;opacity:${i === ordered.length - 1 ? '0.25' : '1'}" ${i === ordered.length - 1 ? 'disabled' : ''} title="Move down">&#9660;</button>
            </span>
          </td>
          <td>${i + 1}</td>
          ${strategyCell(keyHex, i)}
          <td>
            <div style="font-weight:600;font-size:var(--font-size-sm)">${v.has_badge ? '<span title="Voting badge" style="color:var(--success);margin-right:2px">&#9679;</span>' : '<span title="No badge" style="color:var(--text-muted);margin-right:2px;opacity:0.3">&#9675;</span>'}${escapeHtml(v.name) || (isSelf ? 'This Node' : 'Unknown')}${youBadge}</div>
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
          <td class="mono" style="font-size:var(--font-size-xs)">${v.min_fee_rate != null ? v.min_fee_rate + ' g/B' : '—'}</td>
          <td class="mono" style="font-size:var(--font-size-xs)">${(br.uptime * 100).toFixed(1)}%</td>
          <td class="mono" style="font-size:var(--font-size-xs)">${br.trust_score.toFixed(3)}</td>
          <td>${formatNumber(v.blocks_produced)}</td>
          <td>${v.listers_count ?? 0}</td>
          <td style="font-size:var(--font-size-xs)">${v.last_active ? (v.status === 'alive' ? timeAgo(v.last_active) : formatTimestamp(v.last_active)) : '--'}</td>
          <td style="font-size:var(--font-size-xs);white-space:nowrap">${(() => {
            const c = connectivityScore(v, keyHex);
            const sub = c.label ? `<div class="mono" style="font-size:10px;color:var(--text-muted)">${c.label}</div>` : '';
            return `<div style="display:flex;align-items:center;gap:4px">${signalBars(c.bars, c.score)}<span class="mono" style="font-size:var(--font-size-xs)">${c.score}</span></div>${sub}`;
          })()}</td>
          ${removeCell}
        `;

        // ── Hover: show move arrows, hide grip ──
        const handle = tr.querySelector('.cs-drag-handle');
        const grip = tr.querySelector('.cs-grip');
        const arrows = tr.querySelector('.cs-move-arrows');
        if (handle && grip && arrows) {
          handle.addEventListener('mouseenter', () => {
            grip.style.display = 'none';
            arrows.style.display = 'flex';
          });
          handle.addEventListener('mouseleave', () => {
            grip.style.display = '';
            arrows.style.display = 'none';
          });
        }

        // ── Move arrows: click to reorder ──
        async function moveRow(dir) {
          const srcIdx = parseInt(tr.dataset.idx, 10);
          const destIdx = dir === 'up' ? srcIdx - 1 : srcIdx + 1;
          if (destIdx < 0 || destIdx >= currentDisplayOrder.length) return;
          const newOrder = [...currentDisplayOrder];
          const [moved] = newOrder.splice(srcIdx, 1);
          newOrder.splice(destIdx, 0, moved);
          currentDisplayOrder = newOrder;
          try {
            await rpc.call('noble_setValidatorOrder', { order: newOrder });
            loadValidators();
          } catch (err) {
            console.error('[consensus] move validator:', err);
            loadValidators();
          }
        }
        const upBtn = tr.querySelector('.cs-move-up');
        const downBtn = tr.querySelector('.cs-move-down');
        if (upBtn) upBtn.addEventListener('click', (e) => { e.stopPropagation(); moveRow('up'); });
        if (downBtn) downBtn.addEventListener('click', (e) => { e.stopPropagation(); moveRow('down'); });

        // ── Drag-and-drop: set draggable on the row directly for reliable initiation ──
        if (handle) {
          handle.addEventListener('mousedown', () => { tr.draggable = true; });
          handle.addEventListener('touchstart', () => { tr.draggable = true; }, { passive: true });
        }
        tr.addEventListener('dragstart', (e) => {
          if (!e.target.closest('.cs-drag-handle')) {
            e.preventDefault(); return;
          }
          dragSrcIdx = i;
          _isDragging = true;
          e.dataTransfer.effectAllowed = 'move';
          e.dataTransfer.setData('text/plain', String(i));
          tr.style.opacity = '0.5';
        });
        tr.addEventListener('dragend', () => {
          tr.style.opacity = '';
          tr.draggable = false;
          _isDragging = false;
          dragSrcIdx = null;
        });
        tr.addEventListener('dragover', (e) => {
          e.preventDefault();
          e.dataTransfer.dropEffect = 'move';
          tr.style.background = 'var(--bg-tertiary)';
        });
        tr.addEventListener('dragleave', () => { tr.style.background = ''; });
        tr.addEventListener('drop', async (e) => {
          e.preventDefault();
          tr.style.background = '';
          _isDragging = false;
          const destIdx = parseInt(tr.dataset.idx, 10);
          if (dragSrcIdx === null || dragSrcIdx === destIdx) { dragSrcIdx = null; return; }
          const newOrder = [...currentDisplayOrder];
          const [moved] = newOrder.splice(dragSrcIdx, 1);
          newOrder.splice(destIdx, 0, moved);
          currentDisplayOrder = newOrder;
          dragSrcIdx = null;
          try {
            await rpc.call('noble_setValidatorOrder', { order: newOrder });
            loadValidators();
          } catch (err) {
            console.error('[consensus] set validator order:', err);
            loadValidators();
          }
        });

        tr.addEventListener('click', (e) => {
          if (e.target.closest('.cs-remove-btn') || e.target.closest('.cs-drag-handle')
              || e.target.closest('.cs-subset-chk') || e.target.closest('.cs-fixed-radio')) return;
          showValidatorDetail(v);
        });
        validatorsTbody.appendChild(tr);
      });

      // Attach remove handlers
      validatorsTbody.querySelectorAll('.cs-remove-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const pubkey = btn.dataset.pubkey;
          const name = ordered.find(v => valKey(v.public_key) === pubkey)?.name || pubkey.slice(0, 16);
          showRemoveConfirmation(pubkey, name, selfKey);
        });
      });

      // ── Strategy column: immediate-save handlers ──

      // Checkbox (SubsetRotation): collect all checked keys, save immediately
      validatorsTbody.querySelectorAll('.cs-subset-chk').forEach(chk => {
        chk.addEventListener('change', async (e) => {
          e.stopPropagation();
          const allChecked = [...validatorsTbody.querySelectorAll('.cs-subset-chk:checked')].map(c => c.dataset.key);
          const params = { validators: allChecked };
          try {
            if (r1Select.value === 'subset_rotation') {
              currentStrategyParams.r1 = params;
              await rpc.call('noble_setVotingStrategy', { round: 1, strategy: 'subset_rotation', params });
            }
            if (r2Select.value === 'subset_rotation') {
              currentStrategyParams.r2 = params;
              await rpc.call('noble_setVotingStrategy', { round: 2, strategy: 'subset_rotation', params });
            }
          } catch (err) {
            console.error('[consensus] save subset:', err);
          }
        });
      });

      // Radio (FixedValidator): save selected key immediately
      validatorsTbody.querySelectorAll('.cs-fixed-radio').forEach(radio => {
        radio.addEventListener('change', async (e) => {
          e.stopPropagation();
          const selectedKey = radio.dataset.key;
          const params = { validator_key: selectedKey };
          try {
            if (r1Select.value === 'fixed_validator') {
              currentStrategyParams.r1 = params;
              await rpc.call('noble_setVotingStrategy', { round: 1, strategy: 'fixed_validator', params });
            }
            if (r2Select.value === 'fixed_validator') {
              currentStrategyParams.r2 = params;
              await rpc.call('noble_setVotingStrategy', { round: 2, strategy: 'fixed_validator', params });
            }
          } catch (err) {
            console.error('[consensus] save fixed validator:', err);
          }
        });
      });
    } catch (e) {
      console.error('[consensus] load validators:', e);
    }
  }

  function showValidatorDetail(v) {
    const keyHex = valKey(v.public_key);
    const scheme = 'secp256k1';
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
              <input id="cs-add-key" type="text" placeholder="nbl1… address or hex key" maxlength="128" spellcheck="false" autocomplete="off">
              <div class="form-hint">Noble address (nbl1…) or hex public key</div>
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
      const keyInput_ = keyInput.value.trim();
      const name = nameInput.value.trim();
      const isNbl1 = keyInput_.toLowerCase().startsWith('nbl1');
      const isHex64 = /^[0-9a-fA-F]{64}$/.test(keyInput_);

      if (!isNbl1 && !isHex64) {
        errorEl.textContent = 'Invalid key: enter a Noble address (nbl1…) or hex public key.';
        return;
      }
      const hexKey = isHex64 ? keyInput_.toLowerCase() : keyInput_;

      try {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Adding...';
        await rpc.call('noble_addValidator', { public_key: hexKey, name: name || undefined });
        closeModal();
        loadValidators();
        loadCandidates();
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

        // Fade out the row in the validator table before calling RPC
        const removedRow = validatorsTbody.querySelector(`tr[data-key="${pubkey}"]`);
        if (removedRow) {
          removedRow.style.transition = 'opacity 0.35s ease, background 0.35s ease';
          removedRow.style.opacity = '0.2';
          removedRow.style.background = 'color-mix(in srgb, var(--danger) 10%, transparent)';
        }

        await rpc.call('noble_removeValidator', { public_key: pubkey });
        closeModal();
        detailPanel.innerHTML = '';

        // Brief delay to let the fade finish, then reload both tables
        await new Promise(r => setTimeout(r, 350));
        await Promise.all([loadValidators(), loadCandidates()]);

        // Highlight the newly-appeared candidate row (the expelled node)
        const candidateRows = root.querySelectorAll('.cs-candidate-row');
        for (const row of candidateRows) {
          if (row.dataset.key === pubkey) {
            row.style.transition = 'background 0.5s ease';
            row.style.background = 'color-mix(in srgb, var(--accent) 18%, transparent)';
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
            setTimeout(() => { row.style.background = ''; }, 2000);
            break;
          }
        }
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
        valResult.validators.map(v => valKey(v.public_key))
      );

      // Filter: wants to participate AND not already a validator
      const candidates = peers.filter(p =>
        (p.wants_to_validate || p.wants_to_vote) && !validatorKeys.has(p.identity_key)
      );

      // Inject SELF if this node is a validator candidate but not yet accepted
      const selfKey2 = nodeInfo.validator_pubkey_display || nodeInfo.validator_pubkey;
      if (selfKey2 && !validatorKeys.has(selfKey2)) {
        const now = Math.floor(Date.now() / 1000);
        candidates.unshift({
          identity_key: selfKey2,
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
        tr.className = 'cs-candidate-row';
        tr.dataset.key = peer.identity_key;
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
          <td class="mono" style="font-size:var(--font-size-xs)">${peer.min_fee_rate != null ? peer.min_fee_rate + ' g/B' : '—'}</td>
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
  if (badgeGear) badgeGear.addEventListener('click', openBadgeModal);
  if (badgeModalClose) badgeModalClose.addEventListener('click', closeBadgeModal);
  if (badgeModal) badgeModal.addEventListener('click', (e) => { if (e.target === badgeModal) closeBadgeModal(); });

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
  // Fire all loads immediately (no serial chain gating timeline/tallies).
  // Validator name lookup may not be ready on first render — WS-triggered
  // reloads will re-render with friendly names within seconds.
  loadVotingStrategy().then(() => loadValidators());
  let _retryTimers = [];
  loadCycle().then(ok => { if (!ok) _retryTimers.push(setTimeout(loadCycle, 3000)); });
  loadTimeline().then(ok => { if (!ok) _retryTimers.push(setTimeout(loadTimeline, 3000)); });
  loadVoteTallies();
  loadCandidates();
  unsubs.push(() => _retryTimers.forEach(t => clearTimeout(t)));

  // Refresh buttons + 30s auto-refresh for validator registry and candidates.
  const refreshValBtn = root.querySelector('#cs-refresh-validators');
  if (refreshValBtn) {
    refreshValBtn.addEventListener('click', () => {
      refreshValBtn.textContent = 'Refreshing...';
      refreshValBtn.disabled = true;
      loadValidators().finally(() => { refreshValBtn.textContent = 'Refresh'; refreshValBtn.disabled = false; });
    });
  }
  const refreshCandBtn = root.querySelector('#cs-refresh-candidates');
  if (refreshCandBtn) {
    refreshCandBtn.addEventListener('click', () => {
      refreshCandBtn.textContent = 'Refreshing...';
      refreshCandBtn.disabled = true;
      loadCandidates().finally(() => { refreshCandBtn.textContent = 'Refresh'; refreshCandBtn.disabled = false; });
    });
  }
  const valInterval = setInterval(loadValidators, 30_000);
  const candInterval = setInterval(loadCandidates, 30_000);
  unsubs.push(() => { clearInterval(valInterval); clearInterval(candInterval); });

  return {
    destroy() {
      if (tickFn) { window._nobleTick.remove(tickFn); tickFn = null; }
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
