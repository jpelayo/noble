/**
 * NOBLE Dashboard — Consensus Page
 * PoR cycle superposition timeline + Accepted Validator Registry
 */

import { formatNumber, formatCountdown, bytesToHex, truncateHash, timeAgo, formatTimestamp } from '../utils.js';

function extractIpFromMultiaddr(ma) {
  if (!ma) return '--';
  const m = ma.match(/\/ip[46]\/([^/]+)/);
  return m ? m[1] : '--';
}

// ── Phase & status colors ──
const PHASE_COLORS = {
  Proposal:      { bg: '#3b82f6', fg: '#fff' },
  Voting:        { bg: '#8b5cf6', fg: '#fff' },
  Confirmation:  { bg: '#f59e0b', fg: '#000' },
  Finalization:  { bg: '#10b981', fg: '#fff' },
};

const STATE_STYLES = {
  complete: 'opacity:1',
  active:   'opacity:1;box-shadow:0 0 0 2px var(--accent)',
  pending:  'opacity:0.3',
  skipped:  'opacity:0.2',
};

export function init(root, ctx) {
  const { rpc, ws } = ctx;
  const unsubs = [];
  let countdownInterval = null;

  // Helper: extract hex key from ValidatorEntry.public_key
  // Live API returns a hex string; mock returns { Ed25519: [u8] } or { Secp256k1: [u8] }.
  function valKeyHex(pk) {
    if (typeof pk === 'string') return pk;
    const k = pk.Ed25519 || pk.Secp256k1 || [];
    return k.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  root.innerHTML = `
    <div class="page-header"><h1>Consensus</h1><p>Proof of Reputation cycle status, accepted validator registry, and network candidate discovery</p></div>

    <!-- Superposition Timeline -->
    <div class="panel">
      <div class="panel-header">
        <span>Cycle Superposition Timeline</span>
        <span style="font-weight:400;font-size:var(--font-size-xs);color:var(--text-muted)">Last 3 cycles</span>
      </div>
      <div class="panel-body">
        <!-- Phase pipeline -->
        <div style="display:flex;align-items:center;gap:0;margin-bottom:var(--gap-lg);flex-wrap:wrap">
          <div style="font-weight:700;font-size:var(--font-size-sm);color:var(--text-muted);margin-right:var(--gap-sm)">CYCLE <span id="cs-cycle-info">#--</span></div>
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
        <div class="panel-header">Phase Progression</div>
        <div class="panel-body" id="cs-phases"></div>
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
          <strong>Round 1 (Reflection)</strong> selects the candidate block. <strong>Round 2 (Confirmation)</strong> ratifies the R1 winner —
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
          <thead><tr><th style="width:32px" title="Drag to set priority order">&#9776;</th><th>#</th><th>Validator</th><th>IP</th><th>Country</th><th>Status</th><th>Reputation</th><th>B(V)</th><th>U(V)</th><th>T(V)</th><th>Blocks</th><th>Listers</th><th>Last Active</th><th></th></tr></thead>
          <tbody id="cs-validators"></tbody>
        </table>
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
  `;

  // ── DOM refs ──
  const csPipeline = root.querySelector('#cs-phase-pipeline');
  const csCycleInfo = root.querySelector('#cs-cycle-info');
  const csCycleNum = root.querySelector('#cs-cycle-num');
  const csPhaseName = root.querySelector('#cs-phase-name');
  const csPhaseRemaining = root.querySelector('#cs-phase-remaining');
  const csCycleRemaining = root.querySelector('#cs-cycle-remaining');
  const csValidator = root.querySelector('#cs-validator');
  const csPhases = root.querySelector('#cs-phases');
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
    round_robin: 'Rotate through validators in your list order each cycle.',
    subset_rotation: 'Rotate through a user-defined subset of preferred validators.',
    random: 'Randomly select among valid candidates (deterministic per cycle).',
    weighted_reputation: 'Vote for the candidate from the highest-weight validator.',
    weighted_probability: 'Randomized vote with decreasing probability following your validator list order.',
    follow_majority: 'Wait for tallies, then vote for the leading candidate.',
    manual: 'Do not auto-vote. Requires manual vote via RPC or GUI each cycle.',
  };

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
      tallyMeta.textContent = `Cycle #${formatNumber(result.cycle)} — ${result.phase}`;

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
        const nameTag = t.validator ? `<span style="font-weight:600;font-size:var(--font-size-xs);min-width:90px">${t.validator}</span>` : '';
        return `<div style="display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap-sm)">
          ${nameTag}<span class="mono" style="font-size:var(--font-size-xs);min-width:120px">${truncateHash(t.block_hash, 8)}</span>
          <div style="flex:1;height:8px;background:var(--bg-tertiary);border-radius:4px">
            <div style="height:100%;width:${pct}%;background:var(--accent);border-radius:4px;transition:width 0.3s"></div>
          </div>
          <span style="font-weight:600;min-width:60px;text-align:right">${t.vote_count} (${pct}%)</span>
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

  const PHASES = ['Proposal', 'Voting', 'Confirmation', 'Finalization'];

  // ══════════════════════════════════════════════
  // SUPERPOSITION TIMELINE
  // ══════════════════════════════════════════════

  /** Transform flat API entry into the phase-based format renderTimeline expects. */
  function apiEntryToCycle(entry, isCurrent) {
    // If already has phases (mock data), pass through.
    if (entry.phases) return entry;
    const hasWinner = !!entry.winner;
    const indeterminate = entry.status === 'indeterminate' || (!hasWinner && !isCurrent);
    return {
      cycle_number: entry.cycle_number,
      is_current: isCurrent,
      indeterminate,
      disambiguation: entry.disambiguation,
      winner: entry.winner,
      winning_hash: entry.winning_hash,
      phases: [
        {
          name: 'Proposal',
          state: 'complete',
          proposals: entry.proposals || [],
        },
        {
          name: 'Voting',
          state: isCurrent && !hasWinner ? 'active' : 'complete',
          votes: entry.votes || [],
          total_voters: (entry.votes || []).reduce((s, v) => s + v.vote_count, 0),
        },
        {
          name: 'Confirmation',
          state: indeterminate ? 'skipped' : hasWinner ? 'complete' : isCurrent ? 'pending' : 'complete',
          winner: entry.winner,
          winning_hash: entry.winning_hash,
          disambiguation: entry.disambiguation,
        },
        {
          name: 'Finalization',
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
      const history = await rpc.call('noble_getCycleHistory', TIMELINE_LIMIT * 5);
      const raw = (history.entries || history.cycles || [])
        .filter(e => e.status !== 'indeterminate' || (e.proposals && e.proposals.length > 0) || (e.votes && e.votes.length > 0))
        .slice(0, TIMELINE_LIMIT);
      if (raw.length === 0) {
        csTimeline.innerHTML = '<div class="empty-state">No consensus cycles yet</div>';
        return;
      }
      const cycles = raw.map((e, i) =>
        apiEntryToCycle(e, i === raw.length - 1 && (e.status === 'active' || !e.finalized_at))
      );
      renderTimeline(cycles);
    } catch (e) {
      console.error('[consensus] load timeline:', e);
      csTimeline.innerHTML = '<div class="empty-state">Failed to load cycle history</div>';
    }
  }

  function renderTimeline(cycles) {
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
        ${cycle.winner ? `<span style="margin-left:auto;font-size:var(--font-size-xs);color:var(--text-secondary)">Winner: <strong>${cycle.winner}</strong></span>` : ''}
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
        let label = `<div style="font-weight:700;font-size:0.65rem;letter-spacing:0.03em">${phase.name.toUpperCase()}</div>`;

        // Phase-specific content
        if (pi === 0 && phase.proposals) {
          if (phase.proposals.length === 0) {
            label += `<div style="font-size:0.6rem;opacity:0.5">no proposals</div>`;
          } else {
            const names = phase.proposals.map(p => {
              const name = p.validator.replace('noble-', '');
              return name.length > 16 ? name.slice(0, 8) + '…' + name.slice(-4) : name;
            }).join(', ');
            label += `<div style="font-size:0.6rem;opacity:0.85">${phase.proposals.length} proposal${phase.proposals.length !== 1 ? 's' : ''}${names ? ': ' + names : ''}</div>`;
          }

          // Track participants
          for (const p of phase.proposals) {
            if (!participantMap.has(p.validator)) participantMap.set(p.validator, { roles: [], cycles: [] });
            const entry = participantMap.get(p.validator);
            entry.roles.push('proposed');
            entry.cycles.push(cycle.cycle_number);
          }
        } else if (pi === 1 && phase.votes && phase.votes.length > 0) {
          const voteStr = phase.votes.map(v => `${v.validator.replace('noble-', '')}:${v.vote_count}`).join(' | ');
          label += `<div style="font-size:0.6rem;opacity:0.85">${voteStr}</div>`;
        } else if (pi === 2) {
          if (phase.winner) {
            const icon = phase.disambiguation ? '&#9878;' : '&#10003;';
            label += `<div style="font-size:0.6rem;opacity:0.85">${icon} ${phase.winner.replace('noble-', '')}</div>`;

            if (!participantMap.has(phase.winner)) participantMap.set(phase.winner, { roles: [], cycles: [] });
            participantMap.get(phase.winner).roles.push('won');
          } else if (phase.state === 'skipped') {
            label += `<div style="font-size:0.6rem;opacity:0.5">—</div>`;
          } else if (phase.state === 'pending') {
            label += `<div style="font-size:0.6rem;opacity:0.5">pending</div>`;
          } else {
            label += `<div style="font-size:0.6rem;opacity:0.5">&#10003; done</div>`;
          }
        } else if (pi === 3) {
          if (phase.state === 'skipped') {
            label += `<div style="font-size:0.6rem;opacity:0.5">—</div>`;
          } else if (phase.finalized) {
            label += `<div style="font-size:0.6rem;opacity:0.85">&#10003; sealed</div>`;
          } else if (phase.state === 'active') {
            label += `<div style="font-size:0.6rem;opacity:0.85">sealing...</div>`;
          } else {
            label += `<div style="font-size:0.6rem;opacity:0.5">waiting</div>`;
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
          const vName = p.validator.length > 20 ? truncateHash(p.validator, 6) : p.validator;
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px">
              <strong>${vName}</strong>
              ${icon}
            </div>
            <div style="color:var(--text-muted)">
              ${p.tx_count} txs &middot; <span class="mono">${truncateHash(p.block_hash, 4)}</span>
            </div>
          `;

          // Show vote count if voting phase has data
          const votingPhase = cycle.phases[1];
          if (votingPhase.votes && votingPhase.votes.length > 0) {
            const voteEntry = votingPhase.votes.find(v => v.block_hash === p.block_hash);
            if (voteEntry) {
              const pct = Math.round(voteEntry.vote_count / votingPhase.total_voters * 100);
              card.innerHTML += `
                <div style="margin-top:4px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:2px">
                    <span style="color:var(--text-secondary)">Votes</span>
                    <span style="font-weight:600">${voteEntry.vote_count}/${votingPhase.total_voters} (${pct}%)</span>
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
          ${entries.map(([name, data]) => {
            const won = data.roles.filter(r => r === 'won').length;
            const proposed = data.roles.filter(r => r === 'proposed').length;
            const lost = proposed - won;
            const dotColor = won > 0 ? 'var(--success)' : 'var(--warning)';
            return `<div style="display:flex;align-items:center;gap:var(--gap-xs);padding:3px 8px;background:var(--bg-secondary);border-radius:var(--radius-sm);font-size:var(--font-size-xs)">
              <span style="width:6px;height:6px;border-radius:50%;background:${dotColor}"></span>
              <strong>${name}</strong>
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

  const PHASE_DURATION = 450; // 7:30 per sub-phase

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

  function updateCycleDisplay(status) {
    // Guard u64::MAX sentinel (engine not yet initialized)
    const sane = status.cycle_number < 1e15;
    csCycleNum.textContent = sane ? formatNumber(status.cycle_number) : '—';
    csPhaseName.textContent = sane ? status.phase : 'Initializing';
    csCycleInfo.textContent = sane ? `#${formatNumber(status.cycle_number)}` : 'Awaiting genesis';

    if (status.current_validator) {
      const key = status.current_validator.Ed25519 || status.current_validator.Secp256k1 || [];
      csValidator.textContent = truncateHash(bytesToHex(key), 12);
    }

    const activeIdx = status.phase_index;

    // Phase progression sidebar
    csPhases.innerHTML = PHASES.map((p, i) => {
      const active = i === activeIdx;
      const done = i < activeIdx;
      const color = PHASE_COLORS[p];
      const cls = active ? 'accent' : done ? 'success' : 'text-muted';
      const time = active ? formatCountdown(status.phase_remaining_secs) : done ? '0:00' : formatCountdown(PHASE_DURATION);
      return `<div style="display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap-sm)">
        <span style="width:20px;height:20px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:var(--font-size-xs);font-weight:700;background:${active ? color.bg : done ? 'var(--success)' : 'var(--bg-tertiary)'};color:${active || done ? '#fff' : 'var(--text-muted)'}">${i + 1}</span>
        <span style="font-weight:${active ? '700' : '400'};color:var(--${cls})">${p}</span>
        <span style="margin-left:auto;font-family:var(--font-mono);font-size:var(--font-size-xs);color:var(--text-secondary)">${time}</span>
      </div>`;
    }).join('');

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
      if (remaining <= 0) { loadCycle(); loadTimeline(); }
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
      const [result, nodeInfo] = await Promise.all([
        rpc.call('noble_getValidatorList'),
        rpc.call('noble_getNodeInfo'),
      ]);
      const selfKey = nodeInfo.validator_pubkey || null;
      const validators = result.validators;
      const priorityOrder = result.priority_order || [];
      csPolicy.textContent = `Selection: ${result.selection_policy.replace('_', ' ')}`;

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
            <div style="font-weight:600;font-size:var(--font-size-sm)">${v.name || (isSelf ? 'This Node' : 'Unknown')}${youBadge}</div>
            <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${truncateHash(keyHex, 6)} <button class="btn-copy" data-copy="${keyHex}" title="Copy public key">&#128203;</button></div>
          </td>
          <td class="mono" style="font-size:var(--font-size-xs)">${extractIpFromMultiaddr(v.host_address)}</td>
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
          showRemoveConfirmation(pubkey, name);
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
              <dt>Name</dt><dd>${v.name}</dd>
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

  function showRemoveConfirmation(pubkey, name) {
    modalContainer.innerHTML = `
      <div class="modal-overlay" id="cs-modal-overlay">
        <div class="modal" style="max-width:400px">
          <div class="modal-header">
            <span>Remove Validator</span>
          </div>
          <div class="modal-body">
            <p style="font-size:var(--font-size-sm);margin-bottom:var(--gap)">
              Remove <strong>${name}</strong> from your accepted validator list?
            </p>
            <p style="font-size:var(--font-size-xs);color:var(--text-muted)">
              This only affects your node's list. The validator can be re-added at any time with the same Node ID.
            </p>
            <div class="form-error" id="cs-remove-error" style="margin-top:var(--gap-sm)"></div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" id="cs-modal-cancel">Cancel</button>
            <button class="btn btn-danger" id="cs-modal-confirm">Remove</button>
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
            <div style="font-weight:600;font-size:var(--font-size-sm)">${peer.node_name || 'Unknown'}${youBadge}</div>
            <div class="mono" style="font-size:var(--font-size-xs);color:var(--text-muted)">${peer.identity_key.slice(0, 12)}...${peer.identity_key.slice(-8)} <button class="btn-copy" data-copy="${peer.identity_key}" title="Copy public key">&#128203;</button></div>
          </td>
          <td class="mono" style="font-size:var(--font-size-xs)">${extractIpFromMultiaddr(peer.last_addr || peer.host_address)}</td>
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
  ws.subscribe('cyclePhaseChange', (status) => {
    updateCycleDisplay(status);
    loadTimeline();
    loadVoteTallies();
  });
  unsubs.push(() => ws.unsubscribe('cyclePhaseChange'));

  // ── Copy-to-clipboard delegation ──
  root.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-copy');
    if (btn) {
      e.stopPropagation();
      navigator.clipboard?.writeText(btn.dataset.copy).catch(() => {});
      btn.textContent = '\u2713';
      setTimeout(() => { btn.textContent = '\u{1F4CB}'; }, 1200);
    }
  });

  // ── Bootstrap ──
  loadCycle();
  loadTimeline();
  loadValidators();
  loadCandidates();
  loadVotingStrategy();
  loadVoteTallies();

  return {
    destroy() {
      clearInterval(countdownInterval);
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
