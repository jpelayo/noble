/**
 * NOBLE Dashboard — Storage Management Page
 * Chain pruning status, storage info, disk usage, column family breakdown
 */

import { formatNumber, formatBytes } from '../utils.js';

/** Color for a CF name — blocks/indexes/state/misc grouping. */
function cfColor(name) {
  if (name === 'blocks') return '#10b981';
  if (['block_hashes', 'tx_index', 'checksum_index', 'version_chain', 'publisher_index'].includes(name)) return '#3b82f6';
  if (['chain_state', 'validator_state', 'address_balances', 'address_history'].includes(name)) return '#8b5cf6';
  return '#6b7280';
}

/** Disk usage bar fill color based on percent used. */
function usageColor(pct) {
  if (pct >= 90) return 'var(--error)';
  if (pct >= 70) return 'var(--warning)';
  return 'var(--success)';
}

export function init(root, ctx) {
  const { rpc } = ctx;
  const unsubs = [];

  root.innerHTML = `
    <div class="page-header" style="display:flex;align-items:center;justify-content:space-between">
      <div><h1>Storage</h1><p>Chain data management and pruning controls</p></div>
      <button id="st-config-btn" title="Storage Configuration"
        style="background:none;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;cursor:pointer;font-size:1.3rem;color:var(--text-secondary);transition:color 0.15s,border-color 0.15s"
        onmouseover="this.style.color='var(--accent)';this.style.borderColor='var(--accent)'"
        onmouseout="this.style.color='var(--text-secondary)';this.style.borderColor='var(--border)'"
      >&#9881;</button>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Chain Height</div>
        <div class="kpi-value" id="st-height">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Pruning Mode</div>
        <div class="kpi-value" id="st-mode">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">DB Size</div>
        <div class="kpi-value" id="st-dbsize">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Disk Free</div>
        <div class="kpi-value" id="st-diskfree">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Pruned Up To</div>
        <div class="kpi-value" id="st-pruned">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Lowest Full Block</div>
        <div class="kpi-value" id="st-lowest">--</div>
      </div>
    </div>

    <!-- Data Directory Panel -->
    <div class="panel" id="st-datadir-panel" style="margin-bottom:1rem">
      <div class="panel-header">Data Directory</div>
      <div class="panel-body" id="st-datadir-body">
        <div style="color:var(--text-muted);font-size:var(--font-size-sm)">Loading...</div>
      </div>
    </div>

    <!-- Column Families Panel -->
    <div class="panel" id="st-cf-panel" style="margin-bottom:1rem">
      <div class="panel-header">Column Families</div>
      <div class="panel-body" id="st-cf-body">
        <div style="color:var(--text-muted);font-size:var(--font-size-sm)">Loading...</div>
      </div>
    </div>

    <div class="split-layout">
      <div class="panel">
        <div class="panel-header">Storage Info</div>
        <div class="panel-body">
          <dl class="detail-grid" id="st-info-grid"></dl>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">Pruning Status</div>
        <div class="panel-body">
          <dl class="detail-grid" id="st-pruning-grid"></dl>
          <div id="st-pruning-actions" style="margin-top:1rem;text-align:right"></div>
        </div>
      </div>
    </div>

    <div class="panel" style="margin-top:1rem">
      <div class="panel-header">Block Retention</div>
      <div class="panel-body">
        <div id="st-retention-chart" class="chart-container small"></div>
      </div>
    </div>

    <!-- Storage Configuration Modal -->
    <div id="st-config-modal" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.6);align-items:center;justify-content:center">
      <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius);max-width:900px;width:94%;max-height:90vh;overflow-y:auto;padding:var(--gap-lg);position:relative">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap)">
          <h3 style="margin:0">Storage Configuration</h3>
          <button id="st-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.5rem;cursor:pointer;padding:0 4px;line-height:1" title="Close">&times;</button>
        </div>
        <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap)">
          Configure data directories, cache, pruning, and size limits. Changes are written to <code>noble.toml</code> and take effect on next restart.
        </p>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--gap);margin-bottom:var(--gap)">
          <div class="form-group">
            <label for="stc-data-dir" style="font-weight:600;font-size:var(--font-size-sm)">Data Directory</label>
            <input type="text" id="stc-data-dir" autocomplete="off" spellcheck="false"
              style="font-family:var(--font-mono);font-size:var(--font-size-sm)">
            <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">
              Base path for blockchain data, keys, and state.
            </div>
          </div>
          <div class="form-group">
            <label for="stc-cache-size" style="font-weight:600;font-size:var(--font-size-sm)">Cache Size (MB)</label>
            <input type="number" id="stc-cache-size" min="64" max="16384" step="64"
              style="font-family:var(--font-mono);font-size:var(--font-size-sm)">
            <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">
              RocksDB block cache. More cache = faster reads.
            </div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:var(--gap);margin-bottom:var(--gap)">
          <div class="form-group">
            <label for="stc-pruning" style="font-weight:600;font-size:var(--font-size-sm)">Pruning Mode</label>
            <select id="stc-pruning" style="font-size:var(--font-size-sm)">
              <option value="archive">Archive (keep all)</option>
              <option value="moderate">Moderate</option>
              <option value="aggressive">Aggressive</option>
            </select>
          </div>
          <div class="form-group">
            <label for="stc-keep-blocks" style="font-weight:600;font-size:var(--font-size-sm)">Keep Blocks</label>
            <input type="number" id="stc-keep-blocks" min="100" max="10000000" step="100"
              style="font-family:var(--font-mono);font-size:var(--font-size-sm)">
            <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">
              Blocks to retain when pruning (0 = archive).
            </div>
          </div>
          <div class="form-group">
            <label for="stc-max-size" style="font-weight:600;font-size:var(--font-size-sm)">Max DB Size (GB)</label>
            <input type="number" id="stc-max-size" min="0" max="10000" step="1"
              style="font-family:var(--font-mono);font-size:var(--font-size-sm)">
            <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:2px">
              0 = unlimited. Auto-prune when exceeded.
            </div>
          </div>
        </div>

        <div class="form-group" style="margin-bottom:var(--gap)">
          <label style="display:flex;align-items:center;gap:var(--gap-sm);cursor:pointer">
            <input type="checkbox" id="stc-compression">
            <span style="font-size:var(--font-size-sm);font-weight:600">Enable Zstd Compression</span>
          </label>
          <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-left:24px">
            Reduces disk usage ~40% with slight CPU overhead.
          </div>
        </div>

        <hr style="border:none;border-top:1px solid var(--border);margin:var(--gap) 0">

        <div style="margin-bottom:var(--gap)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--gap-sm)">
            <h4 style="margin:0">Storage Volumes</h4>
            <button id="stc-add-volume" class="btn btn-secondary btn-sm" style="padding:4px 12px;font-size:var(--font-size-xs)">+ Add Volume</button>
          </div>
          <p style="font-size:var(--font-size-xs);color:var(--text-muted);margin-bottom:var(--gap-sm)">
            Distribute chain data across multiple disks or partitions for performance and capacity management.
          </p>
          <div id="stc-volumes-list"></div>
        </div>

        <div style="display:flex;justify-content:flex-end;gap:var(--gap-sm);margin-top:var(--gap)">
          <button id="stc-cancel" class="btn btn-secondary" style="padding:8px 20px">Cancel</button>
          <button id="stc-save" class="btn btn-primary" style="padding:8px 20px">Save Configuration</button>
        </div>
        <div id="stc-status" style="font-size:var(--font-size-xs);margin-top:var(--gap-sm);min-height:1.2em"></div>
      </div>
    </div>
  `;

  const stHeight = root.querySelector('#st-height');
  const stMode = root.querySelector('#st-mode');
  const stDbSize = root.querySelector('#st-dbsize');
  const stDiskFree = root.querySelector('#st-diskfree');
  const stPruned = root.querySelector('#st-pruned');
  const stLowest = root.querySelector('#st-lowest');
  const infoGrid = root.querySelector('#st-info-grid');
  const pruningGrid = root.querySelector('#st-pruning-grid');
  const dataDirBody = root.querySelector('#st-datadir-body');
  const cfBody = root.querySelector('#st-cf-body');
  let retentionChart = null;

  // ── Storage config modal logic ──
  const configModal = root.querySelector('#st-config-modal');
  const configBtn = root.querySelector('#st-config-btn');
  const modalClose = root.querySelector('#st-modal-close');
  const cancelBtn = root.querySelector('#stc-cancel');
  const saveBtn = root.querySelector('#stc-save');
  const addVolumeBtn = root.querySelector('#stc-add-volume');
  const volumesList = root.querySelector('#stc-volumes-list');
  const statusEl = root.querySelector('#stc-status');

  let currentVolumes = [];

  function openConfigModal() {
    configModal.style.display = 'flex';
    loadConfig();
  }

  function closeConfigModal() {
    configModal.style.display = 'none';
    statusEl.textContent = '';
  }

  configBtn.addEventListener('click', openConfigModal);
  modalClose.addEventListener('click', closeConfigModal);
  cancelBtn.addEventListener('click', closeConfigModal);
  configModal.addEventListener('click', (e) => {
    if (e.target === configModal) closeConfigModal();
  });

  async function loadConfig() {
    try {
      const cfg = await rpc.call('noble_getStorageConfig');
      root.querySelector('#stc-data-dir').value = cfg.data_dir || '~/.noble/data';
      root.querySelector('#stc-cache-size').value = cfg.cache_size_mb || 256;
      root.querySelector('#stc-compression').checked = cfg.compression !== false;
      root.querySelector('#stc-pruning').value = cfg.pruning_mode || 'archive';
      root.querySelector('#stc-keep-blocks').value = cfg.keep_blocks || 10000;
      root.querySelector('#stc-max-size').value = cfg.max_db_size_gb || 0;
      currentVolumes = cfg.volumes || [];
      renderVolumes();
    } catch (e) {
      statusEl.textContent = 'Failed to load config: ' + (e.message || e);
      statusEl.style.color = 'var(--error)';
    }
  }

  function renderVolumes() {
    if (currentVolumes.length === 0) {
      volumesList.innerHTML = '<div style="font-size:var(--font-size-xs);color:var(--text-muted);padding:var(--gap-sm);background:var(--bg-tertiary);border-radius:var(--radius-sm);text-align:center">No additional volumes configured. Data stored in the main data directory.</div>';
      return;
    }
    volumesList.innerHTML = '';
    currentVolumes.forEach((vol, i) => {
      const row = document.createElement('div');
      row.style.cssText = 'display:grid;grid-template-columns:1fr 120px 120px auto;gap:var(--gap-sm);align-items:end;padding:var(--gap-sm);background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:var(--gap-xs)';
      row.innerHTML = `
        <div class="form-group" style="margin:0">
          <label style="font-size:var(--font-size-xs);font-weight:600">Path</label>
          <input type="text" data-vol-idx="${i}" data-vol-field="path" value="${_esc(vol.path || '')}"
            placeholder="/mnt/data/noble" autocomplete="off" spellcheck="false"
            style="font-family:var(--font-mono);font-size:var(--font-size-xs);padding:4px 8px">
        </div>
        <div class="form-group" style="margin:0">
          <label style="font-size:var(--font-size-xs);font-weight:600">Max Size (GB)</label>
          <input type="number" data-vol-idx="${i}" data-vol-field="max_size_gb" value="${vol.max_size_gb || 0}"
            min="0" step="1"
            style="font-family:var(--font-mono);font-size:var(--font-size-xs);padding:4px 8px">
        </div>
        <div class="form-group" style="margin:0">
          <label style="font-size:var(--font-size-xs);font-weight:600">Purpose</label>
          <select data-vol-idx="${i}" data-vol-field="purpose" style="font-size:var(--font-size-xs);padding:4px 8px">
            <option value="blocks" ${vol.purpose === 'blocks' ? 'selected' : ''}>Blocks</option>
            <option value="state" ${vol.purpose === 'state' ? 'selected' : ''}>State</option>
            <option value="index" ${vol.purpose === 'index' ? 'selected' : ''}>Index</option>
            <option value="all" ${vol.purpose === 'all' ? 'selected' : ''}>All</option>
          </select>
        </div>
        <button data-vol-remove="${i}" title="Remove volume"
          style="background:none;border:1px solid var(--error);border-radius:var(--radius-sm);color:var(--error);cursor:pointer;padding:4px 8px;font-size:var(--font-size-xs);align-self:end;margin-bottom:2px">&times;</button>
      `;
      volumesList.appendChild(row);
    });

    // Bind input changes
    volumesList.querySelectorAll('input, select').forEach(el => {
      el.addEventListener('change', () => {
        const idx = parseInt(el.dataset.volIdx, 10);
        const field = el.dataset.volField;
        if (isNaN(idx) || !field) return;
        if (field === 'max_size_gb') {
          currentVolumes[idx][field] = parseInt(el.value, 10) || 0;
        } else {
          currentVolumes[idx][field] = el.value;
        }
      });
    });

    // Bind remove buttons
    volumesList.querySelectorAll('[data-vol-remove]').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.volRemove, 10);
        currentVolumes.splice(idx, 1);
        renderVolumes();
      });
    });
  }

  addVolumeBtn.addEventListener('click', () => {
    currentVolumes.push({ path: '', max_size_gb: 0, purpose: 'all' });
    renderVolumes();
    // Focus the new path input
    const lastInput = volumesList.querySelector(`input[data-vol-idx="${currentVolumes.length - 1}"][data-vol-field="path"]`);
    if (lastInput) lastInput.focus();
  });

  saveBtn.addEventListener('click', async () => {
    statusEl.textContent = '';
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';
    try {
      await rpc.call('noble_setStorageConfig', {
        data_dir: root.querySelector('#stc-data-dir').value.trim(),
        cache_size_mb: parseInt(root.querySelector('#stc-cache-size').value, 10) || 256,
        compression: root.querySelector('#stc-compression').checked,
        pruning_mode: root.querySelector('#stc-pruning').value,
        keep_blocks: parseInt(root.querySelector('#stc-keep-blocks').value, 10) || 10000,
        max_db_size_gb: parseInt(root.querySelector('#stc-max-size').value, 10) || 0,
        volumes: currentVolumes.filter(v => v.path),
      });
      statusEl.textContent = 'Configuration saved. Restart the node for changes to take effect.';
      statusEl.style.color = 'var(--success)';
      // Refresh the main page data
      loadStorage();
    } catch (e) {
      statusEl.textContent = 'Save failed: ' + (e.message || e);
      statusEl.style.color = 'var(--error)';
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save Configuration';
    }
  });

  // ── Copy button handler (delegated) ──
  root.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-copy');
    if (!btn) return;
    const text = btn.dataset.copy;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = orig; }, 1500);
    }).catch(() => {});
  });

  function _esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ── Render a single usage bar row ──
  function usageBar(label, filled, capacity, fillColor) {
    const pct = capacity > 0 ? Math.min(filled / capacity * 100, 100) : 0;
    const pctStr = pct < 0.01 && filled > 0 ? '<0.01' : pct.toFixed(2);
    return `
      <div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:var(--font-size-xs);color:var(--text-secondary);margin-bottom:3px">
          <span>${label}</span>
          <span>${formatBytes(filled)} / ${formatBytes(capacity)} (${pctStr}%)</span>
        </div>
        <div style="background:var(--bg-tertiary);border-radius:var(--radius-sm);height:16px;overflow:hidden">
          <div style="height:100%;width:${Math.max(pct, pct > 0 ? 0.5 : 0).toFixed(2)}%;background:${fillColor};border-radius:var(--radius-sm);transition:width 0.3s"></div>
        </div>
      </div>`;
  }

  // ── Render a usage bar that can exceed 100% (for overcommit warnings) ──
  function usageBarUncapped(label, filled, capacity, fillColor, warnColor) {
    const pct = capacity > 0 ? (filled / capacity * 100) : 0;
    const pctStr = pct < 0.01 && filled > 0 ? '<0.01' : pct.toFixed(2);
    const barWidth = Math.min(pct, 100);
    const color = pct > 100 ? (warnColor || '#ef4444') : fillColor;
    return `
      <div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:var(--font-size-xs);color:var(--text-secondary);margin-bottom:3px">
          <span>${label}${pct > 100 ? ' <span style="color:#ef4444;font-weight:600">(overcommitted)</span>' : ''}</span>
          <span>${formatBytes(filled)} / ${formatBytes(capacity)} (${pctStr}%)</span>
        </div>
        <div style="background:var(--bg-tertiary);border-radius:var(--radius-sm);height:16px;overflow:hidden">
          <div style="height:100%;width:${Math.max(barWidth, barWidth > 0 ? 0.5 : 0).toFixed(2)}%;background:${color};border-radius:var(--radius-sm);transition:width 0.3s"></div>
        </div>
      </div>`;
  }

  // ── Render data directory panel — 4 bars ──
  function renderDataDir(stats) {
    const dir = stats.data_dir || 'N/A';
    const db = stats.total_db_bytes || 0;
    const avail = stats.available_bytes || 0;
    const total = stats.total_volume_bytes || 0;
    const diskUsed = total > 0 ? total - avail : 0;
    const cache = stats.cache_size_bytes || 0;
    const cacheMb = cache / (1024 * 1024);
    const compress = stats.compression_enabled;
    const maxDbBytes = stats.max_db_size_bytes || 0;
    const maxDbGb = maxDbBytes / (1024 * 1024 * 1024);
    const hasAllocated = maxDbBytes > 0;

    // Bar 1: Disk Usage — diskUsed / total_volume_bytes
    const diskPct = total > 0 ? (diskUsed / total * 100) : 0;
    const diskColor = usageColor(diskPct);

    // Allocated badge text
    const allocBadge = hasAllocated ? `Allocated: ${maxDbGb.toFixed(1)} GB` : 'Unlimited';

    let bars = '';
    // Bar 1: always shown when total > 0
    if (total > 0) bars += usageBar('Disk Usage', diskUsed, total, diskColor);
    // Bar 2: Noble DB vs Allocated (purple) — only when max_db_size_bytes > 0
    if (hasAllocated) bars += usageBar('Noble DB vs Allocated', db, maxDbBytes, '#8b5cf6');
    // Bar 3: Noble DB vs Free Disk (blue) — always shown
    if (avail > 0) bars += usageBar('Noble DB vs Free Disk', db, avail, '#3b82f6');
    // Bar 4: Allocated vs Free Disk (orange) — only when max_db_size_bytes > 0, can exceed 100%
    if (hasAllocated) bars += usageBarUncapped('Allocated vs Free Disk', maxDbBytes, avail, '#f59e0b', '#ef4444');

    dataDirBody.innerHTML = `
      <div style="display:flex;align-items:center;gap:var(--gap-sm);margin-bottom:var(--gap)">
        <code style="font-size:var(--font-size-sm);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(dir)}</code>
        <button class="btn btn-secondary btn-sm btn-copy" data-copy="${_esc(dir)}"
          style="padding:2px 10px;font-size:var(--font-size-xs);white-space:nowrap">Copy</button>
      </div>
      ${bars}
      <div style="display:flex;justify-content:flex-end;gap:var(--gap-sm);margin-top:4px">
        <span style="font-size:var(--font-size-xs);padding:2px 8px;border-radius:var(--radius-sm);background:var(--bg-tertiary);color:var(--text-secondary)">Cache: ${cacheMb.toFixed(0)} MB</span>
        <span style="font-size:var(--font-size-xs);padding:2px 8px;border-radius:var(--radius-sm);background:var(--bg-tertiary);color:${compress ? 'var(--success)' : 'var(--text-muted)'}">${compress ? 'Zstd On' : 'No Compression'}</span>
        <span style="font-size:var(--font-size-xs);padding:2px 8px;border-radius:var(--radius-sm);background:var(--bg-tertiary);color:${hasAllocated ? '#8b5cf6' : 'var(--text-muted)'}">${allocBadge}</span>
      </div>
    `;
  }

  // ── Render column families table ──
  function renderCfTable(stats) {
    const cfs = (stats.column_families || []).slice().sort((a, b) => b.estimated_bytes - a.estimated_bytes);
    if (cfs.length === 0) {
      cfBody.innerHTML = '<div style="color:var(--text-muted);font-size:var(--font-size-sm);text-align:center;padding:1rem">No column family data available</div>';
      return;
    }

    const maxBytes = Math.max(...cfs.map(c => c.estimated_bytes), 1);

    let rows = '';
    for (const cf of cfs) {
      const pct = (cf.estimated_bytes / maxBytes) * 100;
      const color = cfColor(cf.name);
      rows += `
        <tr>
          <td style="font-family:var(--font-mono);font-size:var(--font-size-xs);white-space:nowrap">${_esc(cf.name)}</td>
          <td style="font-size:var(--font-size-xs);text-align:right;white-space:nowrap">${formatBytes(cf.estimated_bytes)}</td>
          <td style="font-size:var(--font-size-xs);text-align:right;white-space:nowrap">${formatNumber(cf.estimated_keys)}</td>
          <td style="width:40%;padding-left:var(--gap-sm)">
            <div style="background:var(--bg-tertiary);border-radius:2px;height:14px;overflow:hidden">
              <div style="height:100%;width:${pct.toFixed(1)}%;background:${color};border-radius:2px;transition:width 0.3s"></div>
            </div>
          </td>
        </tr>`;
    }

    cfBody.innerHTML = `
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="border-bottom:1px solid var(--border)">
            <th style="text-align:left;font-size:var(--font-size-xs);font-weight:600;padding:4px 0;color:var(--text-secondary)">Column Family</th>
            <th style="text-align:right;font-size:var(--font-size-xs);font-weight:600;padding:4px 0;color:var(--text-secondary)">Est. Size</th>
            <th style="text-align:right;font-size:var(--font-size-xs);font-weight:600;padding:4px 0;color:var(--text-secondary)">Est. Keys</th>
            <th style="text-align:left;font-size:var(--font-size-xs);font-weight:600;padding:4px 0;padding-left:var(--gap-sm);color:var(--text-secondary)">Distribution</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  async function loadStorage() {
    try {
      const [storageInfo, pruningStatus, storageStats] = await Promise.all([
        rpc.call('noble_getStorageInfo'),
        rpc.call('noble_getPruningStatus'),
        rpc.call('noble_getStorageStats'),
      ]);

      // KPI cards
      stHeight.textContent = formatNumber(storageInfo.chain_height);
      stMode.textContent = storageInfo.pruning_mode;
      stMode.style.color = storageInfo.pruning_mode === 'archive'
        ? 'var(--success)' : 'var(--warning)';
      stDbSize.textContent = formatBytes(storageStats.total_db_bytes || 0);
      stDiskFree.textContent = storageStats.available_bytes
        ? formatBytes(storageStats.available_bytes) : 'N/A';
      stPruned.textContent = storageInfo.pruned_up_to > 0
        ? formatNumber(storageInfo.pruned_up_to) : 'None';
      stLowest.textContent = formatNumber(storageInfo.lowest_full_height);

      // Storage info detail grid
      infoGrid.innerHTML = `
        <dt>Chain Height</dt><dd>${formatNumber(storageInfo.chain_height)}</dd>
        <dt>Pruning Mode</dt><dd>${storageInfo.pruning_mode}</dd>
        <dt>Keep Blocks</dt><dd>${formatNumber(storageInfo.keep_blocks)}</dd>
        <dt>Pruned Up To</dt><dd>${storageInfo.pruned_up_to > 0 ? formatNumber(storageInfo.pruned_up_to) : 'N/A'}</dd>
        <dt>Lowest Full Height</dt><dd>${formatNumber(storageInfo.lowest_full_height)}</dd>
      `;

      // Pruning status detail grid
      pruningGrid.innerHTML = `
        <dt>Mode</dt><dd>${pruningStatus.mode}</dd>
        <dt>Blocks Pruned</dt><dd>${formatNumber(pruningStatus.blocks_pruned)}</dd>
        <dt>Transactions Removed</dt><dd>${formatNumber(pruningStatus.transactions_removed)}</dd>
        <dt>Lowest Full Height</dt><dd>${formatNumber(pruningStatus.lowest_full_height)}</dd>
        <dt>More Remaining</dt><dd>${pruningStatus.more_remaining ? 'Yes' : 'No'}</dd>
      `;

      // Data directory panel
      renderDataDir(storageStats);

      // Column families table
      renderCfTable(storageStats);

      // Retention chart
      if (typeof echarts !== 'undefined') {
        initRetentionChart(storageInfo);
      }
    } catch (e) {
      console.error('[storage] load:', e);
      infoGrid.innerHTML = '<dt>Error</dt><dd>Failed to load storage info</dd>';
    }
  }

  function initRetentionChart(info) {
    const dom = root.querySelector('#st-retention-chart');
    if (!dom || typeof echarts === 'undefined') return;
    retentionChart = echarts.init(dom);

    const pruned = info.pruned_up_to;
    const full = info.chain_height > 0 ? info.chain_height - info.lowest_full_height + 1 : 0;
    const kept = info.keep_blocks;
    const isArchive = info.pruning_mode === 'archive' || kept === 0;

    if (isArchive) {
      // Archive mode: show a single "All Blocks" slice or informational text
      if (full === 0) {
        dom.innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:2rem">Archive mode — no blocks yet</div>';
        return;
      }
      retentionChart.setOption({
        tooltip: { trigger: 'item', formatter: '{b}: {c} blocks' },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          itemStyle: { borderRadius: 4, borderColor: 'var(--bg-primary)', borderWidth: 2 },
          label: { show: true, formatter: '{b}\n{c}' },
          data: [
            { value: full, name: 'All Blocks (Archive)', itemStyle: { color: '#10b981' } },
          ],
        }],
      });
    } else {
      retentionChart.setOption({
        tooltip: { trigger: 'item', formatter: '{b}: {c} blocks ({d}%)' },
        legend: { bottom: 0, textStyle: { color: 'var(--text-secondary)' } },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          avoidLabelOverlap: true,
          minAngle: 5,
          itemStyle: { borderRadius: 4, borderColor: 'var(--bg-primary)', borderWidth: 2 },
          label: { show: true, formatter: '{b}\n{c}' },
          data: [
            ...(pruned > 0 ? [{ value: pruned, name: 'Pruned', itemStyle: { color: '#6b7280' } }] : []),
            { value: full, name: 'Full Blocks', itemStyle: { color: '#10b981' } },
            { value: Math.max(0, kept - full), name: 'Retention Buffer', itemStyle: { color: '#3b82f6' } },
          ].filter(d => d.value > 0),
        }],
      });
    }

    const ro = new ResizeObserver(() => retentionChart?.resize());
    ro.observe(dom);
    unsubs.push(() => { ro.disconnect(); retentionChart?.dispose(); });
  }

  // Refresh every 30s
  const refreshInterval = setInterval(loadStorage, 30_000);
  unsubs.push(() => clearInterval(refreshInterval));

  loadStorage();

  return {
    destroy() {
      closeConfigModal();
      unsubs.forEach(fn => { try { fn(); } catch {} });
    },
  };
}
