/**
 * NOBLE Dashboard — Storage Management Page
 * Chain pruning status, storage info, pruning controls
 */

import { formatNumber, formatBytes } from '../utils.js';

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
        <div class="kpi-label">Pruned Up To</div>
        <div class="kpi-value" id="st-pruned">--</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Lowest Full Block</div>
        <div class="kpi-value" id="st-lowest">--</div>
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
  const stPruned = root.querySelector('#st-pruned');
  const stLowest = root.querySelector('#st-lowest');
  const infoGrid = root.querySelector('#st-info-grid');
  const pruningGrid = root.querySelector('#st-pruning-grid');
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

  function _esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  async function loadStorage() {
    try {
      const [storageInfo, pruningStatus] = await Promise.all([
        rpc.call('noble_getStorageInfo'),
        rpc.call('noble_getPruningStatus'),
      ]);

      // KPI cards
      stHeight.textContent = formatNumber(storageInfo.chain_height);
      stMode.textContent = storageInfo.pruning_mode;
      stMode.style.color = storageInfo.pruning_mode === 'archive'
        ? 'var(--success)' : 'var(--warning)';
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
