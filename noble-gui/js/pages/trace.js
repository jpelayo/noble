/**
 * NOBLE Dashboard — Trace Log Viewer
 * Runtime tracing session control and log inspection
 */

const LEVEL_COLORS = {
  TRACE: '#6b7280',
  DEBUG: '#3b82f6',
  INFO: '#10b981',
  WARN: '#f59e0b',
  ERROR: '#ef4444',
};

const DURATION_OPTIONS = [
  { label: '1 min', value: 1 },
  { label: '5 min', value: 5 },
  { label: '15 min', value: 15 },
  { label: '30 min', value: 30 },
  { label: '1 hour', value: 60 },
  { label: '2 hours', value: 120 },
  { label: '6 hours', value: 360 },
  { label: '12 hours', value: 720 },
  { label: '24 hours', value: 1440 },
];

export function init(root, ctx) {
  const { rpc } = ctx;
  const unsubs = [];
  let autoRefreshId = null;
  let countdownId = null;

  root.innerHTML = `
    <div class="page-header"><h1>Trace Log Viewer</h1><p>Runtime tracing session control</p></div>

    <div class="panel">
      <div class="panel-header">Session Controls</div>
      <div class="panel-body">
        <div class="trace-controls">
          <div class="form-group" style="flex:1">
            <label for="trace-filter">Filter Directive</label>
            <input type="text" id="trace-filter" placeholder="trace, noble_core=debug, info" value="trace">
          </div>
          <div class="form-group">
            <label for="trace-duration">Duration</label>
            <select id="trace-duration">
              ${DURATION_OPTIONS.map(d => `<option value="${d.value}"${d.value === 5 ? ' selected' : ''}>${d.label}</option>`).join('')}
            </select>
          </div>
          <div class="form-group" style="align-self:flex-end">
            <button class="btn btn-primary" id="trace-start">Start Session</button>
            <button class="btn btn-danger" id="trace-stop" style="display:none">Stop</button>
          </div>
        </div>
        <div id="trace-session-info" class="trace-session-info" style="display:none">
          <span id="trace-countdown" class="trace-countdown"></span>
          <span id="trace-status-text"></span>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span>Log Entries</span>
        <div class="trace-toolbar">
          <select id="trace-level-filter">
            <option value="">All Levels</option>
            <option value="TRACE">TRACE</option>
            <option value="DEBUG">DEBUG</option>
            <option value="INFO">INFO</option>
            <option value="WARN">WARN</option>
            <option value="ERROR">ERROR</option>
          </select>
          <input type="text" id="trace-task-filter" placeholder="Task filter..." style="width:150px">
          <label class="checkbox-label" style="margin-left:8px">
            <input type="checkbox" id="trace-auto-refresh" checked>
            <span>Auto-refresh</span>
          </label>
          <button class="btn btn-sm" id="trace-refresh">Refresh</button>
          <button class="btn btn-sm btn-danger" id="trace-clear">Clear</button>
        </div>
      </div>
      <div class="panel-body" style="padding:0;max-height:500px;overflow-y:auto">
        <table class="data-table trace-table">
          <thead>
            <tr>
              <th style="width:140px">Time</th>
              <th style="width:60px">Level</th>
              <th style="width:200px">Target</th>
              <th>Message</th>
              <th style="width:100px">Task</th>
            </tr>
          </thead>
          <tbody id="trace-entries"></tbody>
        </table>
      </div>
      <div class="panel-footer" style="padding:8px 12px;font-size:0.8rem;color:var(--text-secondary)">
        <span id="trace-buffer-info">Buffer: 0 / 0</span>
      </div>
    </div>
  `;

  const filterInput = root.querySelector('#trace-filter');
  const durationSelect = root.querySelector('#trace-duration');
  const startBtn = root.querySelector('#trace-start');
  const stopBtn = root.querySelector('#trace-stop');
  const sessionInfo = root.querySelector('#trace-session-info');
  const countdownEl = root.querySelector('#trace-countdown');
  const statusText = root.querySelector('#trace-status-text');
  const levelFilter = root.querySelector('#trace-level-filter');
  const taskFilter = root.querySelector('#trace-task-filter');
  const autoRefreshCheckbox = root.querySelector('#trace-auto-refresh');
  const refreshBtn = root.querySelector('#trace-refresh');
  const clearBtn = root.querySelector('#trace-clear');
  const entriesBody = root.querySelector('#trace-entries');
  const bufferInfo = root.querySelector('#trace-buffer-info');

  // ── Persist trace controls across reloads ──
  const TRACE_PREFS_KEY = 'noble-trace-prefs';
  function saveTracePrefs() {
    try {
      localStorage.setItem(TRACE_PREFS_KEY, JSON.stringify({
        filter: filterInput.value,
        duration: durationSelect.value,
        level: levelFilter.value,
        task: taskFilter.value,
        autoRefresh: autoRefreshCheckbox.checked,
      }));
    } catch { /* storage full/unavailable — controls stay session-local */ }
  }
  try {
    const saved = JSON.parse(localStorage.getItem(TRACE_PREFS_KEY) || 'null');
    if (saved) {
      if (typeof saved.filter === 'string' && saved.filter) filterInput.value = saved.filter;
      if (saved.duration && durationSelect.querySelector(`option[value="${saved.duration}"]`)) {
        durationSelect.value = saved.duration;
      }
      if (typeof saved.level === 'string') levelFilter.value = saved.level;
      if (typeof saved.task === 'string') taskFilter.value = saved.task;
      if (typeof saved.autoRefresh === 'boolean') autoRefreshCheckbox.checked = saved.autoRefresh;
    }
  } catch { /* corrupt blob — fall back to defaults */ }
  for (const el of [filterInput, durationSelect, levelFilter, taskFilter, autoRefreshCheckbox]) {
    el.addEventListener('change', saveTracePrefs);
  }

  async function startSession() {
    try {
      const result = await rpc.call('noble_setTraceFilter', [{
        filter: filterInput.value || 'trace',
        duration_minutes: parseInt(durationSelect.value, 10),
      }]);
      startBtn.style.display = 'none';
      stopBtn.style.display = 'inline-block';
      sessionInfo.style.display = 'block';
      statusText.textContent = `Filter: ${result.filter}`;
      startCountdown(result.remaining_seconds || 0);
      startAutoRefresh();
    } catch (e) {
      console.error('[trace] start:', e);
      statusText.textContent = `Error: ${e.message || e}`;
      sessionInfo.style.display = 'block';
    }
  }

  async function stopSession() {
    try {
      await rpc.call('noble_setTraceFilter', [{
        filter: 'off',
        duration_minutes: null,
      }]);
    } catch (e) {
      console.error('[trace] stop:', e);
    }
    startBtn.style.display = 'inline-block';
    stopBtn.style.display = 'none';
    sessionInfo.style.display = 'none';
    stopCountdown();
    stopAutoRefresh();
  }

  function startCountdown(seconds) {
    stopCountdown();
    const endTime = Date.now() + seconds * 1000;
    updateCountdown(seconds);
    countdownId = () => {
      const left = Math.max(0, Math.round((endTime - Date.now()) / 1000));
      if (left <= 0) {
        stopCountdown();
        startBtn.style.display = 'inline-block';
        stopBtn.style.display = 'none';
        countdownEl.textContent = 'Expired';
        stopAutoRefresh();
      } else {
        updateCountdown(left);
      }
    };
    window._nobleTick.add(countdownId);
    unsubs.push(() => stopCountdown());
  }

  function stopCountdown() {
    if (countdownId) {
      window._nobleTick.remove(countdownId);
      countdownId = null;
    }
  }

  function updateCountdown(secs) {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    countdownEl.textContent = `${m}:${String(s).padStart(2, '0')} remaining`;
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    if (autoRefreshCheckbox.checked) {
      autoRefreshId = setInterval(fetchEntries, 2000);
      unsubs.push(() => clearInterval(autoRefreshId));
    }
  }

  function stopAutoRefresh() {
    if (autoRefreshId) {
      clearInterval(autoRefreshId);
      autoRefreshId = null;
    }
  }

  async function fetchEntries() {
    try {
      const params = { last_n: 200 };
      const task = taskFilter.value.trim();
      if (task) params.task = task;
      const level = levelFilter.value;
      if (level) params.level = level;

      const result = await rpc.call('noble_getTraceBuffer', [params]);
      renderEntries(result.entries || []);
      bufferInfo.textContent = `Buffer: ${result.total_in_buffer} / ${result.capacity}`;
    } catch (e) {
      console.error('[trace] fetch:', e);
    }
  }

  function renderEntries(entries) {
    if (entries.length === 0) {
      entriesBody.innerHTML = '<tr><td colspan="5" class="empty-state">No trace entries</td></tr>';
      return;
    }
    entriesBody.innerHTML = entries.map(entry => {
      const d = new Date(entry.timestamp * 1000);
      const time = d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString();
      const levelColor = LEVEL_COLORS[entry.level] || '#9ca3af';
      const task = entry.fields?.task || '';
      const target = entry.target.length > 30 ? '...' + entry.target.slice(-27) : entry.target;
      return `<tr>
        <td class="mono" style="font-size:0.75rem">${time}</td>
        <td><span style="color:${levelColor};font-weight:600;font-size:0.75rem">${entry.level}</span></td>
        <td class="mono" style="font-size:0.75rem" title="${esc(entry.target)}">${esc(target)}</td>
        <td style="font-size:0.8rem">${esc(entry.message)}</td>
        <td class="mono" style="font-size:0.75rem">${esc(task)}</td>
      </tr>`;
    }).join('');
  }

  async function clearBuffer() {
    try {
      await rpc.call('noble_clearTraceBuffer');
      entriesBody.innerHTML = '<tr><td colspan="5" class="empty-state">Buffer cleared</td></tr>';
      bufferInfo.textContent = 'Buffer: 0 / 0';
    } catch (e) {
      console.error('[trace] clear:', e);
    }
  }

  // Load initial status
  async function loadStatus() {
    try {
      const status = await rpc.call('noble_getTraceStatus');
      if (status.session_active) {
        startBtn.style.display = 'none';
        stopBtn.style.display = 'inline-block';
        sessionInfo.style.display = 'block';
        statusText.textContent = `Filter active`;
        startCountdown(status.remaining_seconds || 0);
        startAutoRefresh();
      }
      bufferInfo.textContent = `Buffer: ${status.buffer_size} / ${status.buffer_capacity}`;
    } catch (e) {
      console.error('[trace] status:', e);
    }
  }

  // Event handlers
  startBtn.addEventListener('click', startSession);
  stopBtn.addEventListener('click', stopSession);
  refreshBtn.addEventListener('click', fetchEntries);
  clearBtn.addEventListener('click', clearBuffer);
  autoRefreshCheckbox.addEventListener('change', () => {
    if (autoRefreshCheckbox.checked) startAutoRefresh();
    else stopAutoRefresh();
  });

  loadStatus();
  fetchEntries();

  return {
    destroy() {
      unsubs.forEach(fn => { try { fn(); } catch {} });
      stopAutoRefresh();
      stopCountdown();
    },
  };
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
