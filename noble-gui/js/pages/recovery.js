// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Recovery page — operator-facing surface for the multi-path storage
// resilience subsystem added in 0.117 (KB §22, sharding-plan Phase 6).
//
// Three controls:
//
//   • Discover — calls noble_discoverShards; renders the full
//     disk-vs-catalog report. No mutation; safe to run at any time.
//   • Inspect a directory — calls noble_listShards(path); answers
//     "does this backup tape contain Noble data?".
//   • Reconcile now — calls noble_reconcileStorage (TOTP-gated);
//     rewrites every per-path catalog from the live DB, returns the
//     updated discovery report, surfaces a restart-required banner
//     if RocksDB needs DB::Repair.

export function init(root, ctx) {
  const { rpc } = ctx;

  root.innerHTML = `
    <div class="page-header">
      <div>
        <h1>Recovery</h1>
        <p>Inspect storage tiers, detect moved SSTs, rewrite per-path catalogs.</p>
      </div>
    </div>

    <div class="panel" style="margin-bottom:1rem">
      <div class="panel-header">Discover shards</div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap-sm)">
          Walk every configured storage tier, read its catalog, compare against disk reality.
          Identifies moved files, duplicates, and strangers. Read-only.
        </p>
        <button id="rec-discover-btn" class="btn btn-secondary btn-sm">Run Discovery</button>
        <div id="rec-discover-out" style="margin-top:var(--gap-sm)"></div>
      </div>
    </div>

    <div class="panel" style="margin-bottom:1rem">
      <div class="panel-header">Inspect a directory</div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap-sm)">
          Lists every <code>*.sst</code> file in an arbitrary directory.
          Useful for verifying that a backup contains Noble data before pointing the node at it.
        </p>
        <div style="display:flex;gap:var(--gap-sm);align-items:center">
          <input id="rec-inspect-path" type="text"
                 placeholder="/mnt/backup/noble"
                 style="flex:1;font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">
          <label style="display:flex;align-items:center;gap:4px;font-size:var(--font-size-xs);color:var(--text-muted)">
            <input id="rec-inspect-hash" type="checkbox"> hash
          </label>
          <button id="rec-inspect-btn" class="btn btn-secondary btn-sm">List Shards</button>
        </div>
        <div id="rec-inspect-out" style="margin-top:var(--gap-sm)"></div>
      </div>
    </div>

    <div class="panel" style="margin-bottom:1rem">
      <div class="panel-header">Reconcile now</div>
      <div class="panel-body">
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary);margin:0 0 var(--gap-sm)">
          Re-walk every tier, rewrite the per-path <code>.noble-shards.cbor</code> catalogs from the
          live <code>DB::live_files()</code> view. Use after a clean shutdown to refresh stale catalogs.
          TOTP-gated. Does <strong>not</strong> run <code>DB::Repair</code> &mdash; that requires a restart.
        </p>
        <button id="rec-reconcile-btn" class="btn btn-secondary btn-sm">Reconcile Storage</button>
        <div id="rec-reconcile-out" style="margin-top:var(--gap-sm)"></div>
      </div>
    </div>
  `;

  // ── Discover ──
  root.querySelector('#rec-discover-btn').addEventListener('click', async () => {
    const out = root.querySelector('#rec-discover-out');
    out.innerHTML = '<span style="color:var(--text-muted)">Running…</span>';
    try {
      const report = await rpc.call('noble_discoverShards');
      out.innerHTML = renderReport(report);
    } catch (e) {
      out.innerHTML = `<div style="color:var(--error)">${esc(e.message || String(e))}</div>`;
    }
  });

  // ── Inspect ──
  root.querySelector('#rec-inspect-btn').addEventListener('click', async () => {
    const out = root.querySelector('#rec-inspect-out');
    const path = root.querySelector('#rec-inspect-path').value.trim();
    const withHash = root.querySelector('#rec-inspect-hash').checked;
    if (!path) {
      out.innerHTML = '<span style="color:var(--warning)">Enter a directory path.</span>';
      return;
    }
    out.innerHTML = '<span style="color:var(--text-muted)">Scanning…</span>';
    try {
      const resp = await rpc.call('noble_listShards', { path, with_hash: withHash });
      out.innerHTML = renderInspect(resp);
    } catch (e) {
      out.innerHTML = `<div style="color:var(--error)">${esc(e.message || String(e))}</div>`;
    }
  });

  // ── Reconcile ──
  root.querySelector('#rec-reconcile-btn').addEventListener('click', async () => {
    const out = root.querySelector('#rec-reconcile-out');
    out.innerHTML = '<span style="color:var(--text-muted)">Rewriting catalogs…</span>';
    try {
      const resp = await rpc.call('noble_reconcileStorage');
      const banner = resp.requires_restart
        ? `<div style="padding:var(--gap-sm);background:color-mix(in srgb, var(--warning) 14%, transparent);border:1px solid var(--warning);border-radius:var(--radius-sm);margin-bottom:var(--gap-sm);font-size:var(--font-size-sm)">
             <strong>Restart required.</strong> The discovery decision was <code>RepairThenOpen</code>; restart the node so it can rebuild the RocksDB MANIFEST.
           </div>`
        : '';
      out.innerHTML = banner +
        `<div style="font-size:var(--font-size-sm);color:var(--text-secondary);margin-bottom:var(--gap-sm)">
           Catalogs rewritten: <strong>${resp.catalogs_rewritten}</strong>
         </div>` + renderReport(resp.report);
    } catch (e) {
      out.innerHTML = `<div style="color:var(--error)">${esc(e.message || String(e))}</div>`;
    }
  });

  return () => {};
}

function renderReport(report) {
  if (!report) return '<span style="color:var(--text-muted)">No data.</span>';
  const color = report.decision === 'OpenNormally' ? 'var(--success)'
              : report.decision === 'RepairThenOpen' ? 'var(--warning)'
              : 'var(--error)';
  const reasonLine = report.decision_reason
    ? `<div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:4px">${esc(report.decision_reason)}</div>`
    : '';
  const dec = `
    <div style="padding:var(--gap-sm);border-left:3px solid ${color};margin-bottom:var(--gap-sm);font-size:var(--font-size-sm)">
      <strong>Decision:</strong> <span style="color:${color}">${esc(report.decision)}</span>
      ${reasonLine}
    </div>`;

  const paths = (report.paths || []).map(p => {
    const cat = p.catalog_present
      ? `<span style="color:var(--success)">present</span>${p.catalog_chain_id ? ` (chain_id ${p.catalog_chain_id})` : ''}`
      : `<span style="color:var(--text-muted)">missing</span>`;
    const missing = (p.missing_from_catalog || []).length;
    const extra = (p.extra_vs_catalog || []).length;
    return `
      <div style="padding:var(--gap-sm);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:var(--gap-xs)">
        <div style="font-family:var(--font-mono,monospace);font-size:var(--font-size-sm)">${esc(p.path)}</div>
        <div style="font-size:var(--font-size-xs);color:var(--text-muted);margin-top:4px">
          catalog: ${cat} · discovered: ${p.discovered.length} SST(s) · missing: ${missing} · extra: ${extra}
        </div>
      </div>`;
  }).join('');

  const dupes = (report.duplicates && report.duplicates.length)
    ? `<div style="padding:var(--gap-sm);background:color-mix(in srgb, var(--error) 10%, transparent);border:1px solid var(--error);border-radius:var(--radius-sm);margin-top:var(--gap-sm);font-size:var(--font-size-sm)">
         <strong>${report.duplicates.length} duplicate(s):</strong>
         <ul style="margin:4px 0 0;padding-left:1.2em">${
           report.duplicates.map(d => `<li><code>${d.content_sha256.slice(0,16)}…</code> in ${d.paths.map(p => `<code>${esc(p)}</code>`).join(', ')}</li>`).join('')
         }</ul>
       </div>`
    : '';
  const strangers = (report.strangers && report.strangers.length)
    ? `<div style="padding:var(--gap-sm);background:color-mix(in srgb, var(--error) 10%, transparent);border:1px solid var(--error);border-radius:var(--radius-sm);margin-top:var(--gap-sm);font-size:var(--font-size-sm)">
         <strong>${report.strangers.length} stranger(s)</strong> (files belonging to a foreign CF or different chain):
         <ul style="margin:4px 0 0;padding-left:1.2em">${
           report.strangers.slice(0,10).map(s => `<li><code>${esc(s.file_name)}</code> at <code>${esc(s.absolute_path)}</code></li>`).join('')
         }</ul>
       </div>`
    : '';
  // Audit Fix #3: surface filesystem-level scan errors and corrupt
  // catalogs explicitly. Both block `decide()` from issuing
  // OpenNormally / RepairThenOpen, so operators need to see them.
  const scanErrs = (report.scan_errors && report.scan_errors.length)
    ? `<div style="padding:var(--gap-sm);background:color-mix(in srgb, var(--error) 10%, transparent);border:1px solid var(--error);border-radius:var(--radius-sm);margin-top:var(--gap-sm);font-size:var(--font-size-sm)">
         <strong>${report.scan_errors.length} filesystem error(s)</strong> during tier discovery:
         <ul style="margin:4px 0 0;padding-left:1.2em">${
           report.scan_errors.slice(0,10).map(([p, e]) =>
             `<li><code>${esc(p)}</code>: ${esc(e)}</li>`
           ).join('')
         }</ul>
         <div style="margin-top:4px;color:var(--text-muted);font-size:var(--font-size-xs)">
           Check filesystem permissions and disk health on the affected tiers.
         </div>
       </div>`
    : '';
  const catErrs = (report.catalog_errors && report.catalog_errors.length)
    ? `<div style="padding:var(--gap-sm);background:color-mix(in srgb, var(--error) 10%, transparent);border:1px solid var(--error);border-radius:var(--radius-sm);margin-top:var(--gap-sm);font-size:var(--font-size-sm)">
         <strong>${report.catalog_errors.length} corrupt catalog(s)</strong>:
         <ul style="margin:4px 0 0;padding-left:1.2em">${
           report.catalog_errors.slice(0,10).map(([p, e]) =>
             `<li><code>${esc(p)}</code>: ${esc(e)}</li>`
           ).join('')
         }</ul>
         <div style="margin-top:4px;color:var(--text-muted);font-size:var(--font-size-xs)">
           Delete the corrupted <code>.noble-shards.cbor</code> file(s) so the node
           regenerates them on next reconcile, or restore from a known-good backup.
         </div>
       </div>`
    : '';
  return dec + paths + dupes + strangers + scanErrs + catErrs;
}

function renderInspect(resp) {
  if (!resp) return '<span style="color:var(--text-muted)">No data.</span>';
  if (!resp.descriptors || !resp.descriptors.length) {
    const errs = resp.errors && resp.errors.length
      ? `<div style="color:var(--error);font-size:var(--font-size-xs);margin-top:4px">${resp.errors.map(esc).join('<br>')}</div>`
      : '';
    return `<div style="color:var(--text-muted);font-size:var(--font-size-sm)">No <code>.sst</code> files found.</div>${errs}`;
  }
  const rows = resp.descriptors.map(d => `
    <tr>
      <td style="font-family:var(--font-mono,monospace);font-size:var(--font-size-xs);padding:4px 8px">${esc(d.file_name)}</td>
      <td style="text-align:right;padding:4px 8px">${formatBytes(d.size_bytes)}</td>
      <td style="font-family:var(--font-mono,monospace);font-size:var(--font-size-xs);padding:4px 8px;color:var(--text-muted)">${d.content_sha256 ? esc(d.content_sha256.slice(0,16))+'…' : '—'}</td>
    </tr>
  `).join('');
  return `
    <table style="width:100%;border-collapse:collapse;font-size:var(--font-size-sm)">
      <thead><tr style="color:var(--text-muted);text-align:left">
        <th style="padding:4px 8px">File</th>
        <th style="padding:4px 8px;text-align:right">Size</th>
        <th style="padding:4px 8px">SHA-256</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function formatBytes(n) {
  if (n === 0) return '0';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}
