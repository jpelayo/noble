/**
 * NOBLE Dashboard — Metadata Schema Parser
 *
 * Parses the self-describing metadata schema convention where slot 0
 * contains a descriptor telling client software how to interpret remaining slots.
 *
 * Schema format v2 (5-field, from client WebUI):
 *   <slot>:<typeCode>:<visibility>:<encoding>:<fieldKey>
 *   Example: 1:T07:pub:utf8:author
 *            2:T10:priv:ecies:signer:email
 *            3:SIG:pub:cms:sig:2
 *
 * Schema format v1 (5-field, legacy dashboard):
 *   <slot>:<visibility>:<encoding>:<required>:<label>
 *   Example: 0:pub:utf8:opt:schema
 *
 * Schema format v0 (4-field, pre-encoding):
 *   <slot>:<typeCode>:<visibility>:<fieldKey>
 *   Example: 1:T07:pub:author
 *
 * Detection: if parts[1] starts with 'T' or is 'SIG' → v2/v0 (type code present).
 * Otherwise → v1 (visibility in parts[1]).
 */

/**
 * Parse a metadata schema descriptor from metadata entries.
 *
 * @param {Array<{key: string, value: string}>} metadataEntries - Metadata entries (value is hex-encoded)
 * @returns {Map<number, {visibility: string, encoding: string, required: string, label: string}>|null}
 *   Returns a Map keyed by slot index, or null if no schema descriptor found.
 */
export function parseMetadataSchema(metadataEntries) {
  if (!metadataEntries || metadataEntries.length === 0) return null;

  // Find the entry with key "schema"
  const schemaEntry = metadataEntries.find(e => e.key === 'schema');
  if (!schemaEntry) return null;

  // Decode hex value to UTF-8
  const text = hexToUtf8(schemaEntry.value);
  if (!text) return null;

  const slotMap = new Map();

  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(':');
    if (parts.length < 4) continue;
    const slotNum = parseInt(parts[0], 10);
    if (isNaN(slotNum)) continue;

    // Detect format by parts[1]: type codes start with T or are SIG
    const hasTypeCode = /^T\d+$/.test(parts[1]) || parts[1] === 'SIG';

    let vis, encoding, label;
    if (hasTypeCode && parts.length >= 5) {
      // v2: slot:typeCode:vis:enc:key (key may contain colons)
      vis = parts[2];
      encoding = parts[3];
      label = parts.slice(4).join(':');
    } else if (hasTypeCode && parts.length === 4) {
      // v0: slot:typeCode:vis:key (no encoding — infer from visibility)
      vis = parts[2];
      encoding = vis === 'priv' ? 'ecies' : vis === 'pwd' ? 'aesgcm' : 'utf8';
      label = parts[3];
    } else {
      // v1 legacy: slot:vis:enc:req:label
      vis = parts[1];
      encoding = parts[2];
      label = parts.length >= 5 ? parts.slice(4).join(':') : parts[3];
    }

    slotMap.set(slotNum, {
      visibility: vis,
      encoding: encoding,
      required: 'opt',
      label: label,
    });
  }

  return slotMap.size > 0 ? slotMap : null;
}

/**
 * Render a single metadata value according to its schema encoding type.
 *
 * @param {string} hexValue - Hex-encoded value bytes
 * @param {{visibility: string, encoding: string, required: string, label: string}} slotInfo
 * @returns {string} HTML string for the rendered value
 */
export function renderSchemaValue(hexValue, slotInfo) {
  const encoding = slotInfo.encoding;

  switch (encoding) {
    case 'utf8': {
      const text = hexToUtf8(hexValue);
      return text ? escapeHtml(text) : `<span class="mono">${hexValue}</span>`;
    }

    case 'b64': {
      try {
        const bytes = hexToBytes(hexValue);
        const b64 = btoa(String.fromCharCode(...bytes));
        const decoded = atob(b64);
        return escapeHtml(decoded);
      } catch {
        return `<span class="mono">${hexValue}</span>`;
      }
    }

    case 'hex':
      return `<span class="mono">${hexValue}</span>`;

    case 'der': {
      const byteLen = hexValue.length / 2;
      const fingerprint = hexValue.slice(0, 16);
      return `Certificate (${byteLen} bytes) <span class="mono" style="font-size:var(--font-size-xs)">${fingerprint}...</span>`;
    }

    case 'ecies':
      return `<span class="badge-encrypted">ENCRYPTED</span> (${hexValue.length / 2} bytes)`;

    case 'aesgcm':
      return `<span class="badge-protected" style="background:color-mix(in srgb,var(--warning,#f59e0b) 15%,transparent);color:var(--warning,#f59e0b);padding:1px 6px;border-radius:4px;font-size:0.6rem;font-weight:600">PROTECTED</span> (${hexValue.length / 2} bytes)`;

    case 'cms':
      return `<span class="badge" style="background:var(--success);color:#fff;font-size:0.6rem;padding:1px 6px">SIGNATURE</span> (${hexValue.length / 2} bytes)`;

    case 'raw':
    default:
      return `<span class="mono">${hexValue}</span>`;
  }
}

/**
 * Get the visibility badge HTML.
 *
 * @param {string} visibility - "pub" or "priv"
 * @returns {string} HTML badge
 */
export function visibilityBadge(visibility) {
  if (visibility === 'priv') {
    return '<span class="badge-encrypted">ENCRYPTED</span>';
  }
  if (visibility === 'pwd') {
    return '<span class="badge-protected" style="background:color-mix(in srgb,var(--warning,#f59e0b) 15%,transparent);color:var(--warning,#f59e0b);padding:1px 6px;border-radius:4px;font-size:0.6rem;font-weight:600">PROTECTED</span>';
  }
  return '<span class="badge-public">PUBLIC</span>';
}

/**
 * Render a full metadata table using schema-aware rendering.
 *
 * @param {Array<{key: string, value: string}>} metadataEntries
 * @returns {string} HTML string for the metadata panel body
 */
export function renderMetadataWithSchema(metadataEntries) {
  const schema = parseMetadataSchema(metadataEntries);

  if (!schema) {
    // Fallback: raw key/value table
    return renderRawMetadata(metadataEntries);
  }

  // Schema-aware rendering
  let html = '<table class="data-table"><thead><tr><th>Slot</th><th>Label</th><th>Visibility</th><th>Value</th></tr></thead><tbody>';

  metadataEntries.forEach((entry, index) => {
    const slotInfo = schema.get(index);

    if (slotInfo) {
      // Skip rendering the schema descriptor itself as a regular row
      if (slotInfo.label === 'schema') {
        html += `<tr><td>${index}</td><td><em>Schema Descriptor</em></td><td>${visibilityBadge(slotInfo.visibility)}</td><td style="color:var(--text-muted);font-size:var(--font-size-xs)">${schema.size} slot(s) defined</td></tr>`;
        return;
      }

      html += `<tr>
        <td>${index}</td>
        <td><strong>${escapeHtml(slotInfo.label)}</strong></td>
        <td>${visibilityBadge(slotInfo.visibility)}</td>
        <td>${renderSchemaValue(entry.value, slotInfo)}</td>
      </tr>`;
    } else {
      // Slot not in schema — render as raw
      html += `<tr>
        <td>${index}</td>
        <td><strong>${escapeHtml(entry.key)}</strong></td>
        <td></td>
        <td class="mono">${escapeHtml(tryDecodeHexUtf8(entry.value))}</td>
      </tr>`;
    }
  });

  html += '</tbody></table>';
  return html;
}

/**
 * Fallback: render metadata as simple key/value table.
 */
function renderRawMetadata(metadataEntries) {
  // Show entries in the order the user wrote them (node may return reversed).
  const ordered = [...metadataEntries].reverse();
  let html = '<table class="data-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>';
  for (const entry of ordered) {
    const valueStr = tryDecodeHexUtf8(entry.value);
    const isSchema = entry.key === 'schema';
    const style = isSchema ? ' style="color:var(--text-muted);font-size:var(--font-size-xs)"' : '';
    html += `<tr${style}><td>${isSchema ? '<em>' : '<strong>'}${escapeHtml(entry.key)}${isSchema ? '</em>' : '</strong>'}</td><td class="mono">${escapeHtml(valueStr)}</td></tr>`;
  }
  html += '</tbody></table>';
  return html;
}

// ── Internal helpers ──

function hexToUtf8(hex) {
  try {
    const bytes = hexToBytes(hex);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function tryDecodeHexUtf8(hex) {
  const text = hexToUtf8(hex);
  if (text && /^[\x20-\x7E\t\n\r]+$/.test(text)) return text;
  return hex;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
