/**
 * NOBLE Dashboard — Metadata Schema Parser
 *
 * Parses the self-describing metadata schema convention where slot 0
 * contains a descriptor telling client software how to interpret remaining slots.
 *
 * Schema format (one line per slot):
 *   <slot>:<visibility>:<encoding>:<required>:<label>
 *
 * Example:
 *   0:pub:utf8:opt:schema
 *   1:pub:b64:opt:description
 *   2:priv:ecies:opt:doc_url_enc
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
    if (parts.length < 5) continue;
    const [slot, vis, encoding, required, ...labelParts] = parts;
    const slotNum = parseInt(slot, 10);
    if (isNaN(slotNum)) continue;

    slotMap.set(slotNum, {
      visibility: vis,     // "pub" | "priv"
      encoding: encoding,  // "utf8" | "b64" | "hex" | "der" | "ecies" | "raw"
      required: required,  // "req" | "opt"
      label: labelParts.join(':'),
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
