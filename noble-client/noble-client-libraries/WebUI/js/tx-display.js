// NOBLE — Transaction display logic (shared by all clients)
// Single source of truth for type codes, labels, and value computation.

export const TX_TYPES = {
    NOTARIZATION:      0x00,
    TRANSFER:          0x01,
    KEY_ROTATION:      0x02,
    BADGE_PROPOSAL:    0x03,
    BADGE_VOTE:        0x04,
    BADGE_REVOCATION:  0x05,
    LOCKED:            0x06,
    UNLOCKING:         0x07,
    COINBASE:          0x10,
    FEE_DISTRIBUTION:  0x11,
};

export const TX_TYPE_NAMES = {
    0x00: 'Notarization',
    0x01: 'Transfer',
    0x02: 'Key Rotation',
    0x03: 'Badge Proposal',
    0x04: 'Badge Vote',
    0x05: 'Badge Revocation',
    0x06: 'Locked',
    0x07: 'Unlocking',
    0x10: 'Block Reward',
    0x11: 'Fee Distribution',
};

/**
 * Type-aware display value for a transaction.
 * Returns { label, amount, showFee }.
 *
 * - Transfer: "Amount Sent" = transfer_value
 * - Coinbase: "Block Reward" = total_output
 * - Everything else (notarization, locked, etc.): "Fee" = fee
 *
 * Uses ?? (not ||) to correctly handle transfer_value = 0.
 */
export function txDisplayAmount(tx) {
    const t = tx.tx_type ?? tx.txType ?? tx.type;
    // Normalize type to number if it's a string
    const txType = typeof t === 'string' ? parseTypeString(t) : t;

    switch (txType) {
        case TX_TYPES.TRANSFER:
            return {
                label: 'Amount Sent',
                amount: tx.transfer_value ?? tx.total_output ?? 0,
                showFee: true,
            };
        case TX_TYPES.COINBASE:
            return {
                label: 'Block Reward',
                amount: tx.total_output ?? 0,
                showFee: false,
            };
        case TX_TYPES.FEE_DISTRIBUTION:
            return {
                label: 'Fee Income',
                amount: tx.total_output ?? 0,
                showFee: false,
            };
        default:
            // Notarization, Locked, Unlocking, Key Rotation, Badge types
            // The meaningful "cost" is the fee. All outputs are change.
            return {
                label: 'Fee',
                amount: tx.fee ?? 0,
                showFee: false,
            };
    }
}

/** Parse a type string like "notarization" back to a numeric code. */
function parseTypeString(s) {
    if (!s) return -1;
    const lower = s.toLowerCase().replace(/[_\s-]/g, '');
    const map = {
        notarization: 0x00, transfer: 0x01, keyrotation: 0x02,
        badgeproposal: 0x03, badgevote: 0x04, badgerevocation: 0x05,
        locked: 0x06, unlocking: 0x07, blockreward: 0x10, coinbase: 0x10,
        feedistribution: 0x11, feeincome: 0x11,
    };
    return map[lower] ?? -1;
}

/** Format tx_type as human-readable label. */
export function formatTxType(txType) {
    return TX_TYPE_NAMES[txType] || `Type 0x${(txType ?? 0).toString(16).padStart(2, '0')}`;
}

/** True for system metadata keys (not user content). */
export function isSystemKey(key) {
    if (!key) return false;
    return key.startsWith('locked:')
        || key.startsWith('unlock:')
        || key.startsWith('sig:')
        || key === 'schema'
        || key === 'doc:version'
        || key === 'doc:prev_checksum'
        || key === 'new_pubkey'
        || key === 'target_pubkey'
        || key === 'proposal_type'
        || key === 'reason'
        || key === 'proposal_hash'
        || key === 'vote'
        || key === 'badge_id';
}

/**
 * Classify metadata entries into categories.
 * @param {Array<{key, value}>} metadata
 * @param {number} txType
 * @returns {{ system: Array, user: Array, signatures: Array }}
 */
export function classifyMetadata(metadata, txType) {
    const system = [];
    const user = [];
    const signatures = [];

    for (const entry of (metadata || [])) {
        if (!entry.key) continue;

        // CMS signature entries: sig:N
        const sigMatch = entry.key.match(/^sig:(\d+)$/);
        if (sigMatch) {
            signatures.push({ slotIndex: parseInt(sigMatch[1], 10), ...entry });
            continue;
        }

        if (isSystemKey(entry.key)) {
            system.push(entry);
        } else {
            user.push(entry);
        }
    }

    return { system, user, signatures };
}

/**
 * Check if a transaction is a zero-checksum type (no document hash).
 */
export function isZeroChecksum(checksum) {
    if (!checksum) return true;
    return /^0+$/.test(checksum);
}

/**
 * Decode a metadata value that might be hex-encoded UTF-8.
 * Returns the decoded string, or the original hex if not valid UTF-8.
 */
export function decodeMetadataValue(value) {
    if (!value || typeof value !== 'string') return String(value ?? '');
    // If it looks like printable ASCII/UTF-8 already, return as-is
    if (!/^[0-9a-fA-F]+$/.test(value)) return value;
    // Try hex → UTF-8
    try {
        const bytes = new Uint8Array(value.length / 2);
        for (let i = 0; i < value.length; i += 2) {
            bytes[i / 2] = parseInt(value.substring(i, i + 2), 16);
        }
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (/^[\x20-\x7E\t\n\r]+$/.test(text)) return text;
    } catch { /* not valid UTF-8 hex */ }
    return value;
}

/**
 * Transaction status badge with pie-chart filling icon.
 * 4-state lifecycle: Pending → Admitted → Maturing → Complete.
 * @param {number|null|undefined} confirmations — null/undefined = pending (mempool)
 * @param {string} status — "pending", "confirmed", etc. from RPC
 * @param {number} maturity — COINBASE_MATURITY (default 6)
 * @returns {{ html: string, cls: string }}
 */
export function txStatusBadge(confirmations, status, maturity = 6) {
    if (status === 'pending' || confirmations == null || confirmations < 0) {
        return { html: '\u25D4 Pending', cls: 'badge-pending' };
    }
    if (confirmations === 0) {
        return { html: '\u25D1 Admitted', cls: 'badge-admitted' };
    }
    if (confirmations < maturity) {
        return { html: `\u25D5 Maturing (${confirmations}/${maturity})`, cls: 'badge-maturing' };
    }
    return { html: `\u25CF Complete`, cls: 'badge-confirmed' };
}
