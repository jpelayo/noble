/**
 * NOBLE Dashboard — Transaction display logic
 * Shared type registry, value computation, and metadata classification.
 */

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
    DAO:               0x12,
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
    0x12: 'DAO Poll',
};

/** Short labels for compact displays (mempool stream, block tx list). */
export const TX_TYPE_SHORT = {
    0x00: 'Doc', 0x01: 'Transfer', 0x02: 'Key Rot.',
    0x03: 'Badge', 0x04: 'Vote', 0x05: 'Revoke',
    0x06: 'Locked', 0x07: 'Unlock', 0x10: 'Reward',
    0x11: 'Fees', 0x12: 'DAO',
};

/**
 * Type-aware display value for a transaction.
 * Uses ?? (not ||) to handle transfer_value = 0 correctly.
 */
export function txDisplayAmount(tx) {
    const t = tx.tx_type;
    switch (t) {
        case TX_TYPES.TRANSFER:
            return {
                label: 'Amount',
                amount: tx.transfer_value ?? tx.total_output ?? 0,
                showFee: true,
            };
        case TX_TYPES.COINBASE:
            return {
                label: 'Reward',
                amount: tx.total_output ?? 0,
                showFee: false,
            };
        case TX_TYPES.FEE_DISTRIBUTION:
            return {
                label: 'Fee Income',
                amount: tx.total_output ?? 0,
                showFee: false,
            };
        case TX_TYPES.DAO:
            return {
                label: 'Governance',
                amount: 0,
                showFee: false,
            };
        default:
            return {
                label: 'Fee',
                amount: tx.fee ?? 0,
                showFee: false,
            };
    }
}

export function formatTxType(txType) {
    if (txType === TX_TYPES.COINBASE) return '<span class="badge coinbase">Block Reward</span>';
    if (txType === TX_TYPES.FEE_DISTRIBUTION) return '<span class="badge tx-fee-distribution">Fee Distribution</span>';
    if (txType === TX_TYPES.DAO) return '<span class="badge tx-dao">DAO Poll</span>';
    return TX_TYPE_NAMES[txType] || `Type 0x${(txType ?? 0).toString(16).padStart(2, '0')}`;
}

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

export function classifyMetadata(metadata) {
    const system = [], user = [], signatures = [];
    for (const entry of (metadata || [])) {
        if (!entry.key) continue;
        const sigMatch = entry.key.match(/^sig:(\d+)$/);
        if (sigMatch) {
            signatures.push({ slotIndex: parseInt(sigMatch[1], 10), ...entry });
            continue;
        }
        if (isSystemKey(entry.key)) system.push(entry);
        else user.push(entry);
    }
    return { system, user, signatures };
}

export function isZeroChecksum(checksum) {
    if (!checksum) return true;
    return /^0+$/.test(checksum);
}
