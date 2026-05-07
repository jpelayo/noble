// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Pure-regex client-side classifier for canonical address / public-key
// strings. Used for input-feedback only — the Swift / Rust bridge does the
// actual format conversion server-side. JS never converts bech32 to hex.

/**
 * Classify a user-typed address string.
 *
 * @param {string} input
 * @returns {{ canonical: string, display: string, kind: string }|null}
 *   `kind` is one of: 'noble-bech32', 'bitcoin-bech32', 'bitcoin-base58', 'hex'.
 *   Returns `null` if the input is empty or matches no known canonical form.
 */
export function normalizeAddress(input) {
    const s = String(input || '').trim();
    if (!s) return null;

    if (/^nbl1[qp][a-z0-9]+$/i.test(s) && s.length >= 12) {
        return { canonical: s.toLowerCase(), display: s.toLowerCase(), kind: 'noble-bech32' };
    }
    if (/^(bc1|tb1)[qp][a-z0-9]+$/i.test(s) && s.length >= 14) {
        return { canonical: s.toLowerCase(), display: s.toLowerCase(), kind: 'bitcoin-bech32' };
    }
    // Bitcoin Base58 P2PKH (mainnet 1…, testnet m…/n…) and P2SH (3…, testnet 2…).
    if (/^[13mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(s)) {
        return { canonical: s, display: s, kind: 'bitcoin-base58' };
    }
    // Hex wire format: 66 (bare SEC1), 68 (Noble wire), or 42 (Bitcoin Hash160 with prefix).
    if (/^[0-9a-f]+$/i.test(s) && (s.length === 66 || s.length === 68 || s.length === 42 || s.length === 66)) {
        return { canonical: s.toLowerCase(), display: s.toLowerCase(), kind: 'hex' };
    }
    return null;
}

/**
 * Apply visual feedback to an `<input>` element based on whether its value
 * is a recognized canonical address. Adds/removes the `addr-invalid` class.
 *
 * Does NOT block submission — that is the bridge's job. This is purely a
 * hint to the user that their input is unlikely to work.
 *
 * @param {HTMLInputElement} el
 */
export function attachAddressValidation(el) {
    if (!el) return;
    const update = () => {
        const v = (el.value || '').trim();
        if (!v) {
            el.classList.remove('addr-invalid');
            el.removeAttribute('title');
            return;
        }
        const norm = normalizeAddress(v);
        if (norm) {
            el.classList.remove('addr-invalid');
            el.setAttribute('title', `${norm.kind} ✓`);
        } else {
            el.classList.add('addr-invalid');
            el.setAttribute('title', 'Unrecognized address format. Expected nbl1…, bc1…, 1…/3…, or hex.');
        }
    };
    el.addEventListener('input', update);
    el.addEventListener('blur', update);
    update();
}
