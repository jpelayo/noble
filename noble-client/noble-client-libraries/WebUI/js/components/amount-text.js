// Atomic units → display format (8 decimals, trim trailing zeros, min 2).
// 1 NOBLE = 100,000,000 groats (8 decimal places).
function formatFrac(frac) {
    const full = String(frac).padStart(8, '0');
    const trimmed = full.replace(/0+$/, '');
    // Minimum 2 decimal places for readability.
    return trimmed.length < 2 ? full.slice(0, 2) : trimmed;
}

export function amountText(atomic) {
    const n = Number(atomic);
    const whole = Math.floor(n / 100_000_000);
    const frac = n % 100_000_000;

    const el = document.createElement('span');
    el.className = 'mono';
    el.textContent = `${whole.toLocaleString()}.${formatFrac(frac)}`;
    return el;
}

// Return formatted string (no DOM element).
export function formatAmount(atomic) {
    const n = Number(atomic);
    const whole = Math.floor(n / 100_000_000);
    const frac = n % 100_000_000;
    return `${whole.toLocaleString()}.${formatFrac(frac)}`;
}

// Formatted string with directional sign prefix.
// direction: "incoming" → "+", "outgoing" → "−" (U+2212), else no sign.
export function formatSignedAmount(atomic, direction) {
    const formatted = formatAmount(atomic);
    if (!atomic || atomic === 0) return formatted;
    if (direction === 'outgoing') return `\u2212${formatted}`;
    if (direction === 'incoming') return `+${formatted}`;
    return formatted;
}
