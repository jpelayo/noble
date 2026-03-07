// Atomic units → display format (6 decimals, trim trailing zeros).
// 1 NOBLE = 1,000,000 atomic units.
export function amountText(atomic) {
    const n = Number(atomic);
    const whole = Math.floor(n / 1_000_000);
    const frac = n % 1_000_000;
    const fracStr = String(frac).padStart(6, '0').replace(/0+$/, '') || '0';

    const el = document.createElement('span');
    el.className = 'mono';
    el.textContent = `${whole.toLocaleString()}.${fracStr}`;
    return el;
}

// Return formatted string (no DOM element).
export function formatAmount(atomic) {
    const n = Number(atomic);
    const whole = Math.floor(n / 1_000_000);
    const frac = n % 1_000_000;
    const fracStr = String(frac).padStart(6, '0').replace(/0+$/, '') || '0';
    return `${whole.toLocaleString()}.${fracStr}`;
}
