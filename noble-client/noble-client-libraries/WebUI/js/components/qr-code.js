// Minimal QR code generator — renders to <canvas>.
// Supports alphanumeric/byte mode, error correction level M.

/**
 * Render a QR code into a container element.
 * @param {HTMLElement} container
 * @param {string} text
 * @param {number} size - Canvas pixel size (default 200)
 */
export function renderQR(container, text, size = 200) {
    const matrix = generateQR(text);
    const dpr = window.devicePixelRatio || 1;
    const canvas = document.createElement('canvas');
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    canvas.className = 'qr-canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'QR code for ' + text);

    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    const modules = matrix.length;
    const cellSize = size / modules;

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';

    for (let y = 0; y < modules; y++) {
        for (let x = 0; x < modules; x++) {
            if (matrix[y][x]) {
                ctx.fillRect(
                    Math.floor(x * cellSize),
                    Math.floor(y * cellSize),
                    Math.ceil(cellSize),
                    Math.ceil(cellSize)
                );
            }
        }
    }

    container.appendChild(canvas);
    return canvas;
}

// ── QR Matrix Generation (Version 1-6, ECC M, Byte mode) ──

function generateQR(text) {
    const data = new TextEncoder().encode(text);
    const version = selectVersion(data.length);
    const size = version * 4 + 17;

    // Create the grid
    const grid = Array.from({ length: size }, () => new Uint8Array(size));
    const reserved = Array.from({ length: size }, () => new Uint8Array(size));

    // Place finder patterns
    placeFinder(grid, reserved, 0, 0);
    placeFinder(grid, reserved, size - 7, 0);
    placeFinder(grid, reserved, 0, size - 7);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
        grid[6][i] = (i % 2 === 0) ? 1 : 0;
        grid[i][6] = (i % 2 === 0) ? 1 : 0;
        reserved[6][i] = 1;
        reserved[i][6] = 1;
    }

    // Alignment pattern (version >= 2)
    if (version >= 2) {
        const pos = alignmentPositions(version);
        for (const r of pos) {
            for (const c of pos) {
                if (reserved[r][c]) continue;
                placeAlignment(grid, reserved, r, c);
            }
        }
    }

    // Dark module
    grid[size - 8][8] = 1;
    reserved[size - 8][8] = 1;

    // Reserve format info areas
    reserveFormatAreas(reserved, size);

    // Encode data
    const encoded = encodeData(data, version);
    const ecBlocks = addErrorCorrection(encoded, version);

    // Place data bits
    placeData(grid, reserved, ecBlocks, size);

    // Apply mask (pattern 0: (row+col)%2==0)
    applyMask(grid, reserved, size, 0);

    // Write format info
    writeFormatInfo(grid, size, 0); // mask 0, ECC M

    return grid;
}

function selectVersion(dataLen) {
    // Byte mode capacity for ECC level M
    const caps = [0, 14, 26, 42, 62, 84, 106];
    for (let v = 1; v <= 6; v++) {
        if (dataLen <= caps[v]) return v;
    }
    return 6; // clamp
}

function placeFinder(grid, reserved, row, col) {
    const pattern = [
        [1,1,1,1,1,1,1],
        [1,0,0,0,0,0,1],
        [1,0,1,1,1,0,1],
        [1,0,1,1,1,0,1],
        [1,0,1,1,1,0,1],
        [1,0,0,0,0,0,1],
        [1,1,1,1,1,1,1],
    ];
    for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
            const gr = row + r, gc = col + c;
            if (gr < 0 || gc < 0 || gr >= grid.length || gc >= grid.length) continue;
            reserved[gr][gc] = 1;
            if (r >= 0 && r < 7 && c >= 0 && c < 7) {
                grid[gr][gc] = pattern[r][c];
            } else {
                grid[gr][gc] = 0; // separator
            }
        }
    }
}

function placeAlignment(grid, reserved, centerR, centerC) {
    for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
            const r = centerR + dr, c = centerC + dc;
            grid[r][c] = (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) ? 1 : 0;
            reserved[r][c] = 1;
        }
    }
}

function alignmentPositions(version) {
    const table = { 2: [6,18], 3: [6,22], 4: [6,26], 5: [6,30], 6: [6,34] };
    return table[version] || [];
}

function reserveFormatAreas(reserved, size) {
    for (let i = 0; i < 8; i++) {
        reserved[8][i] = 1;
        reserved[i][8] = 1;
        reserved[8][size - 1 - i] = 1;
        reserved[size - 1 - i][8] = 1;
    }
    reserved[8][8] = 1;
}

function encodeData(data, version) {
    const caps = [0, 14, 26, 42, 62, 84, 106];
    const totalBytes = caps[version];

    const bits = [];
    // Mode indicator: 0100 (byte)
    bits.push(0, 1, 0, 0);
    // Character count (8 bits for versions 1-9)
    for (let i = 7; i >= 0; i--) bits.push((data.length >> i) & 1);
    // Data
    for (const byte of data) {
        for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
    }
    // Terminator
    const capacity = totalBytes * 8;
    const termLen = Math.min(4, capacity - bits.length);
    for (let i = 0; i < termLen; i++) bits.push(0);
    // Pad to byte boundary
    while (bits.length % 8 !== 0) bits.push(0);
    // Pad bytes
    const padBytes = [0xEC, 0x11];
    let pi = 0;
    while (bits.length < capacity) {
        for (let i = 7; i >= 0; i--) bits.push((padBytes[pi] >> i) & 1);
        pi = (pi + 1) % 2;
    }

    // Convert to bytes
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | (bits[i + j] || 0);
        bytes.push(b);
    }
    return bytes;
}

function addErrorCorrection(data, version) {
    // ECC M parameters: [totalCodewords, dataCodewords, eccPerBlock, blocks]
    const eccTable = {
        1: [26, 16, 10, 1],
        2: [44, 28, 16, 1],
        3: [70, 44, 26, 1],
        4: [100, 64, 18, 2],
        5: [134, 86, 24, 2],
        6: [172, 108, 16, 4],
    };
    const [total, dataLen, eccLen, blocks] = eccTable[version];

    const blockSize = Math.floor(dataLen / blocks);
    const remainder = dataLen % blocks;

    const dataBlocks = [];
    const eccBlocks = [];
    let offset = 0;

    for (let b = 0; b < blocks; b++) {
        const size = blockSize + (b >= blocks - remainder ? 1 : 0);
        const block = data.slice(offset, offset + size);
        offset += size;
        dataBlocks.push(block);
        eccBlocks.push(reedSolomon(block, eccLen));
    }

    // Interleave
    const result = [];
    const maxDataLen = Math.max(...dataBlocks.map(b => b.length));
    for (let i = 0; i < maxDataLen; i++) {
        for (const block of dataBlocks) {
            if (i < block.length) result.push(block[i]);
        }
    }
    for (let i = 0; i < eccLen; i++) {
        for (const block of eccBlocks) {
            if (i < block.length) result.push(block[i]);
        }
    }

    return result;
}

function reedSolomon(data, eccLen) {
    const gen = generatorPoly(eccLen);
    const msg = [...data, ...new Array(eccLen).fill(0)];

    for (let i = 0; i < data.length; i++) {
        const coef = msg[i];
        if (coef === 0) continue;
        for (let j = 0; j < gen.length; j++) {
            msg[i + j] ^= gfMul(gen[j], coef);
        }
    }
    return msg.slice(data.length);
}

// GF(256) with polynomial 0x11D
const _gfExp = new Uint8Array(512);
const _gfLog = new Uint8Array(256);
(function initGF() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        _gfExp[i] = x;
        _gfLog[x] = i;
        x <<= 1;
        if (x >= 256) x ^= 0x11D;
    }
    for (let i = 255; i < 512; i++) _gfExp[i] = _gfExp[i - 255];
})();

function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return _gfExp[_gfLog[a] + _gfLog[b]];
}

function generatorPoly(degree) {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
        const factor = [1, _gfExp[i]];
        const result = new Array(poly.length + 1).fill(0);
        for (let j = 0; j < poly.length; j++) {
            for (let k = 0; k < factor.length; k++) {
                result[j + k] ^= gfMul(poly[j], factor[k]);
            }
        }
        poly = result;
    }
    return poly;
}

function placeData(grid, reserved, data, size) {
    let bitIdx = 0;
    const totalBits = data.length * 8;

    // Traverse from bottom-right, two columns at a time, going up then down
    let upward = true;
    for (let col = size - 1; col >= 1; col -= 2) {
        if (col === 6) col = 5; // skip timing column

        const rows = upward
            ? Array.from({ length: size }, (_, i) => size - 1 - i)
            : Array.from({ length: size }, (_, i) => i);

        for (const row of rows) {
            for (const c of [col, col - 1]) {
                if (c < 0 || reserved[row][c]) continue;
                if (bitIdx < totalBits) {
                    const byteIdx = Math.floor(bitIdx / 8);
                    const bitPos = 7 - (bitIdx % 8);
                    grid[row][c] = (data[byteIdx] >> bitPos) & 1;
                    bitIdx++;
                }
            }
        }
        upward = !upward;
    }
}

function applyMask(grid, reserved, size, maskNum) {
    for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
            if (reserved[r][c]) continue;
            let mask = false;
            switch (maskNum) {
                case 0: mask = (r + c) % 2 === 0; break;
                case 1: mask = r % 2 === 0; break;
                case 2: mask = c % 3 === 0; break;
                case 3: mask = (r + c) % 3 === 0; break;
            }
            if (mask) grid[r][c] ^= 1;
        }
    }
}

function writeFormatInfo(grid, size, maskNum) {
    // Format info for ECC M (00) + mask pattern
    // Pre-computed BCH(15,5) with mask 101010000010010
    const formatBits = [
        0x5412, 0x5125, 0x5E7C, 0x5B4B,
    ];
    const info = formatBits[maskNum] || formatBits[0];

    // Horizontal (row 8)
    const hPositions = [0,1,2,3,4,5,7,8, size-8,size-7,size-6,size-5,size-4,size-3,size-2,size-1];
    for (let i = 0; i < 15; i++) {
        grid[8][hPositions[i]] = (info >> (14 - i)) & 1;
    }

    // Vertical (col 8)
    const vPositions = [size-1,size-2,size-3,size-4,size-5,size-6,size-7, 8,7,5,4,3,2,1,0];
    for (let i = 0; i < 15; i++) {
        grid[vPositions[i]][8] = (info >> (14 - i)) & 1;
    }
}
