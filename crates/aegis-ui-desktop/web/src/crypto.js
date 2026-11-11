// crypto helpers (from the prototype core)

// ── crypto: real keys and hashes, nothing pretends ───────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const W256 = new Uint32Array(64);
function sha256(bytes) {
  const l = bytes.length, nb = ((l + 9 + 63) >> 6) << 6;
  const m = new Uint8Array(nb);
  m.set(bytes); m[l] = 0x80;
  const dv = new DataView(m.buffer), bits = l * 8;
  dv.setUint32(nb - 4, bits >>> 0); dv.setUint32(nb - 8, Math.floor(bits / 4294967296));
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const W = W256;
  for (let o = 0; o < nb; o += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = W[i - 15], b = W[i - 2];
      W[i] = (W[i - 16] + ((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ (a >>> 3)) + W[i - 7] + ((b >>> 17 | b << 15) ^ (b >>> 19 | b << 13) ^ (b >>> 10))) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + K256[i] + W[i]) | 0;
      const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
  }
  const out = new Uint8Array(32), od = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => od.setUint32(i * 4, v >>> 0));
  return out;
}
const enc = new TextEncoder();
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => crypto.getRandomValues(new Uint8Array(n));
/* fingerprint as in the app: hex of the X25519 key, groups of 4, first 8 */
function cmpBytes(a, b) { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; }
const fingerprint = x => hex(x).match(/.{4}/g).slice(0, 8);
/* safety number as in identity.rs: 6 groups of 5 digits */
function safetyNumber(a, b) {
  const [lo, hi] = cmpBytes(a, b) <= 0 ? [a, b] : [b, a];
  const d = sha256(cat(enc.encode('aegis-v2 safety'), lo, hi));
  const g = [];
  for (let i = 0; i < 6; i++) { let v = 0; for (let j = 0; j < 5; j++) v = v * 256 + d[i * 5 + j]; g.push(String(v % 100000).padStart(5, '0')); }
  return g;
}
/* identicon as in avatar.rs: 5x5 mirrored grid, greys from the hash. Drawn like render.rs,
   the cells as one path; only the cells snap to pixels, so the round ground stays smooth */
function identicon(ed) {
  const hsh = sha256(cat(enc.encode('aegis-v2 avatar'), ed));
  const bg = 0x1c + (hsh[2] % 0x18), fg = 0xa0 + (hsh[3] % 0x50);
  const g = v => '#' + v.toString(16).padStart(2, '0').repeat(3);
  let d = '';
  for (let r = 0; r < 5; r++) for (let c = 0; c < 3; c++) {
    const k = r * 3 + c;
    if ((hsh[k >> 3] >> (k % 8)) & 1) {
      d += `M${c + 1} ${r + 1}h1v1h-1z`;
      if (c !== 2) d += `M${5 - c} ${r + 1}h1v1h-1z`;
    }
  }
  return `<svg viewBox="0 0 7 7" class="kg" aria-hidden="true"><rect class="avb" width="7" height="7" rx="3.5" fill="${g(bg)}"/><path fill="${g(fg)}" shape-rendering="crispEdges" d="${d}"/></svg>`;
}
