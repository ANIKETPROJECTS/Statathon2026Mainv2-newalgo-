// Four-round format-preserving anonymization/decryption — streaming browser simulation.
// This is a custom FPE simulation, not an AES-GCM implementation:
// it uses xorshift128+ keystream bytes and reversible character-class operations.
// 4-round key chain: each cell is encrypted once per round (round1→round2→round3→round4),
// decrypted in reverse (round4→round3→round2→round1).
// Each alphanumeric character passes through 5 independent micro-operations per round,
// consuming 5 keystream bytes. Non-alphanumeric characters are passed through unchanged
// (consuming 5 keystream bytes to keep offsets aligned).

// ── §9 — xorshift128+ PRNG ────────────────────────────────────────────────────
function makeKeystream(seed: number) {
  let a = ((seed ^ 0x9e3779b9) >>> 0) || 1;
  let b = ((seed ^ 0x6c62272e) >>> 0) || 2;
  return () => {
    a ^= a << 13; a = a >>> 0;
    a ^= a >> 17;
    a ^= a << 5;  a = a >>> 0;
    b ^= b >> 7;  b = b >>> 0;
    b ^= b << 9;  b = b >>> 0;
    b ^= b >> 8;  b = b >>> 0;
    return (((a + b) >>> 0) / 0x100000000);
  };
}

// ── §8.1 — Random key from seed ───────────────────────────────────────────────
function generateRandomKey(seed: number): string {
  const rng = makeKeystream((seed ^ 0xdeadbeef) >>> 0);
  const bytes: string[] = [];
  for (let i = 0; i < 32; i++)
    bytes.push(Math.floor(rng() * 256).toString(16).padStart(2, "0"));
  return bytes.join("");
}

// ── §8.2 — PBKDF2-like passphrase key ────────────────────────────────────────
function deriveKeyFromPassphrase(passphrase: string, iterations: number): string {
  let h = 0x5a827999;
  for (let i = 0; i < passphrase.length; i++)
    h = (Math.imul(h, 31) + passphrase.charCodeAt(i)) >>> 0;
  const rng = makeKeystream(h);
  for (let i = 0; i < Math.min(iterations, 200); i++) rng();
  const bytes: string[] = [];
  for (let i = 0; i < 32; i++)
    bytes.push(Math.floor(rng() * 256).toString(16).padStart(2, "0"));
  return bytes.join("");
}

// ── §11 — Column IV hash (deterministic per key+col) ─────────────────────────
function hashColIV(keyHex: string, colName: string): number {
  let h = parseInt(keyHex.slice(0, 8), 16) ^ 0xa5a5a5a5;
  const s = "COL\x00" + colName;
  for (let i = 0; i < s.length; i++)
    h = (Math.imul(h, 1664525) + s.charCodeAt(i) + 1013904223) >>> 0;
  return h;
}

// ── §12 — Per-cell keystream bytes ────────────────────────────────────────────
function makeCellKsBytes(size: number, keyHex: string, ivSeed: number): Uint8Array {
  const combined = (parseInt(keyHex.slice(0, 8), 16) ^ ivSeed) >>> 0;
  const ksRng = makeKeystream(combined);
  const ksBytes = new Uint8Array(size);
  for (let i = 0; i < size; i++)
    ksBytes[i] = Math.floor(ksRng() * 256);
  return ksBytes;
}

// ── §10 — 5-operation format-preserving cipher ───────────────────────────────
// Each alphanumeric character is transformed by 5 sequential micro-operations,
// each driven by one keystream byte. The four operation types are:
//   0 = Add    (v + amount) mod S          — where amount = floor(k/4)%(S-1)+1
//   1 = Sub    (v - amount) mod S          — same amount derivation
//   2 = Mul    (v * coprime) mod S         — coprime chosen from COPRIME_MULS[S]
//   3 = Flip   (S − 1 − v)                — self-inverse complement

function gcd(a: number, b: number): number { return b === 0 ? a : gcd(b, a % b); }

function modInverse(a: number, m: number): number {
  let [r0, r1, s0, s1] = [a, m, 1, 0];
  while (r1 !== 0) {
    const q = Math.floor(r0 / r1);
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ((s0 % m) + m) % m;
}

// Precomputed coprime multipliers per alphabet size (all m in [2,S) with gcd(m,S)=1)
const COPRIME_MULS: Record<number, number[]> = {
  9:  [2, 4, 5, 7, 8],
  10: [3, 7, 9],
  26: [3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25],
};
function getMuls(size: number): number[] {
  if (COPRIME_MULS[size]) return COPRIME_MULS[size];
  const res: number[] = [];
  for (let m = 2; m < size; m++) if (gcd(m, size) === 1) res.push(m);
  return res;
}

// Apply one micro-op forward (returns updated position v′)
function applyOpFwd(v: number, k: number, size: number, muls: number[]): number {
  const opType = k % 4;
  if (opType === 0) return (v + Math.floor(k / 4) % (size - 1) + 1) % size;
  if (opType === 1) return ((v - (Math.floor(k / 4) % (size - 1) + 1)) % size + size) % size;
  if (opType === 2) return (v * muls[Math.floor(k / 4) % muls.length]) % size;
  return (size - 1 - v); // flip — always in [0, S-1], no modulo needed
}

// Apply the inverse of one micro-op (used during decryption)
function applyOpInv(v: number, k: number, size: number, muls: number[]): number {
  const opType = k % 4;
  if (opType === 0) return ((v - (Math.floor(k / 4) % (size - 1) + 1)) % size + size) % size;
  if (opType === 1) return (v + Math.floor(k / 4) % (size - 1) + 1) % size;
  if (opType === 2) return (v * modInverse(muls[Math.floor(k / 4) % muls.length], size)) % size;
  return (size - 1 - v); // flip is self-inverse
}

// Encrypt one cell value through one round.
// Consumes exactly 5 keystream bytes per character (alphanumeric or not).
// Alphabet selection is purely by character type — no leading-digit special case —
// so the mapping is unambiguously invertible regardless of intermediate values.
function encryptFPECell(ksBytes: Uint8Array, value: string): string {
  const chars = [...value];
  let ki = 0;
  return chars.map((ch) => {
    const code = ch.charCodeAt(0);
    let base: number, size: number;
    if      (code >= 48 && code <= 57)  { base = 48; size = 10; }
    else if (code >= 65 && code <= 90)  { base = 65; size = 26; }
    else if (code >= 97 && code <= 122) { base = 97; size = 26; }
    else { ki += 5; return ch; } // skip, but still advance 5 bytes to stay in sync
    const muls = getMuls(size);
    let v = code - base;
    for (let i = 0; i < 5; i++) v = applyOpFwd(v, ksBytes[ki++ % ksBytes.length], size, muls);
    return String.fromCharCode(v + base);
  }).join("");
}

// Decrypt one cell value through one round (exact inverse of encryptFPECell).
// Reads the same 5 keystream bytes as encryption, applies inverse ops in reverse order.
function decryptFPECell(ksBytes: Uint8Array, value: string): string {
  const chars = [...value];
  let ki = 0;
  return chars.map((ch) => {
    const code = ch.charCodeAt(0);
    let base: number, size: number;
    if      (code >= 48 && code <= 57)  { base = 48; size = 10; }
    else if (code >= 65 && code <= 90)  { base = 65; size = 26; }
    else if (code >= 97 && code <= 122) { base = 97; size = 26; }
    else { ki += 5; return ch; }
    const muls = getMuls(size);
    // Collect 5 keystream bytes in forward order (same positions as encryption)
    const ks5: number[] = [];
    for (let i = 0; i < 5; i++) ks5.push(ksBytes[ki++ % ksBytes.length]);
    // Apply inverse ops in reverse order (op4⁻¹ → op3⁻¹ → op2⁻¹ → op1⁻¹ → op0⁻¹)
    let v = code - base;
    for (let i = 4; i >= 0; i--) v = applyOpInv(v, ks5[i], size, muls);
    return String.fromCharCode(v + base);
  }).join("");
}

// ── 4-round chain helpers ─────────────────────────────────────────────────────

// Encrypt value through all 4 rounds (round1 → round2 → round3 → round4).
function encryptChain4(ksArr: Uint8Array[], value: string): string {
  let v = value;
  for (const ks of ksArr) v = encryptFPECell(ks, v);
  return v;
}

// Decrypt in reverse (round4 → round3 → round2 → round1).
function decryptChain4(ksArr: Uint8Array[], value: string): string {
  let v = value;
  for (let i = ksArr.length - 1; i >= 0; i--) v = decryptFPECell(ksArr[i], v);
  return v;
}

// ── CSV helpers ───────────────────────────────────────────────────────────────
function csvEscape(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n"))
    return '"' + val.replace(/"/g, '""') + '"';
  return val;
}

function splitCSVLine(line: string): string[] {
  const cells: string[] = [];
  let inQ = false, cur = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
      else inQ = !inQ;
    } else if (c === "," && !inQ) {
      cells.push(cur); cur = "";
    } else cur += c;
  }
  cells.push(cur);
  return cells;
}

// ── Public types ──────────────────────────────────────────────────────────────

export interface FieldSpec {
  varName: string;
  start: number;
  end: number;
}

export interface AnonymizeOptions {
  keyMode: "random" | "pbkdf2" | "hex";
  /** Four seed values — one per encryption round. The value jumps through 4 transformations. */
  seeds: number[];
  passphrase: string;
  pbkdf2Iterations: number;
  deterministic: boolean;
  keyHex?: string;
}

export interface AnonymizeResult {
  blob: Blob;
  keyHex: string;
}

// Resolve the 4-key chain from options.
// KEY SEQUENCE RULE: each round's key is derived from a rolling accumulator that
// folds in every seed seen so far — reordering any two seeds changes ALL subsequent
// round keys, making the sequence of seeds a cryptographic input.
export function resolveKeyChain(options: AnonymizeOptions): string[] {
  if (options.keyMode === "hex") {
    const base = (options.keyHex ?? "").toLowerCase().trim();
    if (!/^[0-9a-f]{64}$/.test(base)) {
      throw new Error("A raw hex key must contain exactly 64 hexadecimal characters.");
    }
    // Chain-derive 4 sub-keys: each key's seed incorporates all prior round indices
    let rolling = (parseInt(base.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
    return [0, 1, 2, 3].map(i => {
      rolling = (Math.imul(rolling, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
      rolling = (rolling ^ (rolling >>> 16)) >>> 0;
      return generateRandomKey(rolling);
    });
  }
  if (options.keyMode === "pbkdf2") {
    if (options.passphrase.trim().length === 0) {
      throw new Error("A passphrase is required when PBKDF2 mode is selected.");
    }
    // Chain-derive 4 sub-keys: each passphrase variant includes all prior round tags
    // so round order is embedded in the key material.
    let tag = "";
    return [0, 1, 2, 3].map(i => {
      tag += `\x00R${i}`;
      return deriveKeyFromPassphrase(options.passphrase + tag, options.pbkdf2Iterations);
    });
  }
  // Random (seed) mode — master-key-then-split derivation:
  //   Phase 1: Fold all 4 seeds in sequence into a single 32-bit master seed.
  //            Reordering any two seeds changes the master seed and therefore
  //            all four round keys — seed sequence is cryptographically significant.
  //   Phase 2: Expand the master seed into one 256-bit master key (32 bytes)
  //            via xorshift128+ seeded with (masterSeed ⊕ 0xDEADBEEF).
  //   Phase 3: Derive 4 round keys from the master key via XOR + rolling mixer
  //            seeded from the master key's first 32 bits (same as hex-key mode).
  const s = options.seeds;
  const ordered = [s[0] ?? 42, s[1] ?? 137, s[2] ?? 2024, s[3] ?? 7];
  // Phase 1 — fold all 4 seeds into a single 32-bit master seed
  let rolling = 0x9e3779b9;
  for (const seed of ordered) {
    rolling = (Math.imul(rolling, 0x9e3779b9) ^ (seed >>> 0)) >>> 0;
    rolling = (rolling ^ (rolling >>> 16)) >>> 0;
    rolling = (Math.imul(rolling, 0x85ebca6b)) >>> 0;
    rolling = (rolling ^ (rolling >>> 13)) >>> 0;
  }
  // Phase 2 — expand master seed into a single 256-bit master key via xorshift128+
  const masterKey = generateRandomKey(rolling);
  // Phase 3 — derive 4 round keys from master key via XOR + rolling mixer
  //   (same mechanism as hex-key mode — seeded from first 32 bits of master key)
  let rollingK = (parseInt(masterKey.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
  return [0, 1, 2, 3].map(i => {
    rollingK = (Math.imul(rollingK, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
    rollingK = (rollingK ^ (rollingK >>> 16)) >>> 0;
    return generateRandomKey(rollingK);
  });
}

// Compat: return first key (used by UI to display "the key" summary)
export function resolveKeyHex(options: AnonymizeOptions): string {
  return resolveKeyChain(options)[0];
}

const STREAM_CHUNK = 50_000;

// Keystream bytes needed per cell value: 5 bytes per character + 64-byte headroom
function ksSize(valueLen: number): number { return valueLen * 5 + 64; }

// Pre-computed keystream size for deterministic mode (supports values up to 256 chars)
const DET_KS_SIZE = 256 * 5 + 64; // = 1344

// ── Streaming encrypt: FWF raw text → anonymized CSV Blob ─────────────────────
export async function encryptFWFToBlob(
  rawText: string,
  fields: FieldSpec[],
  encCols: ReadonlySet<string>,
  options: AnonymizeOptions,
  onProgress: (pct: number) => void
): Promise<AnonymizeResult> {
  const keyChain = resolveKeyChain(options);
  // In raw-hex mode, preserve the user-supplied root key in the exported
  // metadata. keyChain[0] is a derived round key and cannot be pasted back
  // into hex mode to reconstruct the same chain.
  const keyHex = options.keyMode === "hex"
    ? (options.keyHex ?? "").toLowerCase().trim()
    : keyChain[0];

  // Pre-compute 4 per-column keystreams for deterministic mode
  const colKs4: Record<string, Uint8Array[]> = {};
  if (options.deterministic) {
    for (const f of fields) {
      if (encCols.has(f.varName)) {
        colKs4[f.varName] = keyChain.map(kh =>
          makeCellKsBytes(DET_KS_SIZE, kh, hashColIV(kh, f.varName))
        );
      }
    }
  }

  const lines = rawText.split(/\r?\n/);
  let dataLines: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > 0) dataLines.push(lines[i]);
  }
  if (dataLines.length > 0 && dataLines[0].includes(",")) {
    dataLines = dataLines.slice(1);
  }
  const total = dataLines.length;

  const header = fields.map((f) => csvEscape(f.varName)).join(",");
  const chunks: string[] = [header + "\n"];

  const detCache = new Map<string, string>();
  // Keep a separate counter per column. This makes non-deterministic
  // decryption robust when the user selects only a subset of encrypted
  // columns: each selected column can reproduce its own sequence without
  // needing counters from the other columns.
  const ivCounters: Record<string, number> = {};

  for (let i = 0; i < total; i += STREAM_CHUNK) {
    const end = Math.min(i + STREAM_CHUNK, total);
    const rowLines: string[] = [];

    for (let li = i; li < end; li++) {
      const line = dataLines[li];
      const csvCells: string[] = [];

      for (const f of fields) {
        let val = line.padEnd(f.end).substring(f.start - 1, f.end).trim();

        if (encCols.has(f.varName) && val.length > 0) {
          if (options.deterministic) {
            const ck = f.varName + "\x00" + val;
            if (detCache.has(ck)) {
              val = detCache.get(ck)!;
            } else {
              const enc = encryptChain4(colKs4[f.varName], val);
              detCache.set(ck, enc);
              val = enc;
            }
          } else {
            ivCounters[f.varName] = ((ivCounters[f.varName] ?? 0) + 1) >>> 0;
            const ivCounter = ivCounters[f.varName];
            const columnSeed = hashColIV(keyChain[0], f.varName);
            // Each round gets a unique IV derived from the counter + round index
            const ksArr = keyChain.map((kh, ri) =>
              makeCellKsBytes(ksSize(val.length), kh, (ivCounter ^ columnSeed ^ (ri * 0x12345679)) >>> 0)
            );
            val = encryptChain4(ksArr, val);
          }
        }
        csvCells.push(csvEscape(val));
      }
      rowLines.push(csvCells.join(","));
    }

    chunks.push(rowLines.join("\n") + "\n");
    onProgress(Math.min(99, Math.round((end / total) * 100)));
    await new Promise((r) => setTimeout(r, 0));
  }

  onProgress(100);
  return { blob: new Blob(chunks, { type: "text/csv;charset=utf-8;" }), keyHex };
}

// ── Streaming decrypt: CSV text → decrypted CSV Blob ─────────────────────────
export async function decryptCSVToBlob(
  csvText: string,
  decCols: ReadonlySet<string>,
  options: AnonymizeOptions,
  onProgress: (pct: number) => void
): Promise<Blob> {
  const lines = csvText.split(/\r?\n/);

  let headerIdx = 0;
  while (headerIdx < lines.length && lines[headerIdx].trim() === "") headerIdx++;
  if (headerIdx >= lines.length) throw new Error("Empty CSV file");

  const headers = splitCSVLine(lines[headerIdx]);
  if (headers.length === 0) throw new Error("No headers found in CSV");

  const keyChain = resolveKeyChain(options);

  // Pre-compute 4 per-column keystreams for deterministic mode
  const colKs4: Record<string, Uint8Array[]> = {};
  if (options.deterministic) {
    for (const col of decCols) {
      colKs4[col] = keyChain.map(kh =>
        makeCellKsBytes(DET_KS_SIZE, kh, hashColIV(kh, col))
      );
    }
  }

  const dataLines: string[] = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    if (lines[i].trim().length > 0) dataLines.push(lines[i]);
  }
  const total = dataLines.length;

  const headerLine = headers.map(csvEscape).join(",");
  const chunks: string[] = [headerLine + "\n"];

  const detCache = new Map<string, string>();
  const ivCounters: Record<string, number> = {};

  for (let i = 0; i < total; i += STREAM_CHUNK) {
    const end = Math.min(i + STREAM_CHUNK, total);
    const rowLines: string[] = [];

    for (let li = i; li < end; li++) {
      const cells = splitCSVLine(dataLines[li]);
      const outCells: string[] = [];

      for (let ci = 0; ci < headers.length; ci++) {
        const col = headers[ci];
        let val = cells[ci] ?? "";

        if (decCols.has(col) && val.length > 0) {
          if (options.deterministic) {
            const ck = col + "\x00" + val;
            if (detCache.has(ck)) {
              val = detCache.get(ck)!;
            } else {
              const dec = decryptChain4(colKs4[col], val);
              detCache.set(ck, dec);
              val = dec;
            }
          } else {
            ivCounters[col] = ((ivCounters[col] ?? 0) + 1) >>> 0;
            const ivCounter = ivCounters[col];
            const columnSeed = hashColIV(keyChain[0], col);
            const ksArr = keyChain.map((kh, ri) =>
              makeCellKsBytes(ksSize(val.length), kh, (ivCounter ^ columnSeed ^ (ri * 0x12345679)) >>> 0)
            );
            val = decryptChain4(ksArr, val);
          }
        }
        outCells.push(csvEscape(val));
      }
      rowLines.push(outCells.join(","));
    }

    chunks.push(rowLines.join("\n") + "\n");
    onProgress(Math.min(99, Math.round((end / total) * 100)));
    await new Promise((r) => setTimeout(r, 0));
  }

  onProgress(100);
  return new Blob(chunks, { type: "text/csv;charset=utf-8;" });
}

// ── CSV header reader (first line only — for column selector UI) ──────────────
export function readCSVHeaders(text: string): string[] {
  const firstLine = text.slice(0, 8192).split(/\r?\n/).find((l) => l.trim().length > 0) ?? "";
  return splitCSVLine(firstLine);
}
