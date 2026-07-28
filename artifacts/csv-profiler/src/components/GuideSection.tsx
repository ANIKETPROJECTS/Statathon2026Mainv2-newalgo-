import { useState, useMemo } from "react";
import { ChevronLeft, ChevronRight, ArrowRight, ArrowDown, RotateCcw, Download } from "lucide-react";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Algorithm (matches anonymize.ts exactly — used to produce live values)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

function generateRandomKey(seed: number): string {
  const rng = makeKeystream((seed ^ 0xdeadbeef) >>> 0);
  return Array.from({ length: 32 }, () => Math.floor(rng() * 256).toString(16).padStart(2, "0")).join("");
}

function hashColIV(keyHex: string, colName: string): number {
  let h = parseInt(keyHex.slice(0, 8), 16) ^ 0xa5a5a5a5;
  const s = "COL\x00" + colName;
  for (let i = 0; i < s.length; i++)
    h = (Math.imul(h, 1664525) + s.charCodeAt(i) + 1013904223) >>> 0;
  return h;
}

function makeCellKsBytes(size: number, keyHex: string, ivSeed: number): Uint8Array {
  const combined = (parseInt(keyHex.slice(0, 8), 16) ^ ivSeed) >>> 0;
  const ksRng = makeKeystream(combined);
  return Uint8Array.from({ length: size }, () => Math.floor(ksRng() * 256));
}

// ── Multi-operation helpers ───────────────────────────────────────────────────

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

// Ordered alphabet of all printable non-alphanumeric ASCII characters (S=33).
// Covers: space, !"#$%&'()*+,-./ (33–47), :;<=>?@ (58–64), [\]^_` (91–96), {|}~ (123–126).
const SYMBOL_CHARS = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

// Precomputed coprime multipliers per alphabet size (excluding 1)
const COPRIME_MULS: Record<number, number[]> = {
  9:  [2, 4, 5, 7, 8],
  10: [3, 7, 9],
  26: [3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25],
  33: [2, 4, 5, 7, 8, 10, 13, 14, 16, 17, 19, 20, 23, 25, 26, 28, 29, 31, 32], // 33=3×11
};
function getMuls(size: number): number[] {
  if (COPRIME_MULS[size]) return COPRIME_MULS[size];
  const res: number[] = [];
  for (let m = 2; m < size; m++) if (gcd(m, size) === 1) res.push(m);
  return res;
}

// opType: 0=add, 1=subtract, 2=multiply(coprime), 3=flip(complement)
interface MicroOp {
  opType: 0 | 1 | 2 | 3;
  k: number;          // keystream byte that drives this sub-op
  amount: number;     // add/sub: shift amount; mul: multiplier; flip: unused (0)
  vBefore: number;    // alphabet offset (0-indexed) before this op
  vAfter: number;     // alphabet offset (0-indexed) after this op
  size: number;       // alphabet size (9 for first-digit, 10 for other digits, 26 for letters)
  isFirstDigit?: boolean; // true when this op was applied with the S=9 leading-zero-prevention alphabet
}

// Apply one MicroOp forward
function applyOp(v: number, k: number, size: number, muls: number[]): MicroOp {
  const opType = (k % 4) as 0|1|2|3;
  const vBefore = v;
  let amount: number, vAfter: number;
  if (opType === 0) {
    amount = Math.floor(k / 4) % (size - 1) + 1;
    vAfter = (v + amount) % size;
  } else if (opType === 1) {
    amount = Math.floor(k / 4) % (size - 1) + 1;
    vAfter = ((v - amount) % size + size) % size;
  } else if (opType === 2) {
    const mulIdx = Math.floor(k / 4) % muls.length;
    amount = muls[mulIdx];
    vAfter = (v * amount) % size;
  } else {
    amount = 0;
    vAfter = (size - 1 - v + size) % size;
  }
  return { opType, k, amount, vBefore, vAfter, size };
}

// 5 micro-operations per character — encrypt
// charIdx: position of this character within the cell value (0 = first char).
// When charIdx===0 and the character is a non-zero digit, the S=9 (1–9) alphabet
// is used instead of S=10 so the encrypted first character is never '0'.
// When charIdx===0 and the character is '0', it passes through unchanged (edge case).
function fpeEncryptChar5(ch: string, ks5: number[], charIdx: number): { out: string; microOps: MicroOp[]; isLeadingZeroPassthrough?: boolean } {
  const code = ch.charCodeAt(0);

  // ── Leading-zero-prevention at position 0 ────────────────────────
  if (charIdx === 0 && code >= 48 && code <= 57) {
    if (code === 48) return { out: ch, microOps: [], isLeadingZeroPassthrough: true }; // '0' passthrough
    // '1'..'9' → S=9, base=49
    const size = 9, base = 49;
    const muls = getMuls(size);
    let v = code - base;
    const microOps: MicroOp[] = [];
    for (let i = 0; i < 5; i++) {
      const op = applyOp(v, ks5[i], size, muls);
      microOps.push({ ...op, isFirstDigit: true });
      v = op.vAfter;
    }
    return { out: String.fromCharCode(v + base), microOps };
  }

  let base: number, size: number;
  if      (code >= 48 && code <= 57)  { base = 48; size = 10; }
  else if (code >= 65 && code <= 90)  { base = 65; size = 26; }
  else if (code >= 97 && code <= 122) { base = 97; size = 26; }
  else {
    // Printable symbol → encrypt within SYMBOL_CHARS alphabet (S=33)
    const symIdx = SYMBOL_CHARS.indexOf(ch);
    if (symIdx !== -1) {
      const symSize = SYMBOL_CHARS.length;
      const symMuls = getMuls(symSize);
      let v = symIdx;
      const microOps: MicroOp[] = [];
      for (let i = 0; i < 5; i++) {
        const op = applyOp(v, ks5[i], symSize, symMuls);
        microOps.push(op);
        v = op.vAfter;
      }
      return { out: SYMBOL_CHARS[v], microOps };
    }
    return { out: ch, microOps: [] }; // non-printable / out-of-range
  }
  const muls = getMuls(size);
  let v = code - base;
  const microOps: MicroOp[] = [];
  for (let i = 0; i < 5; i++) {
    const op = applyOp(v, ks5[i], size, muls);
    microOps.push(op);
    v = op.vAfter;
  }
  return { out: String.fromCharCode(v + base), microOps };
}

// 5 micro-operations per character — decrypt (reverses forward ops in reverse order)
function fpeDecryptChar5(ch: string, ks5: number[], charIdx: number): { out: string; microOps: MicroOp[]; isLeadingZeroPassthrough?: boolean } {
  const code = ch.charCodeAt(0);

  // ── Leading-zero-prevention at position 0 (mirror of encrypt) ────
  if (charIdx === 0 && code >= 48 && code <= 57) {
    if (code === 48) return { out: ch, microOps: [], isLeadingZeroPassthrough: true }; // '0' passthrough
    // '1'..'9' → S=9 inverse
    const size = 9, base = 49;
    const muls = getMuls(size);
    const fwdParams = ks5.map(k => {
      const opType = (k % 4) as 0|1|2|3;
      let amount: number;
      if (opType === 0 || opType === 1) amount = Math.floor(k / 4) % (size - 1) + 1;
      else if (opType === 2) amount = muls[Math.floor(k / 4) % muls.length];
      else amount = 0;
      return { opType, amount };
    });
    let v = code - base;
    const microOps: MicroOp[] = [];
    for (let i = 4; i >= 0; i--) {
      const { opType, amount } = fwdParams[i];
      const vBefore = v;
      let vAfter: number;
      if (opType === 0) vAfter = ((v - amount) % size + size) % size;
      else if (opType === 1) vAfter = (v + amount) % size;
      else if (opType === 2) vAfter = (v * modInverse(amount, size)) % size;
      else vAfter = (size - 1 - v + size) % size;
      microOps.push({ opType, k: ks5[i], amount, vBefore, vAfter, size, isFirstDigit: true });
      v = vAfter;
    }
    return { out: String.fromCharCode(v + base), microOps };
  }

  let base: number, size: number;
  if      (code >= 48 && code <= 57)  { base = 48; size = 10; }
  else if (code >= 65 && code <= 90)  { base = 65; size = 26; }
  else if (code >= 97 && code <= 122) { base = 97; size = 26; }
  else {
    // Printable symbol → decrypt within SYMBOL_CHARS alphabet (S=33)
    const symIdx = SYMBOL_CHARS.indexOf(ch);
    if (symIdx !== -1) {
      const symSize = SYMBOL_CHARS.length;
      const symMuls = getMuls(symSize);
      const fwdParams = ks5.map(k => {
        const opType = (k % 4) as 0|1|2|3;
        let amount: number;
        if (opType === 0 || opType === 1) amount = Math.floor(k / 4) % (symSize - 1) + 1;
        else if (opType === 2) amount = symMuls[Math.floor(k / 4) % symMuls.length];
        else amount = 0;
        return { opType, amount };
      });
      let v = symIdx;
      const microOps: MicroOp[] = [];
      for (let i = 4; i >= 0; i--) {
        const { opType, amount } = fwdParams[i];
        const vBefore = v;
        let vAfter: number;
        if (opType === 0) vAfter = ((v - amount) % symSize + symSize) % symSize;
        else if (opType === 1) vAfter = (v + amount) % symSize;
        else if (opType === 2) vAfter = (v * modInverse(amount, symSize)) % symSize;
        else vAfter = (symSize - 1 - v + symSize) % symSize;
        microOps.push({ opType, k: ks5[i], amount, vBefore, vAfter, size: symSize });
        v = vAfter;
      }
      return { out: SYMBOL_CHARS[v], microOps };
    }
    return { out: ch, microOps: [] }; // non-printable / out-of-range
  }
  const muls = getMuls(size);
  // Reconstruct forward op parameters (amount & type) from ks5 — independent of v
  const fwdParams = ks5.map(k => {
    const opType = (k % 4) as 0|1|2|3;
    let amount: number;
    if (opType === 0 || opType === 1) amount = Math.floor(k / 4) % (size - 1) + 1;
    else if (opType === 2) amount = muls[Math.floor(k / 4) % muls.length];
    else amount = 0;
    return { opType, amount };
  });
  let v = code - base;
  const microOps: MicroOp[] = [];
  for (let i = 4; i >= 0; i--) {
    const { opType, amount } = fwdParams[i];
    const vBefore = v;
    let vAfter: number;
    if (opType === 0) vAfter = ((v - amount) % size + size) % size;
    else if (opType === 1) vAfter = (v + amount) % size;
    else if (opType === 2) vAfter = (v * modInverse(amount, size)) % size;
    else vAfter = (size - 1 - v + size) % size;
    microOps.push({ opType, k: ks5[i], amount, vBefore, vAfter, size });
    v = vAfter;
  }
  return { out: String.fromCharCode(v + base), microOps };
}

// Updated runRound: consumes 5 keystream bytes per character
function runRound(value: string, ks: Uint8Array, mode: "enc" | "dec"): { output: string; charShifts: CharShift[] } {
  const chars = [...value];
  let ki = 0;
  const charShifts: CharShift[] = [];
  let output = "";
  for (let idx = 0; idx < chars.length; idx++) {
    const ch = chars[idx];
    const ks5 = Array.from({ length: 5 }, () => ks[ki++ % ks.length]);
    if (mode === "enc") {
      const { out, microOps, isLeadingZeroPassthrough } = fpeEncryptChar5(ch, ks5, idx);
      charShifts.push({ from: ch, to: out, k: ks5[0], changed: ch !== out, microOps, isLeadingZeroPassthrough });
      output += out;
    } else {
      const { out, microOps, isLeadingZeroPassthrough } = fpeDecryptChar5(ch, ks5, idx);
      charShifts.push({ from: ch, to: out, k: ks5[0], changed: ch !== out, microOps, isLeadingZeroPassthrough });
      output += out;
    }
  }
  return { output, charShifts };
}

interface CharShift { from: string; to: string; k: number; changed: boolean; microOps: MicroOp[]; isLeadingZeroPassthrough?: boolean; }

interface KeyDerivStep {
  seedIdx: number;
  seed: number;
  rollingBefore: number;
  afterMulXor: number;
  afterMix1: number;
  afterMul2: number;
  afterMix2: number;
  rollingAfter: number;
}

interface Trace {
  keys: string[];
  colIVs: number[];
  encStages: string[];
  encShifts: CharShift[][];
  decStages: string[];
  decShifts: CharShift[][];
  finalEncrypted: string;
  finalDecrypted: string;
  keyDerivSteps: KeyDerivStep[];
  masterSeed: number;
  masterKey: string;
  ksFirstBytes: number[][];
}

function computeTrace(seeds: number[], colName: string, rawValue: string): Trace {
  const value = rawValue || "A";

  // Phase 1: fold all 4 seeds into a single master seed
  let rolling = 0x9e3779b9;
  const keyDerivSteps: KeyDerivStep[] = [];
  for (let i = 0; i < 4; i++) {
    const seed = seeds[i] ?? 0;
    const rollingBefore = rolling;
    const afterMulXor = (Math.imul(rolling, 0x9e3779b9) ^ (seed >>> 0)) >>> 0;
    const afterMix1 = (afterMulXor ^ (afterMulXor >>> 16)) >>> 0;
    const afterMul2 = Math.imul(afterMix1, 0x85ebca6b) >>> 0;
    const afterMix2 = (afterMul2 ^ (afterMul2 >>> 13)) >>> 0;
    rolling = afterMix2;
    keyDerivSteps.push({ seedIdx: i, seed, rollingBefore, afterMulXor, afterMix1, afterMul2, afterMix2, rollingAfter: rolling });
  }
  const masterSeed = rolling;

  // Phase 2: expand master seed into a single 256-bit master key via xorshift128+
  const masterKey = generateRandomKey(masterSeed);

  // Phase 3: derive 4 round keys from master key via XOR + rolling mixer
  let rollingK = (parseInt(masterKey.slice(0, 8), 16) ^ 0xdeadbeef) >>> 0;
  const keys = [0, 1, 2, 3].map(i => {
    rollingK = (Math.imul(rollingK, 0x9e3779b9) ^ (i * 0x5a5a5a5b)) >>> 0;
    rollingK = (rollingK ^ (rollingK >>> 16)) >>> 0;
    return generateRandomKey(rollingK);
  });

  const colIVs = keys.map(k => hashColIV(k, colName));
  // 5 keystream bytes consumed per character, so request 5× the length
  const ksArr = keys.map((k, i) => makeCellKsBytes(value.length * 5 + 64, k, colIVs[i]));

  const encStages: string[] = [value];
  const encShifts: CharShift[][] = [];
  let cur = value;
  for (let i = 0; i < 4; i++) {
    const { output, charShifts } = runRound(cur, ksArr[i], "enc");
    encStages.push(output);
    encShifts.push(charShifts);
    cur = output;
  }

  const finalEncrypted = cur;

  const decStages: string[] = [finalEncrypted];
  const decShifts: CharShift[][] = [];
  let dec = finalEncrypted;
  for (let i = 3; i >= 0; i--) {
    const { output, charShifts } = runRound(dec, ksArr[i], "dec");
    decStages.push(output);
    decShifts.push(charShifts);
    dec = output;
  }

  const ksFirstBytes = ksArr.map(ks => Array.from(ks.slice(0, 10)));
  return { keys, colIVs, encStages, encShifts, decStages, decShifts, finalEncrypted, finalDecrypted: dec, keyDerivSteps, masterSeed, masterKey, ksFirstBytes };
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PDF export — opens a styled print window
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function hex8(n: number) { return "0x" + n.toString(16).toUpperCase().padStart(8, "0"); }

function charTypeName(ch: string): string {
  const c = ch.charCodeAt(0);
  if (c >= 48 && c <= 57) return "Digit";
  if (c >= 65 && c <= 90) return "Uppercase";
  if (c >= 97 && c <= 122) return "Lowercase";
  return "Symbol";
}

function exportTracePDF(trace: Trace, seeds: number[], colName: string, cellValue: string) {
  const now = new Date().toLocaleString("en-IN", { dateStyle: "long", timeStyle: "short" });
  const value = cellValue || "A";

  function charTable(shifts: CharShift[], stageLabel: string, outputLabel: string, phase: "enc" | "dec"): string {
    const rows = shifts.map((s, i) => {
      const netShift = s.microOps.length > 0
        ? (() => {
            const vB = s.microOps[0].vBefore;
            const vA = s.microOps[s.microOps.length - 1].vAfter;
            const S  = s.microOps[0].size;
            return ((vA - vB) % S + S) % S;
          })()
        : null;
      const spinAmt = netShift !== null ? `+${netShift} (net, 5 micro-ops)` : "—";
      const bg = i % 2 === 0 ? "#fff" : "#f8f9fa";
      const resultColor = phase === "enc" ? "#16a34a" : "#2563eb";
      return `<tr style="background:${bg}">
        <td>${i + 1}</td>
        <td style="font-family:monospace;font-weight:bold;color:#2563eb">'${s.from}' (${s.from.charCodeAt(0)})</td>
        <td>${charTypeName(s.from)}</td>
        <td style="font-family:monospace;font-weight:bold;color:#b45309">${s.k}</td>
        <td style="font-family:monospace;color:#7c3aed">${spinAmt}</td>
        <td style="font-family:monospace;font-weight:bold;color:${resultColor}">'${s.to}' (${s.to.charCodeAt(0)})</td>
        <td>${s.changed ? (phase === "enc" ? "shifted" : "un-shifted") : "unchanged"}</td>
      </tr>`;
    }).join("");
    return `
      <div class="section-label">${stageLabel}</div>
      <div class="value-row">
        <span class="tag blue">${phase === "enc" ? "Input" : "Encrypted input"}</span>
        <code>${shifts.map(s => s.from).join("")}</code>
        <span style="margin:0 8px;color:#94a3b8">→</span>
        <span class="tag ${phase === "enc" ? "green" : "blue-dark"}">${outputLabel}</span>
        <code>${shifts.map(s => s.to).join("")}</code>
      </div>
      <table>
        <thead><tr>
          <th>#</th><th>Input char</th><th>Type</th><th>Key byte (k)</th>
          <th>Net shift (5 micro-ops)</th><th>Output char</th><th>Action</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  const keyDerivRows = trace.keyDerivSteps.map((s, i) => {
    const bg = i % 2 === 0 ? "#fff" : "#f8f9fa";
    const isMaster = i === 3;
    return `<tr style="background:${isMaster ? "#eef2ff" : bg};${isMaster ? "font-weight:bold;" : ""}">
      <td>${i + 1}</td>
      <td style="font-family:monospace;font-weight:bold">${s.seed}</td>
      <td style="font-family:monospace">${hex8(s.rollingBefore)}</td>
      <td style="font-family:monospace">${hex8(s.afterMulXor)}</td>
      <td style="font-family:monospace">${hex8(s.afterMix1)}</td>
      <td style="font-family:monospace">${hex8(s.afterMul2)}</td>
      <td style="font-family:monospace;color:${isMaster ? "#4338ca" : "inherit"};font-weight:${isMaster ? "bold" : "normal"}">${hex8(s.afterMix2)}${isMaster ? " ← Master Seed" : ""}</td>
    </tr>`;
  }).join("");

  const encRoundSections = trace.encShifts.map((shifts, i) => `
    <div class="phase-card">
      <div class="round-header green">Round ${i + 1} of 4 — Key ${i + 1}</div>
      <div class="key-display"><strong>Key:</strong> <code>${trace.keys[i]}</code></div>
      <div class="key-display"><strong>Column IV:</strong> <code>${hex8(trace.colIVs[i])}</code></div>
      ${charTable(shifts, `Encrypting with Key ${i + 1}`, `After round ${i + 1}`, "enc")}
    </div>`).join("");

  const decRoundSections = trace.decShifts.map((shifts, i) => `
    <div class="phase-card">
      <div class="round-header violet">Undo Round ${4 - i} of 4 — Key ${4 - i}</div>
      <div class="key-display"><strong>Key:</strong> <code>${trace.keys[3 - i]}</code></div>
      <div class="key-display"><strong>Column IV:</strong> <code>${hex8(trace.colIVs[3 - i])}</code></div>
      ${charTable(shifts, `Decrypting with Key ${4 - i}`, i === 3 ? "Original recovered ✓" : `After undo ${i + 1}`, "dec")}
    </div>`).join("");

  const journeyRows = trace.encStages.map((s, i) => `
    <tr style="background:${i % 2 === 0 ? "#fff" : "#f8f9fa"}">
      <td>${i === 0 ? "Original" : `After encryption round ${i}`}</td>
      <td style="font-family:monospace;font-weight:bold;color:${i === 0 ? "#2563eb" : i === 4 ? "#16a34a" : "#374151"}">${s}</td>
      <td>${i === 0 ? "Starting value" : `Key ${i} applied (forward)`}</td>
    </tr>`).join("") + trace.decStages.slice(1).map((s, i) => `
    <tr style="background:${(i + 1) % 2 === 0 ? "#fff" : "#f8f9fa"}">
      <td>${i === trace.decStages.length - 2 ? "Fully decrypted" : `After undo round ${i + 1}`}</td>
      <td style="font-family:monospace;font-weight:bold;color:${i === trace.decStages.length - 2 ? "#2563eb" : "#374151"}">${s}</td>
      <td>${`Key ${4 - i} reversed`}</td>
    </tr>`).join("");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>AIRAVATA DEA — Anonymization Trace Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: "Segoe UI", system-ui, sans-serif; font-size: 11px; color: #1e293b; background: #fff; }
    @page { size: A4; margin: 18mm 16mm; }
    @media print { body { font-size: 10px; } .no-print { display: none !important; } }

    /* Header */
    .report-header { border-bottom: 3px solid #4f46e5; padding-bottom: 14px; margin-bottom: 20px; display: flex; align-items: flex-start; justify-content: space-between; }
    .report-title { font-size: 22px; font-weight: 800; color: #3730a3; letter-spacing: -0.5px; }
    .report-subtitle { font-size: 12px; color: #6366f1; margin-top: 2px; }
    .report-meta { text-align: right; font-size: 10px; color: #64748b; line-height: 1.6; }

    /* Params box */
    .params-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 22px; }
    .param-box { background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 14px; }
    .param-label { font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-bottom: 4px; }
    .param-value { font-family: monospace; font-size: 13px; font-weight: 700; color: #1e293b; }
    .seeds-row { display: flex; gap: 6px; }
    .seed-chip { background: #e0e7ff; border: 1px solid #a5b4fc; border-radius: 6px; padding: 3px 8px; font-family: monospace; font-weight: 700; color: #3730a3; }

    /* Phase headings */
    .phase-heading { font-size: 15px; font-weight: 800; color: #1e293b; margin: 24px 0 10px; padding: 8px 14px; background: #f8fafc; border-left: 4px solid #4f46e5; border-radius: 0 6px 6px 0; }
    .phase-sub { font-size: 10px; color: #64748b; font-weight: 400; margin-left: 8px; }
    .phase-card { margin-bottom: 18px; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px; break-inside: avoid; }
    .round-header { font-weight: 700; font-size: 12px; margin-bottom: 8px; padding: 4px 10px; border-radius: 5px; display: inline-block; }
    .round-header.green { background: #dcfce7; color: #15803d; }
    .round-header.violet { background: #ede9fe; color: #6d28d9; }
    .key-display { font-size: 9.5px; color: #475569; margin-bottom: 5px; line-height: 1.5; }
    .key-display code { font-family: monospace; font-size: 9px; color: #1e293b; background: #f1f5f9; padding: 1px 4px; border-radius: 3px; word-break: break-all; }
    .section-label { font-weight: 600; font-size: 10px; color: #475569; margin: 10px 0 5px; }

    /* Value display row */
    .value-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; padding: 8px 12px; background: #f8fafc; border-radius: 7px; flex-wrap: wrap; }
    .value-row code { font-family: monospace; font-size: 14px; font-weight: 700; color: #1e293b; }
    .tag { font-size: 9px; font-weight: 700; padding: 2px 7px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.3px; }
    .tag.blue { background: #dbeafe; color: #1d4ed8; }
    .tag.green { background: #dcfce7; color: #15803d; }
    .tag.blue-dark { background: #1e40af; color: #fff; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 10px; }
    th { background: #1e293b; color: #f8fafc; font-size: 9.5px; font-weight: 600; text-align: left; padding: 5px 7px; }
    td { padding: 4px 7px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }

    /* Journey table */
    .journey-section { margin-top: 20px; break-inside: avoid; }
    .summary-box { background: #f0fdf4; border: 1.5px solid #86efac; border-radius: 10px; padding: 14px 18px; margin-top: 20px; }
    .summary-label { font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; color: #15803d; margin-bottom: 4px; }
    .summary-val { font-family: monospace; font-size: 16px; font-weight: 800; color: #14532d; }
    .match-badge { display: inline-block; padding: 3px 12px; border-radius: 20px; font-weight: 700; font-size: 10px; margin-top: 8px; }
    .match-ok { background: #16a34a; color: #fff; }
    .match-fail { background: #dc2626; color: #fff; }

    /* Footer */
    .report-footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid #e2e8f0; font-size: 9px; color: #94a3b8; display: flex; justify-content: space-between; }

    /* Print button */
    .print-btn { no-print; position: fixed; top: 20px; right: 20px; background: #4f46e5; color: #fff; border: none; border-radius: 8px; padding: 10px 20px; font-size: 13px; font-weight: 700; cursor: pointer; z-index: 999; box-shadow: 0 4px 12px rgba(79,70,229,0.4); }
    .print-btn:hover { background: #4338ca; }
  </style>
</head>
<body>
  <button class="print-btn no-print" onclick="window.print()">🖨️ Save as PDF</button>

  <div class="report-header">
    <div>
      <div class="report-title">AIRAVATA DEA</div>
      <div class="report-subtitle">Anonymization Step-by-Step Trace Report</div>
    </div>
    <div class="report-meta">
      Generated: ${now}<br/>
      Algorithm: 4-Round FPE Chain (xorshift128+)<br/>
      Key size: 256 bits per round
    </div>
  </div>

  <!-- Parameters -->
  <div class="params-grid">
    <div class="param-box">
      <div class="param-label">Seeds (in order)</div>
      <div class="seeds-row">${seeds.map(s => `<span class="seed-chip">${s}</span>`).join("")}</div>
    </div>
    <div class="param-box">
      <div class="param-label">Column name</div>
      <div class="param-value">${colName || "(none)"}</div>
    </div>
    <div class="param-box">
      <div class="param-label">Cell value</div>
      <div class="param-value">${value}</div>
    </div>
  </div>

  <!-- Phase 1: Master Key Generation -->
  <div class="phase-heading">Phase 1 — Master Key Generation <span class="phase-sub">4 seeds → master seed → 256-bit master key → 4 × 256-bit round keys</span></div>
  <p style="font-size:10px;color:#475569;margin-bottom:10px;line-height:1.6">
    <strong>Step 1 (Fold):</strong> Starting from the golden-ratio constant <code style="font-family:monospace;background:#f1f5f9;padding:1px 4px;border-radius:3px">0x9E3779B9</code>,
    all 4 seeds are blended into a single 32-bit <strong>master seed</strong> using a Horner-style multiply-XOR fold + MurmurHash3 avalanche — the highlighted row below is the final master seed.<br/>
    <strong>Step 2 (Expand):</strong> The master seed is fed into xorshift128+ (seeded with masterSeed ⊕ 0xDEADBEEF) to generate 32 bytes → one <strong>256-bit master key</strong>.<br/>
    <strong>Step 3 (Derive):</strong> 4 round keys are derived from the master key via XOR + rolling mixer: r ← (masterKey[0..7] ⊕ 0xDEADBEEF); for each round i: r ← mix(r, i); K{i+1} = xorshift128+(r).
  </p>
  <p style="font-size:10px;color:#4338ca;font-weight:600;margin-bottom:8px">Master Seed: ${hex8(trace.masterSeed)}</p>
  <p style="font-size:10px;color:#475569;margin-bottom:4px">Master Key (256 bits = 64 hex chars):</p>
  <p style="font-family:monospace;font-size:8px;word-break:break-all;color:#1e293b;background:#f1f5f9;padding:6px 8px;border-radius:4px;margin-bottom:10px">${trace.masterKey}</p>
  <table>
    <thead><tr>
      <th>Fold #</th><th>Seed</th><th>Rolling before</th><th>After mul⊕seed</th>
      <th>After mix #1</th><th>After mul #2</th><th>After mix #2 (rolling after)</th>
    </tr></thead>
    <tbody>${keyDerivRows}</tbody>
  </table>
  <p style="font-size:10px;color:#475569;margin:10px 0 6px"><strong>Round keys (derived via rolling mixer from master key):</strong></p>
  <table>
    <thead><tr><th>Key</th><th>Derivation</th><th>Value (256 bits = 64 hex chars)</th></tr></thead>
    <tbody>${[0,1,2,3].map((i) => `<tr style="background:${i%2===0?"#fff":"#f8f9fa"}"><td>K${i+1}</td><td style="font-size:9px;color:#475569">r ← mix(r, ${i}); xorshift128+(r)</td><td style="font-family:monospace;font-size:8px;word-break:break-all">${trace.keys[i]}</td></tr>`).join("")}</tbody>
  </table>

  <!-- Phase 2: Encryption -->
  <div class="phase-heading" style="page-break-before:always">Phase 2 — Encryption <span class="phase-sub">4 rounds of Format-Preserving Encryption applied in order</span></div>
  <p style="font-size:10px;color:#475569;margin-bottom:10px;line-height:1.6">
    Each round derives a keystream from the round key and the column IV. Each alphanumeric character is shifted forward
    within its alphabet (first digit: 1–9, other digits: 0–9, uppercase A–Z, lowercase a–z, symbols: S=33) by <em>1 + (keyByte mod alphabetSize)</em>.
    Non-printable characters are left unchanged. The 4 rounds are applied in sequence (R1 → R2 → R3 → R4).
  </p>
  ${encRoundSections}

  <!-- Phase 3: Decryption -->
  <div class="phase-heading" style="page-break-before:always">Phase 3 — Decryption <span class="phase-sub">4 rounds reversed in reverse order (R4 → R3 → R2 → R1)</span></div>
  <p style="font-size:10px;color:#475569;margin-bottom:10px;line-height:1.6">
    Decryption uses the <em>identical</em> keystream bytes as the corresponding encryption round (same key + same IV = same bytes).
    Instead of shifting forward, each character is shifted <em>backward</em> by the same amount.
    Rounds are applied in reverse order: R4 first, then R3, R2, R1.
  </p>
  ${decRoundSections}

  <!-- Full journey table -->
  <div class="journey-section">
    <div class="phase-heading">Full Journey — Value at every stage</div>
    <table>
      <thead><tr><th>Stage</th><th>Value</th><th>Note</th></tr></thead>
      <tbody>${journeyRows}</tbody>
    </table>
  </div>

  <!-- Summary -->
  <div class="summary-box">
    <div style="display:flex;gap:40px;align-items:flex-start">
      <div>
        <div class="summary-label">Original value</div>
        <div class="summary-val">${value}</div>
      </div>
      <div style="font-size:20px;margin-top:12px;color:#94a3b8">→</div>
      <div>
        <div class="summary-label">Anonymized value</div>
        <div class="summary-val" style="color:#15803d">${trace.finalEncrypted}</div>
      </div>
      <div style="font-size:20px;margin-top:12px;color:#94a3b8">→</div>
      <div>
        <div class="summary-label">Decrypted value</div>
        <div class="summary-val" style="color:#1d4ed8">${trace.finalDecrypted}</div>
      </div>
    </div>
    <div class="match-badge ${trace.finalDecrypted === value ? "match-ok" : "match-fail"}">
      ${trace.finalDecrypted === value ? "✓ Perfect round-trip — decrypted value matches original exactly" : "⚠ Mismatch detected"}
    </div>
  </div>

  <div class="report-footer">
    <div>AIRAVATA DEA — Anonymization Trace Report</div>
    <div>${now}</div>
  </div>

  <script>
    window.addEventListener("load", () => { setTimeout(() => window.print(), 400); });
  </script>
</body>
</html>`;

  const win = window.open("", "_blank", "width=900,height=700");
  if (!win) { alert("Please allow pop-ups for this page to download the PDF."); return; }
  win.document.write(html);
  win.document.close();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UI pieces
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function ValuePill({ value, color }: { value: string; color: string }) {
  return (
    <span className={`inline-block font-mono font-bold px-4 py-2 rounded-xl text-xl tracking-widest ${color}`}>
      {value}
    </span>
  );
}

function BigCard({ children, color = "bg-white border-slate-200" }: { children: React.ReactNode; color?: string }) {
  return (
    <div className={`rounded-2xl border-2 p-8 ${color}`}>
      {children}
    </div>
  );
}

function SeedBox({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) {
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wide">{label}</div>
      <input
        type="number"
        value={value}
        onChange={e => onChange(parseInt(e.target.value) || 0)}
        className="w-24 h-14 text-center text-2xl font-bold font-mono border-2 border-indigo-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 bg-white text-indigo-700"
      />
    </div>
  );
}

// Small character shift bubble
function getCharType(code: number): { type: string; base: number; size: number } | null {
  if (code >= 65 && code <= 90) return { type: "Uppercase", base: 65, size: 26 };
  if (code >= 97 && code <= 122) return { type: "Lowercase", base: 97, size: 26 };
  if (code >= 48 && code <= 57)  return { type: "Digit", base: 48, size: 10 };
  return null;
}

// Op badge styling per operation type
const OP_BADGE: Record<number, { label: (n: number) => string; cls: string }> = {
  0: { label: n => `+${n}`,   cls: "bg-amber-100 text-amber-800 border-amber-300" },
  1: { label: n => `−${n}`,   cls: "bg-red-100 text-red-700 border-red-300" },
  2: { label: n => `×${n}`,   cls: "bg-violet-100 text-violet-700 border-violet-300" },
  3: { label: _n => `flip`,   cls: "bg-teal-100 text-teal-700 border-teal-300" },
};

function ShiftBubble({ shift }: { shift: CharShift }) {
  if (shift.microOps.length === 0) {
    return (
      <div className="flex flex-col items-center gap-1 px-2">
        <span className="text-2xl font-mono font-bold text-slate-400">{shift.from}</span>
        <span className="text-[9px] text-slate-300">—</span>
        <span className="text-2xl font-mono font-bold text-slate-400">{shift.to}</span>
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center gap-1 px-2">
      <span className="text-2xl font-mono font-bold text-blue-600">{shift.from}</span>
      <div className="flex gap-0.5 flex-wrap justify-center">
        {shift.microOps.map((op, i) => {
          const def = OP_BADGE[op.opType];
          return (
            <span key={i} className={`text-[8px] font-bold border rounded px-1 py-px leading-tight ${def.cls}`}>
              {def.label(op.amount)}
            </span>
          );
        })}
      </div>
      <span className="text-2xl font-mono font-bold text-green-600">{shift.to}</span>
    </div>
  );
}

// Round progress bar
function RoundBar({ stages, active }: { stages: string[]; active: number }) {
  return (
    <div className="flex items-center gap-2 justify-center flex-wrap">
      {stages.map((s, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className={`rounded-lg px-3 py-2 font-mono font-bold text-sm ${i === active ? "bg-indigo-600 text-white" : i < active ? "bg-green-100 text-green-700 border border-green-300" : "bg-slate-100 text-slate-400"}`}>
            {i === 0 ? "Start" : `Round ${i}`}
            <div className="text-xs font-mono mt-0.5 opacity-75">{s}</div>
          </div>
          {i < stages.length - 1 && <ArrowRight className="w-4 h-4 text-slate-300 shrink-0" />}
        </div>
      ))}
    </div>
  );
}

const STEP_LABELS = [
  "Set Up Your Example",
  "How Keys Are Made",
  "Encrypting",
  "Decrypting",
  "The Full Journey",
];

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main component
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export function GuideSection() {
  const [step, setStep] = useState(0);
  const [seeds, setSeeds] = useState([42, 137, 2024, 7]);
  const [colName, setColName] = useState("Age");
  const [cellValue, setCellValue] = useState("12345");
  const [encRoundIdx, setEncRoundIdx] = useState(0);
  const [decRoundIdx, setDecRoundIdx] = useState(0);

  const trace = useMemo(() => computeTrace(seeds, colName, cellValue), [seeds, colName, cellValue]);

  function setSeed(i: number, v: number) {
    setSeeds(s => { const c = [...s]; c[i] = isNaN(v) ? 0 : v; return c; });
  }

  const totalSteps = STEP_LABELS.length;

  function goNext() { if (step < totalSteps - 1) setStep(s => s + 1); }
  function goBack() { if (step > 0) setStep(s => s - 1); }

  const encShifts = trace.encShifts[encRoundIdx] ?? [];
  const decShifts = trace.decShifts[decRoundIdx] ?? [];

  return (
    <div className="flex flex-col h-full">

      {/* ── Step progress ─────────────────────────────────────────── */}
      <div className="px-10 pt-6 pb-4 border-b border-slate-100 bg-white shrink-0">
        <div className="flex items-center gap-0">
          {STEP_LABELS.map((label, i) => (
            <button
              key={i}
              onClick={() => setStep(i)}
              className="flex-1 flex flex-col items-center gap-1.5 group"
            >
              <div className={`w-full h-1.5 rounded-full transition-all ${i <= step ? "bg-indigo-500" : "bg-slate-200"}`} />
              <div className={`text-xs font-medium transition-colors ${i === step ? "text-indigo-700" : i < step ? "text-green-600" : "text-slate-400"} group-hover:text-slate-700 hidden sm:block`}>
                {i < step ? "✓ " : ""}{label}
              </div>
            </button>
          ))}
        </div>
        <div className="mt-2 text-center text-xs text-slate-400">Step {step + 1} of {totalSteps}: <span className="font-semibold text-slate-600">{STEP_LABELS[step]}</span></div>
      </div>

      {/* ── Content area ──────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-4 py-8">

        {/* ══ STEP 0: Setup ══════════════════════════════════════════ */}
        {step === 0 && (
          <div className="w-full space-y-8">
            <div className="text-center">
              <div className="text-5xl mb-4">👋</div>
              <h2 className="text-3xl font-bold text-slate-800 mb-3">Let's See How Anonymization Works!</h2>
              <p className="text-lg text-slate-500 leading-relaxed">
                We'll take a real value from your survey data, <strong>scramble it</strong> so no one can tell what it was,<br />
                and then show how we can <strong>get it back</strong> — perfectly — using your secret keys.
              </p>
            </div>

            {/* The Problem */}
            <BigCard color="bg-white border-red-200">
              <h3 className="text-xl font-bold text-slate-800 mb-3">🚨 The Problem: Survey Data Is Sensitive</h3>
              <p className="text-slate-600 leading-relaxed mb-4">
                Large surveys like NSSO/HCES record things like household income, age, caste, location, and spending. This is incredibly useful for research — but also very private. If the raw data were shared openly, anyone could look up a household and learn their exact financial situation.
              </p>
              <div className="grid grid-cols-3 gap-3">
                {[
                  ["❌ Share raw data", "A researcher in another country could see that Household #4821 earns ₹18,400/month and lives in Jaipur.", "bg-red-50 border-red-200 text-red-700"],
                  ["✅ Share anonymized data", "They see Household #4821 earns ₹73,191/month (fake). The pattern in the data still holds for research — but the specific value is hidden.", "bg-green-50 border-green-200 text-green-700"],
                  ["🔓 Decrypt when needed", "The original surveyor, who holds the 4 secret seeds, can reverse the anonymization and recover ₹18,400 exactly — no data is lost.", "bg-blue-50 border-blue-200 text-blue-700"],
                ].map(([title, body, cls]) => (
                  <div key={title as string} className={`rounded-xl border-2 p-4 ${cls}`}>
                    <div className="font-bold text-sm mb-2">{title}</div>
                    <div className="text-xs leading-relaxed">{body}</div>
                  </div>
                ))}
              </div>
            </BigCard>

            {/* Pipeline visual */}
            <BigCard color="bg-white border-slate-200">
              <h3 className="text-xl font-bold text-slate-800 mb-4">🔄 The 4-Stage Pipeline</h3>
              <p className="text-slate-500 text-sm mb-5">Every cell value passes through exactly these 4 stages when anonymized:</p>
              <div className="flex items-stretch gap-0">
                {[
                  { num: "1", color: "bg-indigo-600", label: "Seeds → Master Key → Round Keys", body: "4 seeds are folded into 1 master seed (32-bit), expanded into 1 master key (256-bit), then used to derive 4 independent 256-bit round keys. The order of seeds matters — swapping any two changes everything." },
                  { num: "2", color: "bg-blue-500", label: "Key + Column → IV", body: "Each column name is hashed together with its round key to produce a unique Column IV — an address that separates columns from each other." },
                  { num: "3", color: "bg-green-600", label: "IV → Keystream", body: "The key and IV are fed into a fast pseudo-random number generator (xorshift128+), producing a stream of random bytes — one per character." },
                  { num: "4", color: "bg-emerald-700", label: "Keystream → Shift", body: "Each character is shifted within its own alphabet (digit↔digit, letter↔letter) by an amount controlled by the keystream byte. Repeated 4 times." },
                ].map((s, i, arr) => (
                  <div key={i} className="flex items-center flex-1">
                    <div className="flex-1 rounded-xl border-2 border-slate-200 p-4 h-full">
                      <div className={`w-8 h-8 rounded-full ${s.color} text-white font-bold flex items-center justify-center text-sm mb-2`}>{s.num}</div>
                      <div className="font-bold text-slate-800 text-sm mb-1">{s.label}</div>
                      <div className="text-xs text-slate-500 leading-relaxed">{s.body}</div>
                    </div>
                    {i < arr.length - 1 && <ArrowRight className="w-6 h-6 text-slate-300 shrink-0 mx-1" />}
                  </div>
                ))}
              </div>
            </BigCard>

            {/* Format preservation visual */}
            <BigCard color="bg-white border-amber-200">
              <h3 className="text-xl font-bold text-slate-800 mb-3">🔄 What "Format-Preserving" Means</h3>
              <p className="text-slate-500 text-sm mb-5">Normal encryption turns data into random-looking garbage. AIRAVATA DEA uses Format-Preserving Encryption (FPE), which keeps the output in the same shape as the input.</p>
              <div className="grid grid-cols-2 gap-6">
                <div className="rounded-xl bg-red-50 border-2 border-red-200 p-5">
                  <div className="font-bold text-red-700 mb-3">❌ Normal encryption</div>
                  <div className="space-y-2 text-sm font-mono">
                    <div className="flex items-center gap-2"><span className="text-blue-700">"12345"</span><ArrowRight className="w-3 h-3" /><span className="text-red-600">"xK9#mP!2"</span></div>
                    <div className="flex items-center gap-2"><span className="text-blue-700">"Ramesh"</span><ArrowRight className="w-3 h-3" /><span className="text-red-600">"Bq7$nR09k"</span></div>
                    <div className="flex items-center gap-2"><span className="text-blue-700">"50"</span><ArrowRight className="w-3 h-3" /><span className="text-red-600">"mX#9!@zA3"</span></div>
                  </div>
                  <p className="text-xs text-red-600 mt-3">The output changes length, contains symbols, looks nothing like the original. The CSV structure breaks.</p>
                </div>
                <div className="rounded-xl bg-green-50 border-2 border-green-200 p-5">
                  <div className="font-bold text-green-700 mb-3">✅ Format-preserving (AIRAVATA DEA)</div>
                  <div className="space-y-2 text-sm font-mono">
                    <div className="flex items-center gap-2"><span className="text-blue-700">"12345"</span><ArrowRight className="w-3 h-3" /><span className="text-green-700">"{trace.encStages.length > 1 ? trace.encStages[trace.encStages.length - 1] : "39461"}"</span></div>
                    <div className="flex items-center gap-2"><span className="text-blue-700">"Ramesh"</span><ArrowRight className="w-3 h-3" /><span className="text-green-700">"Vfzlne"</span></div>
                    <div className="flex items-center gap-2"><span className="text-blue-700">"50"</span><ArrowRight className="w-3 h-3" /><span className="text-green-700">"83"</span></div>
                  </div>
                  <p className="text-xs text-green-600 mt-3">Same length, same type of characters, same position in the CSV. Research tools still work correctly on the anonymized data.</p>
                </div>
              </div>
            </BigCard>

            {/* Big journey preview */}
            <div className="flex items-center justify-center gap-4 py-6 bg-slate-50 rounded-2xl border-2 border-slate-200">
              <div className="text-center">
                <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Your Data</div>
                <ValuePill value={cellValue || "A"} color="text-blue-700 bg-blue-50 border-2 border-blue-200" />
              </div>
              <div className="flex flex-col items-center gap-1">
                <ArrowRight className="w-8 h-8 text-green-400" />
                <span className="text-xs text-slate-400">encrypt</span>
              </div>
              <div className="text-center">
                <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Hidden Value</div>
                <ValuePill value={trace.finalEncrypted} color="text-green-700 bg-green-50 border-2 border-green-200" />
              </div>
              <div className="flex flex-col items-center gap-1">
                <ArrowRight className="w-8 h-8 text-indigo-400" />
                <span className="text-xs text-slate-400">decrypt</span>
              </div>
              <div className="text-center">
                <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Recovered</div>
                <ValuePill value={trace.finalDecrypted} color="text-indigo-700 bg-indigo-50 border-2 border-indigo-200" />
              </div>
            </div>

            {/* Inputs */}
            <BigCard color="bg-white border-indigo-200">
              <h3 className="text-xl font-bold text-slate-800 mb-2">🎛️ Set Your Example Inputs</h3>
              <p className="text-slate-500 mb-6 text-sm leading-relaxed">
                Change any value below — all the calculations in the following steps update <strong>instantly</strong> with real computed numbers.
              </p>
              <div className="flex gap-4 justify-center mb-6">
                {[0, 1, 2, 3].map(i => (
                  <SeedBox key={i} label={`Seed ${i + 1}`} value={seeds[i]} onChange={v => setSeed(i, v)} />
                ))}
              </div>
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-5 text-sm text-amber-800">
                <strong>🔐 Seeds = your secret password.</strong> All 4 seeds must be known, and their order matters. Swapping seed 1 and seed 2 gives a completely different result — try it now and watch the value above change.
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">Column Name</label>
                  <input value={colName} onChange={e => setColName(e.target.value)}
                    className="w-full border-2 border-slate-200 rounded-xl px-4 py-3 text-base font-mono focus:outline-none focus:ring-2 focus:ring-indigo-400"
                    placeholder="e.g. Age, Salary, Name" />
                  <p className="text-xs text-slate-400 mt-1.5">The column name is hashed into the keystream so that "Age" and "Salary" encrypt differently even with identical seeds and values.</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">Cell Value to Scramble</label>
                  <input value={cellValue} onChange={e => setCellValue(e.target.value)}
                    className="w-full border-2 border-slate-200 rounded-xl px-4 py-3 text-base font-mono focus:outline-none focus:ring-2 focus:ring-indigo-400"
                    placeholder="e.g. 12345 or Hello" />
                  <p className="text-xs text-slate-400 mt-1.5">Try a pure number (e.g. <span className="font-mono">12345</span>), a word (e.g. <span className="font-mono">Hello</span>), or a mix (e.g. <span className="font-mono">ABC123</span>).</p>
                </div>
              </div>
            </BigCard>
          </div>
        )}

        {/* ══ STEP 1: Keys ════════════════════════════════════════════ */}
        {step === 1 && (
          <div className="w-full space-y-8">
            <div className="text-center">
              <div className="text-5xl mb-4">🔑</div>
              <h2 className="text-3xl font-bold text-slate-800 mb-3">Making the Secret Keys</h2>
              <p className="text-lg text-slate-500 leading-relaxed">
                Your 4 seed numbers are folded into a single <strong>32-bit master seed</strong>.<br />
                That master seed expands into one <strong>256-bit master key</strong>, from which<br />
                <strong>4 independent 256-bit round keys are derived</strong> via a rolling mixer. Here's exactly how.
              </p>
            </div>

            {/* Concepts needed */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-blue-50 border-2 border-blue-200 rounded-xl p-5">
                <div className="text-2xl mb-2">⊕</div>
                <div className="font-bold text-blue-800 mb-2">XOR (Exclusive-Or)</div>
                <p className="text-blue-700 text-xs leading-relaxed mb-3">XOR compares two numbers bit by bit. If a bit is <em>different</em> between the two numbers, the result is 1. If the bits are the <em>same</em>, the result is 0.</p>
                <div className="bg-white rounded-lg p-3 font-mono text-xs border border-blue-200">
                  <div className="text-slate-500 mb-1">5 in binary:</div>
                  <div>  0 1 0 1</div>
                  <div className="text-slate-500">⊕</div>
                  <div className="text-slate-500 mb-1">3 in binary:</div>
                  <div>  0 0 1 1</div>
                  <div className="border-t border-slate-200 mt-1 pt-1 text-green-700 font-bold">= 0 1 1 0 = 6</div>
                </div>
                <p className="text-blue-600 text-xs mt-2">We use XOR to mix seed values into the running accumulator — it scrambles bits without losing information.</p>
              </div>
              <div className="bg-violet-50 border-2 border-violet-200 rounded-xl p-5">
                <div className="text-2xl mb-2">🌊</div>
                <div className="font-bold text-violet-800 mb-2">Avalanche Effect</div>
                <p className="text-violet-700 text-xs leading-relaxed mb-3">The "avalanche" mixing steps ensure that a <strong>tiny change in input causes a huge change in output</strong>. Changing just one bit of any seed should flip roughly half the bits in the final key.</p>
                <div className="bg-white rounded-lg p-3 text-xs border border-violet-200 font-mono space-y-1">
                  <div><span className="text-blue-600">seed=42</span> → key starts <span className="text-green-700">{trace.keys[0].slice(0,8)}</span></div>
                  <div><span className="text-blue-600">seed=43</span> → key starts <span className="text-red-600 text-[10px]">completely different</span></div>
                </div>
                <p className="text-violet-600 text-xs mt-2">This comes from the MurmurHash3 finaliser — a proven technique from fast hash functions.</p>
              </div>
              <div className="bg-amber-50 border-2 border-amber-200 rounded-xl p-5">
                <div className="text-2xl mb-2">🎲</div>
                <div className="font-bold text-amber-800 mb-2">xorshift128+</div>
                <p className="text-amber-700 text-xs leading-relaxed mb-3">Once we have the final rolling accumulator, we feed it into <strong>xorshift128+</strong> — a fast pseudo-random number generator (PRNG). "Pseudo-random" means: given the same seed, it always produces the same sequence of numbers that <em>looks</em> random.</p>
                <p className="text-amber-700 text-xs leading-relaxed">We call this PRNG 32 times to generate 32 random bytes (256 bits) — that becomes the key. The PRNG is seeded with <span className="font-mono">rolling ⊕ 0xDEADBEEF</span> to further decorrelate the output.</p>
              </div>
            </div>

            {/* Phase 1 — Seed Folding */}
            <BigCard color="bg-white border-slate-200">
              <h3 className="text-xl font-bold text-slate-800 mb-2">Phase 1 — Fold All 4 Seeds into One Master Seed</h3>
              <p className="text-slate-500 text-sm mb-2 leading-relaxed">
                We maintain a single 32-bit <strong>rolling accumulator</strong> that starts at the golden-ratio constant and is updated once per seed using a <em>Horner-style multiply-XOR fold</em> followed by a MurmurHash3 avalanche mix. After processing all 4 seeds the final accumulator value is the <strong>master seed</strong>. Because every seed feeds into every subsequent multiply/XOR, reordering any two seeds produces a completely different master seed.
              </p>
              <div className="mb-5 bg-slate-50 rounded-xl border border-slate-200 p-4 text-xs font-mono space-y-1 text-slate-700">
                <div className="text-slate-400 font-semibold uppercase text-[10px] mb-2">General formula applied for each seed sᵢ:</div>
                <div><span className="text-blue-600">A:</span>  rolling ← (rolling × 0x9E3779B9) ⊕ (sᵢ &gt;&gt;&gt; 0)    <span className="text-slate-400">// Horner multiply then XOR-mix with seed</span></div>
                <div><span className="text-violet-600">B:</span>  rolling ← rolling ⊕ (rolling &gt;&gt;&gt; 16)              <span className="text-slate-400">// Avalanche mix #1 — spread high bits downward</span></div>
                <div><span className="text-amber-600">C:</span>  rolling ← rolling × 0x85EBCA6B                     <span className="text-slate-400">// MurmurHash3 constant — maximises bit avalanche</span></div>
                <div><span className="text-emerald-600">D:</span>  rolling ← rolling ⊕ (rolling &gt;&gt;&gt; 13)              <span className="text-slate-400">// Avalanche mix #2 — spread mid bits downward</span></div>
                <div className="text-slate-400 mt-1">All arithmetic is unsigned 32-bit (truncated with &gt;&gt;&gt; 0 after each multiply)</div>
              </div>

              <div className="flex gap-4 items-start mb-5">
                <div className="w-10 h-10 rounded-full bg-indigo-100 text-indigo-700 font-bold flex items-center justify-center shrink-0 text-sm">0</div>
                <div className="flex-1">
                  <div className="font-semibold text-slate-800 mb-1">Starting point: the Golden Ratio constant</div>
                  <p className="text-slate-500 text-sm mb-2">
                    We don't start from zero — we start from <strong>0x9E3779B9</strong>. This is the fractional part of the golden ratio φ = 1.6180339887… multiplied by 2³² = 4,294,967,296, then rounded to the nearest integer. Golden-ratio-based constants have excellent bit-diffusion properties (known as <em>Knuth's multiplicative hash</em>).
                  </p>
                  <div className="font-mono text-xs bg-slate-50 border border-slate-200 text-emerald-700 rounded-lg px-4 py-3 inline-block space-y-1">
                    <div>φ = 1.6180339887…</div>
                    <div>φ × 2³² = 6,948,403,464.3… → fractional part × 2³² = 2,654,435,769</div>
                    <div className="text-slate-800 font-bold mt-1">rolling₀ = 0x9E3779B9 = 2,654,435,769</div>
                  </div>
                </div>
              </div>

              {trace.keyDerivSteps.map((kd, i) => {
                const bgColors = ["bg-blue-50 border-blue-200","bg-violet-50 border-violet-200","bg-amber-50 border-amber-200","bg-emerald-50 border-emerald-200"];
                const textColors = ["text-blue-700","text-violet-700","text-amber-700","text-emerald-700"];
                const headerBg = ["bg-blue-600","bg-violet-600","bg-amber-600","bg-emerald-700"];
                const isLast = i === 3;
                const h8 = (n: number) => "0x" + n.toString(16).toUpperCase().padStart(8, "0");
                // Intermediates for step A
                const mulOnly = (Math.imul(kd.rollingBefore, 0x9e3779b9) >>> 0);
                // Intermediate for step B: shift part
                const shift16val = (kd.afterMulXor >>> 16);
                // Intermediate for step C: computed from afterMix1
                // (afterMul2 already in kd)
                // Intermediate for step D: shift part
                const shift13val = (kd.afterMul2 >>> 13);
                return (
                  <div key={i} className={`rounded-xl border-2 ${bgColors[i]} mb-5`}>
                    {/* Header */}
                    <div className={`${headerBg[i]} rounded-t-xl px-5 py-3 flex items-center justify-between`}>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-white/20 font-bold flex items-center justify-center text-white text-base">{i+1}</div>
                        <div>
                          <div className="font-bold text-white text-base">Seed {i+1} = {kd.seed} (decimal) = {h8(kd.seed)} (hex)</div>
                          <div className="text-white/70 text-xs">Rolling accumulator coming in: <span className="font-mono text-white">{h8(kd.rollingBefore)} = {kd.rollingBefore.toLocaleString()}</span></div>
                        </div>
                      </div>
                      {isLast && <div className="text-xs font-bold bg-white/20 text-white px-3 py-1 rounded-full border border-white/30">→ Produces Master Seed</div>}
                    </div>

                    {/* Steps */}
                    <div className="p-5 space-y-3">

                      {/* Step A */}
                      <div className="bg-white rounded-xl border border-slate-200 p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-bold text-blue-600 text-sm bg-blue-50 px-2 py-0.5 rounded">A</span>
                          <span className="font-semibold text-slate-700 text-sm">Horner multiply, then XOR with seed</span>
                          <span className="text-[10px] text-slate-400 font-mono ml-auto">rolling ← (rolling × 0x9E3779B9) ⊕ seed</span>
                        </div>
                        <div className="font-mono text-xs space-y-1 bg-slate-50 rounded-lg p-3 border border-slate-100">
                          <div className="text-slate-500">Step A1 — multiply (32-bit truncated):</div>
                          <div className="pl-3"><span className="text-blue-700">{h8(kd.rollingBefore)}</span> × 0x9E3779B9 = <span className="text-amber-700">{h8(mulOnly)}</span> <span className="text-slate-400">(lower 32 bits kept)</span></div>
                          <div className="text-slate-500 mt-1">Step A2 — XOR with seed:</div>
                          <div className="pl-3"><span className="text-amber-700">{h8(mulOnly)}</span> ⊕ <span className="text-green-700">{h8(kd.seed >>> 0)}</span> = <span className="font-bold text-slate-900">{h8(kd.afterMulXor)}</span></div>
                        </div>
                        <div className="flex items-center justify-end mt-2">
                          <span className="text-xs text-slate-400 mr-2">Result after A:</span>
                          <span className="font-mono font-bold text-slate-800 text-sm bg-slate-100 px-3 py-1 rounded-lg">{h8(kd.afterMulXor)}</span>
                        </div>
                      </div>

                      {/* Step B */}
                      <div className="bg-white rounded-xl border border-slate-200 p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-bold text-violet-600 text-sm bg-violet-50 px-2 py-0.5 rounded">B</span>
                          <span className="font-semibold text-slate-700 text-sm">Avalanche mix #1 — XOR with right-shift of 16 bits</span>
                          <span className="text-[10px] text-slate-400 font-mono ml-auto">rolling ← rolling ⊕ (rolling &gt;&gt;&gt; 16)</span>
                        </div>
                        <div className="font-mono text-xs space-y-1 bg-slate-50 rounded-lg p-3 border border-slate-100">
                          <div className="text-slate-500">Shift 16 bits right (moves top half into bottom half):</div>
                          <div className="pl-3"><span className="text-violet-700">{h8(kd.afterMulXor)}</span> &gt;&gt;&gt; 16 = <span className="text-amber-700">{h8(shift16val)}</span></div>
                          <div className="text-slate-500 mt-1">XOR together (mixes high and low halves):</div>
                          <div className="pl-3"><span className="text-violet-700">{h8(kd.afterMulXor)}</span> ⊕ <span className="text-amber-700">{h8(shift16val)}</span> = <span className="font-bold text-slate-900">{h8(kd.afterMix1)}</span></div>
                        </div>
                        <div className="flex items-center justify-between mt-2">
                          <div className="text-[10px] text-slate-400 leading-relaxed max-w-xs">Purpose: ensures bits in the upper half influence the lower half — a single changed seed bit now affects both halves of the accumulator.</div>
                          <span className="font-mono font-bold text-slate-800 text-sm bg-slate-100 px-3 py-1 rounded-lg shrink-0 ml-3">{h8(kd.afterMix1)}</span>
                        </div>
                      </div>

                      {/* Step C */}
                      <div className="bg-white rounded-xl border border-slate-200 p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-bold text-amber-600 text-sm bg-amber-50 px-2 py-0.5 rounded">C</span>
                          <span className="font-semibold text-slate-700 text-sm">Multiply by MurmurHash3 constant</span>
                          <span className="text-[10px] text-slate-400 font-mono ml-auto">rolling ← rolling × 0x85EBCA6B</span>
                        </div>
                        <div className="font-mono text-xs space-y-1 bg-slate-50 rounded-lg p-3 border border-slate-100">
                          <div className="text-slate-500">Multiply (32-bit truncated — lower 32 bits of the 64-bit product):</div>
                          <div className="pl-3"><span className="text-amber-700">{h8(kd.afterMix1)}</span> × 0x85EBCA6B = <span className="font-bold text-slate-900">{h8(kd.afterMul2)}</span></div>
                        </div>
                        <div className="flex items-center justify-between mt-2">
                          <div className="text-[10px] text-slate-400 leading-relaxed max-w-xs">0x85EBCA6B is the MurmurHash3 finaliser constant, chosen because it maximises the <em>avalanche effect</em> — every input bit influences every output bit.</div>
                          <span className="font-mono font-bold text-slate-800 text-sm bg-slate-100 px-3 py-1 rounded-lg shrink-0 ml-3">{h8(kd.afterMul2)}</span>
                        </div>
                      </div>

                      {/* Step D */}
                      <div className="bg-white rounded-xl border border-slate-200 p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-bold text-emerald-600 text-sm bg-emerald-50 px-2 py-0.5 rounded">D</span>
                          <span className="font-semibold text-slate-700 text-sm">Avalanche mix #2 — XOR with right-shift of 13 bits</span>
                          <span className="text-[10px] text-slate-400 font-mono ml-auto">rolling ← rolling ⊕ (rolling &gt;&gt;&gt; 13)</span>
                        </div>
                        <div className="font-mono text-xs space-y-1 bg-slate-50 rounded-lg p-3 border border-slate-100">
                          <div className="text-slate-500">Shift 13 bits right:</div>
                          <div className="pl-3"><span className="text-emerald-700">{h8(kd.afterMul2)}</span> &gt;&gt;&gt; 13 = <span className="text-amber-700">{h8(shift13val)}</span></div>
                          <div className="text-slate-500 mt-1">XOR together:</div>
                          <div className="pl-3"><span className="text-emerald-700">{h8(kd.afterMul2)}</span> ⊕ <span className="text-amber-700">{h8(shift13val)}</span> = <span className="font-bold text-slate-900">{h8(kd.afterMix2)}</span></div>
                        </div>
                        <div className="flex items-center justify-between mt-2">
                          <div className="text-[10px] text-slate-400 leading-relaxed max-w-xs">A second shift-XOR using 13 (not 16) ensures the remaining correlation between adjacent bits is eliminated. Together, steps B+D form the complete MurmurHash3 finaliser.</div>
                          <span className="font-mono font-bold text-slate-800 text-sm bg-slate-100 px-3 py-1 rounded-lg shrink-0 ml-3">{h8(kd.afterMix2)}</span>
                        </div>
                      </div>

                      {/* Rolling after summary */}
                      <div className={`rounded-lg p-4 ${isLast ? "bg-indigo-900 border border-indigo-700" : "bg-slate-800 border border-slate-700"}`}>
                        <div className={`text-xs font-semibold uppercase mb-2 ${isLast ? "text-indigo-300" : "text-slate-400"}`}>
                          {isLast ? "✦ Master Seed — encodes all 4 seeds and their order (32-bit)" : `Rolling accumulator after seed ${i+1}`}
                        </div>
                        <div className={`font-mono font-bold ${isLast ? "text-indigo-200 text-lg" : "text-white text-sm"}`}>
                          {h8(kd.rollingAfter)} <span className="text-slate-400 font-normal text-xs">=</span> <span className={isLast ? "text-indigo-100" : "text-slate-300"}>{kd.rollingAfter.toLocaleString()}</span>
                        </div>
                        {isLast && (
                          <div className="text-indigo-400 text-xs mt-2">This single 32-bit value is the irreversible fingerprint of seeds [{seeds.join(", ")}] in that exact order. It drives everything that follows.</div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </BigCard>

            {/* Phase 2 — Master Key */}
            <BigCard color="bg-white border-indigo-200">
              <h3 className="text-xl font-bold text-slate-800 mb-2">Phase 2 — Expand Master Seed into One 256-bit Master Key</h3>
              <p className="text-slate-500 text-sm mb-4 leading-relaxed">
                The 32-bit master seed is expanded into <strong>32 random bytes (256 bits)</strong> — the <em>master key</em>. We do this by feeding the seed into the <strong>xorshift128+</strong> pseudo-random number generator (PRNG) and sampling 32 consecutive outputs, each converted to one byte (0–255). The seed is first mixed with <span className="font-mono bg-slate-100 px-1 rounded">0xDEADBEEF</span> to decorrelate the PRNG initialisation from the master seed itself.
              </p>

              {(() => {
                const h8 = (n: number) => "0x" + n.toString(16).toUpperCase().padStart(8, "0");
                const prngseed = (trace.masterSeed ^ 0xdeadbeef) >>> 0;
                const a0 = ((prngseed ^ 0x9e3779b9) >>> 0) || 1;
                const b0 = ((prngseed ^ 0x6c62272e) >>> 0) || 2;
                return (
                  <div className="space-y-4">
                    {/* Step 1: seed mixing */}
                    <div className="bg-slate-50 rounded-xl border border-slate-200 p-4">
                      <div className="text-xs font-semibold text-slate-500 uppercase mb-3">Step 2a — Mix the master seed into the PRNG seed</div>
                      <div className="font-mono text-xs space-y-1.5">
                        <div>masterSeed               = <span className="text-indigo-600 font-bold">{h8(trace.masterSeed)}</span> = {trace.masterSeed.toLocaleString()}</div>
                        <div>prngseed = masterSeed ⊕ 0xDEADBEEF</div>
                        <div className="pl-4">= <span className="text-indigo-600">{h8(trace.masterSeed)}</span> ⊕ <span className="text-red-600">0xDEADBEEF</span></div>
                        <div className="pl-4">= <span className="font-bold text-emerald-700">{h8(prngseed)}</span></div>
                      </div>
                    </div>

                    {/* Step 2: PRNG init */}
                    <div className="bg-slate-50 rounded-xl border border-slate-200 p-4">
                      <div className="text-xs font-semibold text-slate-500 uppercase mb-3">Step 2b — Initialise xorshift128+ state (two 32-bit registers a, b)</div>
                      <div className="font-mono text-xs space-y-1.5">
                        <div>a₀ = prngseed ⊕ 0x9E3779B9 = <span className="text-blue-600">{h8(prngseed)}</span> ⊕ 0x9E3779B9 = <span className="font-bold text-blue-800">{h8(a0)}</span> <span className="text-slate-400">{a0 === 0 ? "(→ forced to 1, degenerate guard)" : ""}</span></div>
                        <div>b₀ = prngseed ⊕ 0x6C62272E = <span className="text-blue-600">{h8(prngseed)}</span> ⊕ 0x6C62272E = <span className="font-bold text-blue-800">{h8(b0)}</span> <span className="text-slate-400">{b0 === 0 ? "(→ forced to 2, degenerate guard)" : ""}</span></div>
                        <div className="text-slate-400 text-[10px] mt-1">0x6C62272E is the FNV prime — a different constant from the golden ratio to ensure a and b start with uncorrelated bits</div>
                      </div>
                    </div>

                    {/* Step 3: iteration */}
                    <div className="bg-slate-50 rounded-xl border border-slate-200 p-4">
                      <div className="text-xs font-semibold text-slate-500 uppercase mb-3">Step 2c — Each PRNG call advances the state and produces one byte</div>
                      <div className="font-mono text-[10px] bg-slate-50 border border-slate-200 text-slate-700 rounded-lg p-3 space-y-0.5 mb-3">
                        <div className="text-emerald-600 text-xs mb-1">// xorshift128+ iterate (called 32 times):</div>
                        <div>a ← a ⊕ (a &lt;&lt; 13);   a = a &gt;&gt;&gt; 0   <span className="text-slate-400">// left-shift XOR</span></div>
                        <div>a ← a ⊕ (a &gt;&gt; 17)              <span className="text-slate-400">// right-shift XOR</span></div>
                        <div>a ← a ⊕ (a &lt;&lt;  5);   a = a &gt;&gt;&gt; 0   <span className="text-slate-400">// left-shift XOR</span></div>
                        <div className="mt-1">b ← b ⊕ (b &gt;&gt;  7);   b = b &gt;&gt;&gt; 0</div>
                        <div>b ← b ⊕ (b &lt;&lt;  9);   b = b &gt;&gt;&gt; 0</div>
                        <div>b ← b ⊕ (b &gt;&gt;  8);   b = b &gt;&gt;&gt; 0</div>
                        <div className="mt-1 text-amber-600">raw = (a + b) &gt;&gt;&gt; 0               <span className="text-slate-400">// sum of both registers (32-bit)</span></div>
                        <div className="text-amber-600">byte = Math.floor(raw / 0x100000000 × 256)  <span className="text-slate-400">// scale to 0–255</span></div>
                      </div>
                      <div className="text-xs text-slate-500">32 such calls produce 32 bytes (256 bits). Each call is deterministic given the seed, so the same master seed always produces the same 32 bytes.</div>
                    </div>

                    {/* Master Key display */}
                    <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-5">
                      <div className="text-indigo-700 text-xs font-bold uppercase mb-2">Master Key — 256 bits = 32 bytes = 64 hex characters</div>
                      <div className="font-mono text-sm break-all text-indigo-800 leading-relaxed tracking-wider">
                        {trace.masterKey.match(/.{1,8}/g)?.map((chunk, ci) => (
                          <span key={ci} className={`${ci % 2 === 0 ? "text-indigo-700" : "text-indigo-500"} mr-1`}>{chunk}</span>
                        ))}
                      </div>
                      <div className="text-indigo-500 text-[10px] mt-3">Bytes 0–7 shown in groups of 8 hex chars (4 bytes). The first 8 hex chars (<span className="font-mono text-indigo-700">{trace.masterKey.slice(0,8)}</span>) seed Phase 3.</div>
                    </div>

                    <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4 text-xs text-indigo-800 leading-relaxed">
                      <strong>Key insight:</strong> The master key is <em>not</em> split into 4 parts. It is one single 256-bit secret. Phase 3 uses only the first 32 bits of this key as a seed to start a brand-new rolling derivation process that generates 4 entirely separate 256-bit round keys.
                    </div>
                  </div>
                );
              })()}
            </BigCard>

            {/* Phase 3 — Rolling Mixer */}
            <BigCard color="bg-white border-violet-200">
              <h3 className="text-xl font-bold text-slate-800 mb-2">Phase 3 — Derive 4 Independent Round Keys via Rolling Mixer</h3>
              <p className="text-slate-500 text-sm mb-4 leading-relaxed">
                The master key is <strong>not split</strong>. Instead, its first 8 hex characters (32 bits) seed a brand-new rolling accumulator <span className="font-mono bg-slate-100 px-1 rounded">r</span>. For each round index <span className="font-mono bg-slate-100 px-1 rounded">i ∈ {"{0,1,2,3}"}</span>, <span className="font-mono">r</span> is updated with a Horner multiply + XOR (using a round-index-specific constant), then a 16-bit avalanche mix. The updated <span className="font-mono">r</span> seeds a fresh xorshift128+ run that produces <strong>32 bytes = one 256-bit round key</strong>. The four round keys are completely independent — none shares bits with the master key or each other.
              </p>

              {(() => {
                const h8 = (n: number) => "0x" + n.toString(16).toUpperCase().padStart(8, "0");
                const base32 = parseInt(trace.masterKey.slice(0, 8), 16);
                let r = (base32 ^ 0xdeadbeef) >>> 0;
                const rSteps: { rBefore: number; afterMul: number; afterXorIdx: number; afterMix16: number; rAfter: number }[] = [];
                for (let i = 0; i < 4; i++) {
                  const rBefore = r;
                  const afterMul = (Math.imul(r, 0x9e3779b9)) >>> 0;
                  const afterXorIdx = (afterMul ^ (i * 0x5a5a5a5b)) >>> 0;
                  const afterMix16 = (afterXorIdx ^ (afterXorIdx >>> 16)) >>> 0;
                  r = afterMix16;
                  rSteps.push({ rBefore, afterMul, afterXorIdx, afterMix16, rAfter: r });
                }
                const roundColors = [
                  { bg: "bg-blue-50 border-blue-200", hdr: "bg-blue-600", txt: "text-blue-700", mono: "text-blue-800" },
                  { bg: "bg-violet-50 border-violet-200", hdr: "bg-violet-600", txt: "text-violet-700", mono: "text-violet-800" },
                  { bg: "bg-amber-50 border-amber-200", hdr: "bg-amber-600", txt: "text-amber-700", mono: "text-amber-800" },
                  { bg: "bg-emerald-50 border-emerald-200", hdr: "bg-emerald-700", txt: "text-emerald-700", mono: "text-emerald-800" },
                ];

                return (
                  <div className="space-y-4">
                    {/* Starting r */}
                    <div className="bg-slate-50 rounded-xl border border-slate-200 p-4">
                      <div className="text-xs font-semibold text-slate-500 uppercase mb-3">Step 3a — Seed the rolling accumulator r from the master key's first 32 bits</div>
                      <div className="font-mono text-xs space-y-1.5">
                        <div>masterKey[0..7] = <span className="text-indigo-600 font-bold">{trace.masterKey.slice(0,8)}</span> → as integer = <span className="text-indigo-600">{h8(base32)}</span></div>
                        <div>r₀ = {h8(base32)} ⊕ 0xDEADBEEF = <span className="font-bold text-emerald-700">{h8((base32 ^ 0xdeadbeef) >>> 0)}</span></div>
                      </div>
                    </div>

                    {/* Per-round derivation */}
                    {rSteps.map((rs, i) => {
                      const idxMul = (i * 0x5a5a5a5b) >>> 0;
                      const c = roundColors[i];
                      return (
                        <div key={i} className={`rounded-xl border-2 ${c.bg}`}>
                          <div className={`${c.hdr} rounded-t-xl px-5 py-2.5 flex items-center justify-between`}>
                            <div className="text-white font-bold text-sm">Round Key {i+1} — i = {i}</div>
                            <div className="text-white/70 text-xs font-mono">r coming in: {h8(rs.rBefore)}</div>
                          </div>
                          <div className="p-4 space-y-2">
                            <div className="bg-white rounded-lg border border-slate-200 p-3 font-mono text-xs space-y-1.5">
                              <div className="text-slate-500">Step 1 — multiply by golden-ratio prime (32-bit truncated):</div>
                              <div className="pl-3">{h8(rs.rBefore)} × 0x9E3779B9 = <span className="text-amber-700">{h8(rs.afterMul)}</span></div>
                              <div className="text-slate-500 mt-1">Step 2 — XOR with round-index constant (i × 0x5A5A5A5B = {i} × 0x5A5A5A5B = {h8(idxMul)}):</div>
                              <div className="pl-3"><span className="text-amber-700">{h8(rs.afterMul)}</span> ⊕ <span className="text-violet-700">{h8(idxMul)}</span> = <span className="text-orange-700">{h8(rs.afterXorIdx)}</span></div>
                              <div className="text-slate-500 mt-1">Step 3 — avalanche mix (XOR with 16-bit right-shift):</div>
                              <div className="pl-3"><span className="text-orange-700">{h8(rs.afterXorIdx)}</span> ⊕ ({h8(rs.afterXorIdx)} &gt;&gt;&gt; 16 = {h8(rs.afterXorIdx >>> 16)}) = <span className={`font-bold ${c.mono}`}>{h8(rs.afterMix16)}</span></div>
                              <div className="text-slate-500 mt-1">Step 4 — feed updated r into xorshift128+, sample 32 bytes:</div>
                              <div className="pl-3 text-slate-400">K{i+1} = xorshift128+(<span className={c.mono}>{h8(rs.rAfter)}</span>) → 32 bytes (256 bits)</div>
                            </div>
                            <div className="bg-white rounded-lg border border-slate-200 p-3">
                              <div className={`text-[10px] font-bold ${c.txt} uppercase mb-1`}>K{i+1} — 256-bit Round Key:</div>
                              <div className={`font-mono text-[10px] break-all leading-relaxed ${c.mono}`}>{trace.keys[i]}</div>
                            </div>
                          </div>
                        </div>
                      );
                    })}

                    <div className="bg-violet-50 border border-violet-200 rounded-xl p-4 text-xs text-violet-800 leading-relaxed">
                      <strong>Why multiply by i × 0x5A5A5A5B?</strong> The constant 0x5A5A5A5B ensures round index 0 and round index 1 produce different multipliers — so even if two rounds started with the same <span className="font-mono">r</span>, the resulting round keys would be completely different. Without it, K1 and K2 would be correlated. The constant 0x5A5A5A5B has a bit pattern (01011010…) chosen to differ maximally from 0x9E3779B9.
                    </div>
                  </div>
                );
              })()}
            </BigCard>
          </div>
        )}

        {/* ══ STEP 2: Encryption ══════════════════════════════════════ */}
        {step === 2 && (
          <div className="w-full space-y-8">
            <div className="text-center">
              <div className="text-5xl mb-4">🔐</div>
              <h2 className="text-3xl font-bold text-slate-800 mb-3">Scrambling Your Value</h2>
              <p className="text-lg text-slate-500 leading-relaxed">
                We apply 4 independent rounds of scrambling, one per key. Each round uses a <strong>keystream</strong> derived from the column name to shift every character. Here's the full picture.
              </p>
            </div>

            {/* Substep A: Column IV */}
            <BigCard color="bg-white border-blue-200">
              <h3 className="text-lg font-bold text-slate-800 mb-2">🔵 Sub-step A: Column IV — Why columns encrypt differently</h3>
              <p className="text-slate-500 text-sm leading-relaxed mb-4">
                Imagine two columns: <strong>Age</strong> and <strong>Income</strong>. Both contain the value <span className="font-mono font-bold">50</span>. Without a column-specific element, both would encrypt to the exact same output — revealing that those two people have the same value in both columns. That's a privacy leak!
              </p>
              <p className="text-slate-500 text-sm leading-relaxed mb-5">
                To prevent this, we hash the column name together with the round key to produce a <strong>Column IV</strong> (Initialization Vector). This makes the keystream completely different per column. The hash uses a technique called a <em>linear congruential mixing loop</em> over the characters of <span className="font-mono bg-slate-100 px-1 rounded">"COL" + columnName</span>.
              </p>
              <div className="overflow-x-auto rounded-xl border border-slate-200">
                <table className="w-full text-xs border-collapse">
                  <thead><tr className="bg-slate-100">
                    <th className="px-4 py-2 text-left text-slate-600">Round</th>
                    <th className="px-4 py-2 text-left text-slate-600">Key (first 8 hex chars)</th>
                    <th className="px-4 py-2 text-left text-slate-600">Column</th>
                    <th className="px-4 py-2 text-left text-slate-600">Column IV (hex)</th>
                    <th className="px-4 py-2 text-left text-slate-600">Column IV (decimal)</th>
                  </tr></thead>
                  <tbody>
                    {trace.colIVs.map((iv, i) => (
                      <tr key={i} className={i % 2 === 0 ? "bg-white" : "bg-slate-50"}>
                        <td className="px-4 py-2 font-semibold text-slate-700">Round {i+1}</td>
                        <td className="px-4 py-2 font-mono text-blue-700">{trace.keys[i].slice(0,8)}…</td>
                        <td className="px-4 py-2 font-mono font-bold text-slate-800">{colName || "(empty)"}</td>
                        <td className="px-4 py-2 font-mono font-bold text-amber-700">0x{iv.toString(16).toUpperCase().padStart(8,"0")}</td>
                        <td className="px-4 py-2 font-mono text-slate-600">{iv.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-slate-400 mt-3">✦ If you change the column name above (Step 1 inputs), all 4 IVs change — and so does the final encrypted value.</p>
            </BigCard>

            {/* Substep B: Keystream */}
            <BigCard color="bg-white border-green-200">
              <h3 className="text-lg font-bold text-slate-800 mb-2">🟢 Sub-step B: Generating the Keystream</h3>
              <p className="text-slate-500 text-sm leading-relaxed mb-4">
                With the Column IV in hand, we XOR it with the first 8 hex characters of the round key to get a <strong>combined seed</strong>. This combined seed is fed into the <strong>xorshift128+</strong> pseudo-random number generator, which produces a stream of random bytes (0–255) — one byte per character of the cell value.
              </p>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="text-xs font-semibold text-slate-500 uppercase mb-2">Combined seed formula</div>
                  <div className="font-mono text-xs text-slate-700 leading-relaxed">
                    combined = (key[0..7] as hex) ⊕ colIV<br/>
                    <span className="text-blue-600">{trace.keys[encRoundIdx].slice(0,8)}</span> ⊕ <span className="text-amber-600">0x{trace.colIVs[encRoundIdx].toString(16).toUpperCase().padStart(8,"0")}</span><br/>
                    = <span className="text-green-700">0x{((parseInt(trace.keys[encRoundIdx].slice(0,8),16) ^ trace.colIVs[encRoundIdx]) >>> 0).toString(16).toUpperCase().padStart(8,"0")}</span>
                  </div>
                </div>
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="text-xs font-semibold text-slate-500 uppercase mb-2">First 10 keystream bytes — Round {encRoundIdx+1}</div>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {(trace.ksFirstBytes[encRoundIdx] ?? []).map((b, i) => (
                      <span key={i} className="font-mono text-xs bg-amber-100 text-amber-800 px-2 py-0.5 rounded-lg font-bold border border-amber-200">{b}</span>
                    ))}
                  </div>
                  <p className="text-xs text-slate-400 mt-2"><strong>5 consecutive bytes consumed per character</strong> — each drives one sub-operation (add, subtract, multiply, or flip).</p>
                </div>
              </div>
              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-xs text-blue-800">
                <strong>Why 5 bytes per character?</strong> Each character goes through <strong>5 sequential sub-operations</strong> per round: add, subtract, multiply (by a number coprime to the alphabet size), or complement/flip. Using 5 independent keystream bytes means an attacker cannot predict the operation sequence from any single byte. The character’s alphabet index bounces through 5 distinct mathematical transformations before producing the final output.
              </div>
            </BigCard>

            {/* Substep C: Multi-op formulas */}
            <BigCard color="bg-white border-amber-200">
              <h3 className="text-lg font-bold text-slate-800 mb-1">🟡 Sub-step C: The 4 Operation Types</h3>
              <p className="text-slate-400 text-xs font-medium uppercase tracking-wide mb-4">How each character is mathematically scrambled</p>

              {/* Plain-English summary */}
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-6">
                <p className="text-sm text-amber-900 leading-relaxed">
                  Every character runs through <strong>5 mini-operations</strong> per round. For each mini-op, one keystream byte (<code className="bg-amber-100 px-1 rounded text-xs">k</code>) decides <em>what kind</em> of math to do (<code className="bg-amber-100 px-1 rounded text-xs">k mod 4</code>) and <em>how much</em> to shift (<code className="bg-amber-100 px-1 rounded text-xs">k ÷ 4</code>). The character's position in its alphabet (<code className="bg-amber-100 px-1 rounded text-xs">v</code>) is updated after each step. All four operations are <strong>perfectly reversible</strong>, so decryption always gets the original back exactly.
                </p>
              </div>

              {/* How the key byte is split */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-6">
                <div className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-3">How one keystream byte drives one sub-operation</div>
                <div className="flex flex-col sm:flex-row gap-4 items-stretch">
                  <div className="flex-1 bg-white border border-slate-200 rounded-lg p-3">
                    <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">Low 2 bits → Operation type</div>
                    <div className="font-mono text-sm font-bold text-slate-700 mb-1">k mod 4</div>
                    <div className="text-xs text-slate-500">Gives 0, 1, 2, or 3 — picks Add / Subtract / Multiply / Flip</div>
                  </div>
                  <div className="flex items-center text-slate-300 font-bold text-lg">+</div>
                  <div className="flex-1 bg-white border border-slate-200 rounded-lg p-3">
                    <div className="text-[10px] font-bold text-slate-400 uppercase mb-1">Upper bits → Shift amount</div>
                    <div className="font-mono text-sm font-bold text-slate-700 mb-1">(⌊k / 4⌋ mod (S−1)) + 1</div>
                    <div className="text-xs text-slate-500">Always between 1 and S−1 — determines how far to shift (S = alphabet size)</div>
                  </div>
                </div>
              </div>

              {/* ── WHY THESE 4 OPERATIONS ── */}
              <div className="border-2 border-indigo-200 rounded-xl overflow-hidden mb-6">
                <div className="bg-indigo-600 px-5 py-3 flex items-center gap-3">
                  <span className="text-white font-black text-base">🎯</span>
                  <span className="text-white font-bold text-base">Why exactly these 4 operations?</span>
                </div>
                <div className="p-5 bg-indigo-50 space-y-4">
                  <p className="text-sm text-indigo-900 leading-relaxed">
                    The goal is to scramble a character's alphabet position in ways that are <strong>mathematically diverse</strong>, <strong>always reversible</strong>, and <strong>together cover every possible type of modular bijection</strong> on a finite alphabet. Each operation was chosen because it attacks a different weakness that a single operation alone would leave open.
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="bg-white border border-indigo-200 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="bg-amber-400 text-white text-[10px] font-black px-2 py-0.5 rounded-full">Add</span>
                        <span className="bg-red-500 text-white text-[10px] font-black px-2 py-0.5 rounded-full">Subtract</span>
                        <span className="text-xs font-bold text-slate-500 ml-1">linear shift pair</span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        Add and Subtract are <strong>additive inverses</strong> — if the key applies an Add by 3 in one sub-op and a Subtract by 3 in another, they partially cancel. This is intentional: it makes the net shift unpredictable without knowing all 5 keystream bytes. Using both directions means an attacker cannot assume the value always increases or always decreases.
                      </p>
                    </div>
                    <div className="bg-white border border-indigo-200 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="bg-violet-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full">Multiply</span>
                        <span className="text-xs font-bold text-slate-500 ml-1">non-linear jump</span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        Multiplication is a fundamentally <strong>different type of operation</strong> from addition. It does not move the value forward or backward by a fixed step — it stretches and wraps the entire alphabet in a non-uniform way. A character at position 3 multiplied by 7 jumps to position 1 (mod 10), which is nowhere near 3. This breaks any remaining linear pattern that Add/Subtract alone would leave. Crucially, using only <em>coprime</em> multipliers ensures the operation is a perfect bijection — every input maps to a unique output, and the inverse always exists.
                      </p>
                    </div>
                    <div className="bg-white border border-indigo-200 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="bg-teal-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full">Flip</span>
                        <span className="text-xs font-bold text-slate-500 ml-1">mirror / complement</span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        Flip maps every value to its mirror image (<code className="bg-slate-100 px-1 rounded">S−1−v</code>). It is an <strong>involution</strong> — applying it twice gives the original. This is useful because it requires no extra key material to reverse, and it introduces a reflection symmetry that neither addition nor multiplication can produce. Without Flip, values near the middle of the alphabet would be statistically harder to move far from their start position in a single step.
                      </p>
                    </div>
                    <div className="bg-white border border-indigo-200 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xs font-bold text-slate-600">Together:</span>
                        <span className="text-xs text-slate-500">complete coverage</span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        These four types together form a <strong>complete set of reversible modular transformations</strong>: additive shift (Add/Subtract), multiplicative scaling (Multiply), and reflective complement (Flip). No other simple reversible single-character operation exists that these don't cover. Using all four means any statistical pattern in the input is attacked from multiple independent mathematical angles per round.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* ── ORDER AND DECISION PROCESS ── */}
              <div className="border-2 border-slate-300 rounded-xl overflow-hidden mb-6">
                <div className="bg-slate-800 px-5 py-3 flex items-center gap-3">
                  <span className="text-white font-black text-base">🔀</span>
                  <span className="text-white font-bold text-base">How the order and every step is decided — the full decision chain</span>
                </div>
                <div className="bg-white p-5 space-y-5">

                  <p className="text-sm text-slate-600 leading-relaxed">
                    There is <strong>no preset order</strong> for the 4 operation types. The sequence — which operations fire, in what order, with what amount — is entirely determined by the keystream bytes generated from the key and column IV. A different key, or a different column, produces a completely different sequence even for identical input values.
                  </p>

                  {/* Decision flowchart for a single sub-op */}
                  <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
                    <div className="text-xs font-bold text-slate-500 uppercase tracking-wide mb-4">Decision chain for one sub-operation (repeated 5× per character)</div>

                    <div className="flex flex-col gap-0">
                      {/* Step 1 */}
                      <div className="flex gap-4 items-start">
                        <div className="flex flex-col items-center shrink-0">
                          <div className="w-8 h-8 rounded-full bg-slate-700 text-white flex items-center justify-center font-black text-sm">1</div>
                          <div className="w-0.5 h-6 bg-slate-300 mt-1" />
                        </div>
                        <div className="pt-1 pb-6">
                          <div className="font-bold text-slate-700 text-sm mb-1">Consume the next keystream byte <code className="bg-slate-200 px-1.5 py-0.5 rounded font-mono text-xs">k</code></div>
                          <p className="text-xs text-slate-500 leading-relaxed">
                            The keystream is a deterministic sequence of numbers derived from the round key + column IV. For each character, 5 consecutive bytes are consumed — one per sub-op. This byte is the <em>only</em> source of randomness for this step.
                          </p>
                        </div>
                      </div>
                      {/* Step 2 */}
                      <div className="flex gap-4 items-start">
                        <div className="flex flex-col items-center shrink-0">
                          <div className="w-8 h-8 rounded-full bg-amber-500 text-white flex items-center justify-center font-black text-sm">2</div>
                          <div className="w-0.5 h-6 bg-slate-300 mt-1" />
                        </div>
                        <div className="pt-1 pb-6">
                          <div className="font-bold text-slate-700 text-sm mb-1">Compute <code className="bg-amber-100 px-1.5 py-0.5 rounded font-mono text-xs">k mod 4</code> → operation type (0, 1, 2, or 3)</div>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2">
                            {([
                              { r: "= 0", name: "Add", c: "bg-amber-50 border-amber-300 text-amber-800" },
                              { r: "= 1", name: "Subtract", c: "bg-red-50 border-red-300 text-red-700" },
                              { r: "= 2", name: "Multiply", c: "bg-violet-50 border-violet-300 text-violet-700" },
                              { r: "= 3", name: "Flip", c: "bg-teal-50 border-teal-300 text-teal-700" },
                            ] as const).map(o => (
                              <div key={o.r} className={`rounded-lg border px-3 py-2 text-xs ${o.c}`}>
                                <div className="font-mono font-black">{o.r}</div>
                                <div className="font-bold mt-0.5">{o.name}</div>
                              </div>
                            ))}
                          </div>
                          <p className="text-xs text-slate-400 mt-2">
                            Because any integer mod 4 gives exactly one of {"{0,1,2,3}"}, each byte maps to exactly one operation. The four outcomes are roughly equally likely (each has probability ~¼ over all key values).
                          </p>
                        </div>
                      </div>
                      {/* Step 3 */}
                      <div className="flex gap-4 items-start">
                        <div className="flex flex-col items-center shrink-0">
                          <div className="w-8 h-8 rounded-full bg-violet-600 text-white flex items-center justify-center font-black text-sm">3</div>
                          <div className="w-0.5 h-6 bg-slate-300 mt-1" />
                        </div>
                        <div className="pt-1 pb-6">
                          <div className="font-bold text-slate-700 text-sm mb-1">Compute <code className="bg-violet-100 px-1.5 py-0.5 rounded font-mono text-xs">⌊k / 4⌋</code> → raw upper bits → derive the amount or multiplier</div>
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-2">
                            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs">
                              <div className="font-bold text-slate-600 mb-1">For Add / Subtract:</div>
                              <div className="font-mono text-slate-700">amt = (⌊k/4⌋ mod (S−1)) + 1</div>
                              <div className="text-slate-400 mt-1">Always 1 to S−1. Never 0 (a shift of 0 does nothing) and never S (which wraps to 0).</div>
                            </div>
                            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs">
                              <div className="font-bold text-slate-600 mb-1">For Multiply:</div>
                              <div className="font-mono text-slate-700">idx = ⌊k/4⌋ mod len(coprimes)</div>
                              <div className="text-slate-400 mt-1">Indexes into the precomputed coprime list for this alphabet. Guarantees a valid invertible multiplier.</div>
                            </div>
                            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs">
                              <div className="font-bold text-slate-600 mb-1">For Flip:</div>
                              <div className="font-mono text-slate-700">⌊k/4⌋ is ignored</div>
                              <div className="text-slate-400 mt-1">Flip needs no amount — the mirror is always S−1−v regardless of the key byte's upper bits.</div>
                            </div>
                          </div>
                        </div>
                      </div>
                      {/* Step 4 */}
                      <div className="flex gap-4 items-start">
                        <div className="flex flex-col items-center shrink-0">
                          <div className="w-8 h-8 rounded-full bg-emerald-600 text-white flex items-center justify-center font-black text-sm">4</div>
                          <div className="w-0.5 h-6 bg-slate-300 mt-1" />
                        </div>
                        <div className="pt-1 pb-6">
                          <div className="font-bold text-slate-700 text-sm mb-1">Apply the operation to the current position <code className="bg-emerald-100 px-1.5 py-0.5 rounded font-mono text-xs">v</code> → get new position <code className="bg-emerald-100 px-1.5 py-0.5 rounded font-mono text-xs">v'</code></div>
                          <p className="text-xs text-slate-500 leading-relaxed">
                            The result is always kept within bounds using <code className="bg-slate-100 px-1 rounded font-mono text-xs">mod S</code>, so the output is always a valid alphabet index. The position <code className="bg-slate-100 px-1 rounded font-mono text-xs">v'</code> becomes the input <code className="bg-slate-100 px-1 rounded font-mono text-xs">v</code> for the next sub-op.
                          </p>
                        </div>
                      </div>
                      {/* Step 5 */}
                      <div className="flex gap-4 items-start">
                        <div className="flex flex-col items-center shrink-0">
                          <div className="w-8 h-8 rounded-full bg-indigo-600 text-white flex items-center justify-center font-black text-sm">5</div>
                        </div>
                        <div className="pt-1">
                          <div className="font-bold text-slate-700 text-sm mb-1">After sub-op 5: convert final position back to a character</div>
                          <p className="text-xs text-slate-500 leading-relaxed">
                            The final <code className="bg-slate-100 px-1 rounded font-mono text-xs">v'</code> is offset back to the character's ASCII range (digits → +48, uppercase → +65, lowercase → +97) to produce the encrypted character. This is the output that appears in the anonymized value.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Why 5 sub-ops, not 1 or 10 */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                      <div className="font-bold text-slate-700 text-sm mb-2">Why 5 sub-ops per character?</div>
                      <p className="text-xs text-slate-500 leading-relaxed">
                        5 gives a high probability that all 4 operation types appear at least once per character per round (probability ≈ 94%). Fewer sub-ops (e.g. 1 or 2) leave a large chance that only one type of operation fires, making the scrambling statistically detectable.
                      </p>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                      <div className="font-bold text-slate-700 text-sm mb-2">Why is the order random, not fixed?</div>
                      <p className="text-xs text-slate-500 leading-relaxed">
                        A fixed order (e.g. always Add → Subtract → Multiply → Flip → Add) would be a known pattern. An attacker who sees enough encrypted values could reverse-engineer the order and reduce the problem to guessing 4 amounts instead of 5 operation+amount pairs. Randomising the order via the keystream makes each position an independent unknown.
                      </p>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                      <div className="font-bold text-slate-700 text-sm mb-2">Why does each sub-op get its own key byte?</div>
                      <p className="text-xs text-slate-500 leading-relaxed">
                        Reusing the same byte for multiple sub-ops would create correlation — the operation type and amount of sub-op 1 would perfectly predict those of sub-op 2. Using 5 independent bytes from the keystream means each sub-op's type and amount are independently random given the key.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Operation cards */}
              <div className="text-xs font-bold text-slate-500 uppercase tracking-wide mb-3">The 4 operation types in detail</div>
              <div className="space-y-5 mb-6">

                {/* Op 0: Add */}
                <div className="rounded-xl border-2 border-amber-200 overflow-hidden">
                  <div className="bg-amber-50 px-4 py-3 flex items-center gap-3">
                    <span className="bg-amber-400 text-white text-xs font-black px-2.5 py-1 rounded-full">Type 0</span>
                    <span className="font-bold text-amber-900 text-base">Add</span>
                    <span className="ml-auto font-mono text-xs bg-amber-100 text-amber-700 border border-amber-300 px-2 py-0.5 rounded">k mod 4 = 0</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 text-xs text-amber-800">
                      <strong>Why chosen:</strong> The simplest reversible shift. It covers the "move forward" direction and is the easiest to understand and verify. It also cancels perfectly with Subtract, making the net effect of a forward+backward pair indeterminate without knowing both key bytes.
                    </div>
                    <p className="text-sm text-slate-600 leading-relaxed">
                      <strong>In plain English:</strong> Shift the character's alphabet position forward by <code className="bg-slate-100 px-1 rounded text-xs">amt</code> steps. Wrap around if you go past the end (like clock arithmetic — going past midnight loops back to 12).
                    </p>
                    <div className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
                      <span className="font-semibold text-slate-600">Example:</span> digit '3' (position 3 in 0–9) + amt 5 → position 8 → character '8'
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-emerald-600 uppercase mb-1.5">🔒 Encrypt</div>
                        <div className="font-mono text-sm text-emerald-800 font-bold">v' = (v + amt) mod S</div>
                      </div>
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-blue-600 uppercase mb-1.5">🔓 Decrypt</div>
                        <div className="font-mono text-sm text-blue-800 font-bold">v = (v' − amt + S) mod S</div>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-slate-500 uppercase mb-1.5">📐 Amount</div>
                        <div className="font-mono text-xs text-slate-700">(⌊k/4⌋ mod (S−1)) + 1</div>
                        <div className="text-[10px] text-slate-400 mt-1">Always 1 to S−1</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Op 1: Subtract */}
                <div className="rounded-xl border-2 border-red-200 overflow-hidden">
                  <div className="bg-red-50 px-4 py-3 flex items-center gap-3">
                    <span className="bg-red-500 text-white text-xs font-black px-2.5 py-1 rounded-full">Type 1</span>
                    <span className="font-bold text-red-900 text-base">Subtract</span>
                    <span className="ml-auto font-mono text-xs bg-red-100 text-red-700 border border-red-300 px-2 py-0.5 rounded">k mod 4 = 1</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-xs text-red-800">
                      <strong>Why chosen:</strong> The mirror of Add. Including both directions means the sequence of operations can partially or fully cancel itself (e.g. +3 then −3 = net 0), which is unpredictable without knowing all 5 key bytes. It also ensures that the value can reach any position in the alphabet regardless of starting point.
                    </div>
                    <p className="text-sm text-slate-600 leading-relaxed">
                      <strong>In plain English:</strong> Shift the character's position backward by <code className="bg-slate-100 px-1 rounded text-xs">amt</code> steps. Wrap around from the beginning back to the end if needed.
                    </p>
                    <div className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
                      <span className="font-semibold text-slate-600">Example:</span> digit '2' (position 2) − amt 5 → 2 − 5 + 10 = 7 → character '7' (the +10 prevents going below 0)
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-emerald-600 uppercase mb-1.5">🔒 Encrypt</div>
                        <div className="font-mono text-sm text-emerald-800 font-bold">v' = (v − amt + S) mod S</div>
                      </div>
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-blue-600 uppercase mb-1.5">🔓 Decrypt</div>
                        <div className="font-mono text-sm text-blue-800 font-bold">v = (v' + amt) mod S</div>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-slate-500 uppercase mb-1.5">📐 Amount</div>
                        <div className="font-mono text-xs text-slate-700">(⌊k/4⌋ mod (S−1)) + 1</div>
                        <div className="text-[10px] text-slate-400 mt-1">Always 1 to S−1</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Op 2: Multiply */}
                <div className="rounded-xl border-2 border-violet-200 overflow-hidden">
                  <div className="bg-violet-50 px-4 py-3 flex items-center gap-3">
                    <span className="bg-violet-600 text-white text-xs font-black px-2.5 py-1 rounded-full">Type 2</span>
                    <span className="font-bold text-violet-900 text-base">Multiply (coprime)</span>
                    <span className="ml-auto font-mono text-xs bg-violet-100 text-violet-700 border border-violet-300 px-2 py-0.5 rounded">k mod 4 = 2</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="bg-violet-50 border border-violet-200 rounded-lg px-3 py-2 text-xs text-violet-800">
                      <strong>Why chosen:</strong> Multiplication is a qualitatively different transformation from addition — it stretches the alphabet non-uniformly. Without it, all five sub-ops would be additive shifts, and their combined effect could be reduced to a single net shift (the sum mod S). Multiply breaks this linearity entirely, making the combined effect impossible to collapse into a simpler form without knowing which sub-ops were multiplicative.
                    </div>
                    <p className="text-sm text-slate-600 leading-relaxed">
                      <strong>In plain English:</strong> Multiply the character's position by a special number (<code className="bg-slate-100 px-1 rounded text-xs">mul</code>) then wrap around. The multiplier is always <em>coprime</em> to the alphabet size — this guarantees every position maps to a unique new position and the operation is perfectly reversible.
                    </p>
                    <div className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
                      <span className="font-semibold text-slate-600">Example:</span> digit '3' (position 3) × 7 = 21 → 21 mod 10 = 1 → '1'. Decrypt: 1 × 3 (the modular inverse of 7 mod 10) = 3 ✓
                    </div>
                    <div className="bg-violet-50 border border-violet-200 rounded-lg px-3 py-2 text-xs text-violet-800">
                      <strong>Coprime multipliers used:</strong> first digit (S=9) → {'{'}2,4,5,7,8{'}'} &nbsp;|&nbsp; other digits (S=10) → {'{'}3,7,9{'}'} &nbsp;|&nbsp; letters (S=26) → {'{'}3,5,7,9,11,15,17,19,21,23,25{'}'} &nbsp;|&nbsp; symbols (S=33) → {'{'}2,4,5,7,8,10,13,14,16,17,19,20,23,25,26,28,29,31,32{'}'}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-emerald-600 uppercase mb-1.5">🔒 Encrypt</div>
                        <div className="font-mono text-sm text-emerald-800 font-bold">v' = (v × mul) mod S</div>
                      </div>
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-blue-600 uppercase mb-1.5">🔓 Decrypt</div>
                        <div className="font-mono text-sm text-blue-800 font-bold">v = (v' × mul⁻¹) mod S</div>
                        <div className="text-[10px] text-blue-500 mt-1">mul⁻¹ = modular inverse of mul</div>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-slate-500 uppercase mb-1.5">📐 Multiplier</div>
                        <div className="font-mono text-xs text-slate-700">indexed from coprime list</div>
                        <div className="text-[10px] text-slate-400 mt-1">Unique inverse always exists</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Op 3: Flip */}
                <div className="rounded-xl border-2 border-teal-200 overflow-hidden">
                  <div className="bg-teal-50 px-4 py-3 flex items-center gap-3">
                    <span className="bg-teal-600 text-white text-xs font-black px-2.5 py-1 rounded-full">Type 3</span>
                    <span className="font-bold text-teal-900 text-base">Flip / Complement</span>
                    <span className="ml-auto font-mono text-xs bg-teal-100 text-teal-700 border border-teal-300 px-2 py-0.5 rounded">k mod 4 = 3</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="bg-teal-50 border border-teal-200 rounded-lg px-3 py-2 text-xs text-teal-800">
                      <strong>Why chosen:</strong> Flip introduces a reflection that neither addition nor multiplication can replicate. It is self-inverse (no extra key material needed to reverse it), and it is the only operation that maps the midpoint of the alphabet to itself — a fixed point — while moving all other values. This property means it interacts with the other operations in a genuinely non-linear way. It also saturates all 4 possible values of <code className="bg-teal-100 px-1 rounded font-mono">k mod 4</code>, so each byte of the keystream maps to an assigned role with no gaps.
                    </div>
                    <p className="text-sm text-slate-600 leading-relaxed">
                      <strong>In plain English:</strong> Mirror the character to the opposite end of the alphabet — '0' swaps with '9', 'a' swaps with 'z', 'A' swaps with 'Z'. Applying it twice always returns the original, so no key material is needed to decrypt.
                    </p>
                    <div className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">
                      <span className="font-semibold text-slate-600">All digit swaps:</span> '0'↔'9' &nbsp; '1'↔'8' &nbsp; '2'↔'7' &nbsp; '3'↔'6' &nbsp; '4'↔'5'
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-emerald-600 uppercase mb-1.5">🔒 Encrypt</div>
                        <div className="font-mono text-sm text-emerald-800 font-bold">v' = S − 1 − v</div>
                      </div>
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-blue-600 uppercase mb-1.5">🔓 Decrypt</div>
                        <div className="font-mono text-sm text-blue-800 font-bold">Same operation</div>
                        <div className="text-[10px] text-blue-500 mt-1">Self-inverse (involutory)</div>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
                        <div className="text-[10px] font-bold text-slate-500 uppercase mb-1.5">📐 Amount</div>
                        <div className="font-mono text-xs text-slate-700">None needed</div>
                        <div className="text-[10px] text-slate-400 mt-1">Apply twice → original</div>
                      </div>
                    </div>
                  </div>
                </div>

              </div>

              <div className="rounded-xl bg-slate-100 border border-slate-200 p-4 flex gap-3 items-start text-sm text-slate-600">
                <span className="text-lg leading-none">ℹ️</span>
                <div>
                  <strong>Symbols, spaces, and punctuation</strong> — All printable keyboard symbols (S=33 alphabet: <code className="font-mono bg-white rounded px-1">{'  !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'}</code>) are now encrypted just like digits and letters — they map to a different symbol on output. Only non-printable control characters are left unchanged.
                </div>
              </div>
            </BigCard>
            {/* Round selector + visualization — full bleed */}
            <div className="-mx-4 bg-slate-50 border-y-2 border-slate-200 px-6 py-6">
              <h3 className="font-bold text-slate-700 mb-4">🔄 Explore Each Encryption Round</h3>
              <div className="flex gap-3 justify-center mb-5">
                {[0,1,2,3].map(i => (
                  <button key={i} onClick={() => setEncRoundIdx(i)}
                    className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all ${encRoundIdx === i ? "bg-green-600 text-white shadow-lg" : "bg-white border-2 border-slate-200 text-slate-600 hover:bg-slate-100"}`}>
                    Round {i+1}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-6 mb-5 p-5 bg-white rounded-xl border border-slate-200">
                <div className="text-center flex-1">
                  <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Input to Round {encRoundIdx+1}</div>
                  <ValuePill value={trace.encStages[encRoundIdx]} color="text-blue-700 bg-blue-50 border-2 border-blue-200" />
                </div>
                <div className="text-center shrink-0">
                  <div className="text-xs text-slate-400 mb-1">Key {encRoundIdx+1}</div>
                  <ArrowRight className="w-8 h-8 text-green-400" />
                </div>
                <div className="text-center flex-1">
                  <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Output of Round {encRoundIdx+1}</div>
                  <ValuePill value={trace.encStages[encRoundIdx+1]} color="text-green-700 bg-green-50 border-2 border-green-200" />
                </div>
              </div>
              {(() => {
                const roundInput = trace.encStages[encRoundIdx];
                return (
                  <>
                    <div className="flex flex-wrap gap-2 justify-center mb-4">
                      {encShifts.slice(0, 12).map((s, i) => <ShiftBubble key={i} shift={s} />)}
                      {encShifts.length > 12 && <div className="flex items-center text-slate-400 text-sm italic">+{encShifts.length - 12} more…</div>}
                    </div>
                    {/* Legend */}
                    <div className="flex items-center gap-4 text-xs flex-wrap justify-center mb-5">
                      <span><span className="font-mono font-bold text-blue-600">X</span> = input</span>
                      <span className="flex items-center gap-1"><span className="text-[9px] font-bold border rounded px-1 py-px bg-amber-100 text-amber-800 border-amber-300">+N</span> add</span>
                      <span className="flex items-center gap-1"><span className="text-[9px] font-bold border rounded px-1 py-px bg-red-100 text-red-700 border-red-300">−N</span> subtract</span>
                      <span className="flex items-center gap-1"><span className="text-[9px] font-bold border rounded px-1 py-px bg-violet-100 text-violet-700 border-violet-300">×N</span> multiply</span>
                      <span className="flex items-center gap-1"><span className="text-[9px] font-bold border rounded px-1 py-px bg-teal-100 text-teal-700 border-teal-300">flip</span> complement</span>
                      <span><span className="font-mono font-bold text-green-600">Y</span> = output</span>
                      <span><span className="font-mono font-bold text-slate-400">—</span> symbol</span>
                    </div>

                    {/* Per-character 5-op derivation table */}
                    <div className="rounded-xl border border-slate-200 overflow-hidden">
                      <div className="bg-slate-800 px-6 py-4 border-b border-slate-700 flex flex-wrap items-center gap-3">
                        <span className="text-base font-bold text-white">🔢 5-Operation Derivation — Round {encRoundIdx+1}</span>
                        <span className="text-xs text-slate-400">Each character passes through 5 independent sub-operations, one keystream byte per step</span>
                      </div>
                      {/* Column guide */}
                      <div className="bg-slate-700 px-6 py-3 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-x-8 gap-y-2 text-[11px] text-slate-300 border-b border-slate-600">
                        <span><span className="font-bold text-white">Char</span> — input → output character</span>
                        <span><span className="font-bold text-white">Step</span> — sub-op number (1–5)</span>
                        <span><span className="font-bold text-white">k byte</span> — raw keystream value</span>
                        <span><span className="font-bold text-white">k mod 4</span> — selects operation type (0–3)</span>
                        <span><span className="font-bold text-white">⌊k/4⌋</span> — upper bits, used to derive amount</span>
                        <span><span className="font-bold text-white">Operation</span> — which of the 4 types is applied</span>
                        <span><span className="font-bold text-white">Amount</span> — the shift/multiplier used</span>
                        <span><span className="font-bold text-white">Alphabet (S)</span> — character class &amp; alphabet size</span>
                        <span><span className="font-bold text-white">v before → after</span> — position index before &amp; after</span>
                        <span><span className="font-bold text-white">Full Working</span> — the complete arithmetic</span>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm min-w-[1100px]">
                          <thead>
                            <tr className="border-b-2 border-slate-200 bg-slate-50">
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Char</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Step</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">k byte</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">k mod 4</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">⌊k/4⌋</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Operation</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Amount</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Alphabet (S)</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">v before → after</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Full Working</th>
                              <th className="px-4 py-3 text-left text-slate-500 font-bold text-[11px] uppercase tracking-wide">Result</th>
                            </tr>
                          </thead>
                          <tbody>
                            {encShifts.flatMap((s, ci) => {
                              const OP_NAMES = ["Add", "Subtract", "Multiply", "Flip"];
                              const OP_BADGE = [
                                "text-amber-800 bg-amber-100 border-amber-300",
                                "text-red-700 bg-red-100 border-red-300",
                                "text-violet-700 bg-violet-100 border-violet-300",
                                "text-teal-700 bg-teal-100 border-teal-300",
                              ];
                              const OP_DOT = ["bg-amber-400", "bg-red-400", "bg-violet-500", "bg-teal-500"];
                              const CHAR_BG = ci % 2 === 0 ? "bg-white" : "bg-blue-50/30";
                              const sep = ci > 0 ? [
                                <tr key={`sep-${ci}`}><td colSpan={11} className="h-0 border-t-2 border-slate-200 p-0" /></tr>
                              ] : [];

                              const alphabetLabel = (size: number) => {
                                if (size === 9)  return "digits 1–9 (S=9)";
                                if (size === 10) return "digits 0–9 (S=10)";
                                if (size === 26) return s.from >= 'a' && s.from <= 'z' ? "a–z lowercase (S=26)" : "A–Z uppercase (S=26)";
                                if (size === 33) return "symbols (S=33)";
                                return `S=${size}`;
                              };

                              if (s.microOps.length === 0) {
                                return [
                                  ...sep,
                                  <tr key={`s-${ci}`} className={`${CHAR_BG}`}>
                                    <td colSpan={11} className="px-4 py-4">
                                      <div className="flex items-center gap-3">
                                        <span className="font-mono font-black text-xl text-slate-500">{s.from}</span>
                                        {s.isLeadingZeroPassthrough
                                          ? <span className="text-xs text-amber-700 bg-amber-50 border border-amber-300 rounded-full px-4 py-1.5 font-semibold">
                                              First digit '0' — passed through unchanged (leading-zero preservation); five keystream bytes are still consumed for synchronization.
                                            </span>
                                          : <span className="text-xs text-slate-400 bg-slate-100 border border-slate-200 rounded-full px-4 py-1.5">
                                              Non-printable character — passed through unchanged; five keystream bytes are still consumed for synchronization.
                                            </span>
                                        }
                                      </div>
                                    </td>
                                  </tr>
                                ];
                              }
                              return [
                                ...sep,
                                ...s.microOps.map((op, mi) => {
                                  const isFirst = mi === 0;
                                  const isLast = mi === s.microOps.length - 1;
                                  const kMod4 = op.k % 4;
                                  const kDiv4 = Math.floor(op.k / 4);
                                  const formulaTemplate = op.opType === 0
                                    ? `(v + amt) mod S`
                                    : op.opType === 1
                                    ? `(v − amt + S) mod S`
                                    : op.opType === 2
                                    ? `(v × mul) mod S`
                                    : `S − 1 − v`;
                                  const math = op.opType === 0
                                    ? `(${op.vBefore} + ${op.amount}) mod ${op.size} = ${op.vAfter}`
                                    : op.opType === 1
                                    ? `(${op.vBefore} − ${op.amount} + ${op.size}) mod ${op.size} = ${op.vAfter}`
                                    : op.opType === 2
                                    ? `(${op.vBefore} × ${op.amount}) mod ${op.size} = ${op.vAfter}`
                                    : `${op.size} − 1 − ${op.vBefore} = ${op.vAfter}`;
                                  return (
                                    <tr key={`${ci}-${mi}`} className={`${CHAR_BG} border-b border-slate-100`}>
                                      {/* Char — only first row */}
                                      <td className="px-4 py-3.5 align-middle">
                                        {isFirst ? (
                                          <div className="flex flex-col gap-1">
                                            <div className="flex items-center gap-1.5">
                                              <span className="font-mono font-black text-xl text-blue-600">{s.from}</span>
                                              <span className="text-slate-300 text-lg">→</span>
                                              <span className="font-mono font-black text-xl text-green-600">{s.to}</span>
                                            </div>
                                            <span className="text-[10px] text-slate-400 whitespace-nowrap">5 sub-ops</span>
                                          </div>
                                        ) : (
                                          <div className="flex justify-center"><div className="w-0.5 h-5 bg-slate-200 rounded-full" /></div>
                                        )}
                                      </td>
                                      {/* Step */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex items-center gap-2">
                                          <div className={`w-6 h-6 rounded-full ${OP_DOT[op.opType]} flex items-center justify-center text-white text-xs font-black shrink-0`}>{mi+1}</div>
                                          <span className="text-[10px] text-slate-400">/ 5</span>
                                        </div>
                                      </td>
                                      {/* k byte */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <span className="font-mono font-bold text-sm bg-amber-50 text-amber-800 border border-amber-300 rounded-lg px-3 py-1.5">{op.k}</span>
                                      </td>
                                      {/* k mod 4 */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex flex-col gap-0.5">
                                          <span className="font-mono text-xs text-slate-500">{op.k} mod 4</span>
                                          <span className={`font-bold text-base font-mono ${["text-amber-700","text-red-600","text-violet-700","text-teal-600"][op.opType]}`}>= {kMod4}</span>
                                        </div>
                                      </td>
                                      {/* ⌊k/4⌋ */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex flex-col gap-0.5">
                                          <span className="font-mono text-xs text-slate-500">⌊{op.k}/4⌋</span>
                                          <span className="font-bold text-base font-mono text-slate-700">= {kDiv4}</span>
                                        </div>
                                      </td>
                                      {/* Operation + formula */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex flex-col gap-1">
                                          <span className={`font-bold text-xs border rounded-lg px-2.5 py-1 w-fit ${OP_BADGE[op.opType]}`}>{OP_NAMES[op.opType]}</span>
                                          <span className="font-mono text-[10px] text-slate-400">{formulaTemplate}</span>
                                        </div>
                                      </td>
                                      {/* Amount */}
                                      <td className="px-4 py-3.5 align-middle">
                                        {op.opType === 3 ? (
                                          <span className="text-slate-300 text-sm">— (none)</span>
                                        ) : (
                                          <div className="flex flex-col gap-0.5">
                                            <span className="font-mono font-black text-lg text-slate-800">{op.amount}</span>
                                            {op.opType === 2
                                              ? <span className="text-[10px] text-slate-400">coprimes[{kDiv4} mod n]</span>
                                              : <span className="text-[10px] text-slate-400">(⌊k/4⌋ mod (S−1)) + 1</span>
                                            }
                                          </div>
                                        )}
                                      </td>
                                      {/* Alphabet */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex flex-col gap-1">
                                          <span className={`text-xs bg-slate-100 border border-slate-200 rounded-lg px-2 py-1 whitespace-nowrap ${op.isFirstDigit ? "text-amber-700 bg-amber-50 border-amber-300" : "text-slate-500"}`}>{alphabetLabel(op.size)}</span>
                                          {op.isFirstDigit && <span className="text-[9px] text-amber-600 font-semibold whitespace-nowrap">leading zero prevention</span>}
                                        </div>
                                      </td>
                                      {/* v before → after */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex items-center gap-2 font-mono">
                                          <div className="flex flex-col items-center">
                                            <span className="text-[9px] text-slate-400 uppercase">before</span>
                                            <span className="text-base font-bold text-slate-600">{op.vBefore}</span>
                                          </div>
                                          <span className="text-slate-300 text-lg">→</span>
                                          <div className="flex flex-col items-center">
                                            <span className="text-[9px] text-indigo-400 uppercase">after</span>
                                            <span className="text-base font-black text-indigo-600">{op.vAfter}</span>
                                          </div>
                                        </div>
                                      </td>
                                      {/* Full Working */}
                                      <td className="px-4 py-3.5 align-middle">
                                        <div className="flex flex-col gap-1">
                                          <span className="font-mono text-xs text-slate-700 bg-slate-100 border border-slate-200 rounded-lg px-3 py-1.5 whitespace-nowrap">{math}</span>
                                          {isLast && (
                                            <span className="text-xs font-bold text-green-700 whitespace-nowrap">✓ position {op.vAfter} → char '{s.to}'</span>
                                          )}
                                        </div>
                                      </td>
                                      {/* Result */}
                                      <td className="px-4 py-3.5 align-middle">
                                        {isLast ? (
                                          <div className="flex flex-col items-center gap-0.5">
                                            <span className="font-mono font-black text-2xl text-green-600">{s.to}</span>
                                            <span className="text-[9px] text-green-500 uppercase font-bold">done</span>
                                          </div>
                                        ) : (
                                          <span className="text-slate-200 text-sm">·</span>
                                        )}
                                      </td>
                                    </tr>
                                  );
                                })
                              ];
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </>
                );
              })()}
            </div>

            {/* Why 4 rounds */}
            <BigCard color="bg-white border-slate-200">
              <h3 className="text-lg font-bold text-slate-800 mb-3">🔗 Why 4 Rounds Instead of 1?</h3>
              <div className="grid grid-cols-2 gap-5">
                <div>
                  <p className="text-slate-500 text-sm leading-relaxed mb-3">With 1 round, an attacker who sees many anonymized values might spot statistical patterns. The distribution of output characters would still roughly reflect the input distribution.</p>
                  <p className="text-slate-500 text-sm leading-relaxed mb-3">With 4 independent rounds (each using a different key), any correlation between input and output is multiplied through 4 layers of independent random shifts. The probability of guessing the original from the anonymized value falls dramatically.</p>
                  <p className="text-slate-500 text-sm leading-relaxed">Think of it like painting over a wall 4 times with 4 different colours — you can't tell the original colour by looking at the surface.</p>
                </div>
                <div className="rounded-xl bg-slate-50 border border-slate-200 p-4">
                  <div className="text-slate-600 text-xs font-bold uppercase mb-3">Value after each round:</div>
                  {trace.encStages.map((s, i) => (
                    <div key={i} className="flex items-center gap-3 mb-2">
                      <span className="text-xs text-slate-500 w-16 text-right shrink-0">{i === 0 ? "Original" : `Round ${i}`}</span>
                      <span className={`font-mono font-bold px-3 py-1 rounded-lg ${i === 0 ? "text-blue-700 bg-blue-100" : i === 4 ? "text-green-700 bg-green-100" : "text-slate-600 bg-slate-100"}`}>{s}</span>
                    </div>
                  ))}
                </div>
              </div>
            </BigCard>

            <div className="rounded-2xl bg-green-50 border border-green-200 p-6 text-center">
              <div className="text-green-700 text-sm font-semibold uppercase tracking-wide mb-2">Final Anonymized Value</div>
              <ValuePill value={trace.finalEncrypted} color="text-green-700 bg-green-100 border-2 border-green-400" />
              <p className="text-green-600 text-sm mt-3">This is what gets written to the CSV. Without all 4 seeds in the correct order, there is no way to reverse this.</p>
            </div>
          </div>
        )}

        {/* ══ STEP 3: Decryption ══════════════════════════════════════ */}
        {step === 3 && (
          <div className="w-full space-y-8">
            <div className="text-center">
              <div className="text-5xl mb-4">🔓</div>
              <h2 className="text-3xl font-bold text-slate-800 mb-3">Unscrambling the Value</h2>
              <p className="text-lg text-slate-500 leading-relaxed">
                Decryption uses the <strong>same keys and the same keystream</strong> — but applies the shift <em>backwards</em> and works through the rounds in <em>reverse order</em>. Here's the full picture.
              </p>
            </div>

            {/* Enc vs Dec formulas side by side */}
            <BigCard color="bg-white border-violet-200">
              <h3 className="text-lg font-bold text-slate-800 mb-2">↔️ Encryption vs. Decryption — The Exact Formulas</h3>
              <p className="text-slate-500 text-sm leading-relaxed mb-5">
                Both paths consume the <strong>same five keystream bytes</strong> for each character. Encryption applies five forward micro-operations; decryption applies their mathematical inverses in reverse order. The operation type comes from <span className="font-mono bg-slate-100 px-1 rounded">k % 4</span>, and all arithmetic stays inside the character class alphabet.
              </p>
              <div className="overflow-x-auto rounded-xl border border-slate-200">
                <table className="w-full text-xs border-collapse">
                  <thead><tr className="bg-slate-100">
                    <th className="px-3 py-2.5 text-left text-slate-600">Character type</th>
                    <th className="px-3 py-2.5 text-left text-green-700">🔐 Encrypt</th>
                    <th className="px-3 py-2.5 text-left text-violet-700">🔓 Decrypt</th>
                    <th className="px-3 py-2.5 text-left text-slate-500">Why it's the inverse</th>
                  </tr></thead>
                  <tbody>
                    {[
                      ["First digit '1'–'9'", "v = c−49; apply 5 forward ops with S=9; output = 49+v (always '1'–'9')", "Start at v = c−49; apply inverse ops 5→1 with S=9; output = 49+v", "S=9 (alphabet 1–9) guarantees the first character of the output is never '0'. All 4 rounds use this alphabet at position 0, so intermediates are always in '1'–'9' and decryption can mirror the choice exactly."],
                      ["First digit '0'", "passed through unchanged; 5 keystream bytes consumed for sync", "passed through unchanged; 5 keystream bytes consumed for sync", "Edge case: '0' cannot be represented in the 1–9 alphabet, so it is preserved as-is across all rounds. The encrypted value will also start with '0'."],
                      ["Other digits (0–9)", "v = c−48; apply 5 forward ops with S=10; output = 48+v", "Start at v = c−48; apply inverse ops 5→1 with S=10; output = 48+v", "Standard alphabet for all digit positions other than the first."],
                      ["Uppercase (A–Z)", "v = c−65; apply 5 forward ops with S=26; output = 65+v", "Start at v = c−65; apply inverse ops 5→1 with S=26; output = 65+v", "The same five bytes and operation parameters are reconstructed from the key stream."],
                      ["Lowercase (a–z)", "v = c−97; apply 5 forward ops with S=26; output = 97+v", "Start at v = c−97; apply inverse ops 5→1 with S=26; output = 97+v", "Same as uppercase, with base 97; case is preserved."],
                      ["Printable symbol", "symIdx = SYMBOL_CHARS.indexOf(c); apply 5 forward ops with S=33; output = SYMBOL_CHARS[v]", "symIdx = SYMBOL_CHARS.indexOf(c); apply inverse ops 5→1 with S=33; output = SYMBOL_CHARS[v]", "Symbols map to symbols within the 33-character printable-symbol alphabet, so character class is preserved — a symbol in, a symbol out."],
                      ["Non-printable / other", "unchanged", "unchanged", "Control characters and non-ASCII bytes are never transformed."],
                    ].map(([type, enc, dec, why]) => (
                      <tr key={type as string} className="border-t border-slate-100">
                        <td className="px-3 py-3 font-semibold text-slate-700 align-top">{type}</td>
                        <td className="px-3 py-3 font-mono text-green-800 bg-green-50 align-top">{enc}</td>
                        <td className="px-3 py-3 font-mono text-violet-800 bg-violet-50 align-top">{dec}</td>
                        <td className="px-3 py-3 text-slate-500 leading-relaxed align-top">{why}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="mt-4 bg-amber-50 border border-amber-200 rounded-xl p-4 text-xs text-amber-800">
                <strong>Proof it works:</strong> each micro-operation is bijective on its alphabet. Decryption reads the same five bytes in reverse order and applies each inverse, so the complete five-operation round returns every digit or letter to its original position.
              </div>
            </BigCard>

            {/* Why reverse order is essential */}
            <BigCard color="bg-white border-rose-200">
              <h3 className="text-lg font-bold text-slate-800 mb-3">🔁 Why Reverse Order Is Essential</h3>
              <div className="grid grid-cols-2 gap-5">
                <div>
                  <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-3">
                    <div className="font-bold text-red-700 mb-2 text-sm">❌ Wrong: Decrypting the rounds in forward order (1→2→3→4)</div>
                    <div className="text-xs text-red-600 leading-relaxed">
                      Round 1 decrypt is not the inverse of the outermost transformation. The value still has rounds 2–4 applied on top, so reversing in this order does not undo the composition.
                    </div>
                  </div>
                  <div className="bg-green-50 border border-green-200 rounded-xl p-4">
                    <div className="font-bold text-green-700 mb-2 text-sm">✅ Correct: Decrypting in reverse order (4→3→2→1)</div>
                    <div className="text-xs text-green-600 leading-relaxed">
                      Round 4 decrypt undoes <em>exactly</em> Round 4's shift — because the value we hold has had exactly Round 4 applied most recently. After removing Round 4, we see what Round 3 produced — which is exactly what Round 3 decrypt expects.
                    </div>
                  </div>
                </div>
                <div className="rounded-xl bg-slate-50 border border-slate-200 p-5">
                  <div className="text-slate-600 text-xs font-bold uppercase mb-3">Decryption chain (your values):</div>
                  {[...trace.decStages].map((s, i) => (
                    <div key={i} className="flex items-center gap-2 mb-2">
                      <span className="text-xs text-slate-500 w-20 text-right shrink-0">
                        {i === 0 ? "Encrypted" : `Undo R${4 - i + 1}`}
                      </span>
                      <span className={`font-mono font-bold px-2 py-1 rounded text-xs ${i === 0 ? "text-green-700 bg-green-100" : i === 4 ? "text-blue-700 bg-blue-100" : "text-slate-600 bg-slate-100"}`}>{s}</span>
                      {i < trace.decStages.length - 1 && <span className="text-xs text-violet-600">← Key {4-i}</span>}
                    </div>
                  ))}
                </div>
              </div>
            </BigCard>

            {/* What if seeds are wrong */}
            <BigCard color="bg-white border-slate-200">
              <h3 className="text-lg font-bold text-slate-800 mb-3">🔑 What Happens With Wrong Seeds?</h3>
              <p className="text-slate-500 text-sm leading-relaxed mb-4">
                If you try to decrypt with wrong seeds, the algorithm <strong>doesn't fail or give an error</strong> — it just produces a different, garbage value. This is intentional: an attacker can't tell whether their guessed seeds are right or wrong just from the output.
              </p>
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                  <div className="font-bold text-blue-700 mb-2">✅ Correct seeds [{seeds.join(", ")}]</div>
                  <div className="text-slate-500 mb-1">Encrypted:</div>
                  <div className="font-mono font-bold text-green-700">{trace.finalEncrypted}</div>
                  <div className="text-slate-500 mb-1 mt-2">Decrypted:</div>
                  <div className="font-mono font-bold text-blue-700">{trace.finalDecrypted}</div>
                  <div className="text-green-600 mt-1 font-semibold">✓ Matches original</div>
                </div>
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="font-bold text-slate-600 mb-2">❌ Wrong seed order [{seeds[1]}, {seeds[0]}, {seeds[2]}, {seeds[3]}]</div>
                  <div className="text-slate-500 mb-1">Decrypted:</div>
                  <div className="font-mono font-bold text-red-600 text-[10px]">{(() => {
                    const s = [seeds[1], seeds[0], seeds[2], seeds[3]];
                    return computeTrace(s, colName, trace.finalEncrypted).finalDecrypted.slice(0, 20);
                  })()}</div>
                  <div className="text-red-600 mt-1 font-semibold">✗ Garbage result</div>
                </div>
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="font-bold text-slate-600 mb-2">❌ Wrong column name "Salary"</div>
                  <div className="text-slate-500 mb-1">Decrypted:</div>
                  <div className="font-mono font-bold text-red-600 text-[10px]">{(() => {
                    const t2 = computeTrace(seeds, "Salary", trace.finalEncrypted);
                    return t2.finalDecrypted.slice(0, 20);
                  })()}</div>
                  <div className="text-red-600 mt-1 font-semibold">✗ Garbage result</div>
                </div>
              </div>
            </BigCard>

            {/* Interactive round explorer */}
            <div className="rounded-2xl bg-slate-50 border-2 border-slate-200 p-6">
              <h3 className="font-bold text-slate-700 mb-4">🔓 Explore Each Decryption Undo Round</h3>
              <div className="flex gap-3 justify-center mb-5">
                {[0,1,2,3].map(i => (
                  <button key={i} onClick={() => setDecRoundIdx(i)}
                    className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all ${decRoundIdx === i ? "bg-violet-600 text-white shadow-lg" : "bg-white border-2 border-slate-200 text-slate-600 hover:bg-slate-100"}`}>
                    Undo R{4-i}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-6 mb-5 p-5 bg-white rounded-xl border border-slate-200">
                <div className="text-center flex-1">
                  <div className="text-xs font-semibold text-slate-400 uppercase mb-2">
                    {decRoundIdx === 0 ? "Anonymized (start)" : `After undo ${decRoundIdx}`}
                  </div>
                  <ValuePill value={trace.decStages[decRoundIdx]} color="text-violet-700 bg-violet-50 border-2 border-violet-200" />
                </div>
                <div className="text-center shrink-0">
                  <div className="text-xs text-slate-400 mb-1">Key {4-decRoundIdx} reversed</div>
                  <ArrowRight className="w-8 h-8 text-violet-400" />
                </div>
                <div className="text-center flex-1">
                  <div className="text-xs font-semibold text-slate-400 uppercase mb-2">
                    {decRoundIdx === 3 ? "Original ✓" : `After undo ${decRoundIdx+1}`}
                  </div>
                  <ValuePill value={trace.decStages[decRoundIdx+1]} color={decRoundIdx === 3 ? "text-blue-700 bg-blue-50 border-2 border-blue-400" : "text-indigo-700 bg-indigo-50 border-2 border-indigo-200"} />
                </div>
              </div>
              <div className="flex flex-wrap gap-3 justify-center mb-3">
                {decShifts.slice(0,14).map((s,i) => <ShiftBubble key={i} shift={s} />)}
                {decShifts.length > 14 && <div className="flex items-center text-slate-400 text-sm italic">+{decShifts.length-14} more…</div>}
              </div>
              <div className="bg-blue-50 rounded-xl p-4 text-sm text-blue-800 mt-3">
                <strong>Same keystream bytes, reversed operations.</strong> The 5 keystream bytes per character for this round are <em>identical</em> to those used during encryption (same key → same PRNG output). But instead of applying the 5 sub-ops <em>forward</em>, decryption applies them in <em>reverse order</em>, using each operation’s mathematical inverse: add↔subtract, multiply↔divide by modular inverse, flip↔flip (its own inverse).
              </div>
            </div>

            <div className="rounded-2xl bg-blue-900 p-6 text-center">
              <div className="text-blue-300 text-sm font-semibold uppercase tracking-wide mb-2">Original Value Recovered</div>
              <ValuePill value={trace.finalDecrypted} color="text-blue-300 bg-blue-800 border-2 border-blue-600" />
              <div className="mt-3">
                <span className={`text-sm font-semibold px-3 py-1 rounded-full ${trace.finalDecrypted === (cellValue || "A") ? "bg-green-700 text-green-200" : "bg-red-800 text-red-200"}`}>
                  {trace.finalDecrypted === (cellValue || "A") ? "✓ Exactly matches the original!" : "⚠ Doesn't match — check your inputs"}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ══ STEP 4: Summary ═════════════════════════════════════════ */}
        {step === 4 && (
          <div className="w-full space-y-8">
            <div className="text-center">
              <div className="text-5xl mb-4">🎉</div>
              <h2 className="text-3xl font-bold text-slate-800 mb-3">The Full Journey</h2>
              <p className="text-lg text-slate-500 leading-relaxed">
                Here's everything that happened — with real numbers — plus the security properties that make this algorithm trustworthy.
              </p>
            </div>

            {/* ── Live System Trace Diagram ─────────────────────────── */}
            <div className="rounded-2xl bg-slate-50 border border-slate-200 overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200 text-center">
                <h3 className="text-slate-800 font-bold text-lg">🔍 Full System Trace — Your Actual Values</h3>
                <p className="text-slate-500 text-sm mt-1">Seeds [{seeds.join(", ")}] · Column "{colName}" · Value "{cellValue || "A"}"</p>
              </div>
              <div className="p-6 space-y-4">

                {/* Seeds */}
                <div className="flex items-stretch gap-3 justify-center">
                  {seeds.map((s, i) => (
                    <div key={i} className="bg-white border border-slate-200 rounded-xl px-5 py-3 text-center">
                      <div className="text-[10px] text-slate-500 font-semibold uppercase mb-1">Seed {i+1}</div>
                      <div className="font-mono font-bold text-slate-800 text-xl">{s}</div>
                    </div>
                  ))}
                </div>

                {/* Seeds → Master Seed arrow */}
                <div className="flex flex-col items-center gap-0.5">
                  <div className="w-px h-3 bg-slate-300"/>
                  <div className="text-[10px] text-slate-500 font-semibold">fold via rolling accumulator + MurmurHash3</div>
                  <ArrowDown className="w-4 h-4 text-slate-400"/>
                </div>

                {/* Master Seed */}
                <div className="mx-auto w-fit bg-indigo-50 border border-indigo-200 rounded-xl px-10 py-3 text-center">
                  <div className="text-[10px] text-indigo-600 font-semibold uppercase mb-1">Master Seed (32-bit)</div>
                  <div className="font-mono font-bold text-indigo-700 text-base">{"0x" + trace.masterSeed.toString(16).toUpperCase().padStart(8,"0")}</div>
                </div>

                {/* Master Seed → Master Key arrow */}
                <div className="flex flex-col items-center gap-0.5">
                  <div className="w-px h-3 bg-slate-300"/>
                  <div className="text-[10px] text-slate-500 font-semibold">xorshift128+(masterSeed ⊕ 0xDEADBEEF) → 32 bytes</div>
                  <ArrowDown className="w-4 h-4 text-slate-400"/>
                </div>

                {/* Master Key */}
                <div className="bg-violet-50 border border-violet-200 rounded-xl px-6 py-3 text-center">
                  <div className="text-[10px] text-violet-600 font-semibold uppercase mb-1">Master Key (256-bit)</div>
                  <div className="font-mono text-violet-700 text-xs">{trace.masterKey.slice(0,24)}<span className="text-violet-400">…</span>{trace.masterKey.slice(-24)}</div>
                </div>

                {/* Master Key → 4 Round Keys arrow */}
                <div className="flex flex-col items-center gap-0.5">
                  <div className="w-px h-3 bg-slate-300"/>
                  <div className="text-[10px] text-slate-500 font-semibold">derive 4 round keys via rolling mixer (each is a fresh 256-bit key)</div>
                  <ArrowDown className="w-4 h-4 text-slate-400"/>
                </div>

                {/* 4 Round Keys */}
                <div className="grid grid-cols-4 gap-2">
                  {trace.keys.map((k, i) => {
                    const bgs = ["bg-blue-50 border-blue-200","bg-sky-50 border-sky-200","bg-teal-50 border-teal-200","bg-emerald-50 border-emerald-200"];
                    const texts = ["text-blue-700","text-sky-700","text-teal-700","text-emerald-700"];
                    return (
                      <div key={i} className={`${bgs[i]} border rounded-xl p-3 text-center`}>
                        <div className={`text-[10px] font-bold uppercase mb-1 ${texts[i]}`}>Key {i+1}</div>
                        <div className={`font-mono text-[9px] break-all leading-relaxed ${texts[i]}`}>{k.slice(0,10)}…{k.slice(-6)}</div>
                      </div>
                    );
                  })}
                </div>

                {/* 4-round label */}
                <div className="flex flex-col items-center gap-0.5 pt-1">
                  <div className="w-px h-2 bg-slate-300"/>
                  <div className="text-[10px] text-slate-500 font-semibold uppercase tracking-wide">4-round character shifting</div>
                  <div className="w-px h-2 bg-slate-300"/>
                </div>

                {/* 4 Encryption Rounds */}
                {[0,1,2,3].map(ri => {
                  const bgs = ["bg-blue-50 border-blue-200","bg-sky-50 border-sky-200","bg-teal-50 border-teal-200","bg-emerald-50 border-emerald-200"];
                  const textCols = ["text-blue-700","text-sky-700","text-teal-700","text-emerald-700"];
                  const ks = trace.ksFirstBytes[ri].slice(0,4);
                  const charResults = trace.encShifts[ri].slice(0,4).map(s =>
                    s.changed ? `${s.from}→${s.to}` : s.from
                  );
                  return (
                    <div key={ri} className={`border ${bgs[ri].split(" ")[1]} rounded-xl p-3`}>
                      <div className="flex items-center gap-2">
                        <div className="bg-white border border-slate-200 rounded-lg px-3 py-2 text-center shrink-0 w-[90px]">
                          <div className="text-[9px] text-slate-500 mb-0.5">{ri === 0 ? "Input" : `R${ri} out`}</div>
                          <div className="font-mono font-bold text-slate-800 text-sm truncate">{trace.encStages[ri]}</div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-slate-400 shrink-0"/>
                        <div className={`${bgs[ri].split(" ")[0]} border ${bgs[ri].split(" ")[1]} rounded-lg px-3 py-2 flex-1`}>
                          <div className={`font-bold text-[10px] ${textCols[ri]} mb-1`}>Round {ri+1} — Key {ri+1} + xorshift128+</div>
                          <div className="text-[9px] text-slate-500">Keystream (first 4): {ks.join(", ")} · first 4 chars: {charResults.join(", ")}</div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-slate-400 shrink-0"/>
                        <div className="bg-white border border-slate-200 rounded-lg px-3 py-2 text-center shrink-0 w-[90px]">
                          <div className="text-[9px] text-slate-500 mb-0.5">After R{ri+1}</div>
                          <div className={`font-mono font-bold text-sm truncate ${ri === 3 ? "text-green-700" : "text-slate-800"}`}>{trace.encStages[ri+1]}</div>
                        </div>
                      </div>
                    </div>
                  );
                })}

                {/* Full transformation chain strip */}
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <div className="text-[10px] text-slate-500 text-center mb-3 uppercase font-semibold tracking-wide">Full transformation chain</div>
                  <div className="flex items-center justify-center gap-1 flex-wrap">
                    {trace.encStages.map((stage, i) => (
                      <>
                        <div key={`s${i}`} className={`font-mono font-bold text-sm px-3 py-1.5 rounded-lg border ${i === 0 ? "text-blue-700 bg-blue-100 border-blue-200" : i === 4 ? "text-green-700 bg-green-100 border-green-200" : "text-slate-600 bg-slate-100 border-slate-200"}`}>
                          {stage}
                        </div>
                        {i < 4 && (
                          <div key={`a${i}`} className="flex flex-col items-center shrink-0">
                            <ArrowRight className="w-4 h-4 text-slate-400"/>
                            <span className="text-[8px] text-slate-400">R{i+1}</span>
                          </div>
                        )}
                      </>
                    ))}
                  </div>
                </div>

                {/* Reversible section */}
                <div className="bg-violet-50 border border-violet-200 rounded-xl p-4 text-center">
                  <div className="font-bold text-violet-700 mb-2 text-sm">↔️ Reversible with the same keys</div>
                  <div className="text-[10px] text-violet-600 mb-3">
                    Decrypt: run rounds {[4,3,2,1].join(" → ")} (reverse order)
                  </div>
                  <div className="flex items-center justify-center gap-1 flex-wrap mb-3">
                    {trace.decStages.map((stage, i) => (
                      <>
                        <div key={`ds${i}`} className={`font-mono font-bold text-xs px-2 py-1 rounded border ${i === 0 ? "text-green-700 bg-green-100 border-green-200" : i === 4 ? "text-blue-700 bg-blue-100 border-blue-200" : "text-slate-600 bg-slate-100 border-slate-200"}`}>
                          {stage}
                        </div>
                        {i < 4 && (
                          <div key={`da${i}`} className="flex flex-col items-center shrink-0">
                            <ArrowRight className="w-3 h-3 text-violet-400"/>
                            <span className="text-[8px] text-violet-500">K{4-i}</span>
                          </div>
                        )}
                      </>
                    ))}
                  </div>
                  <span className={`text-xs font-bold px-3 py-1 rounded-full border ${trace.finalDecrypted === (cellValue || "A") ? "bg-green-100 text-green-800 border-green-300" : "bg-red-100 text-red-800 border-red-300"}`}>
                    {trace.finalDecrypted === (cellValue || "A") ? `✓  "${trace.finalEncrypted}" → "${trace.finalDecrypted}" — matches original exactly` : `⚠ Mismatch: got "${trace.finalDecrypted}"`}
                  </span>
                </div>

                {/* Footer notes */}
                <div className="space-y-1 text-center pt-1">
                  <p className="text-[10px] text-slate-600">Identity check: ciphertext may occasionally equal the input; reversibility is verified by the decrypt result below.</p>
                  <p className="text-[10px] text-slate-600">Column IV: same value "{cellValue || "A"}" in a different column → different ciphertext (column name "{colName}" is hashed into IV)</p>
                  <p className="text-[10px] text-slate-600">This prevents frequency analysis across columns even when values repeat</p>
                </div>

              </div>
            </div>

            {/* Big journey combined */}
            <div className="rounded-2xl bg-slate-50 border border-slate-200 p-8">
              <div className="grid grid-cols-2 gap-8">
                <div>
                  <div className="text-slate-600 text-xs font-bold uppercase tracking-wide mb-4">🔐 Encryption (R1 → R2 → R3 → R4)</div>
                  <div className="space-y-2">
                    {trace.encStages.map((stage, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <div className="w-16 text-xs text-slate-500 text-right shrink-0">{i === 0 ? "Original" : `After R${i}`}</div>
                        <div className={`font-mono font-bold text-sm px-3 py-1.5 rounded-lg flex-1 min-w-0 truncate ${i === 0 ? "text-blue-700 bg-blue-100" : i === 4 ? "text-green-700 bg-green-100" : "text-slate-600 bg-slate-100"}`}>{stage}</div>
                        {i < trace.encStages.length - 1 && <div className="text-[10px] text-slate-500 shrink-0">K{i+1}</div>}
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-slate-600 text-xs font-bold uppercase tracking-wide mb-4">🔓 Decryption (R4 → R3 → R2 → R1)</div>
                  <div className="space-y-2">
                    {trace.decStages.map((stage, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <div className="w-16 text-xs text-slate-500 text-right shrink-0">{i === 0 ? "Encrypted" : `Undo R${4-(i-1)}`}</div>
                        <div className={`font-mono font-bold text-sm px-3 py-1.5 rounded-lg flex-1 min-w-0 truncate ${i === 0 ? "text-green-700 bg-green-100" : i === 4 ? "text-blue-700 bg-blue-100" : "text-slate-600 bg-slate-100"}`}>{stage}</div>
                        {i < trace.decStages.length - 1 && <div className="text-[10px] text-slate-500 shrink-0">K{4-i}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <div className="mt-6 border-t border-slate-200 pt-5 text-center">
                <span className={`inline-block text-sm font-semibold px-4 py-2 rounded-full border ${trace.finalDecrypted === (cellValue || "A") ? "bg-green-100 text-green-800 border-green-300" : "bg-red-100 text-red-800 border-red-300"}`}>
                  {trace.finalDecrypted === (cellValue || "A") ? `✅  "${cellValue || "A"}" → "${trace.finalEncrypted}" → "${trace.finalDecrypted}" — Perfect round-trip!` : `⚠ Decrypted "${trace.finalDecrypted}" ≠ original "${cellValue || "A"}"`}
                </span>
              </div>
            </div>

            {/* Security properties */}
            <BigCard color="bg-white border-slate-200">
              <h3 className="text-xl font-bold text-slate-800 mb-5">🛡️ Security Properties</h3>
              <div className="space-y-4">
                {[
                  {
                    name: "Deterministic",
                    icon: "🎯",
                    badge: "bg-blue-100 text-blue-700",
                    body: "The same input (seeds + column + value) always produces the same output. This is essential: you need to be able to decrypt the same cell the same way every time.",
                    check: true
                  },
                  {
                    name: "Format-Preserving (FPE)",
                    icon: "🔄",
                    badge: "bg-green-100 text-green-700",
                    body: "Digits stay digits, letters stay letters, symbols stay symbols. Each character class maps only within its own alphabet — the anonymized value has the same shape as the original, so existing research tools work without modification.",
                    check: true
                  },
                  {
                    name: "Column-Isolated",
                    icon: "📍",
                    badge: "bg-amber-100 text-amber-700",
                    body: "Identical values in different columns always encrypt differently because the column name is mixed into the keystream via the Column IV. This prevents cross-column correlation attacks.",
                    check: true
                  },
                  {
                    name: "Order-Sensitive",
                    icon: "🔢",
                    badge: "bg-violet-100 text-violet-700",
                    body: "Swapping any two seeds produces a completely different encrypted value — even though the same set of 4 numbers was used. This means 4! = 24 distinct orderings of the same seeds.",
                    check: true
                  },
                  {
                    name: "Non-malleable (within rounds)",
                    icon: "🧱",
                    badge: "bg-rose-100 text-rose-700",
                    body: "Because we use 4 independent keystreams (one per key/IV pair), knowing one character's shift tells you nothing about another character's shift — even within the same round.",
                    check: true
                  },
                  {
                    name: "No identity leakage",
                    icon: "👤",
                    badge: "bg-slate-100 text-slate-700",
                    body: "The runtime preserves character classes and is reversible with the matching key material. It does not guarantee that every character changes on every round: the five operations can cancel, and a final value may occasionally equal its input.",
                    check: true
                  },
                ].map(p => (
                  <div key={p.name} className="flex items-start gap-4 py-3 border-b border-slate-100 last:border-0">
                    <div className="text-2xl shrink-0">{p.icon}</div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${p.badge}`}>{p.name}</span>
                        {p.check && <span className="text-xs text-green-600 font-bold">✓ guaranteed</span>}
                      </div>
                      <p className="text-slate-500 text-sm leading-relaxed">{p.body}</p>
                    </div>
                  </div>
                ))}
              </div>
            </BigCard>

            {/* What would an attacker need? */}
            <BigCard color="bg-white border-rose-200">
              <h3 className="text-xl font-bold text-slate-800 mb-3">🔍 What Would an Attacker Need?</h3>
              <p className="text-slate-500 text-sm leading-relaxed mb-5">
                To reverse-engineer an anonymized value without the seeds, an attacker would need to:
              </p>
              <div className="space-y-3">
                {[
                  ["Guess all 4 seeds", "Each seed is a 32-bit integer → 2³² ≈ 4.3 billion possibilities per seed. With 4 seeds in a specific order: (2³²)⁴ = 2¹²⁸ ≈ 3.4 × 10³⁸ combinations to try.", "bg-red-50 border-red-200 text-red-800"],
                  ["Guess the column name", "If the attacker doesn't know the exact column name string, the column IV changes the entire keystream — adding another unbounded unknown.", "bg-red-50 border-red-200 text-red-800"],
                  ["Undo all 4 rounds", "Even with a correct guess, the attacker must undo 4 layers of independent key-based shifting. There's no shortcut — each layer uses a different 256-bit key.", "bg-red-50 border-red-200 text-red-800"],
                  ["No oracle feedback", "Unlike some schemes, this algorithm gives no 'wrong password' error. Every set of seeds produces some output — the attacker can't tell valid decryption from garbage.", "bg-amber-50 border-amber-200 text-amber-800"],
                ].map(([title, body, cls]) => (
                  <div key={title as string} className={`rounded-xl border-2 p-4 ${cls}`}>
                    <div className="font-bold text-sm mb-1">{title}</div>
                    <div className="text-xs leading-relaxed opacity-80">{body}</div>
                  </div>
                ))}
              </div>
              <div className="mt-4 bg-slate-50 border border-slate-200 rounded-xl p-4 text-center">
                <div className="text-slate-600 text-xs font-semibold uppercase mb-1">Brute-force search space</div>
                <div className="font-mono text-emerald-700 font-bold text-lg">(2³²)⁴ = 2¹²⁸ ≈ 3.4 × 10³⁸</div>
                <div className="text-slate-600 text-xs mt-1">combinations of 4 ordered 32-bit seeds alone</div>
                <div className="text-slate-500 text-xs mt-1">At 10¹⁵ guesses/second, this would take longer than the age of the universe.</div>
              </div>
            </BigCard>

            {/* Algorithm glossary */}
            <BigCard color="bg-white border-slate-200">
              <h3 className="text-xl font-bold text-slate-800 mb-5">📚 Key Terms Reference</h3>
              <div className="grid grid-cols-2 gap-4">
                {[
                  ["Seed 🌱", "One of 4 numbers that form your password. Each must be known and in the correct order to decrypt."],
                  ["Key 🔑", "One of 4 × 256-bit (64 hex char) round keys. All 4 are derived by expanding a single master seed (formed from all 4 seeds) into 128 bytes, then splitting into four 32-byte segments."],
                  ["Column IV 📍", "A 32-bit integer derived by hashing (key prefix + column name). Separates the keystream of each column."],
                  ["Keystream 🌊", "The sequence of random bytes (one per character) produced by xorshift128+ seeded with (key prefix ⊕ column IV)."],
                  ["FPE 🔄", "Format-Preserving Encryption — characters stay within their own alphabet (digit→digit, letter→letter)."],
                  ["Modular arithmetic 🕐", "Like a clock: 9 + 3 = 2 (mod 10). Used to wrap shifted characters back into their valid range."],
                  ["xorshift128+ 🎲", "A fast PRNG that generates pseudo-random bytes. 'Pseudo' = same seed always gives same sequence."],
                  ["4-Round Chain 🔗", "Applying 4 independent encryption rounds multiplies the effective security — undoing any round requires knowing that round's key."],
                  ["Avalanche effect 🌊", "A property where changing 1 bit of a seed flips ~50% of the bits in the final key."],
                  ["Master Seed 🌱→🔐", "The final 32-bit rolling accumulator value after all 4 seeds have been folded in. It encodes all 4 seeds and their order — one bit different in any seed changes this completely."],
                  ["Master Key 🗝️", "256-bit (64 hex char) key generated from the master seed via xorshift128+. The root secret — 4 round keys are derived from it via rolling mixer."],
                  ["Rolling accumulator 🔢", "The 32-bit value that accumulates all 4 seeds one-by-one. The final value becomes the master seed."],
                ].map(([term, def]) => (
                  <div key={term as string} className="flex gap-3 items-start py-2 border-b border-slate-100">
                    <div className="font-bold text-slate-800 text-sm shrink-0 w-36">{term}</div>
                    <div className="text-slate-500 text-xs leading-relaxed">{def}</div>
                  </div>
                ))}
              </div>
            </BigCard>

            <div className="text-center">
              <button onClick={() => setStep(0)}
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-indigo-600 text-white font-semibold hover:bg-indigo-700 transition-colors">
                <RotateCcw className="w-4 h-4" />
                Try different values
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Navigation ────────────────────────────────────────────── */}
      <div className="shrink-0 border-t border-slate-200 px-10 py-4 bg-white flex items-center justify-between gap-4">
        <button
          onClick={goBack}
          disabled={step === 0}
          className="flex items-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm transition-all disabled:opacity-30 disabled:cursor-not-allowed bg-slate-100 text-slate-700 hover:bg-slate-200"
        >
          <ChevronLeft className="w-4 h-4" />
          Back
        </button>

        <div className="flex items-center gap-4">
          {/* Dot pips */}
          <div className="flex gap-2">
            {STEP_LABELS.map((_, i) => (
              <button key={i} onClick={() => setStep(i)} className={`h-2.5 rounded-full transition-all ${i === step ? "bg-indigo-600 w-6" : i < step ? "bg-green-400 w-2.5" : "bg-slate-300 w-2.5"}`} />
            ))}
          </div>

          {/* Export PDF button — always visible */}
          <button
            onClick={() => exportTracePDF(trace, seeds, colName, cellValue)}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm bg-slate-800 text-white hover:bg-slate-700 transition-colors border border-slate-700"
            title="Download full trace as PDF"
          >
            <Download className="w-4 h-4" />
            Export PDF
          </button>
        </div>

        <button
          onClick={goNext}
          disabled={step === totalSteps - 1}
          className="flex items-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm transition-all disabled:opacity-30 disabled:cursor-not-allowed bg-indigo-600 text-white hover:bg-indigo-700"
        >
          {step === totalSteps - 2 ? "See Summary" : "Next"}
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
