import {
  decryptCSVToBlob,
  encryptFWFToBlob,
  type AnonymizeOptions,
  type FieldSpec,
} from "../artifacts/csv-profiler/src/lib/anonymize.ts";

const fields: FieldSpec[] = [
  { varName: "A", start: 1, end: 5 },
  { varName: "B", start: 6, end: 10 },
  { varName: "C", start: 11, end: 15 },
];

const records = [
  ["17937", "Ab9-x", "xyZ!"],
  ["00001", "zz9-y", "ABC9"],
  ["12345", "A0a-!", "00000"],
  ["17937", "Ab9-x", "xyZ!"],
];
const raw = records.map((row) => row.join("")).join("\n");
const expected = `A,B,C\n${records.map((row) => row.join(",")).join("\n")}\n`;

async function roundTrip(options: AnonymizeOptions, mode: "all" | "subset") {
  const encryptedColumns = new Set(["A", "C"]);
  const encrypted = await encryptFWFToBlob(raw, fields, encryptedColumns, options, () => {});
  const encryptedText = await encrypted.blob.text();
  const selectedColumns = mode === "all" ? encryptedColumns : new Set(["C"]);
  const decrypted = await decryptCSVToBlob(encryptedText, selectedColumns, options, () => {});
  const decryptedText = await decrypted.text();
  return { encryptedText, decryptedText };
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const base: AnonymizeOptions = {
  keyMode: "random",
  seeds: [42, 137, 2024, 7],
  passphrase: "",
  pbkdf2Iterations: 100_000,
  deterministic: true,
};

const deterministic1 = await roundTrip(base, "all");
const deterministic2 = await roundTrip(base, "all");
assert(deterministic1.encryptedText === deterministic2.encryptedText, "deterministic output changed");
assert(deterministic1.decryptedText === expected, "deterministic round trip failed");

const selective = await roundTrip({ ...base, deterministic: false }, "subset");
const selectiveLines = selective.decryptedText.trimEnd().split("\n");
assert(selectiveLines[0] === "A,B,C", "selective output header changed");
assert(selectiveLines.slice(1).every((line, index) => {
  const cells = line.split(",");
  return cells[0] !== records[index][0] && cells[1] === records[index][1] && cells[2] === records[index][2];
}), "selective non-deterministic decrypt did not restore the selected column");

const hexKey = "0123456789abcdef".repeat(4);
const hexOptions: AnonymizeOptions = { ...base, keyMode: "hex", keyHex: hexKey };
const hexEncrypted = await encryptFWFToBlob(raw, fields, new Set(["A", "B", "C"]), hexOptions, () => {});
assert(hexEncrypted.keyHex === hexKey, "hex mode did not return the supplied root key");
const hexDecrypted = await decryptCSVToBlob(await hexEncrypted.blob.text(), new Set(["A", "B", "C"]), hexOptions, () => {});
assert(await hexDecrypted.text() === expected, "hex-key round trip failed");

for (const invalid of [
  { ...base, keyMode: "pbkdf2" as const, passphrase: "" },
  { ...base, keyMode: "hex" as const, keyHex: "not-a-key" },
]) {
  let threw = false;
  try {
    await encryptFWFToBlob(raw, fields, new Set(["A"]), invalid, () => {});
  } catch {
    threw = true;
  }
  assert(threw, `invalid ${invalid.keyMode} settings were accepted`);
}

console.log("anonymize smoke test passed");

// ── Leading-zero-prevention tests ────────────────────────────────────────────
// Test that encrypt(x)[0] !== '0' for any x that starts with a non-zero digit,
// and that decrypt(encrypt(x)) === x for all test values across all 4 rounds.

// ── Smoke-test helpers ───────────────────────────────────────────────────────
//
// encryptFWFToBlob skips the first line if it contains a comma (CSV header
// detection).  To test values that include commas or other symbols, we always
// send TWO FWF lines:
//   Line 1 — all "A"s (no comma, treated as a data row, never read back)
//   Line 2 — "X" + test value  (two fields: ignored prefix "P" + test field "V")
// The CSV output therefore has a header row + 2 data rows; we read the SECOND
// data row (index 2 in the zero-based split).
// Decryption: deterministic mode means value identity drives the keystream, so
// re-encrypting in a single-row CSV always gives the same result.

const ANCHOR_CHAR = "A";
const PREFIX_CHAR = "X";

// RFC-4180 quote for embedding a value in a CSV cell.
function csvQuote(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n") || val.includes("\r")) {
    return '"' + val.replace(/"/g, '""') + '"';
  }
  return val;
}

// Extract column `colIdx` (0-based) from a single CSV line, respecting quoting.
function parseCsvLine(line: string): string[] {
  const cols: string[] = [];
  let inQ = false, cur = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
      else inQ = !inQ;
    } else if (c === ',' && !inQ) { cols.push(cur); cur = ""; }
    else if ((c === '\n' || c === '\r') && !inQ) break;
    else cur += c;
  }
  cols.push(cur);
  return cols;
}

async function encryptSingleValue(value: string, options: AnonymizeOptions): Promise<string> {
  const width = 1 + value.length; // prefix char + value chars
  const anchor = ANCHOR_CHAR.repeat(width); // all "A"s — no comma, no trim issue
  const dataLine = PREFIX_CHAR + value;
  const fields: FieldSpec[] = [
    { varName: "P", start: 1, end: 1 },
    { varName: "V", start: 2, end: width },
  ];
  const result = await encryptFWFToBlob(anchor + "\n" + dataLine, fields, new Set(["V"]), options, () => {});
  const csvText = await result.blob.text();
  // "P,V\n[row1]\n[row2]\n"  — we want row2's V column
  const lines = csvText.trimEnd().split("\n");
  return (parseCsvLine(lines[2] ?? "")[1]) ?? "";
}

async function decryptSingleValue(encrypted: string, options: AnonymizeOptions): Promise<string> {
  // Deterministic mode: value → keystream is independent of row position.
  // Use the same two-row layout (anchor + test row) so the row index is consistent.
  const width = 1 + encrypted.length;
  const anchorEnc = ANCHOR_CHAR.repeat(width); // anchor row V col is "AAA..." — decrypts to itself
  const csvText = `P,V\n${PREFIX_CHAR},${csvQuote(anchorEnc)}\n${PREFIX_CHAR},${csvQuote(encrypted)}\n`;
  const result = await decryptCSVToBlob(csvText, new Set(["V"]), options, () => {});
  const text = await result.text();
  const lines = text.trimEnd().split("\n");
  return (parseCsvLine(lines[2] ?? "")[1]) ?? "";
}

const testValues = [
  "12345",
  "10000",
  "99999",
  "50001",
  "11111",
  "987654321",
];

// Verify with multiple seed sets and both key modes
for (const opts of [
  base,
  { ...base, seeds: [1, 2, 3, 4] },
  { ...base, seeds: [999, 1, 0, 42] },
]) {
  for (const v of testValues) {
    const enc = await encryptSingleValue(v, opts);
    assert(enc.length === v.length, `length changed: "${v}" → "${enc}"`);
    assert(enc[0] !== "0", `leading zero in encrypted output: "${v}" → "${enc}"`);
    const dec = await decryptSingleValue(enc, opts);
    assert(dec === v, `round-trip failed: "${v}" → enc="${enc}" → dec="${dec}"`);
  }
}

// Leading-zero source values: encrypt should not corrupt them
const leadingZeroValues = ["01234", "00001", "00000", "09999"];
for (const v of leadingZeroValues) {
  const enc = await encryptSingleValue(v, base);
  assert(enc.length === v.length, `length changed for leading-zero value: "${v}" → "${enc}"`);
  const dec = await decryptSingleValue(enc, base);
  assert(dec === v, `round-trip failed for leading-zero value: "${v}" → enc="${enc}" → dec="${dec}"`);
}

console.log("leading-zero-prevention tests passed");

// ── Symbol encryption tests ──────────────────────────────────────────────────
// Every printable keyboard symbol must round-trip and must map to another symbol.

const SYMBOL_CHARS = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

// Values containing only symbols.
// Note: encryptFWFToBlob trims field values (FWF padding convention), so values
// with leading/trailing spaces cannot be round-tripped through that API.
// We test space embedded inside mixed values instead.
const symbolOnlyValues = ['@', '!@#', '$%^&*', '()', '+-=', '/\\', '.:;', '|{}~'];
// Mixed values (symbols + alphanumeric) — also covers space in non-leading position
const mixedValues = ['Ab9-x', 'xy@Z!', 'A0a-!', '#foo1', 'test@123', 'a b c', '1+2=3'];
// All 33 symbols except leading/trailing space (32 chars — space is covered by mixedValues above)
const allSymbols = SYMBOL_CHARS.trim(); // '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

for (const v of [...symbolOnlyValues, ...mixedValues, allSymbols]) {
  const enc = await encryptSingleValue(v, base);
  assert(enc.length === v.length, `symbol test length changed: "${v}" → "${enc}"`);
  // Every char that was a symbol must still be a symbol
  for (let i = 0; i < v.length; i++) {
    const origIsSymbol = SYMBOL_CHARS.includes(v[i]);
    const encIsSymbol  = SYMBOL_CHARS.includes(enc[i]);
    assert(origIsSymbol === encIsSymbol,
      `character class changed at position ${i}: "${v[i]}" → "${enc[i]}" in "${v}" → "${enc}"`);
  }
  const dec = await decryptSingleValue(enc, base);
  assert(dec === v, `symbol round-trip failed: "${v}" → enc="${enc}" → dec="${dec}"`);
}

console.log("symbol encryption tests passed");
