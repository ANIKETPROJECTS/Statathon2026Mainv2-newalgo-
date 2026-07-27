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

async function encryptSingleValue(
  value: string,
  options: AnonymizeOptions,
): Promise<string> {
  const singleField: FieldSpec[] = [{ varName: "ID", start: 1, end: value.length }];
  const line = value.padEnd(value.length);
  const result = await encryptFWFToBlob(line, singleField, new Set(["ID"]), options, () => {});
  const text = await result.blob.text();
  // CSV: header line + data line
  const lines = text.trim().split("\n");
  return lines[1]?.trim() ?? "";
}

async function decryptSingleValue(
  encrypted: string,
  options: AnonymizeOptions,
): Promise<string> {
  const singleField: FieldSpec[] = [{ varName: "ID", start: 1, end: encrypted.length }];
  const csvText = `ID\n${encrypted}\n`;
  const result = await decryptCSVToBlob(csvText, new Set(["ID"]), options, () => {});
  const text = await result.text();
  const lines = text.trim().split("\n");
  return lines[1]?.trim() ?? "";
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
