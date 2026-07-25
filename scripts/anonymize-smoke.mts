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