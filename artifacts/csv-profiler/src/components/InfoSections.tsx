import { ChevronRight } from "lucide-react";

// ── Shared primitives ──────────────────────────────────────────────────────

export function Formula({ children }: { children: React.ReactNode }) {
  return (
    <div className="my-3 px-4 py-3 bg-slate-950 rounded-lg font-mono text-sm text-emerald-300 whitespace-pre-wrap leading-relaxed overflow-x-auto">
      {children}
    </div>
  );
}

export function Sub({ children }: { children: React.ReactNode }) {
  return <span className="text-xs align-sub">{children}</span>;
}

export function H({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-base font-bold text-slate-900 mt-6 mb-2 flex items-center gap-1.5">
      <ChevronRight className="w-4 h-4 text-indigo-500" />
      {children}
    </h3>
  );
}

export function P({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-slate-600 leading-relaxed mb-2">{children}</p>;
}

export function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="bg-slate-100 text-indigo-700 px-1 py-0.5 rounded text-xs font-mono">
      {children}
    </code>
  );
}

export function Table({ rows }: { rows: [string, string][] }) {
  return (
    <table className="w-full text-sm mb-4 border-collapse">
      <thead>
        <tr className="bg-indigo-50">
          <th className="text-left px-3 py-2 text-indigo-700 font-semibold border border-indigo-100 w-1/3">Symbol</th>
          <th className="text-left px-3 py-2 text-indigo-700 font-semibold border border-indigo-100">Meaning</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([sym, def], i) => (
          <tr key={i} className={i % 2 === 0 ? "bg-white" : "bg-slate-50"}>
            <td className="px-3 py-1.5 font-mono text-xs border border-slate-200 text-indigo-800">{sym}</td>
            <td className="px-3 py-1.5 text-slate-600 border border-slate-200">{def}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Section components ─────────────────────────────────────────────────────

export function SectionSeeds() {
  return (
    <div>
      <p className="text-sm text-slate-500 mb-4 italic">
        All key material is deterministically derived from four integer seeds <Code>s₁, s₂, s₃, s₄</Code>.
        Reordering any two seeds changes every subsequent round key — the seed sequence is a cryptographic input.
      </p>

      <H>Step 1 — xorshift128+ PRNG Initialisation</H>
      <P>Each seed is expanded into a two-state xorshift128+ pseudo-random number generator. The internal state is a pair of 32-bit integers <Code>(a, b)</Code> seeded by XOR-mixing the raw seed with two distinct magic constants:</P>
      <Formula>{`a₀ = (seed ⊕ 0x9E3779B9) >>> 0   [golden-ratio constant]
b₀ = (seed ⊕ 0x6C62272E) >>> 0   [FNV prime]

// Force non-zero (degenerate state guard):
a₀ = a₀ || 1
b₀ = b₀ || 2`}</Formula>

      <H>Step 2 — xorshift128+ Iterate</H>
      <P>Each call to the generator advances the state and returns a float in [0, 1):</P>
      <Formula>{`a ← a ⊕ (a << 13);   a = a >>> 0
a ← a ⊕ (a >> 17)
a ← a ⊕ (a <<  5);   a = a >>> 0

b ← b ⊕ (b >>  7);   b = b >>> 0
b ← b ⊕ (b <<  9);   b = b >>> 0
b ← b ⊕ (b >>  8);   b = b >>> 0

output = ((a + b) >>> 0) / 0x100000000   ∈ [0, 1)`}</Formula>

      <H>Step 3 — Master Seed from all 4 Seeds</H>
      <P>All four seeds are folded into the rolling accumulator <em>in sequence</em>. Only after all four have been mixed does the final accumulator value become the <strong>master seed</strong>. Swapping any two seeds changes the master seed — and therefore every round key:</P>
      <Formula>{`rolling₀ = 0x9E3779B9   [golden-ratio constant — initial state]

For each seed sᵢ in {s₁, s₂, s₃, s₄}:

  // Horner-style fold — multiply then XOR-mix with seed
  rolling ← (rolling × 0x9E3779B9) ⊕ (sᵢ >>> 0)   >>> 0
  rolling ← rolling ⊕ (rolling >>> 16)              >>> 0
  rolling ← (rolling × 0x85EBCA6B)                  >>> 0
  rolling ← rolling ⊕ (rolling >>> 13)              >>> 0

masterSeed = rolling   [32-bit — encodes all 4 seeds and their order]`}</Formula>

      <H>Step 4 — Master Key Expansion and Round-Key Derivation</H>
      <P>The master seed expands into a single <strong>256-bit master key</strong> via xorshift128+. Four independent round keys are then derived from the master key using an XOR + rolling mixer — the same mechanism used in hex-key mode:</P>
      <Formula>{`// Phase 2 — expand master seed into one 256-bit master key
masterKey[i] = ⌊ xorshift128+((masterSeed ⊕ 0xDEADBEEF) >>> 0) × 256 ⌋   for i = 0..31
masterKeyHex = masterKey.map(b => hex(b)).join("")   [64 hex chars]

// Phase 3 — derive 4 round keys via XOR + rolling mixer
r = (parseInt(masterKeyHex[0..7], 16) ⊕ 0xDEADBEEF) >>> 0

For each round i ∈ {0, 1, 2, 3}:
  r ← (r × 0x9E3779B9) ⊕ (i × 0x5A5A5A5B)   >>> 0
  r ← r ⊕ (r >>> 16)                          >>> 0
  keyChain[i] = generateKey(r)                 [32-byte xorshift128+ output]`}</Formula>

      <Table rows={[
        ["s₁, s₂, s₃, s₄", "Four integer seeds (user-supplied, order matters)"],
        ["rolling / masterSeed", "32-bit accumulator; final value encodes all 4 seeds and their order"],
        ["masterKeyHex", "64-char hex string (256-bit) derived from masterSeed via xorshift128+"],
        ["0x9E3779B9", "Golden-ratio constant (Knuth multiplicative hash)"],
        ["0x85EBCA6B", "MurmurHash3 mix constant (Phase 1 avalanche)"],
        ["0x5A5A5A5B", "Round-index multiplier (Phase 3 key diversification)"],
        ["keyChain[i]", "32-byte (256-bit) round key derived from master key via rolling mixer"],
      ]} />

      <H>Passphrase Mode (PBKDF2-like)</H>
      <P>When a passphrase is used instead of numeric seeds, each round appends a unique salt tag so round order is embedded in the key material:</P>
      <Formula>{`h = 0x5A827999   [initial hash state]
For each character c in passphrase:
  h = (h × 31 + charCode(c) + 1013904223) >>> 0

tag = ""
For each round i ∈ {0, 1, 2, 3}:
  tag  += "\\x00R" + i           [round-unique salt]
  seed  = hash(passphrase + tag, h, iterations)
  keyChain[i] = generateKey(seed)`}</Formula>

      <H>Hex Key Mode</H>
      <P>A 64-char hex key is chain-derived into 4 sub-keys using a rolling mixer seeded from the key's first 32 bits:</P>
      <Formula>{`base32 = parseInt(hexKey[0..7], 16)
rolling₀ = (base32 ⊕ 0xDEADBEEF) >>> 0

For each round i ∈ {0, 1, 2, 3}:
  rolling ← (rolling × 0x9E3779B9) ⊕ (i × 0x5A5A5A5B)   >>> 0
  rolling ← rolling ⊕ (rolling >>> 16)                    >>> 0
  keyChain[i] = generateKey(rolling)`}</Formula>
    </div>
  );
}

export function SectionFPE() {
  return (
    <div>
      <P>Format-Preserving Encryption (FPE) maps each character to a new character in the same alphabet — digits stay digits, letters stay letters, punctuation is unchanged. This preserves the original data format and length exactly.</P>

      <H>Column IV (Initialisation Vector) Hash</H>
      <P>For deterministic mode, every column gets a unique IV derived from the key and column name. This ensures the same value encrypts to a different ciphertext in a different column:</P>
      <Formula>{`h = (parseInt(keyHex[0..7], 16) ⊕ 0xA5A5A5A5) >>> 0
s = "COL\\x00" + columnName

For each character c in s:
  h = (h × 1664525 + charCode(c) + 1013904223) >>> 0

colIV = h   [32-bit deterministic IV per key+column pair]`}</Formula>

      <H>Per-Cell Keystream Bytes</H>
      <P>Each cell's keystream is seeded from the XOR of the first 32 bits of the key and either the column IV (deterministic) or a monotonic counter (non-deterministic):</P>
      <Formula>{`combined = (parseInt(keyHex[0..7], 16) ⊕ ivSeed) >>> 0
ks[i]    = ⌊ xorshift128+(combined) × 256 ⌋   for i = 0..len-1`}</Formula>

      <H>FPE Character Transform</H>
      <P>Each alphanumeric character consumes five keystream bytes. Each byte selects one reversible operation: add, subtract, multiply by a coprime, or flip/complement. Digits use the 0–9 alphabet; letters use a 26-character alphabet. There is no special leading-digit rule, so leading zeroes are preserved as ordinary digit characters.</P>
      <Formula>{`// For each character, with alphabet size S:
v = code - base
for each of 5 keystream bytes k:
  op = k mod 4
  add/sub amount = (floor(k / 4) mod (S - 1)) + 1
  multiply factor = coprime[floor(k / 4) mod coprime.length]

op 0: v = (v + amount) mod S
op 1: v = (v - amount) mod S
op 2: v = (v × factor) mod S
op 3: v = S - 1 - v

// Decryption uses the same five bytes in reverse:
add ↔ subtract, multiply ↔ modular inverse, flip ↔ flip`}</Formula>

      <Table rows={[
        ["c", "Original character code"],
        ["c'", "Encrypted character code"],
        ["k", "Keystream byte at this character position"],
        ["mod", "Modulo (keeps result within alphabet range)"],
        ["S", "Alphabet size: 10 for digits, 26 for letters"],
        ["op", "Operation selected by k mod 4"],
        ["factor⁻¹", "Modular inverse used to undo multiplication"],
      ]} />
    </div>
  );
}

export function SectionChain() {
  return (
    <div>
      <P>A single FPE pass could be reversed if an attacker knew the key. AIRAVATA DEA chains <strong>four rounds</strong>, each using a different derived key. Each round is a composition of five reversible operations per character; the overall transformation is undone in reverse round order.</P>

      <H>4-Round Encryption Chain</H>
      <Formula>{`// Encrypt value v through all four round keys:
v₀ = original_value
v₁ = FPE_encrypt(ks₁, v₀)   [round 1 — key from seed s₁]
v₂ = FPE_encrypt(ks₂, v₁)   [round 2 — key from seed s₂]
v₃ = FPE_encrypt(ks₃, v₂)   [round 3 — key from seed s₃]
v₄ = FPE_encrypt(ks₄, v₃)   [round 4 — key from seed s₄]
ciphertext = v₄`}</Formula>

      <H>4-Round Decryption Chain (exact reverse)</H>
      <Formula>{`// Decrypt by reversing round order:
v₃ = FPE_decrypt(ks₄, ciphertext)
v₂ = FPE_decrypt(ks₃, v₃)
v₁ = FPE_decrypt(ks₂, v₂)
v₀ = FPE_decrypt(ks₁, v₁)
plaintext = v₀`}</Formula>

      <H>Collision and identity behavior</H>
      <P>The runtime does not add a tiebreaker round. Because the transformation is a permutation, an encrypted value can occasionally equal its input; this is not a decryption failure. The guide’s round-trip check verifies reversibility, not that every character or value changes.</P>

      <H>Non-Deterministic Mode — Per-Cell IV</H>
      <P>In non-deterministic mode, each cell gets a unique IV from a monotonic counter XOR-mixed with the round index, making identical values in the same column encrypt to different ciphertexts:</P>
      <Formula>{`counter ← counter + 1   [monotonic, increments per cell]

For each round i ∈ {0, 1, 2, 3}:
  ivSeed_i = (counter ⊕ (i × 0x12345679)) >>> 0
  ks_i     = makeCellKsBytes(len + 32, keyChain[i], ivSeed_i)`}</Formula>

      <Table rows={[
        ["ks₁…ks₄", "Keystream byte arrays, one per round"],
        ["counter", "Monotonic cell counter (non-det. mode only)"],
        ["0x12345679", "Round-index multiplier for per-round IV diversification"],
      ]} />
    </div>
  );
}

export function SectionKAnon() {
  return (
    <div>
      <P>The Prosecutor Attack simulates an adversary who <em>knows</em> a target is in the dataset and tries to single them out using quasi-identifiers — attributes available from external sources (census, voter rolls, etc.).</P>

      <H>Equivalence Class (EC) Construction</H>
      <P>All records that share identical values across every chosen Quasi-Identifier (QI) are grouped into an Equivalence Class:</P>
      <Formula>{`EC(r) = { r' ∈ Dataset  |  r'[QI₁] = r[QI₁]  ∧  r'[QI₂] = r[QI₂]  ∧ … }

EC_key(r) = r[QI₁] ∥ "|" ∥ r[QI₂] ∥ "|" ∥ …   [string join]`}</Formula>

      <H>k-Anonymity</H>
      <P>A dataset satisfies k-anonymity if every equivalence class contains at least k records. An attacker cannot identify a target with probability better than 1/k:</P>
      <Formula>{`k = min { |EC(r)|  :  r ∈ Dataset }

// A record r satisfies k-anonymity iff:
|EC(r)| ≥ k_threshold   (default k_threshold = 5)`}</Formula>

      <H>Link Score (Re-identification Probability)</H>
      <P>The Link Score of a record is the probability that an attacker can uniquely re-identify it given its equivalence class. For a record in an EC of size m:</P>
      <Formula>{`LinkScore(r) = 1 / |EC(r)|

// Examples:
//   Singleton  (|EC| = 1) → LinkScore = 1.000   (certain)
//   EC size 2             → LinkScore = 0.500
//   EC size 5             → LinkScore = 0.200
//   EC size 20            → LinkScore = 0.050`}</Formula>

      <H>Uniqueness Rate</H>
      <Formula>{`UniquenessRate = |{ EC  :  |EC| = 1 }| / N

// N = total number of records
// Numerator = count of singleton equivalence classes`}</Formula>

      <H>At-Risk Flag</H>
      <Formula>{`AtRisk(r) = 1   if |EC(r)| < k_threshold
           = 0   otherwise`}</Formula>

      <Table rows={[
        ["QI", "Quasi-Identifier — attribute linkable to external data"],
        ["EC(r)", "Equivalence Class of record r"],
        ["|EC(r)|", "Size (number of records) in the equivalence class"],
        ["k", "Minimum equivalence class size across the dataset"],
        ["k_threshold", "Risk threshold (default 5)"],
        ["LinkScore", "Probability of unique re-identification: 1 / |EC|"],
      ]} />
    </div>
  );
}

export function SectionLDiv() {
  return (
    <div>
      <P>l-Diversity strengthens k-Anonymity by requiring that each equivalence class contains at least <em>l</em> distinct values for every Sensitive Attribute (SA). Without it, an EC of k=5 could still expose the SA if all 5 records share the same value.</P>

      <H>l-Diversity Definition</H>
      <Formula>{`An EC satisfies l-diversity for sensitive attribute SA iff:
  |{ distinct values of SA within EC }| ≥ l_threshold

A dataset satisfies l-diversity iff every EC satisfies it.`}</Formula>

      <H>Minimum l Across the Dataset</H>
      <Formula>{`minL(SA) = min { |{ SA values in EC }|  :  EC ∈ Dataset }`}</Formula>

      <H>Violation Rate</H>
      <Formula>{`ViolatingECs(SA) = |{ EC  :  |distinct SA in EC| < l_threshold }|

ViolatingRecordPct(SA) = (records in violating ECs / N) × 100%`}</Formula>

      <H>Pass / Fail Criterion</H>
      <Formula>{`status(SA) = PASS   if ViolatingECs(SA) = 0
           = FAIL   otherwise`}</Formula>

      <Table rows={[
        ["SA", "Sensitive Attribute (e.g. income, disease)"],
        ["l_threshold", "Minimum distinct SA values per EC (default 3)"],
        ["minL(SA)", "Worst-case l across all equivalence classes"],
        ["ViolatingECs", "Count of ECs that fail the l requirement"],
      ]} />
    </div>
  );
}

export function SectionTClose() {
  return (
    <div>
      <P>t-Closeness goes further than l-Diversity: it requires that the <em>distribution</em> of the Sensitive Attribute within each EC must be close to its global distribution across the whole dataset. This prevents attribute inference even when diversity is high.</P>

      <H>Global Distribution</H>
      <Formula>{`P_global(v, SA) = |{ r ∈ Dataset  :  r[SA] = v }| / N

// Computed once across the entire dataset for every distinct value v of SA`}</Formula>

      <H>Local Distribution within an EC</H>
      <Formula>{`P_local(v, SA, EC) = |{ r ∈ EC  :  r[SA] = v }| / |EC|`}</Formula>

      <H>Total Variation Distance (TVD)</H>
      <P>AIRAVATA DEA uses the Total Variation Distance as the distributional divergence measure. TVD is half the L1 distance between two probability distributions:</P>
      <Formula>{`TVD(EC, SA) = (1/2) × Σᵥ | P_local(v, SA, EC) − P_global(v, SA) |

// Sum runs over all distinct values v of SA
// TVD ∈ [0, 1]  where 0 = identical distribution, 1 = completely disjoint`}</Formula>

      <H>t-Closeness Criterion</H>
      <Formula>{`An EC satisfies t-closeness for SA iff:
  TVD(EC, SA) ≤ t_threshold   (default t = 0.2)

maxDistance(SA) = max { TVD(EC, SA)  :  EC ∈ Dataset }

status(SA) = PASS   if ViolatingECs(SA) = 0
           = FAIL   otherwise`}</Formula>

      <Table rows={[
        ["P_global(v)", "Fraction of the whole dataset with SA = v"],
        ["P_local(v, EC)", "Fraction of EC members with SA = v"],
        ["TVD", "Total Variation Distance — distributional gap"],
        ["t_threshold", "Maximum allowed TVD per EC (default 0.2)"],
        ["maxDistance", "Worst-case TVD across all ECs"],
      ]} />
    </div>
  );
}

export function SectionReID() {
  return (
    <div>
      <P>The overall Re-Identification Risk aggregates all per-record link scores into a single dataset-level metric. It represents the expected probability that a randomly selected record can be uniquely identified by an attacker.</P>

      <H>Re-ID Risk (Average Link Score)</H>
      <Formula>{`ReIDRisk = (1/N) × Σᵢ LinkScore(rᵢ)
         = (1/N) × Σᵢ (1 / |EC(rᵢ)|)

// Equivalently, summed over equivalence classes:
ReIDRisk = (1/N) × Σ_EC  ( |EC| × (1/|EC|) )
         = (1/N) × Σ_EC  1
         = |ECs| / N`}</Formula>

      <H>Risk Level Thresholds</H>
      <Formula>{`ReIDRisk ≥ 0.70  →  CRITICAL   (red)
ReIDRisk ≥ 0.50  →  HIGH       (orange)
ReIDRisk ≥ 0.30  →  MEDIUM     (yellow)
ReIDRisk <  0.30  →  LOW        (green)`}</Formula>

      <H>High-Risk Rate</H>
      <Formula>{`HighRiskRate = AtRiskCount / N
            = |{ r : |EC(r)| < k_threshold }| / N`}</Formula>

      <H>Average EC Size</H>
      <Formula>{`AvgECSize = N / |ECs|`}</Formula>

      <H>Summary of All Metrics</H>
      <Table rows={[
        ["N", "Total number of records"],
        ["|ECs|", "Number of distinct equivalence classes"],
        ["ReIDRisk", "Expected re-identification probability (0–1)"],
        ["minK", "Minimum EC size — worst-case k-anonymity"],
        ["UniquenessRate", "Fraction of singletons (|EC|=1)"],
        ["HighRiskRate", "Fraction of records below k_threshold"],
        ["AvgECSize", "N / |ECs| — average class size"],
        ["LinkScore(r)", "1 / |EC(r)| — per-record re-ID probability"],
        ["TVD(EC, SA)", "(½)·Σ|P_local − P_global| — distributional gap"],
      ]} />

      <H>Recommendation Thresholds</H>
      <Formula>{`Singleton records exist     → SUPPRESS or GENERALISE QI
ReIDRisk > 0.20            → CRITICAL — apply k-anonymisation
ReIDRisk > 0.05            → MEDIUM — consider additional generalisation
l-Diversity FAIL           → ensure ≥ l_threshold distinct SA values per EC
t-Closeness FAIL (TVD > t) → distribution within ECs diverges too much`}</Formula>
    </div>
  );
}
