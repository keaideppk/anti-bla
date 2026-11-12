# Anti-BLA Empirical Breakthrough Drill Report

- **Fixture Provider**: `live-bla-v3.2.5` (Target Shield Version: `3.2.5`, Intensity: `bankrupt`)
- **All Behavioral & Hash Equivalence Checks**: `PASS`

## 1. Executive Summary Matrix

| Surface & Shield Mechanism | Naive / Default Analyzer Outcome | `anti-bla` Resilient Outcome | Cost / Payload Reduction | Fidelity Verification |
| :--- | :--- | :--- | :--- | :--- |
| **JS AST Shield + BPE Amplifier + Tarpit + `--self-seal`** | **EXHAUSTED / POISONED** (`60,464` BPE tokens, `2^16` string branch fanout, `23` poison markers) | **COLLAPSED IN MEMORY** (`246` BPE tokens, `0` poison markers, `0` conditional string chains) | **-99.59% BPE tokens** (`139,843 B` -> `564 B`) | `100%` output match + `self-seal` untouched |
| **JS Dynamic V8 Coverage (`Profiler.takePreciseCoverage`)** | Disk patching trips `Error: integrity check failed` | **NON-INVASIVE SLICE** (`120` cold functions & `90` dead branches pruned, `0` disk bytes changed) | **-82.12% BPE tokens** from coverage alone | On-disk SHA-256 unchanged (`true`) |
| **SQLite `VIRTUAL` UDF Trap + Honey Tables** | **CRASHED** (`unknown function: enclave_unseal_payload()`) | **RECOVERED** (`PRAGMA table_xinfo` skipped `3` virtual UDF columns; quarantined `5` honey tables) | `57,344 B` DB -> `365 B` clean schema/rows | Business table SHA-256 `100%` match |
| **Safetensors 35-Level JSON Nesting Breaker** | **ABORTED** (`ModelFormatFailure: Safetensors JSON nesting depth 33 exceeds MODEL_MAX_JSON_NESTING (32)`) | **RECOVERED** (`O(1)` iterative cursor skipped depth-`36` `enclave_topology_seal` & `43` chaff keys) | `10,096 B` -> `194 B` tensor spec | Tensor float32 SHA-256 `100%` match |
| **WebAssembly 250-Export Interface Budget Breaker** | **BUDGET TRIPPED / BLOATED** (`49.30 MiB` charge across `251` exports) | **CANONICALIZED** (Grouped by `(kind, index)` into `1` canonical function; quarantined `9` custom sections) | **-99.9997%** (`134 B`) | `WebAssembly.instantiate` verified |
| **Electron ASAR 17 MiB Header & Erlang BEAM Flood** | **ADMISSION REJECTED** (ASAR `16.63 MiB > 16 MiB`; BEAM `BeamCapacityFailure: chunk count 260 exceeds default max_chunks (64)`) | **RECOVERED** (Collapsed `4000` shard decoys; skipped `257` vendor chunks & `4148` decoy atoms) | `2` real ASAR files & `12` genuine BEAM atoms | Exact entrypoint & atom recovery |

---

## 2. JavaScript Deobfuscation & Cost Breakdown (`bankrupt` + `--self-seal`)

- **Original Unhardened Source**: `741 B` (`266` estimated BPE tokens)
- **BLA `bankrupt` + `--self-seal` Artifact**: `139,843 B` (`60,464` estimated BPE tokens — **227.3x token amplification**)
- **Self-Seal Armed Verification**:
  - Canonical SHA-256 self-digest valid on disk: `true`
  - 1-byte on-disk modification caught by `self-seal`: `true`
- **Bit-Vector + Export/Write-Only Slice Stats**:
  - Top-level `KnownBits` parity-constrained bindings inferred: `2`
  - Closed pure containment-digest calls evaluated: `1`
  - Opaque predicates folded (`Math.imul` consecutive parity / odd-square mod 8 / non-residue): `68`
  - Combinatorial string chunks collapsed: `54`
  - Constant binary expressions folded: `160`
  - Dead `IfStatement` guards/tarpit branches eliminated: `6`
  - Write-only `stepShadowHeap` calls eliminated: `2`
  - Unreachable decoy/labyrinth/chaff declarations pruned: `137`
  - Local BPE-amplified identifiers alpha-normalized: `14`

### Recovered Clean Analysis View (Projected In-Memory from `139,843 B` Hardened Input)

```javascript
function computeQuote(p0, p1, p2) {
  const v0 = p0 === "enterprise" ? "tier:enterprise" : "tier:standard";
  const v1 = v0 === "tier:enterprise" ? 125 : 45;
  const v2 = p1 * v1;
  const v3 = p2 ? 1500 : 0;
  const v4 = v2 * 100 - Math.floor(v2 * 100 * v3 / 10000);
  return {
    badge: v0 + "/v2",
    seats: p1,
    finalCents: v4
  };
}
function verifyChecksumFrame(p0, p1) {
  const v0 = "frame:verified:";
  const v1 = p0 * 31 + p1 * 17 | 0;
  return v0 + String(v1);
}
exports.computeQuote = computeQuote;
exports.verifyChecksumFrame = verifyChecksumFrame;
```
