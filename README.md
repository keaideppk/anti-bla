# anti-bla — Resilient Program Analysis & Anti-Exhaustion Benchmark Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`anti-bla` is an empirical program-analysis resilience suite demonstrating how **compiler-grade pre-processing, non-invasive V8 coverage projection, and depth/schema-resilient container parsers** neutralize adversarial LLM token-amplification and static-analyzer budget breakers (such as [`qybaihe/bla`](https://github.com/qybaihe/bla) targeting [`morluto/rea`](https://github.com/morluto/rea)).

> **Defensive & Synthetic Research Scope**: All benchmarks and tests in this repository run exclusively on self-generated synthetic toy fixtures. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Core Architectural Thesis

Adversarial "Blind LLM Agent" shields operate on an **asymmetric cost assumption**: they assume an analysis agent feeds raw obfuscated ASTs, unreachable sponge tarpits, 250-alias export tables, 35-level nested JSON metadata, and BPE-hostile identifiers (`Zq_X9_Kv_W7`) directly into a fixed-budget static parser or an expensive LLM context window.

`anti-bla` breaks that cost asymmetry by inserting a **deterministic, zero-LLM-token normalization & projection layer** *before* any model context or bounded semantic analyzer runs:

1. **`KnownBits` + 32-Bit Bit-Vector Invariant Simplifier (`src/js/bv-simplifier.ts`)**
   - Propagates 32-bit `KnownBits` (`{ zeroMask, oneMask }`) masks across top-level seed initializers and evaluates closed pure containment digests in a zero-capability VM.
   - Soundly folds number-theoretic opaque predicates (`Math.imul(x, x + 1) & 1 === 0`, odd squares $\equiv 1 \pmod 8$, mod-7 quadratic non-residues, 32-bit adder identities) while guarding against false positives on genuine business branches via literal witness injection.
   - Collapses `9+`-chunk combinatorial string ternaries and split integers back into single literals, unwraps `if (true)` guards, and deletes `if (false)` tarpit cross-references.
   - Detects closed **write-only shadow-heap churn** (`shadowHeap` + `stepShadowHeap`) and slices unreachable tarpit/labyrinth/chaff declarations from the **in-memory Analysis View** without altering a single byte on disk.

2. **Non-Invasive V8 Precise Coverage Pruner (`src/js/v8-coverage-pruner.ts`)**
   - Uses Node's built-in `node:inspector/promises` (`Profiler.startPreciseCoverage` + `takePreciseCoverage`) in-process without modifying `NODE_OPTIONS`, `process.execArgv`, or on-disk file bytes.
   - Keeps BLA's `--self-seal` canonical SHA-256 self-digest 100% intact while projecting out `count === 0` cold functions and dead branches.

3. **BPE View Normalizer & Contamination Firewall (`src/js/view-normalizer.ts`, `src/metrics/token-budget.ts`)**
   - Alpha-renames high-fragmentation local identifiers (`Zq_X9_Kv_W7` -> `p0, v0`) while preserving public module exports.
   - Verifies zero prompt-injection / alignment-canary / enclave-mirage strings survive into the downstream analysis view.

4. **Resilient Format & Container Parsers (`src/formats/`)**
   - **SQLite (`resilient-sqlite.ts`)**: Queries `PRAGMA table_xinfo` on a read-only `node:sqlite` connection to skip `hidden === 2` (`VIRTUAL`) trap columns (`enclave_unseal_payload`) and quarantines honey tables structurally without registering untrusted UDFs.
   - **Safetensors (`resilient-safetensors.ts`)**: Single-pass `O(1)`-stack iterative header cursor that skips arbitrary-depth extension traps (`enclave_topology_seal` > 32 levels) while recovering 100% of tensor `dtype`, `shape`, and `data_offsets`.
   - **WASM / ASAR / BEAM (`resilient-containers.ts`)**: Deduplicates WASM exports by `(kind, index)` (collapsing 250+ padded export decoys into canonical function descriptors), groups homogeneous ASAR header shard prefixes (> 16 MiB Pickle JSON headers), and selectively scans standard Erlang BEAM chunks.

---

## Quick Start

Requires **Node.js >= 22.5.0** (Node 24 recommended for built-in `node:sqlite`).

```bash
npm install
npm test
npm run drill
```

- When cloned alongside a built `../bla` (`bla-agents@3.2.5`), `npm run drill` automatically hardens synthetic fixtures using **live `bla` at `intensity: "bankrupt"` + `--self-seal`**.
- In standalone CI environments without `../bla`, `npm test` and `npm run drill` automatically fall back to deterministic built-in `bankrupt` synthetic replicas.
- Full drill outputs are written to [`reports/drill-report.md`](reports/drill-report.md) and [`reports/drill-report.json`](reports/drill-report.json).

---

## Empirical Drill Benchmark (`bla-agents@3.2.5`, `intensity: "bankrupt"` + `--self-seal`)

| Surface & Shield Mechanism | Naive / Default Analyzer | `anti-bla` Resilient Pipeline | Cost / Payload Reduction | Fidelity Check |
| :--- | :--- | :--- | :--- | :--- |
| **JS AST + BPE Amplifier + Tarpit + `--self-seal`** | `60,464` BPE tokens (`139,843 B`, `227.3x` bloat, `2^16` string fanout, `23` poison markers) | **`246` BPE tokens** (`564 B`, `0` poison markers, `0` conditional chains) | **-99.59% BPE tokens** | `100%` output match + `self-seal` intact |
| **JS Dynamic V8 Coverage (`Profiler.takePreciseCoverage`)** | Disk patching trips `Error: integrity check failed` | **`120` cold functions & `90` dead branches** pruned in memory | **-82.12% BPE tokens** | `0` disk bytes modified |
| **SQLite `VIRTUAL` UDF Trap + Honey Tables** | Crashes (`unknown function: enclave_unseal_payload()`) | `PRAGMA table_xinfo` skips `3` virtual columns; quarantines `5` honey tables | `57,344 B` -> **`365 B`** | Business SHA-256 `100%` match |
| **Safetensors 35-Level JSON Nesting Breaker** | Aborts (`depth 33 > MODEL_MAX_JSON_NESTING 32`) | `O(1)` iterative cursor skips depth-`36` trap & `43` chaff keys | `10,096 B` -> **`194 B`** | Tensor SHA-256 `100%` match |
| **WebAssembly 250-Export Budget Breaker** | `49.30 MiB` representation charge (`> 32 MiB` budget) | Grouped by `(kind, index)` into `1` canonical function (`134 B`) | **-99.9997%** | `WebAssembly.instantiate` verified |
| **Electron ASAR 17 MiB Header & Erlang BEAM Flood** | Admission rejected (`16.63 MiB > 16 MiB`; `260 chunks > 64`) | Collapses `4,000` shard decoys; skips `257` vendor chunks & `4,148` decoy atoms | `2` real files & `12` genuine atoms | Exact entrypoint & atom recovery |

---

## Repository Structure

```text
src/
├── metrics/token-budget.ts        # BPE subword estimator, REA limit simulator & poison scanner
├── js/bv-simplifier.ts            # 32-bit KnownBits + bit-vector folder & shadow-heap/export slicer
├── js/v8-coverage-pruner.ts       # Non-invasive V8 Profiler.takePreciseCoverage AST pruner
├── js/view-normalizer.ts          # BPE local alpha-renamer & end-to-end JS resilient pipeline
├── formats/resilient-sqlite.ts    # PRAGMA table_xinfo virtual-column bypass & honey quarantine
├── formats/resilient-safetensors.ts # Iterative O(1)-stack Safetensors header parser
├── formats/resilient-containers.ts  # WASM (kind,index) canonicalizer + ASAR/BEAM resilient readers
└── drill/
    ├── synthetic-fixtures.ts      # Live ../bla v3.2.5 loader + standalone CI synthetic fallback
    └── run-drill.ts               # Empirical breakthrough drill runner & report generator
```

## License

[MIT](LICENSE)
