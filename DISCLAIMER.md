# Scope & Research Disclaimer

`anti-bla` is a **defensive program-analysis resilience and parser-hardening benchmark suite**.

## Intended Use

- Evaluating and improving the resilience of static/dynamic program analyzers, AST simplifiers, and container parsers against resource-exhaustion tarpits, parser depth/budget breakers, and LLM context-amplification noise.
- Benchmarking compiler optimization passes (32-bit bit-vector constant folding, V8 coverage-guided in-memory slice projection, write-only dead-store elimination, and BPE identifier normalization) strictly on **synthetic, self-generated benchmark fixtures**.
- Studying the cost/precision trade-offs between static analyzer resource caps (such as those in `morluto/rea`) and adversarial token-amplification shields (such as `qybaihe/bla`).

## Non-Goals & Restrictions

- This repository does **not** target, include, or process any third-party proprietary software, commercial DRM systems, or real-world licensed binaries.
- All drill artifacts evaluated by `npm run drill` and `npm test` are generated locally in memory or temporary directories from synthetic toy fixtures created within this repository.
- Users are solely responsible for ensuring they have explicit authorization before applying any program-analysis tooling to software they do not own.
