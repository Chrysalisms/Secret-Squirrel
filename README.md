# Secret Squirrel 🐿️

> **GPU-accelerated, CNN-powered credential scanner** — the open-source Betterleaks killer.

[![CI](https://github.com/Chrysalisms/Secret-Squirrel/actions/workflows/ci.yml/badge.svg)](https://github.com/Chrysalisms/Secret-Squirrel/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)


---

## Why Secret Squirrel?

This area is a work in progress

### Benchmark Evaluation (Samsung/CredData)

This area is a work in progress

---

## Pipeline Architecture

```
Input → [Stage 1: Shannon Entropy Gate]  → ~5% pass
      → [Stage 2: Semantic Proximity]    → ~3% pass
      → [Stage 3: Tri-Stream Decompose]  → ~1% pass
      → [Stage 4: AC + Regex Pattern]    → findings
      → [Scoring: Markov + CNN Fusion]   → confidence
      → [Correlation Engine]             → credential chains
      → [Validation Engine]              → active + blast radius
```


## License

[Apache 2.0](LICENSE)
