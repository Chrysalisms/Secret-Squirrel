# Benchmarking Secret-Squirrel vs Betterleaks

This repository now includes a dedicated benchmark harness for comparing
`Secret-Squirrel` and `Betterleaks` on a shared dataset.

The benchmark is intentionally split into two phases:

1. `CredData` for labeled accuracy metrics.
2. A pinned repository-tree corpus for real-world disagreement analysis.

## Benchmark Principles

Use the same dataset, output format, and scan scope for both tools.

The pinned baseline in this repo is:

- `Secret-Squirrel` build: `cargo build --release --bin squirrel --no-default-features --features cli,cpu-simd`
- `Secret-Squirrel` scan flags:
  - `detect`
  - `--severity low`
  - `--confidence 0.5`
  - `--profile fast`
  - `--fail-on critical`
  - `--format json`
- `Betterleaks` scan flags:
  - `dir`
  - `-f json`
  - `-r <output>`
  - `--exit-code 0`

Why these defaults:

- `Secret-Squirrel` uses a CPU-only release build to avoid GPU/hardware variance.
- `--profile fast` keeps the comparison focused on the current, practical directory scanner path.
- `--severity low` and `--confidence 0.5` maximize visibility into recall gaps.
- `--fail-on critical` prevents expected findings from aborting the run while preserving a real CLI contract.
- Validation/network lookups are left off for both tools.

## CredData Accuracy Benchmark

Clone the dataset on demand and run the dedicated harness:

```bash
python scripts/benchmark_compare.py creddata --clone-creddata
```

The harness will:

- build `Secret-Squirrel`
- scan `benchmark/CredData/data`
- scan the same directory with `Betterleaks`
- evaluate both outputs against CredData ground truth
- save compact and detailed JSON reports
- write a markdown summary with metrics and overlap counts

Artifacts are written under `artifacts/benchmarks/creddata/<timestamp>/`.

Key files:

- `benchmark_summary.json`: compact TP/FP/FN/P/R/F1 metrics
- `benchmark_details.json`: metrics plus examples and overlap data
- `benchmark_summary.md`: human-readable summary
- `squirrel_creddata.json`: raw `Secret-Squirrel` findings
- `betterleaks_creddata.json`: raw `Betterleaks` findings
- `run_metadata.json`: exact commands, timing, and log paths

## Repository-Tree Corpus Benchmark

The second phase uses a pinned manifest at `docs/benchmark_repo_corpus.toml`.

Run it with:

```bash
python scripts/benchmark_compare.py corpus --clone-missing
```

This scans checked-out repository trees only, not git history. That keeps the
comparison apples-to-apples with `Secret-Squirrel`'s current CLI scan path.

Artifacts are written under `artifacts/benchmarks/corpus/<timestamp>/`.

For each repo, the harness saves:

- raw `Secret-Squirrel` JSON
- raw `Betterleaks` JSON
- overlap JSON (`shared`, `only_squirrel`, `only_betterleaks`)
- runtime metadata
- a short markdown summary

The root corpus run also writes `corpus_summary.json` and `corpus_summary.md`.

## Manual Review Workflow

The detailed overlap output is the most useful signal for improving
`Secret-Squirrel`.

Start with:

- `only_betterleaks`: likely recall gaps in rules or filtering
- `only_squirrel`: likely false positives or localization differences
- `shared_matches`: stable baseline detections both tools agree on

Use those buckets to drive follow-up work on:

- missing rule coverage
- confidence threshold tuning
- path filtering and ignore behavior
- line normalization bugs

## Notes

- The old `scripts/wsl_fuzz_and_bench.sh` script mixes fuzzing, setup, and benchmarking. Keep it separate from this comparison workflow.
- The benchmark harness assumes `betterleaks` is already installed and on `PATH`, or that you pass `--betterleaks-binary`.
- The detailed CredData evaluator now records example true positives, false positives, false negatives, and tool-overlap samples so you can inspect disagreements without manually diffing raw JSON first.
