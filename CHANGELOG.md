# Changelog

All notable changes to Secret Squirrel are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Phase 4: Database source adapter (PostgreSQL, MySQL, MongoDB dialect detection)
- Phase 4: Elasticsearch/OpenSearch source adapter with Scroll API pagination
- Phase 4: NPM/PyPI package source adapter with in-memory tarball extraction
- Phase 4: Comprehensive integration test suite (`tests/integration/pipeline_e2e.rs`)
  - Fixture presence and content validation tests
  - Entropy correctness tests (all-zero, all-unique, AWS key, GitHub PAT, OpenAI key)
  - RedactedString safety tests (≤40% exposure guarantee)
  - All 4 output formatter integration tests (JSON, SARIF, CSV, Table)
  - CNN tokenizer correctness tests
  - MarkovScorer ranking tests (secrets rank below prose)
- Phase 4: Test fixtures for Ansible, Docker Compose, Python app, Postman, Jupyter, AWS config
- Phase 4: Criterion benchmarks for entropy gate, pipeline, and tokenizer throughput
- Phase 4: GitHub Actions CI workflow (Linux/macOS/Windows, fmt, clippy, audit, release builds)
- Phase 4: README.md with full CLI reference, architecture overview, and source coverage table
- Phase 4: CONTRIBUTING.md with build guide, rule authoring guide, and source adapter guide
- Phase 4: SECURITY.md with threat model, data handling policy, and responsible disclosure

---

## [0.1.0] — 2026-05-27 (Initial Release)

### Phase 1: Foundation

**Core Pipeline**
- 4-stage inverted pipeline: Shannon Entropy Gate → Semantic Proximity → Tri-Stream Decomposition → Pattern Verification
- Smart GPU/CPU router: GPU path for batches >100 MB via wgpu v22; CPU SIMD path for smaller inputs
- SIMD-optimized entropy calculation (AVX2 on x86_64, scalar fallback)
- Aho-Corasick multi-pattern matching (Stage 4) with regex confirmation

**Core Types**
- `RedactedString`: ≤40% visibility cap, `zeroize` on Drop, HMAC-SHA256 per-session hashing
- `Finding`, `FusedScore`, `Location`, `Severity`, `ValidationStatus` — full type system
- `Fragment` with `FragmentMetadata` for all source adapters

**Scoring**
- `MarkovScorer`: 64-char trigram table (~140 KB), ~500K strings/sec throughput
- `FusionEngine`: weighted confidence fusion (entropy 15%, proximity 15%, tristream 20%, markov 25%, pattern 25%)
- `ConfidenceScorer`: path depth, file extension, and variable name provenance adjustments
- `CorrelationEngine`: cross-file credential chain detection (origin → propagation → usage)
- `DeduplicateEngine`: dedup by (rule_id, secret_hash, location)

**Sources**
- Directory scanner (memmap2 zero-copy, .gitignore-aware via ignore crate)
- Git history scanner (gix, configurable depth)
- Stdin/pipe scanner
- Archive scanner (ZIP, TAR, GZ, BZ2, XZ; 100:1 decompression ratio limit)
- .env file scanner with variable name context preservation

**Rules**
- 800+ rules organized by category: cloud, saas, devtools, database, crypto, ai, payments, generic
- TOML rule parser (Betterleaks + Gitleaks format compatible)
- Rule compiler: pre-compile regex, build AhoCorasick automaton, ReDoS detection
- Rule registry with category-based organization and hot-reload

### Phase 2: MCP + Validation + Platform Sources

**MCP Server**
- JSON-RPC over stdio via `rmcp` crate
- 6 tools: `scan_text`, `scan_file` (path-sandboxed), `scan_diff`, `scan_repo`, `validate_finding` (opaque ID only), `get_rules`
- Credential Oracle prevention: `validate_finding` accepts hex IDs only

**Validation Engine**
- 16+ provider validators: AWS (STS), GitHub, GitLab, Slack, Stripe, OpenAI, GCP, Heroku, NPM, Docker Hub, Postman, Shopify, PagerDuty, Mailgun, Datadog, SendGrid
- Per-provider token bucket rate limiting (`governor`)
- Circuit breaker: stops attempting after 5 consecutive failures
- Blast radius enumeration: AWS IAM permissions, GitHub OAuth scopes, Slack bot scopes

**Platform Sources (stubbed, API-ready)**
- GitHub, GitLab, S3/R2/GCS, Docker images, Kubernetes, Terraform, Bitbucket, Azure DevOps

### Phase 3: CNN + CLI + Additional Sources + Action

**CNN/ONNX Classifier**
- 4 model tiers: Tiny (2 MB/96-97%), Large (4 MB/98-99%), Enhanced (55 MB TinyBERT), Maximum (260 MB DistilBERT)
- ONNX Runtime via `ort` crate, FP32 only (no quantization)
- `model_manager.rs`: pull/list/info with SHA-256 checksum verification
- Character-level tokenizer (100-symbol alphabet, always compiled)

**CLI**
- All subcommands: `detect`, `validate`, `protect`, `rules`, `model`, `version`
- All output formats: table (ANSI colored), JSON, SARIF v2.1.0, CSV
- Push protection: `protect install/uninstall/check` with git pre-commit hook

**Additional Sources**
- Ansible playbooks + roles + vault detection
- CI/CD logs: GitHub Actions (ZIP log extraction), GitLab CI, Jenkins, CircleCI stubs
- Slack: conversations.list + history, authorization gate, Tier 3 rate limiting
- Postman: Collection v2.1 JSON, environment files, headers
- Jupyter: .ipynb code cell + output extraction

**GitHub Action**
- `action.yml`, `Dockerfile.action` (multi-stage), `entrypoint.sh`
- Inputs: scan-mode, config-path, severity-threshold, validate, model-tier
- SARIF upload + PR annotation output

### Test Results (v0.1.0)

| Suite | Count | Result |
|-------|-------|--------|
| Unit tests | 432 | ✅ PASS |
| Integration tests | 32 | ✅ PASS |
| Doctests | 15 (4 ignored) | ✅ PASS |
| Benchmarks | Compile verified | ✅ |
| `cargo check --all-features` | — | ✅ Clean |

---

[Unreleased]: https://github.com/Chrysalisms/Secret-Squirrel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Chrysalisms/Secret-Squirrel/releases/tag/v0.1.0
