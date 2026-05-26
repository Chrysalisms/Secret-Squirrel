# Secret Squirrel — Product Requirements Document (PRD)

**Version:** 1.0  
**Date:** May 26, 2026  
**License:** Apache 2.0  
**Status:** Draft — Pending Review

---

## 1. Problem Statement

Leaked credentials are the #1 initial access vector for breaches. Existing open-source secret scanners face three fundamental limitations:

1. **Speed ceiling** — CPU-bound regex scanning caps at ~200 MB/s (Betterleaks) to ~100 MB/s (TruffleHog). Scanning enterprise monorepos or S3 data lakes takes hours.
2. **False positive fatigue** — Regex-only approaches produce 40-60% false positives (Gitleaks: ~46% precision on SecretBench). Teams stop trusting the tool and ignore findings.
3. **Narrow scope** — Most scanners only handle git repos. Secrets leak everywhere: Slack, Jira, Terraform state, Docker images, CI logs, Jupyter notebooks, shell history.

**Secret Squirrel** solves all three by combining GPU-accelerated statistical pre-filtering with the most comprehensive source coverage of any open-source scanner, exposed as both a CLI tool and an AI-agent-native MCP server.

---

## 2. Target Users

### Primary

| Persona | Pain Point | What They Need |
|---|---|---|
| **Security Engineer** | Drowning in false positives from existing scanners | High-precision findings with blast radius context |
| **DevOps / Platform Engineer** | Secrets in CI/CD, Terraform state, Docker images go unscanned | One tool that scans everything |
| **AI/Coding Agent** (Copilot, Cursor, Claude Code) | No real-time pre-commit secret feedback | MCP server returning structured findings instantly |

### Secondary

| Persona | Pain Point | What They Need |
|---|---|---|
| **AppSec Lead** | Managing 3+ scanning tools across the org | Single tool with SARIF output for unified dashboards |
| **Open-source maintainer** | Contributors accidentally commit keys | GitHub Action that blocks PRs with secrets |
| **Incident responder** | Finding the blast radius of a leaked credential | Validation + permissions enumeration in one step |

---

## 3. Deployment Modes

Secret Squirrel ships as **three deployment profiles** optimized for different use cases:

### 3.1 CLI Binary (Lean Profile)

| Attribute | Target |
|---|---|
| Binary size | <15 MB (stripped, no ML model) |
| Startup time | <100 ms |
| ML capability | Tier 1: Trigram Markov chain (140KB, embedded) |
| GPU support | Auto-detected via wgpu; CPU fallback if unavailable |
| Use case | Developer workstation, pre-commit hooks, CI pipelines |
| Distribution | Homebrew, cargo install, GitHub releases, Docker |

**Drop-in Betterleaks/Gitleaks replacement:**
- Reads `.betterleaks.toml` and `.gitleaks.toml` configs unchanged
- Same CLI flags: `--source`, `--config`, `--report-format`, `--exit-code`
- Superset output: adds `confidence`, `blast_radius`, `credential_chain` fields
- Migration: `alias betterleaks=squirrel` should work for >95% of workflows

### 3.2 GitHub Action (ML-Enhanced Profile)

| Attribute | Target |
|---|---|
| Image size | ~150 MB (Docker-based action) |
| Startup time | ~2 seconds (acceptable for CI) |
| ML capability | Tier 1 (Markov) + **Tier 3: Character-level CNN via ONNX Runtime** |
| GPU support | CPU-only (GitHub runners lack GPUs; SIMD-optimized) |
| Use case | PR checks, push protection, scheduled org-wide scans |
| Distribution | GitHub Marketplace, `ghcr.io` container registry |

> [!IMPORTANT]
> **Why CNN/ONNX makes sense here and ONLY here:**
> In a GitHub Action, the usual CLI objections vanish. Startup latency (~200ms ONNX init) is noise in a CI pipeline. Binary size (~30MB ort overhead) is irrelevant in a Docker image. And 7GB runner RAM is plenty. The CNN provides a **second-stage classifier** that reduces false positives by an estimated 15-30% over regex-only, which directly translates to fewer noisy PR comments.

**CNN Architecture — Tiered Model Specs:**

| Tier | Profile | Params | Format | Size | Use Case |
|---|---|---|---|---|---|
| Tiny CNN | GH Action (CPU) | 500K | FP32 ONNX | ~2 MB | Default for CI runners without GPU |
| Large CNN | Self-hosted (CPU) | 1M | FP32 ONNX | ~4 MB | Higher accuracy for self-hosted runners |
| TinyBERT | Self-hosted (GPU) | 14M | FP16 ONNX | ~28 MB | GPU-accelerated runners |
| DistilBERT | Self-hosted (GPU) | 66M | FP16 ONNX | ~130 MB | Maximum accuracy, requires GPU |

- Kernel sizes [2,3,4,5] with 128-dim character embeddings (CNN tiers)
- Inference: ~0.1-1ms per candidate string (CNN), ~1-5ms (transformer tiers)
- Training data: CredData + SecretBench (19M+ labeled lines)
- Purpose: Post-regex classifier that scores candidates as `secret` / `not_secret`
- Framework: `ort` crate (ONNX Runtime wrapper)
- Model selection: automatic based on available hardware; override via `squirrel model pull <tier>`

**GitHub Action features:**
- SARIF upload to GitHub Security tab
- PR comment annotations (inline findings on changed files)
- Push protection mode (fail the check if secrets detected)
- Configurable severity thresholds
- Caching of scan state across runs (incremental scanning)
- `permissions: security-events: write` for SARIF, `pull-requests: write` for comments

### 3.3 MCP Server (Agent Profile)

| Attribute | Target |
|---|---|
| Protocol | MCP (Model Context Protocol) via `rmcp` SDK |
| Transport | stdio (default), HTTP+SSE (optional) |
| ML capability | Same as CLI host (Markov; CNN if Docker-hosted) |
| Use case | Real-time feedback for AI coding agents |
| Distribution | Bundled with CLI binary (`squirrel mcp-server`) |

**MCP Tools exposed:**

| Tool | Input | Output | Latency Target |
|---|---|---|---|
| `scan_text` | Raw text + optional filename | Findings array with confidence scores | <50ms |
| `scan_file` | File path | Findings array | <100ms |
| `scan_diff` | Git diff content | Findings on changed lines only | <100ms |
| `scan_repo` | Repo path + options | Full scan results | Depends on repo size |
| `validate_finding` | Finding ID only | Validation result + blast radius | <2s |
| `get_rules` | Optional category filter | Rule definitions | <10ms |

> [!WARNING]
> `validate_finding` accepts **Finding IDs only**, not raw secret strings. Accepting secret strings would create a credential oracle vulnerability — an attacker could probe arbitrary strings through the MCP interface to confirm whether they are valid credentials.

---

## 4. Functional Requirements

### FR-1: Detection Pipeline (Core)
- **FR-1.1:** Implement the four-stage inverted pipeline: Shannon Entropy → Semantic Proximity → Tri-Stream Decomposition → Pattern Verification
- **FR-1.2:** GPU acceleration via wgpu for Stages 1-3 when GPU is available
- **FR-1.3:** CPU fallback using rayon + SIMD (AVX2/NEON) that produces identical results
- **FR-1.4:** Smart routing: GPU for batches >100MB, CPU for individual files/<10MB
- **FR-1.5:** Trigram Markov chain randomness scoring (replaces BPE token efficiency)
- **FR-1.6:** Character-level CNN classifier via ONNX Runtime (GitHub Action profile only)

### FR-2: Rule Engine
- **FR-2.1:** Full backward compatibility with `.betterleaks.toml` and `.gitleaks.toml` rule formats
- **FR-2.2:** Extended `[rules.squirrel]` sections for GPU-tuning parameters (ignored by Betterleaks)
- **FR-2.3:** 800+ rules organized by provider taxonomy at launch
- **FR-2.4:** Hot-reload rules from URL or local path without restarting
- **FR-2.5:** Rule categories: cloud, saas, devtools, database, crypto, ai, payments, generic

### FR-3: Source Adapters (15 Sources at v1.0; 40+ Aspirational)

> [!IMPORTANT]
> **v1.0 ships with 15 sources.** The full list below is aspirational. Sources marked ✅ are in v1.0 scope; unmarked sources are on the v1.1–v2.0 roadmap. This was tempered per reviewer consensus — shipping fewer sources with higher quality is preferable to 40+ undertested adapters.

- **FR-3.1:** Core sources: Git ✅, Directory ✅, Stdin ✅, Archives ✅, dotenv ✅
- **FR-3.2:** Platform sources: GitHub ✅, GitLab ✅, Bitbucket, Azure DevOps, S3/R2/GCS ✅
- **FR-3.3:** Infrastructure: Docker ✅, Kubernetes ✅, Terraform ✅, Ansible, CloudFormation, Pulumi, Vagrant
- **FR-3.4:** Communication: Slack ✅, Discord, Teams, Jira ✅, Confluence, Notion, Google Docs
- **FR-3.5:** CI/CD: GitHub Actions logs ✅, GitLab CI, Jenkins, CircleCI, Travis CI, CodeBuild
- **FR-3.6:** Data: Databases (Postgres/MySQL/MongoDB/Redis), Elasticsearch, NPM/PyPI packages
- **FR-3.7:** Endpoint: HTTP responses, Postman/Insomnia collections ✅, SSH config, shell history, Jupyter notebooks, browser localStorage
- **FR-3.8:** All sources implement the `Source` trait with streaming iterator interface

### FR-4: Validation Engine
- **FR-4.1:** 30+ provider validators at launch (AWS, GitHub, GCP, Slack, Stripe, etc.)
- **FR-4.2:** Permissions enumeration ("blast radius") for AWS, GitHub, GCP, Slack
- **FR-4.3:** Rate limiting via per-provider token bucket algorithm
- **FR-4.4:** Validation statuses: `active`, `inactive`, `revoked`, `needs_validation`, `error`, `unknown`
- **FR-4.5:** Opt-in via `--validate` flag (never validate by default — security concern)

### FR-5: Cross-File Correlation
- **FR-5.1:** Index findings by secret value AND variable name across scan session
- **FR-5.2:** Detect multi-file credential chains (e.g., .env → docker-compose → app code)
- **FR-5.3:** Output credential chains as linked finding groups
- **FR-5.4:** Enabled via `--correlate` flag

### FR-6: Scoring & Confidence
- **FR-6.1:** Each finding has a `confidence` score (0.0-1.0) combining:
  - Entropy score (Stage 1)
  - Proximity score (Stage 2)
  - Tri-stream fusion score (Stage 3)
  - Pattern match strength (Stage 4)
  - Markov randomness score
  - CNN classification score (GitHub Action only)
  - AST context adjustment (if `--semantic` enabled)
- **FR-6.2:** Configurable confidence threshold for filtering output

### FR-7: Output & Reporting
- **FR-7.1:** JSON output (default, machine-readable)
- **FR-7.2:** SARIF output (GitHub Security tab integration)
- **FR-7.3:** Human-readable table output (terminal)
- **FR-7.4:** CSV output
- **FR-7.5:** Exit codes: 0 (no findings), 1 (findings found), 2 (error)
- **FR-7.6:** `--baseline` mode: compare against previous scan, only report NEW findings

### FR-8: MCP Server
- **FR-8.1:** Expose scan tools via MCP protocol (scan_text, scan_file, scan_diff, scan_repo)
- **FR-8.2:** Expose validate_finding tool for on-demand credential verification
- **FR-8.3:** stdio transport (default) and HTTP+SSE transport (optional)
- **FR-8.4:** Structured JSON responses with finding metadata

### FR-9: GitHub Action
- **FR-9.1:** Docker-based action published to GitHub Marketplace
- **FR-9.2:** SARIF upload to GitHub Security tab
- **FR-9.3:** Inline PR comment annotations on changed files
- **FR-9.4:** Push protection mode (configurable to fail check)
- **FR-9.5:** CNN classification enabled by default in action profile
- **FR-9.6:** Incremental scanning with state caching between runs
- **FR-9.7:** Action inputs: `scan-mode`, `config-path`, `severity-threshold`, `validate`, `sarif-upload`

### FR-11: Additional CLI Commands
- **FR-11.1:** `squirrel model pull <tier>` — Downloads a specific ML model tier (tiny-cnn, large-cnn, tinybert, distilbert) for local use. Models are fetched from GitHub Releases and cached in `~/.squirrel/models/`. Without this command, the CLI uses only the embedded Markov chain (Tier 1).
- **FR-11.2:** `squirrel protect` — Installs Secret Squirrel as a git `pre-commit` hook in the current repository. Equivalent to `squirrel scan --hook pre-commit --install`. Provides a one-command onboarding experience for developers.

### FR-10: Semantic Analysis (Opt-in)
- **FR-10.1:** Tree-sitter AST parsing for matched files (not all files)
- **FR-10.2:** Confidence adjustment based on AST node type (comment: -80%, assignment: +30%, test scope: -50%)
- **FR-10.3:** Enabled via `--semantic` flag
- **FR-10.4:** Supported languages: JavaScript, TypeScript, Python, Go, Rust, Java, Ruby, C/C++, C#, PHP

---

## 5. Non-Functional Requirements

### NFR-1: Performance

| Metric | CLI Target | GitHub Action Target |
|---|---|---|
| Throughput (GPU) | ~1-3 GB/s (to be validated via benchmark) | N/A (no GPU on runners) |
| Throughput (CPU, 8-core) | ≥800 MB/s | ≥800 MB/s |
| Single file latency | <5 ms | <5 ms |
| Startup time | <100 ms | <3 seconds |
| Peak RAM (1GB repo) | <400 MB (CPU) / <200 MB + VRAM (GPU) | <2 GB |

> [!NOTE]
> GPU throughput target tempered from the original ≥5,000 MB/s per code reviewer analysis. The entropy kernel is PCIe transfer-bound, not compute-bound — PCIe 4.0 x16 practical throughput caps at ~12-15 GB/s for bulk transfers, and the full pipeline including host↔device copies is estimated at 1-3 GB/s. This target will be validated via benchmark during Phase 1 development.

### NFR-2: Accuracy

| Metric | Target |
|---|---|
| CredData recall | ≥97% (validate during Phase 1) |
| Precision (SecretBench) | ≥80% CLI, ≥90% with CNN in Action |
| GPU/CPU parity | Identical findings from both paths |
| False positive rate | <20% CLI, <10% Action (with CNN) |

### NFR-3: Compatibility

| Requirement | Detail |
|---|---|
| Betterleaks TOML | Full backward compatibility |
| Gitleaks TOML | Full backward compatibility |
| OS support | Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) |
| GPU backends | Vulkan, Metal, DX12 (via wgpu) |
| MSRV | Rust stable - 3 |

### NFR-4: Security
- The scanner MUST NOT log, transmit, or persist scanned secret values in cleartext
- Validation MUST be opt-in only (`--validate` flag)
- Auto-revocation MUST require explicit confirmation (dry-run by default)
- MCP server MUST NOT execute arbitrary code from agent inputs
- GitHub Action MUST use minimal required permissions

### NFR-5: Reliability
- Crash-free on malformed input (fuzz testing required)
- Graceful degradation: GPU failure → automatic CPU fallback
- Source adapter failures are non-fatal (skip source, log warning, continue)
- Rate limit exhaustion: queue and retry, never crash

---

## 6. User Stories

### Drop-in Replacement
- **US-1:** As a Betterleaks user, I can switch to Secret Squirrel by changing one binary path and keep my existing `.betterleaks.toml` config unchanged.
- **US-2:** As a Gitleaks user, I can switch to Secret Squirrel using my existing `.gitleaks.toml` with zero changes.

### CI/CD Integration
- **US-3:** As a DevOps engineer, I can add Secret Squirrel as a GitHub Action that blocks PRs containing secrets, with inline comments showing exactly where the secret is.
- **US-4:** As an AppSec lead, I can see Secret Squirrel findings in the GitHub Security tab alongside other SAST results.
- **US-5:** As a platform engineer, I can run Secret Squirrel in a scheduled GitHub Action that scans all repos in my org weekly.

### AI Agent Integration
- **US-6:** As an AI coding agent (Copilot, Cursor), I can invoke Secret Squirrel via MCP to check code for secrets before committing.
- **US-7:** As a developer using an AI assistant, I get real-time warnings when my AI generates code containing hardcoded credentials.

### Comprehensive Scanning
- **US-8:** As a security engineer, I can scan our entire S3 data lake, Slack workspace, and Jira project in a single command.
- **US-9:** As an incident responder, I can validate a leaked AWS key and immediately see its blast radius (what permissions it has, what resources it can access).

### Advanced Detection
- **US-10:** As a security engineer, I can see that a credential found in `.env` is also referenced in `docker-compose.yml` and used in `app.py`, showing the full credential chain.

---

## 7. Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| **CredData recall** | ≥97% | Automated benchmark in CI |
| **SecretBench precision** | ≥80% CLI, ≥90% Action | Automated benchmark |
| **Throughput** | ≥4x Betterleaks (CPU), ≥25x (GPU) | Benchmark suite |
| **GitHub stars** | 1,000 in first 6 months | GitHub API |
| **Betterleaks migration** | >50% of community configs work unchanged | Compatibility test suite |
| **Rule count** | 800+ at launch | Automated count in CI |
| **Source count** | 15 at v1.0 launch (40+ aspirational across v1.1-v2.0) | Feature matrix |
| **GitHub Action installs** | 500 in first 3 months | Marketplace analytics |

---

## 8. Out of Scope (v1.0)

- Real-time network traffic interception (NIDS mode)
- Full SAST/SCA capabilities (we scan for secrets, not bugs)
- SaaS hosted platform (we are local-first/open-source)
- Custom model training UI (CNN model is pre-trained and shipped)
- Remediation automation beyond dry-run revocation suggestions
