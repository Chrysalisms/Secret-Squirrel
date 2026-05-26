# Secret Squirrel — Consolidated Review Synthesis

**Date:** May 26, 2026  
**Reviewers:** 4 specialized agents  
**Documents Reviewed:** PRD v1.0, TDD v1.0, Implementation Plan

---

## Executive Summary

> **Verdict: The architecture is fundamentally sound. All four reviewers independently validated the 4-stage inverted pipeline, the GPU/CPU hybrid routing, and the cross-file correlation engine as genuine innovations. However, 12 blockers must be resolved before implementation begins.**

All four reviewers converged on the same core assessment: the pipeline design is the strongest part of the system, but the implementation details — particularly around source scope, memory management, GDPR compliance, and Rust-specific API design — need significant tightening.

---

## Cross-Reviewer Consensus Matrix

Issues where **2+ reviewers independently identified the same problem:**

| Issue | 🔧 Code | 🏗️ Arch | 🔒 Security | ⚙️ SRE | Severity |
|---|---|---|---|---|---|
| **40+ sources at launch is unrealistic** | ✅ C-7 | ✅ C6 | — | ✅ C4 | 🔴 HIGH |
| **GPU/CPU parity testing underspecified** | ✅ B-3 | ✅ C5 | — | ✅ B3 | 🔴 HIGH |
| **RedactedString UTF-8 panic bug** | ✅ C-6 | ✅ C8 | ✅ C1 | — | 🔴 HIGH |
| **No observability / telemetry** | — | ✅ R7 | — | ✅ C5 | 🔴 HIGH |
| **Correlation engine will OOM on large repos** | — | ✅ C2 | — | ✅ C11 | 🟡 MEDIUM-HIGH |
| **No backpressure between pipeline stages** | — | ✅ C4 | — | — | 🟡 MEDIUM-HIGH |
| **No circuit breaker for validators** | — | ✅ C9 | — | ✅ C7 | 🟡 MEDIUM |
| **Trigram alphabet too narrow (26 chars)** | — | ✅ B3 | — | — | 🔴 BLOCKER |

---

## All Blockers — Organized by Resolution Priority

### 🔴 TIER 1: Must Resolve Before Any Code Is Written

| # | Blocker | Source | Resolution |
|---|---|---|---|
| **B1** | **`std::simd` is nightly-only** — conflicts with stable Rust MSRV target | Code | **Use `std::arch` intrinsics** with per-platform implementations (AVX2, NEON), or the `wide`/`pulp` crate for portable SIMD on stable Rust. Do NOT target nightly. |
| **B2** | **`PipelineExecutor` trait is undefined** — referenced in router.rs but never specified | Code | Define the trait with `execute_entropy()`, `execute_proximity()`, `execute_tristream()` methods before writing any stage code. |
| **B3** | **Trigram alphabet is 26 chars (a-z only)** — will miss secrets with digits, uppercase, special chars | Arch | **Expand to 64-char alphabet** (a-z, A-Z, 0-9, `_`, `-`) → 262,144 entries (~1MB). Validate on CredData before hardening the architecture. |
| **B4** | **Router threshold inconsistency** — TDD code says `>100MB → GPU`, implementation plan shows a "profile both" decision node for 10-100MB | Arch | **Commit to a single threshold** (100MB). Remove the "profile both" gray zone from the implementation plan. Document that this is tunable via config. |

### 🔴 TIER 2: Must Resolve Before v1.0 Ships

| # | Blocker | Source | Resolution |
|---|---|---|---|
| **B5** | **GDPR/Privacy — scanning Slack/Jira/Teams** without data controls is a legal liability | Security | **Add `--gdpr-mode` flag**, PII filters, data residency config, and "I acknowledge authorization" for communication sources. Add a Data Privacy section to docs. See §GDPR Framework below. |
| **B6** | **Auto-revocation safety rails insufficient** — no rollback, no dependency check, no multi-party approval | Security | **Remove auto-revocation from v1.0 entirely.** PRD §8 already says it's out of scope. Make the implementation plan match. Ship revocation-suggestions-only in v1.0; actual revocation in v2.0. |
| **B7** | **`match_text` may expose adjacent secrets** — SARIF context regions could leak nearby credentials | Security | **Define that `match_text` always redacts the detected secret.** Scan adjacent context lines for secrets before including them in output. Add integration tests. |
| **B8** | **ONNX Runtime linking undefined for Docker** — `ort` dynamically loads `libonnxruntime.so` but Dockerfile doesn't vendor it | SRE | **Use `ort`'s static-linking feature** or explicitly `COPY libonnxruntime.so` into the runtime image. Add `RUN squirrel --version` health check to Dockerfile. |

### 🟡 TIER 3: Must Resolve During Phase 1 Development

| # | Blocker | Source | Resolution |
|---|---|---|---|
| **B9** | **Incremental scan state has zero design** — `--baseline` and GH Action caching are PRD requirements with no TDD spec | Arch | Design `ScanState` struct with file fingerprints (path + size + modified + xxhash). Persist as `.squirrel-state.json`. |
| **B10** | **Fragment lifecycle and ownership undefined** — when does `Bytes` content get freed in a pipeline with GPU buffers, correlation refs, and backpressure? | Arch | Document the ownership model: fragments are dropped after Stage 4 unless correlation holds a `FindingRef` (which stores hash, not content). |
| **B11** | **No observability architecture** — no structured logging, metrics, or tracing spans | SRE | Add `tracing` + `tracing-subscriber` with JSON formatter. Emit stage-level metrics as structured log events. |
| **B12** | **GPU/CPU parity testing needs automated harness** — floating-point divergence will cause flaky tests | Code + SRE | Define parity as "identical finding sets" with ±0.05 entropy epsilon near thresholds. Build deterministic test vectors. |

---

## Key Decisions Required

> [!IMPORTANT]
> The following decisions need resolution. They affect the architecture and should be decided before coding begins.

### Decision 1: Source Count at v1.0

| Option | Sources | Dev Effort | Maintenance Risk |
|---|---|---|---|
| A: Ship 8-10 stable (All reviewers recommend) | Git, Dir, Stdin, Archives, .env, GitHub, GitLab, S3, Docker | ~40 days | Low |
| **B: Ship 15 sources** ✅ USER SELECTED | Above + K8s, Terraform, Slack, Jira, CI logs, Postman | ~75 days | Medium |
| C: Ship 40+ sources (current plan) | Everything | ~200 days | Very High |

> ✅ **DECIDED:** Option B. Ship 15 sources at v1.0. Remaining 25+ sources moved to Future Features Roadmap for v1.1-v2.0.

### Decision 2: GPU Throughput Target

| Claim | Evidence | Recommendation |
|---|---|---|
| ~~5,000 MB/s~~ **~1-3 GB/s** | No benchmark; PFAC literature suggests possible for compute-only | ✅ **Tempered to ~1-3 GB/s** |
| PCIe 4.0 x16 practical limit | ~12-15 GB/s for bulk transfers | Entropy kernel will be transfer-bound, not compute-bound |
| Code reviewer's estimate | 1-3 GB/s for full pipeline including transfers | Benchmark in Phase 1, revise claims after measurement |

> ✅ **DECIDED:** Mark as ~1-3 GB/s until benchmarked in Phase 1.

### Decision 3: Async vs Sync Source Trait

| Option | Pros | Cons |
|---|---|---|
| A: Unified async trait (current) | Simple interface, one trait | Overhead for filesystem sources (80% case) |
| **B: Dual SyncSource/AsyncSource traits** ✅ SELECTED | Zero overhead for local scanning | Two traits to implement, enum dispatch |
| C: Use `blocking` task bridge | Keep single async trait, use `spawn_blocking` | Some overhead but simpler API |

> ✅ **DECIDED:** Option B. 80% of usage is local filesystem where async overhead is wasted. `SourceStream` enum dispatch is trivial.

### Decision 4: `gix` vs `git2-rs`

| Crate | Compile Time | Safety | Features | Size |
|---|---|---|---|---|
| `gix` (Gitoxide) | 5-10 min clean build | Pure Rust, no C | Full git implementation | ~2MB |
| **`git2-rs` (libgit2)** ✅ SELECTED | ~1 min (uses system C lib) | C bindings, FFI | Mature, proven | ~500KB |

> ✅ **DECIDED:** Use `git2-rs` for v1.0. Compromises on pure-Rust but gix is not fully vetted. Revisit for v2.0 when gix matures.

### Decision 5: Auto-Revocation in v1.0?

| Option | Risk | Recommendation |
|---|---|---|
| **A: Remove entirely from v1.0** ✅ SELECTED | None — PRD §8 already excludes it | ✅ Align implementation plan with PRD scope |
| B: Ship dry-run suggestions only | Low — no actual API calls | Acceptable compromise |
| C: Ship full revocation (current plan Phase 4) | HIGH — insufficient safety rails | ❌ Security reviewer BLOCKER |

> ✅ **DECIDED:** Option A. Auto-revocation moved to v2.0 Future Features Roadmap. Implementation plan updated.

### Decision 6: RedactedString Secret Exposure Policy

| Secret Length | Current (4+****+4) | Recommended (Security reviewer) |
|---|---|---|
| ≤8 chars | Shows **100%** of secret | Show first 2 + `****` only |
| 10 chars | Shows **80%** | Show first 2 + `****` |
| 16 chars | Shows 50% | Show first 4 + `****` + last 2 |
| 32+ chars | Shows 25% | Show first 4 + `****` + last 4 |

> ✅ **DECIDED:** Adopt tiered redaction. Never expose more than 40% of any secret value.

---

## Data Privacy Note (Replaces GDPR Section)

> ✅ **USER DECISION:** GDPR compliance machinery is **not required** for this tool. Secret Squirrel is an open-source CLI tool, not a SaaS platform. Users are self-employed, hobbyists, or employees governed by their organization's internal policies. The tool does not process personal data for marketing activities.

**What we will do instead:**
- Add a **disclaimer** in documentation: "Users are responsible for ensuring compliance with applicable data protection regulations when scanning communication platforms (Slack, Jira, etc.)"
- Add a **first-run warning** when communication source adapters are invoked: "You are about to scan [Slack/Jira/etc]. Ensure you have appropriate authorization."
- **No GDPR-specific flags or PII filters** in v1.0

---

## Security Hardening Requirements (From Security Review)

### Must-Fix in TDD

| Item | Current Design | Required Change |
|---|---|---|
| **RedactedString** | `&self.value[..4]` byte indexing | Use `.chars().take(n)`, never show >40% of value |
| **Secret memory** | Plain `String` in RedactedString | Use `secrecy::Secret<String>` + `zeroize` crate |
| **Secret hashing** | Unsalted SHA-256 | HMAC-SHA256 with per-session random nonce |
| **MCP path handling** | No path validation | Sandbox to workspace root, reject absolute paths, no symlinks |
| **MCP validate_finding** | Accepts "Finding ID or secret string" | Accept Finding IDs only (prevent credential oracle) |
| **MCP HTTP transport** | No authentication | Require bearer token, bind 127.0.0.1 only |
| **Validation HTTP** | Default `reqwest` follows redirects | `redirect::Policy::none()`, hardcode provider URLs |
| **Hot-reload rules** | From any URL, no integrity check | HTTPS-only, require rule signatures |
| **PR comments** | Show partial secret on public repos | For public repos, post to Security tab only |
| **`--show-secrets`** | No access control | Require env var `SQUIRREL_ALLOW_SHOW_SECRETS=1` additionally |
| **Core dumps** | Secrets in heap memory | `zeroize` on Drop, `mlock()` for secret pages |

### Missing Threats to Add to Threat Model

| Threat | Mitigation |
|---|---|
| Rule injection via hot-reload URL | Rule signing (cosign/minisign) |
| Symlink/path traversal in MCP | Path sandboxing, no symlink following |
| ReDoS via crafted rule regex | Regex complexity limits, timeouts |
| Zip bomb / decompression bomb | 100:1 decompression ratio limit |
| MCP credential oracle | Accept Finding IDs only |
| Core dump secret exposure | `zeroize`, `mlock`, disable core dumps |
| SARIF unredacted context | Scan context lines for secrets |
| GPU side-channel | Clear GPU buffers after use |

---

## Architecture Improvements to Incorporate

### From Architecture Reviewer

1. **Bounded channels between pipeline stages** — `crossbeam::channel` with capacity of 256 batches per stage. Provides natural backpressure and bottleneck detection.

2. **Two-phase scan architecture** — Phase 1 (streaming): Source → Pipeline → Findings emitted + accumulated. Phase 2 (batch): Correlation resolve after all sources complete. In non-correlate mode, Phase 2 skipped.

3. **Disk-backed correlation for large repos** — Use `redb` or SQLite when correlation memory exceeds configurable cap (default: 256MB). Add `--correlation-budget <MB>` flag.

4. **ScanSession coordinator** — Central struct owning pipeline lifecycle, cancellation, progress reporting, and cleanup.

5. **Source adapter bulkhead pattern** — Per-source concurrency limits, timeout budgets, error counters with graceful degradation.

6. **Circuit breaker for validation** — After N consecutive failures to a provider, stop attempting for cooldown period.

### From SRE Reviewer

7. **Structured logging via `tracing`** — JSON output with stage-level metrics: `scan_duration_ms`, `files_scanned`, `findings_count`, `gpu_path_used`.

8. **Graceful shutdown** — `tokio::signal` for SIGTERM/SIGINT handling. Flush findings, close connections, write partial scan state.

9. **Composite GitHub Action alternative** — Download pre-built binary + run directly for environments where Docker is problematic.

10. **Rule quality gates** — Every rule needs: one true-positive test, one true-negative test, documented source/origin.

### From Code Reviewer

11. **Use `std::arch` or `wide` crate** for stable SIMD instead of nightly `std::simd`.

12. **Define `PipelineExecutor` trait** explicitly with typed stage methods.

13. **Add `tracing`, `bytes`, `thiserror`** to core dependencies.

14. **Consider `fancy-regex`** as fallback for rules with backreferences.

15. **Accept `Bytes` not `&[u8]`** in EntropyGate for true zero-copy from mmap.

16. **Increase WGSL workgroup data size** — 64 bytes per thread (16KB per workgroup) instead of 4 bytes per thread.

---

## Revised Dependency List

| Crate | Version | Purpose | Notes |
|---|---|---|---|
| `clap` | 4.x | CLI | — |
| `serde` + `toml` | 1.x / 0.8 | Rule parsing | — |
| `aho-corasick` | 1.x | Pattern matching | SIMD-accelerated |
| `regex` | 1.x | Pattern verification | — |
| `fancy-regex` | 0.13+ | Backreference fallback | **NEW** — for Betterleaks rule compat |
| `rayon` | 1.x | Parallel iteration | — |
| `memmap2` | 0.9 | Memory-mapped I/O | — |
| `memchr` | 2.x | SIMD byte search | — |
| `bytes` | 1.x | Zero-copy buffers | **NEW** — for Fragment/mmap pipeline |
| `bytemuck` | 1.x | GPU buffer casting | — |
| `ignore` | 0.4 | .gitignore walking | — |
| `gix` | 0.68+ | Git access | **Decision pending** vs `git2-rs` |
| `tokio` | 1.x | Async runtime | — |
| `reqwest` | 0.12 | HTTP client | `redirect::Policy::none()` for validation |
| `tracing` | 0.1 | Structured logging | **NEW** — required by all reviewers |
| `tracing-subscriber` | 0.3 | Log output | **NEW** |
| `thiserror` | 2.x | Error types | **NEW** — no error type currently defined |
| `secrecy` | 0.10+ | Secret memory handling | **NEW** — replaces hand-rolled RedactedString |
| `zeroize` | 1.x | Memory zeroing on Drop | **NEW** — via secrecy crate |
| `crossbeam-channel` | 0.5 | Bounded stage channels | **NEW** — for backpressure |
| `wgpu` | 29.x | GPU compute | Feature-gated |
| `encase` | 0.9 | WGSL buffer layouts | Feature-gated |
| `ort` | 2.x | ONNX Runtime | Feature-gated (`github-action` only) |
| `rmcp` | 0.1+ | MCP server | Feature-gated |

---

## What All Four Reviewers Agreed On

> [!TIP]
> **These items have strong consensus and should be adopted without further debate:**

1. ✅ **The 4-stage inverted pipeline is the right architecture** — all praised it
2. ✅ **GPU/CPU smart routing with 100MB threshold is correct**
3. ✅ **Cross-file correlation is a genuine differentiator**
4. ✅ **CNN only in GitHub Action profile is the right trade-off**
5. ✅ **Feature-gated build profiles are well-structured**
6. ✅ **Opt-in validation is the correct security posture**
7. ✅ **40+ sources at launch is too ambitious** — ship fewer, ship them right
8. ✅ **The architecture has a legitimate shot at being the best open-source scanner**
