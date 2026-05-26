# Secret Squirrel — Research Synthesis: Market Gaps + CNN Strategy

**Date:** May 26, 2026  
**Sources:** Web research, GitHub issues, Reddit/HN, academic papers, industry reports

---

## Part 1: Market Research — What Engineers Want But Don't Have

### The Opportunity in Numbers

| Statistic | Source |
|---|---|
| **28.65M** new hardcoded secrets on public GitHub in 2025 | GitGuardian 2026 Report |
| **34%** YoY increase — the largest ever recorded | GitGuardian 2026 Report |
| AI-assisted commits leak secrets at **2x the human rate** | GitGuardian 2026 Report |
| **81%** growth in AI service secret leaks (OpenAI, Anthropic, etc.) | GitGuardian 2026 Report |
| **64%** of valid secrets from 2022 remain active and exploitable | Industry analysis |
| **28%** of secrets sprawl originates **outside code repos** (Slack, Jira) | GitGuardian 2026 Report |
| Non-human identities outnumber humans **80:1 to 100:1** | Industry analysis |

### Universal Pain Points (All Tools)

| Pain Point | Impact |
|---|---|
| **False positive fatigue** | #1 complaint — developers disable scanners entirely |
| **Detection without remediation** | "Tool told me I have a problem, now what?" |
| **No context awareness** | Can't distinguish `tests/fixtures/` dummy keys from production configs |
| **Developer bypass culture** | When tools are too noisy, security becomes optional |
| **Binary found/not-found output** | No risk ranking, no prioritization help |

### The 3-Layer Pattern (Industry Best Practice 2026)

Most mature DevSecOps programs now use **three separate tools**:

```
Layer 1: Pre-commit (fast, regex)     → Gitleaks / Betterleaks
Layer 2: CI/CD (deep, verified)       → TruffleHog
Layer 3: Governance (enterprise)      → GitGuardian
```

> [!IMPORTANT]
> **Secret Squirrel's opportunity:** Be the **single tool** that covers all three layers. Fast enough for pre-commit (<100ms), deep enough for CI/CD (verification + blast radius), and rich enough for governance (SARIF, correlation, confidence scoring).

---

### Feature Gap Analysis — What We Can Ship First

#### 🔴 Features NO open-source tool has (Ship in v1.0)

| Feature | Demand Evidence | Competition | Secret Squirrel Status |
|---|---|---|---|
| **Cross-file credential chains** | Universal request across all tool issue trackers | ❌ Nobody | ✅ Already designed |
| **Blast radius / permissions enumeration** | Top request from incident responders | ❌ Nobody (TruffleHog verifies only) | ✅ Designed, v1.0 Phase 2 |
| **Provenance-aware confidence scoring** | "Drowning in undifferentiated alerts" | ❌ Binary only | ✅ Designed in scoring fusion |
| **AI/LLM API key comprehensive rules** | 81% YoY growth in AI key leaks | Partial coverage | ✅ Add 20+ AI provider rules |
| **MCP server for AI agents** | AI-generated code leaks at 2x rate | GitHub MCP (limited) | ✅ Designed |
| **Terraform state file scanning** | Critical unaddressed gap | ❌ Nobody scans `.tfstate` properly | ✅ Add to Phase 2 |

#### 🟡 Features only GitGuardian has (Open-source disruption opportunity)

| Feature | GitGuardian Status | Secret Squirrel Opportunity |
|---|---|---|
| **Honeytoken generation + monitoring** | Enterprise tier only | v1.1 — generate fake AWS/GitHub keys, monitor for use |
| **Centralized dashboard** | SaaS only | v1.1 — lightweight web UI or SARIF aggregation |
| **Remediation playbooks** | Enterprise tier | v1.0 — ship inline remediation guidance per finding |

#### 🟢 New Feature Ideas (from market research)

| Feature | Description | Priority |
|---|---|---|
| **Remediation guidance per finding** | "This is an AWS key. Run `aws iam delete-access-key`. Store in Vault/SSM instead." | HIGH — ship in v1.0 |
| **Baseline-aware drift detection** | Intelligent `--baseline` that tracks secret age, detects re-introduction | MEDIUM — v1.0 Phase 2 |
| **Docker layer history scanning** | Parse `docker history` for ENV/ARG secrets persisted in layers | MEDIUM — v1.0 Phase 2 |
| **Push protection mode** | Pre-receive hook that blocks `git push` if secrets detected | HIGH — ship in v1.0 CLI |
| **AI provider rule pack** | 20+ rules for OpenAI, Anthropic, Cohere, Mistral, HuggingFace, Replicate, Together, Groq, Perplexity, Google AI, Azure AI | HIGH — ship at launch |
| **Policy-as-code engine** | Declarative rules: "production repos must not contain any high-severity secrets" | LOW — v2.0 |
| **Bidirectional Jira/ServiceNow sync** | Create ticket → dev fixes → status flows back | LOW — v2.0 |

---

## Part 2: CNN Architecture Strategy

### Multi-Tier Model Approach ✅ APPROVED

Ship **multiple models** from the same CodeBERT distillation pipeline — users select their accuracy/resource tier:

```
                  ┌──────────────────────────────┐
                  │  CodeBERT Teacher (~99% acc)  │
                  │    Fine-tuned on 15 datasets  │
                  │    + DPO + Contrastive Learn  │
                  └───────────┬──────────────────┘
                              │
                    Knowledge Distillation
                     (soft labels, T=4)
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
 ┌─────────────────┐ ┌────────────────┐ ┌──────────────────┐
 │  GITHUB ACTION  │ │  SELF-HOSTED   │ │   SELF-HOSTED    │
 │  Char-CNN Tiny  │ │  Char-CNN Lg   │ │   GPU TIERS      │
 ├─────────────────┤ ├────────────────┤ ├──────────────────┤
 │ 3× Conv1D       │ │ 5× Conv1D     │ │ Default: TinyBERT│
 │ 128 filters each│ │ 256 filters   │ │  14.5M, ~55MB    │
 │ kernels: 3,4,5  │ │ k: 3,4,5,7,9  │ │  GPU: <1ms       │
 │                 │ │               │ │  Acc: ~99%       │
 │ 500K params     │ │ 1M params     │ │                  │
 │ FP32: ~2MB      │ │ FP32: ~4MB    │ │ Enhanced:        │
 │ Inf: 300-500μs  │ │ CPU: 500μs-1ms│ │  DistilBERT      │
 │ Acc: 96-97%     │ │ GPU: 100-200μs│ │  66M, ~260MB     │
 │                 │ │ Acc: 98-99%   │ │  GPU: 1-2ms      │
 └─────────────────┘ └────────────────┘ │  Acc: ~99.5%     │
                                        └──────────────────┘
```

> [!NOTE]
> All models use **FP32** (no quantization) per user decision. Accuracy > size tradeoff accepted. Models are downloaded on demand, not bundled with CLI binary.

### Model Architecture Details

#### Tiny Model — GitHub Actions (2 vCPU, 7GB RAM, no GPU)

```
Input: ASCII character sequence (max 256 chars, padded)
├── Char Embedding: 100-char alphabet → 64-dim
├── Conv1D(128, kernel=3) → ReLU → GlobalMaxPool1D
├── Conv1D(128, kernel=4) → ReLU → GlobalMaxPool1D
├── Conv1D(128, kernel=5) → ReLU → GlobalMaxPool1D
├── Concatenate (384-dim)
├── Dropout(0.3) → Dense(128, ReLU)
├── Dropout(0.3) → Dense(1, Sigmoid)
```

| Metric | Value |
|---|---|
| Parameters | **500K** |
| Model Size (FP32) | **~2 MB** |
| Load Time | ~100-200ms |
| CPU Inference | **~300-500μs** |
| Accuracy (distilled) | **96-97%** |
| RAM Impact | Trivial (fits in L2 cache) |

> Still **4-7x faster** than the 2ms budget. 2MB is negligible in a Docker image.

#### Large Model — Self-Hosted Docker (4-16 cores, CPU default)

```
Input: ASCII character sequence (max 512 chars, padded)
├── Char Embedding: 100-char alphabet → 128-dim
├── Conv Block 1: Conv1D(256,k=3) → BN → ReLU → Conv1D(256,k=3) → BN → ReLU
├── Conv Block 2: Conv1D(256,k=5) → BN → ReLU → Conv1D(256,k=5) → BN → ReLU
├── Conv Block 3: Conv1D(256,k=7) → BN → ReLU
├── Conv Block 4: Conv1D(128,k=9) → BN → ReLU
├── GlobalMaxPool1D each → Concatenate (896-dim)
├── Dense(512, ReLU) → Dropout(0.4)
├── Dense(256, ReLU) → Dropout(0.3)
└── Dense(num_classes, Softmax)  # multi-class: password/token/key/etc.
```

| Metric | Value |
|---|---|
| Parameters | **1M** |
| Model Size (FP32) | **~4 MB** |
| CPU Inference | **~500μs-1ms** |
| GPU Inference | **~100-200μs** |
| Accuracy (distilled) | **98-99%** |

#### Self-Hosted GPU Tiers (user-selectable)

| Tier | Model | Params | Size | GPU Inference | Accuracy | Use Case |
|---|---|---|---|---|---|---|
| **Default** | Large Char-CNN (FP32) | 1M | ~4 MB | 100-200μs | 98-99% | CPU-first, fast |
| **Enhanced** | TinyBERT (2-pass) | 14.5M | ~55 MB | <1ms | **~99%** | GPU users wanting transformer accuracy |
| **Maximum** | DistilBERT (2-pass) | 66M | ~260 MB | 1-2ms | **~99.5%** | Maximum peace of mind |

> Models are **downloaded on demand** via `squirrel model pull <tier>`. Not bundled with the binary. Configurable via `--model-tier default|enhanced|maximum`.

---

### Training Strategy

#### Training Corpus: 15 Datasets (10 for training pipeline)

##### Tier 1: Primary ML Training Data

| # | Dataset | Source | Scale | Labels | Format | License | Use |
|---|---|---|---|---|---|---|---|
| 1 | **CredData** | [Samsung](https://github.com/Samsung/CredData) | 19.4M lines, 73K labeled | ✅ Manual (8 categories) | CSV + files | MIT | Primary training |
| 2 | **CredSweeper Experiment** | [Samsung](https://github.com/Samsung/CredSweeper) | Full ML pipeline | Uses CredData | Python scripts | MIT | Model retraining reference |
| 3 | **Nosey Parker** | [Praetorian](https://github.com/praetorian-inc/noseyparker) | 100K+ secrets | ✅ Manual by security engineers | YAML rules | Apache-2.0 | High-quality labeled data |

##### Tier 2: Benchmarking & Validation

| # | Dataset | Source | Scale | Labels | Format | License | Use |
|---|---|---|---|---|---|---|---|
| 4 | **SecretBench** | [NC State](https://github.com/seart-group/SecretBench) | 97K candidates, 15K true | ✅ Manual academic | BigQuery | Data agreement | Precision/recall benchmark |
| 5 | **SecurityEval** | [s2e-lab](https://huggingface.co/datasets/s2e-lab/SecurityEval) | 130 CWE samples (inc. CWE-798) | ✅ Academic, per-CWE | JSONL/HuggingFace | Open | CWE-798 eval |
| 6 | **OWASP Benchmark** | [OWASP](https://github.com/OWASP-Benchmark/BenchmarkJava) | 2,740 test cases | ✅ Ground truth CSV | Java | GPL-2.0 | SAST validation |
| 7 | **CASTLE** | arXiv:2503.04561 | 250 programs, 25 CWEs | ✅ Hand-crafted, balanced | Source code | Academic | Balanced recall/FP eval |

##### Tier 3: False Positive Reduction

| # | Dataset | Source | Scale | Labels | Format | License | Use |
|---|---|---|---|---|---|---|---|
| 8 | **FPSecretBench** | [NC State](https://github.com/seart-group/FPSecretBench) | FPs from 9 tools | ✅ Systematic | BigQuery | Contact authors | Hard-negative mining |
| 9 | **SAP Credential Digger** | [SAP](https://github.com/SAP/credential-digger) | 2 ML models (path + code) | SAP internal | Python/Keras | Apache-2.0 | FP filtering reference |

##### Tier 4: Pattern & Format Reference

| # | Dataset | Source | Scale | Format | License | Use |
|---|---|---|---|---|---|---|
| 10 | **Secrets Patterns DB** | [mazen160](https://github.com/mazen160/secrets-patterns-db) | **1,600+ regex** patterns | Multi-format | Open | Largest pattern collection |
| 11 | **Gitleaks Rules** | [Gitleaks](https://github.com/gitleaks/gitleaks) | 150+ rules | TOML | MIT | Provider key formats |
| 12 | **TruffleHog Detectors** | [TruffleSec](https://github.com/trufflesecurity/trufflehog) | 800+ detectors + [test_keys](https://github.com/trufflesecurity/test_keys) | Go tests | AGPL-3.0 | Per-type examples |
| 13 | **GitHub Partner Patterns** | [GitHub Docs](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-types) | 200+ patterns | Documentation | Public | Format reference |

##### Tier 5: Integration Testing

| # | Dataset | Source | Scale | License | Use |
|---|---|---|---|---|---|
| 14 | **detect-secrets Test Data** | [Yelp](https://github.com/Yelp/detect-secrets) | Multi-plugin test files | Apache-2.0 | Test fixtures |
| 15 | **OWASP Vuln Apps** | WebGoat, Juice Shop, DVWA | 3 full apps with planted secrets | Open | Real-world integration testing |

##### Bonus Resources

| Resource | Use |
|---|---|
| **GitGuardian 2026 Report** | Statistical metadata for training data weighting |
| **RockYou Password List** | Password pattern analysis, entropy distribution research |
| **M2 Dataset** (arXiv:2506.13090) | LLM-based CWE-798 detection benchmark |

> [!TIP]
> **Recommended training pipeline uses datasets 1-4, 8, 10, 12, 14** for a combined corpus of ~20M+ lines with manual labels, systematic FP data, and format coverage across 15+ secret types.

#### Knowledge Distillation Pipeline (Highest-Value Strategy)

```
Stage 1: Assemble corpus from 10 datasets (CredData + SecretBench + Nosey Parker +
         FPSecretBench + Secrets Patterns DB + TruffleHog test_keys + detect-secrets +
         OWASP + synthetic generation from pattern refs)
Stage 2: Fine-tune CodeBERT teacher on full corpus → ~99% accuracy
Stage 3: Generate soft labels (temperature T=4) on all training data
Stage 4: Train student CNNs with combined loss:
         L = 0.3 × CE(student, hard_labels) + 0.7 × KL(student_soft, teacher_soft)
Stage 5: Apply DPO fine-tuning using FPSecretBench preference pairs
Stage 6: Apply contrastive learning on hard negatives (UUIDs, hashes, base64)
Stage 7: Export to ONNX (FP32) with ORT_ENABLE_ALL graph optimization
```

**Expected results from distillation (all FP32):**

| Model | Accuracy | Size | CPU Inference |
|---|---|---|---|
| CodeBERT teacher | 99% | 500MB | 50ms |
| Distilled Tiny CNN (FP32) | 96-97% | **~2MB** | **300-500μs** |
| Distilled Large CNN (FP32) | 98-99% | **~4MB** | **500μs-1ms** |
| TinyBERT (GPU 2-pass) | ~99% | ~55MB | <1ms GPU |
| DistilBERT (GPU 2-pass) | ~99.5% | ~260MB | 1-2ms GPU |

#### DPO for False Positive Reduction (Better than RLHF)

> [!TIP]
> **DPO (Direct Preference Optimization) is the right choice**, not RLHF. DPO treats FP reduction as a preference problem without needing a separate reward model. It works well with small datasets (hundreds of preference pairs).

```
1. Collect FP examples from FPSecretBench
2. Create preference pairs:
   - Chosen: model correctly identifies real secret with high confidence
   - Rejected: model incorrectly flags false positive with high confidence
3. Fine-tune CNN using DPO loss
4. Expected result: 30-50% FP reduction without recall loss
```

#### Contrastive Learning on Hard Negatives

Train the CNN encoder to separate secrets from secret-lookalikes:
- **Hard negatives:** Base64 data URIs, hex color codes, hash checksums, UUID v4, JWT in documentation, Lorem ipsum, test fixture strings
- **Loss:** Supervised contrastive (SupCon) with triplets
- **Result:** 80-86% FP reduction while maintaining recall (industry reports)

---

### Quantization Decision

> ✅ **USER DECISION:** Keep all models in **FP32**. Accuracy matters more than size for this use case. The models are small enough in FP32 that quantization savings are minimal.

| Model | FP32 Size | Hypothetical INT8 Size | Accuracy Preserved |
|---|---|---|---|
| Tiny CNN (500K) | 2 MB | 500 KB | ✅ Full accuracy |
| Large CNN (1M) | 4 MB | 1 MB | ✅ Full accuracy |
| TinyBERT (14.5M) | 55 MB | ~14 MB | ✅ Full accuracy |

FP32 models are already trivial in size for their deployment contexts. No quantization needed.

---

### Build Profile Integration

| Profile | Model | Size Added | Load Time | Accuracy |
|---|---|---|---|---|
| **CLI binary** | None (Markov chain only) | 0 | 0 | N/A |
| **GitHub Action** | Tiny CNN (FP32, 500K params) | **+2 MB** | +100-200ms | 96-97% |
| **Self-Hosted Docker (CPU)** | Large CNN (FP32, 1M params) | **+4 MB** | +500ms | 98-99% |
| **Self-Hosted Docker (GPU)** | Large CNN + TinyBERT | **+59 MB** | +2s | ~99% |
| **Self-Hosted Docker (GPU Max)** | Large CNN + DistilBERT | **+264 MB** | +5s | ~99.5% |

---

## Part 3: New Features to Add to v1.0

Based on market research, the following high-demand features should be added to the implementation plan:

### Already Planned (Validated by Research)
- ✅ Cross-file correlation (H-10) — **#1 unmet market need**
- ✅ Blast radius (H-13) — **#2 unmet market need**
- ✅ MCP server (H-14) — AI agents generating secrets at 2x rate
- ✅ SARIF output — GitHub Security Tab integration
- ✅ Confidence scoring — provenance-aware (H-9)

### NEW: Add to v1.0

| Feature | Phase | Effort | Impact |
|---|---|---|---|
| **Remediation guidance per finding** | Phase 1 | Low | HIGH — "This is an AWS key. To fix: rotate via IAM, store in Vault" |
| **AI provider rule pack (20+ rules)** | Phase 1 | Low | HIGH — 81% growth in AI key leaks |
| **Push protection mode** (`squirrel protect`) | Phase 1 | Medium | HIGH — blocks `git push` if secrets found |
| **Terraform `.tfstate` scanning** | Phase 2 | Low | MEDIUM — critical gap, nobody does this |
| **Docker layer history scanning** | Phase 2 | Medium | MEDIUM — ENV/ARG persist in layers |

### NEW: Add to v1.1 Roadmap

| Feature | Effort | Impact |
|---|---|---|
| **Honeytoken generation** | Medium | HIGH — open-source GitGuardian disruption |
| **SIEM export (Splunk, Elastic, Sentinel)** | Low | MEDIUM — syslog/webhook output |
| **Lightweight triage web UI** | Medium | MEDIUM — finding aggregation dashboard |

---

## References

### Papers
- Yoon Kim (2014) — "Convolutional Neural Networks for Sentence Classification"
- Zhang et al. (2015) — "Character-level CNNs for Text Classification"
- Hinton et al. (2015) — "Distilling Knowledge in a Neural Network"
- Feng et al. (2020) — "CodeBERT: Pre-Trained Model for Programming Languages"
- Rafailov et al. (2023) — "Direct Preference Optimization"
- "Secret Breach Detection with LLMs" (2025, arXiv)
- CASTLE Benchmark (arXiv:2503.04561)
- M2 Dataset (arXiv:2506.13090) — LLM-based CWE-798 detection

### Primary Datasets
- [CredData](https://github.com/Samsung/CredData) — Samsung, 19.4M lines, MIT
- [CredSweeper](https://github.com/Samsung/CredSweeper) — Samsung BiLSTM + retraining pipeline, MIT
- [SecretBench](https://github.com/seart-group/SecretBench) — 97K candidates, BigQuery
- [FPSecretBench](https://github.com/seart-group/FPSecretBench) — FP data from 9 tools
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) — 100K+ labeled secrets, Apache-2.0
- [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db) — 1,600+ regex patterns
- [SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval) — CWE-798 benchmark
- [SAP Credential Digger](https://github.com/SAP/credential-digger) — ML FP filtering models, Apache-2.0

### Pattern & Format References
- [Gitleaks Rules](https://github.com/gitleaks/gitleaks) — 150+ TOML rules, MIT
- [TruffleHog Detectors](https://github.com/trufflesecurity/trufflehog) — 800+ detectors + [test_keys](https://github.com/trufflesecurity/test_keys)
- [GitHub Partner Patterns](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-types) — 200+ patterns
- [detect-secrets](https://github.com/Yelp/detect-secrets) — Yelp, test fixtures, Apache-2.0

### Integration Test Apps
- [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) — 2,740 test cases with ground truth
- [WebGoat](https://github.com/WebGoat/WebGoat) / [Juice Shop](https://github.com/juice-shop/juice-shop) / [DVWA](https://github.com/digininja/DVWA) — Planted secrets in real apps
