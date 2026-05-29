# Secret Squirrel 🐿️

> **GPU-accelerated, AI-powered credential scanner** — the open-source Betterleaks killer.

[![CI](https://github.com/Chrysalisms/Secret-Squirrel/actions/workflows/ci.yml/badge.svg)](https://github.com/Chrysalisms/Secret-Squirrel/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

Secret Squirrel finds credentials, API keys, and secrets in your code before attackers do. It scans git history, directories, CI logs, Slack, Postman collections, Jupyter notebooks, databases, and more — with a four-stage pipeline anchored by Aho-Corasick keyword pre-filtering that is **10× faster** than naive regex-first scanners.

---

## Why Secret Squirrel?

| Feature | Secret Squirrel | Betterleaks | TruffleHog | Gitleaks |
|---------|:-:|:-:|:-:|:-:|
| GPU acceleration | ✅ | ❌ | ❌ | ❌ |
| Cross-file correlation | ✅ | ❌ | ❌ | ❌ |
| MCP server (AI agent integration) | ✅ | ❌ | ❌ | ❌ |
| CNN classifier (optional) | ✅ | ❌ | ❌ | ❌ |
| Live secret validation | ✅ | ❌ | ✅ | ❌ |
| Source coverage | 15+ | 5 | 15+ | 3 |
| Binary size | <15 MB | 40 MB | 75 MB | ~15 MB |
| Peak RAM (1 GB repo) | ~400 MB | 4.2 GB | ~1.2 GB | ~500 MB |

---

## Quick Start

```bash
# Install from source (requires Rust 1.75+)
cargo install --path .

# Scan a directory
squirrel detect ./my-project

# Scan git history
squirrel detect --source git ./my-repo

# Scan with live validation
squirrel detect --validate ./my-project

# GitHub Action
```

```yaml
- uses: Chrysalisms/Secret-Squirrel@v1
  with:
    scan-mode: diff
    severity-threshold: high
    sarif-upload: true
```

---

## Installation

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/Chrysalisms/Secret-Squirrel/releases):

```bash
# Linux (musl, statically linked)
curl -sSL https://github.com/Chrysalisms/Secret-Squirrel/releases/latest/download/squirrel-x86_64-unknown-linux-musl -o squirrel
chmod +x squirrel

# macOS (Apple Silicon)
curl -sSL https://github.com/Chrysalisms/Secret-Squirrel/releases/latest/download/squirrel-aarch64-apple-darwin -o squirrel
chmod +x squirrel

# Windows
# Download squirrel-x86_64-pc-windows-msvc.exe from GitHub Releases
```

### Docker

```bash
docker pull ghcr.io/chrysalisms/secret-squirrel:latest
docker run --rm -v $(pwd):/repo ghcr.io/chrysalisms/secret-squirrel detect /repo
```

---

## CLI Reference

### `squirrel detect` — Scan for secrets

```
squirrel detect [OPTIONS] [PATH]

Options:
  --source <SOURCE>         dir | git | stdin | github | gitlab | s3 | docker |
                            kubernetes | terraform | ansible | ci-logs | slack |
                            postman | notebook | database | elasticsearch | npm
  --depth <N>               Git history depth
  --format <FORMAT>         table | json | sarif | csv [default: table]
  --output <FILE>           Write output to file
  --severity <LEVEL>        critical | high | medium | low | info [default: medium]
  --confidence <F>          Minimum confidence 0.0-1.0 [default: 0.5]
  --validate                Live API validation (opt-in)
  --correlate               Cross-file credential chains (opt-in)
  --semantic                Tree-sitter AST confidence adjustment (opt-in)
  --model-tier <TIER>       none | tiny | large | enhanced | maximum [default: none]
  --baseline                Only new findings since last scan
  --show-secrets            Show full values (requires SQUIRREL_ALLOW_SHOW_SECRETS=1)
  --config <FILE>           Config file [default: .squirrel.toml]
  --rules <FILE>            Additional rules file
  --verbose                 Debug logging
```

### `squirrel protect` — Push protection

```bash
squirrel protect install    # Install git pre-commit hook
squirrel protect uninstall  # Remove pre-commit hook
squirrel protect check      # Check staged files manually
```

### `squirrel model` — CNN model management

```bash
squirrel model pull tiny     # ~2 MB — GitHub Actions compatible
squirrel model pull large    # ~4 MB — CPU self-hosted
squirrel model pull enhanced # ~55 MB — GPU (TinyBERT)
squirrel model pull maximum  # ~260 MB — GPU (DistilBERT)
squirrel model list
squirrel model info <tier>
```

---

## Configuration

Create `.squirrel.toml`:

```toml
[scan]
severity_threshold = "medium"
confidence_threshold = 0.5
validate = false
correlate = false
exclude = ["tests/fixtures", "**/*.example", "node_modules"]

[pipeline]
entropy_threshold = 3.5
entropy_chunk_size = 64
min_candidate_length = 8

[scoring.weights]
entropy = 0.15
proximity = 0.15
tristream = 0.20
markov = 0.25
pattern = 0.25

[gpu]
enabled = true
threshold_bytes = 104857600  # 100 MB
fallback_to_cpu = true

[[rules]]
id = "my-internal-token"
description = "Internal service token"
pattern = "INT-[A-Z0-9]{32}"
severity = "critical"
```

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

**Key insight**: Regex only runs against **~1% of input**. On a 1 GB repo, regex sees ~10 MB.

---

## Output Formats

```bash
squirrel detect --format table  ./project   # Human-readable (default)
squirrel detect --format json   ./project   # Machine-readable JSON array
squirrel detect --format sarif  ./project   # SARIF v2.1.0 for GitHub Security Tab
squirrel detect --format csv    ./project   # CSV for spreadsheet analysis
```

---

## MCP Server

```bash
squirrel mcp --transport stdio   # For local AI agent integration
```

Tools: `scan_text`, `scan_file`, `scan_diff`, `scan_repo`, `validate_finding`, `get_rules`

---

## Supported Sources

| Category | Sources |
|----------|---------|
| **Filesystem** | Directory, Git, Stdin, Archives |
| **Cloud** | GitHub, GitLab, S3/R2/GCS |
| **Infrastructure** | Docker, Kubernetes, Terraform, Ansible |
| **CI/CD** | GitHub Actions, GitLab CI, Jenkins, CircleCI |
| **Communication** | Slack, Jira |
| **Dev Tools** | Postman, Jupyter notebooks, .env files |
| **Data** | PostgreSQL, MySQL, MongoDB, Elasticsearch |
| **Packages** | NPM, PyPI |

---

## Rule Coverage (277+ rules across 43 TOML files)

| Category | Providers | Rules |
|----------|-----------|-------|
| **Cloud** | AWS (25+), GCP (7+), Azure (8+), Cloudflare (5+), DigitalOcean, Vercel, Netlify | 55+ |
| **AI/ML** | OpenAI (4+), Anthropic (3+), Google AI (4+), Cohere, Mistral, Replicate, HuggingFace | 16+ |
| **Payments** | Stripe (7+), Square (3+), PayPal (4+), Adyen | 16+ |
| **SaaS** | GitHub (17+), GitLab (13+), Slack (5+), Twilio (5+), SendGrid, Datadog, PagerDuty, Jira, Salesforce, Zendesk | 39+ |
| **Database** | PostgreSQL (4+), MySQL (3+), MongoDB (3+), Redis (3+), Elasticsearch | 13+ |
| **DevTools** | NPM (4+), Docker (4+), Terraform (3+), Kubernetes | 15+ |
| **Crypto** | RSA/EC/DSA/Ed25519/PKCS8 keys, PEM certs, JWT, PASETO, HMAC, SSH | 15+ |
| **Generic** | Passwords, bearer tokens, connection strings, LDAP, SMTP | 16+ |
| **Embedded (default)** | All of the above + more in `rules/default.toml` | 94 |
| **Total** | | **277+** |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE-APACHE)
