# Contributing to Secret Squirrel

Thank you for contributing! This guide covers how to build, test, and extend Secret Squirrel.

---

## Build Requirements

- **Rust** 1.75+ (stable toolchain)
- **Git** 2.30+
- **Optional**: Vulkan/Metal/DX12 GPU driver for GPU path testing

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/Chrysalisms/Secret-Squirrel.git
cd Secret-Squirrel
cargo build

# Run tests
cargo test

# Run with all features
cargo check --all-features
```

---

## Feature Flags

| Flag | Purpose | Extra Requirements |
|------|---------|-------------------|
| `gpu` | wgpu GPU acceleration | Vulkan/Metal/DX12 driver |
| `cpu-simd` | AVX2/NEON SIMD entropy | x86_64 or aarch64 |
| `cnn` | ONNX Runtime CNN classifier | ONNX Runtime library |
| `mcp-server` | MCP stdio/HTTP server | None |
| `semantic` | Tree-sitter AST analysis | None |
| `validate` | Live API validation | Network access |
| `github-action` | GitHub Action bundle | `cnn` + `mcp-server` |

```bash
# Build with specific features
cargo build --features "cnn,mcp-server"

# Build for GitHub Action profile
cargo build --release --features github-action
```

---

## Running Tests

```bash
# Unit tests only (fast)
cargo test --lib

# Including integration tests
cargo test --test pipeline_e2e

# Doctests
cargo test --doc

# All tests
cargo test

# Benchmarks (report throughput)
cargo bench --bench entropy
cargo bench --bench pipeline
```

For cross-tool accuracy and repo-tree comparisons against `Betterleaks`, use
the benchmark workflow documented in `docs/benchmarking.md`.

---

## Authoring Rules

Rules live in `rules/` organized by provider category. Each rule is a TOML file.

### Rule format

```toml
[[rules]]
id = "my-provider-api-key"
description = "My Provider API Key"
severity = "high"
category = "saas"

# Pattern must match the secret value
pattern = 'myprovider_[a-zA-Z0-9]{32}'

# Optional entropy gate (default: 3.5)
entropy_threshold = 4.0

# Test fixtures (required — one TP, one TN)
[[rules.test_fixtures]]
positive = 'api_key = "myprovider_aBcDeFgHiJkLmNoPqRsTuVwXy1234"'
negative = 'api_key = "myprovider_example"'

# Optional: Aho-Corasick keywords for Stage 4 fast-path
keywords = ["myprovider_"]

# Optional: Validation provider name
validator = "myprovider"

# Remediation guidance (shown in output)
remediation = "Rotate this key at https://my-provider.com/account/api-keys"
```

### Rule quality gates

- Every rule **must** have at least one `positive` and one `negative` test fixture.
- Patterns must not be ReDoS-vulnerable (checked by `squirrel rules validate`).
- Entropy threshold should be measured on real examples: `squirrel detect --verbose` shows entropy scores.

---

## Adding Source Adapters

1. Create `src/sources/my_source.rs`
2. Implement either `SyncSource` (for local/blocking sources) or `AsyncSource` (for HTTP sources)
3. Register in `src/sources/mod.rs`
4. Add `SourceType::MySource` variant to `src/types.rs`
5. Wire in `src/main.rs` `--source` flag dispatch
6. Add fixture files to `tests/fixtures/secrets/` and `tests/fixtures/non_secrets/`
7. Add integration tests to `tests/integration/pipeline_e2e.rs`

```rust
// src/sources/my_source.rs
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};
use crate::error::Result;

pub struct MySource { /* ... */ }

impl SyncSource for MySource {
    fn name(&self) -> &str { "my-source" }
    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        Box::new(std::iter::empty()) // replace with real implementation
    }
}
```

---

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy --all-features -- -D warnings` before submitting a PR
- All public items must have doc comments
- Tests must cover error paths, not just happy paths

---

## Submitting a PR

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests first (TDD preferred)
4. Implement the feature
5. Run `cargo test && cargo clippy --all-features`
6. Submit a PR with a clear description of the change

### PR checklist

- [ ] Tests pass (`cargo test`)
- [ ] Clippy clean (`cargo clippy --all-features -- -D warnings`)
- [ ] Formatted (`cargo fmt --check`)
- [ ] Doc comments on all public items
- [ ] New rules have positive + negative test fixtures
- [ ] CHANGELOG.md updated for significant changes

---

## Architecture

See the [Pipeline Architecture](README.md#pipeline-architecture) and [Execution Profiles & Smart Routing](README.md#execution-profiles--smart-routing) sections in the README for the four-stage pipeline, GPU/CPU routing, scoring engine, and correlation system.
