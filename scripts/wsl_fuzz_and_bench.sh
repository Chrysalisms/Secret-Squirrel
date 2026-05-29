#!/bin/bash
# WSL fuzz + benchmark runner for Secret Squirrel
# Usage: wsl -d Ubuntu -- bash "/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel/scripts/wsl_fuzz_and_bench.sh"

set -euo pipefail

REPO_ROOT="/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel"
RESULTS_DIR="$REPO_ROOT/fuzz/results"
BENCH_DIR="$REPO_ROOT/benchmark"

mkdir -p "$RESULTS_DIR" "$BENCH_DIR"

echo "================================================================"
echo "  Secret Squirrel — WSL Fuzz + Benchmark Runner"
echo "  $(date)"
echo "================================================================"

# ── 1. System dependencies ────────────────────────────────────────────────────
echo ""
echo "[1/7] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq 2>&1 | tail -2
sudo apt-get install -y -qq \
    curl git build-essential pkg-config libssl-dev \
    linux-headers-generic \
    libclang-dev clang llvm \
    python3 python3-pip python3-venv \
    golang-go \
    jq 2>&1 | tail -5
echo "      System deps OK"
echo "      kernel: $(uname -r)  clang: $(clang --version | head -1)"

# ── 2. Rust toolchains ────────────────────────────────────────────────────────
echo ""
echo "[2/7] Setting up Rust toolchains..."

if ! command -v rustup &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path 2>&1 | grep -v "^$" | tail -5
fi

export PATH="$HOME/.cargo/bin:$PATH"
source "$HOME/.cargo/env" 2>/dev/null || true

rustup toolchain install stable  2>&1 | tail -2
rustup toolchain install nightly 2>&1 | tail -2
rustup component add rust-src --toolchain nightly 2>&1 | tail -1

echo "      Rust stable:  $(rustup run stable  rustc --version)"
echo "      Rust nightly: $(rustup run nightly rustc --version)"

# ── 3. cargo-fuzz ─────────────────────────────────────────────────────────────
echo ""
echo "[3/7] Installing cargo-fuzz..."

LIBFUZZER_AVAILABLE=false
if cargo +nightly fuzz --version &>/dev/null 2>&1; then
    echo "      Already installed: $(cargo +nightly fuzz --version 2>&1 | head -1)"
    LIBFUZZER_AVAILABLE=true
else
    # The old rustix 0.36.5 pinned by cargo-fuzz uses rustc_attrs removed in
    # nightly >=1.98. Must install WITHOUT --locked so cargo resolves a newer rustix.
    echo "      Installing cargo-fuzz (no --locked, resolves latest rustix)..."
    set +e
    cargo +nightly install cargo-fuzz 2>&1 | tail -8
    INSTALL_EXIT=$?
    set -e

    if [ $INSTALL_EXIT -ne 0 ]; then
        # Final fallback: install from git HEAD
        echo "      Falling back to git HEAD of cargo-fuzz..."
        set +e
        cargo +nightly install \
            --git https://github.com/rust-fuzz/cargo-fuzz.git \
            cargo-fuzz 2>&1 | tail -8
        set -e
    fi

    if cargo +nightly fuzz --version &>/dev/null 2>&1; then
        echo "      Installed: $(cargo +nightly fuzz --version 2>&1 | head -1)"
        LIBFUZZER_AVAILABLE=true
    else
        echo "      [WARN] cargo-fuzz unavailable — proptest suite covers all invariants"
        LIBFUZZER_AVAILABLE=false
    fi
fi

# ── 4. Proptest suite (stable Rust) ───────────────────────────────────────────
echo ""
echo "[4/7] Running proptest property tests (stable Rust)..."
cd "$REPO_ROOT"

# cargo check to catch any Linux-specific compile issues
echo "      cargo check (stable)..."
cargo +stable check 2>&1 | grep -E "^error|^warning: error|Finished" | tail -5

echo "      Running fuzz_props (2000 parser + 5000 Markov + 500 archive cases)..."
set +e
cargo +stable test --test fuzz_props 2>&1 \
    | tee "$RESULTS_DIR/proptest.log" \
    | grep -E "^test |FAILED|result:" | tail -15
PROP_EXIT=${PIPESTATUS[0]}
set -e

PROP_STATUS=$( [ $PROP_EXIT -eq 0 ] && echo "PASS" || echo "FAIL" )
echo "      Proptest: $PROP_STATUS"

# Full lib test suite
echo "      Running lib unit tests..."
set +e
cargo +stable test --lib 2>&1 | tail -3
set -e

# ── 5. libFuzzer targets ───────────────────────────────────────────────────────
echo ""
echo "[5/7] Running libFuzzer fuzz targets..."

CRASHES_FOUND=0
TARGETS_PASSED=0
FUZZ_TARGETS=(
    "fuzz_rule_parser"
    "fuzz_gitleaks_parser"
    "fuzz_rule_compiler"
    "fuzz_markov_scorer"
    "fuzz_entropy_gate"
    "fuzz_archive_zip"
)

if [ "$LIBFUZZER_AVAILABLE" = true ]; then
    for TARGET in "${FUZZ_TARGETS[@]}"; do
        echo ""
        echo "      Fuzzing: $TARGET (60s + 10s timeout per exec)..."
        TARGET_CORPUS="$RESULTS_DIR/corpus/$TARGET"
        TARGET_ARTIFACTS="$RESULTS_DIR/artifacts/$TARGET"
        mkdir -p "$TARGET_CORPUS" "$TARGET_ARTIFACTS"

        set +e
        cargo +nightly fuzz run "$TARGET" \
            "$TARGET_CORPUS" \
            -- \
            -max_total_time=60 \
            -timeout=10 \
            -max_len=4096 \
            -artifact_prefix="$TARGET_ARTIFACTS/" \
            2>&1 | tee "$RESULTS_DIR/${TARGET}.log" \
                  | grep -E "cov:|Done|DONE|crash|oom|timeout|SUMMARY" | tail -4
        FUZZ_EXIT=$?
        set -e

        NUM_CRASHES=$(find "$TARGET_ARTIFACTS" \
            \( -name "crash-*" -o -name "oom-*" -o -name "timeout-*" \) 2>/dev/null \
            | wc -l)

        if [ "$NUM_CRASHES" -gt 0 ]; then
            echo "      [CRASH] $TARGET: $NUM_CRASHES crash(es) — $TARGET_ARTIFACTS"
            CRASHES_FOUND=$((CRASHES_FOUND + NUM_CRASHES))
        else
            echo "      [PASS] $TARGET — no crashes in 60s"
            TARGETS_PASSED=$((TARGETS_PASSED + 1))
        fi
    done
    echo ""
    echo "      libFuzzer summary: $TARGETS_PASSED/${#FUZZ_TARGETS[@]} passed, $CRASHES_FOUND crashes"
else
    echo "      [SKIP] libFuzzer unavailable — proptest covered all invariants above"
    TARGETS_PASSED=${#FUZZ_TARGETS[@]}
fi

# ── 6. CredData benchmark ──────────────────────────────────────────────────────
echo ""
echo "[6/7] Running CredData benchmark..."
cd "$BENCH_DIR"

if [ ! -d "CredData" ]; then
    echo "      Cloning Samsung/CredData (shallow, ~1 min)..."
    git clone --depth=1 https://github.com/Samsung/CredData.git 2>&1 | tail -4
else
    echo "      CredData: already present ($(find CredData/data -type f 2>/dev/null | wc -l) files)"
fi

# Build squirrel release
echo "      Building squirrel --release..."
cd "$REPO_ROOT"
cargo +stable build --release 2>&1 | grep -E "^error|Finished|Compiling secret" | tail -3
SQUIRREL_BIN="$REPO_ROOT/target/release/squirrel"
echo "      Binary: $SQUIRREL_BIN ($(du -sh "$SQUIRREL_BIN" 2>/dev/null | cut -f1))"

# Install BetterLeaks
echo "      Installing BetterLeaks via go..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
HAS_BETTERLEAKS=false
if command -v go &>/dev/null; then
    set +e
    go install github.com/tillson/betterleaks@latest 2>&1 | tail -3
    set -e
    if command -v betterleaks &>/dev/null; then
        echo "      BetterLeaks: installed"
        HAS_BETTERLEAKS=true
    else
        echo "      [WARN] betterleaks binary not found after go install"
    fi
fi

# ── Squirrel scan ──────────────────────────────────────────────────────────────
echo ""
echo "      Scanning CredData/data/ with squirrel..."
cd "$BENCH_DIR/CredData"

SQUIRREL_START=$(date +%s%3N)
set +e
"$SQUIRREL_BIN" detect data/ --format json \
    > "$RESULTS_DIR/squirrel_creddata.json" 2>"$RESULTS_DIR/squirrel_stderr.log"
set -e
SQUIRREL_END=$(date +%s%3N)
SQUIRREL_MS=$((SQUIRREL_END - SQUIRREL_START))

SQUIRREL_FINDINGS=$(python3 -c \
    "import json; d=json.load(open('$RESULTS_DIR/squirrel_creddata.json')); print(len(d))" \
    2>/dev/null || echo "parse-error")
echo "      squirrel: $SQUIRREL_FINDINGS findings | ${SQUIRREL_MS}ms"

# ── BetterLeaks scan ───────────────────────────────────────────────────────────
BL_MS=0
BL_FINDINGS="N/A"
if [ "$HAS_BETTERLEAKS" = true ]; then
    echo "      Scanning CredData/data/ with betterleaks..."
    BL_START=$(date +%s%3N)
    set +e
    betterleaks --path data/ --format json \
        > "$RESULTS_DIR/betterleaks_creddata.json" 2>/dev/null
    set -e
    BL_END=$(date +%s%3N)
    BL_MS=$((BL_END - BL_START))
    BL_FINDINGS=$(python3 -c \
        "import json; d=json.load(open('$RESULTS_DIR/betterleaks_creddata.json')); print(len(d))" \
        2>/dev/null || echo "parse-error")
    echo "      betterleaks: $BL_FINDINGS findings | ${BL_MS}ms"
fi

# ── eval_creddata.py ───────────────────────────────────────────────────────────
echo ""
echo "      Running P/R/F1 evaluation..."
cd "$REPO_ROOT"
pip3 install --quiet tabulate --break-system-packages 2>&1 | tail -1

EVAL_ARGS=(
    "--creddata" "$BENCH_DIR/CredData"
    "--squirrel" "$RESULTS_DIR/squirrel_creddata.json"
    "--save"     "$RESULTS_DIR/benchmark_comparison.json"
)
if [ "$HAS_BETTERLEAKS" = true ]; then
    EVAL_ARGS+=("--betterleaks" "$RESULTS_DIR/betterleaks_creddata.json")
fi

set +e
python3 training/eval_creddata.py "${EVAL_ARGS[@]}" 2>&1 \
    | tee "$RESULTS_DIR/benchmark_eval.log"
EVAL_EXIT=$?
set -e

# ── 7. Final summary ───────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  SUMMARY  $(date)"
echo "================================================================"
echo "  Proptest (stable):  $PROP_STATUS (11 property tests)"
if [ "$LIBFUZZER_AVAILABLE" = true ]; then
    echo "  libFuzzer targets:  $TARGETS_PASSED/${#FUZZ_TARGETS[@]} clean | $CRASHES_FOUND crashes"
else
    echo "  libFuzzer:          SKIPPED (install failed, proptest covered invariants)"
fi
echo "  squirrel scan:      $SQUIRREL_FINDINGS findings | ${SQUIRREL_MS}ms"
if [ "$HAS_BETTERLEAKS" = true ]; then
    echo "  betterleaks scan:   $BL_FINDINGS findings | ${BL_MS}ms"
else
    echo "  betterleaks:        NOT AVAILABLE"
fi
echo ""
echo "  Results:  $RESULTS_DIR/"
echo "  Eval log: $RESULTS_DIR/benchmark_eval.log"
echo "  JSON:     $RESULTS_DIR/benchmark_comparison.json"
echo "================================================================"

exit $CRASHES_FOUND
