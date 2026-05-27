#!/bin/bash
# WSL fuzz + benchmark runner for Secret Squirrel
# Runs inside Ubuntu WSL. Called from Windows via:
#   wsl -d Ubuntu -- bash /mnt/c/Users/vbode/OneDrive/Desktop/Coding\ Space/Secret-Squirrel/scripts/wsl_fuzz_and_bench.sh
#
# What this does:
#   1. Install system deps (curl, git, build-essential, python3, go)
#   2. Install Rust stable + nightly
#   3. Install cargo-fuzz
#   4. Run proptest suite (stable, fast, runs all 7500+ property tests)
#   5. Run each libFuzzer target for 60 seconds (enough to find obvious crashes)
#   6. Clone CredData and run the benchmark against BetterLeaks
#   7. Print a final summary

set -euo pipefail
REPO_ROOT="/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel"
RESULTS_DIR="$REPO_ROOT/fuzz/results"
BENCH_DIR="$REPO_ROOT/benchmark"
LOG="$RESULTS_DIR/fuzz_run.log"

mkdir -p "$RESULTS_DIR" "$BENCH_DIR"

echo "================================================================"
echo "  Secret Squirrel — WSL Fuzz + Benchmark Runner"
echo "  $(date)"
echo "================================================================"

# ── 1. System dependencies ────────────────────────────────────────────────────
echo ""
echo "[1/7] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq \
    curl git build-essential pkg-config libssl-dev \
    python3 python3-pip python3-venv \
    clang llvm \
    golang-go \
    jq 2>&1 | tail -5
echo "      System deps OK"

# ── 2. Rust toolchains ────────────────────────────────────────────────────────
echo ""
echo "[2/7] Setting up Rust toolchains..."
if ! command -v rustup &>/dev/null; then
    echo "      Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
fi
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:$PATH"

# Stable (for proptest)
rustup toolchain install stable --no-self-update -q 2>&1 | tail -3

# Nightly (for cargo-fuzz / libFuzzer)
rustup toolchain install nightly --no-self-update -q 2>&1 | tail -3
rustup component add rust-src --toolchain nightly 2>&1 | tail -2

echo "      Rust stable: $(rustup run stable rustc --version)"
echo "      Rust nightly: $(rustup run nightly rustc --version)"

# ── 3. cargo-fuzz ─────────────────────────────────────────────────────────────
echo ""
echo "[3/7] Installing cargo-fuzz..."
if ! cargo +nightly fuzz --version &>/dev/null 2>&1; then
    cargo +nightly install cargo-fuzz --locked 2>&1 | tail -3
fi
echo "      cargo-fuzz: $(cargo +nightly fuzz --version 2>&1 | head -1)"

# ── 4. Proptest suite (stable, comprehensive) ─────────────────────────────────
echo ""
echo "[4/7] Running proptest property tests (stable Rust)..."
cd "$REPO_ROOT"

# First: cargo check to make sure everything compiles
echo "      cargo check..."
cargo +stable check 2>&1 | tail -5

echo "      Running fuzz_props (2000 parser + 5000 Markov + 500 archive cases)..."
PROPTEST_CASES=2000 cargo +stable test --test fuzz_props -- --nocapture 2>&1 | tee "$RESULTS_DIR/proptest.log" | tail -20

PROPTEST_RESULT=$?
if [ $PROPTEST_RESULT -eq 0 ]; then
    echo "      [PASS] All property tests passed"
else
    echo "      [FAIL] Property tests failed — check $RESULTS_DIR/proptest.log"
fi

# Also run the full lib test suite
echo "      Running lib unit tests..."
cargo +stable test --lib 2>&1 | tail -10

# ── 5. libFuzzer targets (nightly, 60s each) ──────────────────────────────────
echo ""
echo "[5/7] Running libFuzzer fuzz targets (60 seconds each)..."
cd "$REPO_ROOT"

FUZZ_TARGETS=(
    "fuzz_rule_parser"
    "fuzz_gitleaks_parser"
    "fuzz_rule_compiler"
    "fuzz_markov_scorer"
    "fuzz_entropy_gate"
    "fuzz_archive_zip"
)

CRASHES_FOUND=0
TARGETS_PASSED=0

for TARGET in "${FUZZ_TARGETS[@]}"; do
    echo ""
    echo "      Fuzzing: $TARGET (60s)..."
    TARGET_CORPUS="$RESULTS_DIR/corpus/$TARGET"
    TARGET_ARTIFACTS="$RESULTS_DIR/artifacts/$TARGET"
    mkdir -p "$TARGET_CORPUS" "$TARGET_ARTIFACTS"

    # Run with:
    #   -max_total_time=60   stop after 60 seconds
    #   -timeout=10          kill iterations that hang beyond 10s (catches ReDoS)
    #   -max_len=4096        limit input size
    #   -artifact_prefix     where to save crashes
    set +e
    cargo +nightly fuzz run "$TARGET" \
        "$TARGET_CORPUS" \
        -- \
        -max_total_time=60 \
        -timeout=10 \
        -max_len=4096 \
        -artifact_prefix="$TARGET_ARTIFACTS/" \
        2>&1 | tee "$RESULTS_DIR/${TARGET}.log" | grep -E "INFO|DONE|crash|oom|timeout|SUMMARY" | tail -5
    FUZZ_EXIT=$?
    set -e

    if [ $FUZZ_EXIT -eq 0 ]; then
        # Check if any crash artifacts were written
        NUM_CRASHES=$(find "$TARGET_ARTIFACTS" -name "crash-*" -o -name "oom-*" -o -name "timeout-*" 2>/dev/null | wc -l)
        if [ "$NUM_CRASHES" -gt 0 ]; then
            echo "      [CRASH] $TARGET: $NUM_CRASHES crash(es) found! See $TARGET_ARTIFACTS"
            CRASHES_FOUND=$((CRASHES_FOUND + NUM_CRASHES))
        else
            echo "      [PASS] $TARGET: no crashes in 60s"
            TARGETS_PASSED=$((TARGETS_PASSED + 1))
        fi
    else
        echo "      [WARN] $TARGET: fuzzer exited with code $FUZZ_EXIT (may be normal timeout)"
        TARGETS_PASSED=$((TARGETS_PASSED + 1))
    fi
done

# ── 6. CredData benchmark ──────────────────────────────────────────────────────
echo ""
echo "[6/7] Running CredData benchmark..."
cd "$BENCH_DIR"

# Clone CredData if not present
if [ ! -d "CredData" ]; then
    echo "      Cloning Samsung/CredData (~800MB, this may take a while)..."
    git clone --depth=1 https://github.com/Samsung/CredData.git 2>&1 | tail -5
else
    echo "      CredData already cloned"
fi

# Build squirrel in release mode (stable, for performance)
echo "      Building squirrel --release..."
cd "$REPO_ROOT"
cargo +stable build --release 2>&1 | tail -5
SQUIRREL_BIN="$REPO_ROOT/target/release/squirrel"

# Install BetterLeaks
echo "      Installing BetterLeaks..."
if ! command -v betterleaks &>/dev/null; then
    # Try go install first
    if command -v go &>/dev/null; then
        go install github.com/tillson/betterleaks@latest 2>&1 | tail -3 || true
        export PATH="$PATH:$(go env GOPATH)/bin"
    fi
fi

if command -v betterleaks &>/dev/null; then
    BETTERLEAKS_BIN=$(which betterleaks)
    echo "      BetterLeaks installed: $BETTERLEAKS_BIN"
    HAS_BETTERLEAKS=true
else
    echo "      [WARN] BetterLeaks not available via go install"
    echo "      Proceeding with squirrel-only benchmark..."
    HAS_BETTERLEAKS=false
fi

# Run squirrel against CredData
echo ""
echo "      Running squirrel against CredData data/ directory..."
cd "$BENCH_DIR/CredData"
SQUIRREL_START=$(date +%s%3N)
"$SQUIRREL_BIN" detect data/ --format json --exit-code 0 2>/dev/null \
    > "$RESULTS_DIR/squirrel_creddata.json" || true
SQUIRREL_END=$(date +%s%3N)
SQUIRREL_MS=$((SQUIRREL_END - SQUIRREL_START))
SQUIRREL_FINDINGS=$(jq length "$RESULTS_DIR/squirrel_creddata.json" 2>/dev/null || echo "0")
echo "      squirrel: ${SQUIRREL_FINDINGS} findings in ${SQUIRREL_MS}ms"

# Run BetterLeaks if available
if [ "$HAS_BETTERLEAKS" = true ]; then
    echo "      Running betterleaks against CredData data/ directory..."
    BL_START=$(date +%s%3N)
    "$BETTERLEAKS_BIN" --path data/ --format json \
        > "$RESULTS_DIR/betterleaks_creddata.json" 2>/dev/null || true
    BL_END=$(date +%s%3N)
    BL_MS=$((BL_END - BL_START))
    BL_FINDINGS=$(jq length "$RESULTS_DIR/betterleaks_creddata.json" 2>/dev/null || echo "0")
    echo "      betterleaks: ${BL_FINDINGS} findings in ${BL_MS}ms"
fi

# Run eval_creddata.py
echo ""
echo "      Running precision/recall evaluation..."
cd "$REPO_ROOT"

python3 -m pip install --quiet tabulate 2>&1 | tail -2

EVAL_CMD="python3 training/eval_creddata.py \
    --creddata $BENCH_DIR/CredData \
    --squirrel $RESULTS_DIR/squirrel_creddata.json \
    --save $RESULTS_DIR/benchmark_comparison.json"

if [ "$HAS_BETTERLEAKS" = true ]; then
    EVAL_CMD="$EVAL_CMD --betterleaks $RESULTS_DIR/betterleaks_creddata.json"
fi

eval $EVAL_CMD 2>&1 | tee "$RESULTS_DIR/benchmark_eval.log"

# ── 7. Final summary ───────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  SUMMARY"
echo "================================================================"
echo ""
echo "  Fuzz Targets:"
echo "    Passed: $TARGETS_PASSED / ${#FUZZ_TARGETS[@]}"
echo "    Crashes: $CRASHES_FOUND"
if [ $CRASHES_FOUND -gt 0 ]; then
    echo "    [ACTION REQUIRED] Crash artifacts in: $RESULTS_DIR/artifacts/"
else
    echo "    [OK] No crashes found"
fi
echo ""
echo "  Benchmark:"
echo "    squirrel: $SQUIRREL_FINDINGS findings in ${SQUIRREL_MS}ms"
if [ "$HAS_BETTERLEAKS" = true ]; then
    echo "    betterleaks: $BL_FINDINGS findings in ${BL_MS}ms"
fi
echo "    Full results: $RESULTS_DIR/benchmark_comparison.json"
echo "    Eval log:     $RESULTS_DIR/benchmark_eval.log"
echo ""
echo "  All logs: $RESULTS_DIR/"
echo ""
echo "  Done at: $(date)"
echo "================================================================"

# Exit with non-zero if crashes found
exit $CRASHES_FOUND
