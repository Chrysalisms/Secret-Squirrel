#!/usr/bin/env bash
# benchmark_runner.sh — End-to-end CredData benchmark for Secret Squirrel vs Betterleaks
#
# Usage:
#   chmod +x benchmark_runner.sh
#   ./benchmark_runner.sh
#
# Prerequisites:
#   - Rust toolchain (cargo + squirrel binary)
#   - Go toolchain (for betterleaks)
#   - git
#   - Python 3.8+
#
# The script:
#   1. Builds the squirrel binary (release mode)
#   2. Installs betterleaks via `go install` (or downloads a binary)
#   3. Clones CredData (Samsung/CredData) if not already present
#   4. Runs both tools against the CredData corpus
#   5. Calls training/eval_creddata.py to compare results
#   6. Saves the comparison to benchmark_comparison.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/benchmark_results"
CREDDATA_DIR="${SCRIPT_DIR}/CredData"
SQUIRREL_BIN="${SCRIPT_DIR}/target/release/squirrel"

mkdir -p "${RESULTS_DIR}"

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Build squirrel
# ──────────────────────────────────────────────────────────────────────────────
echo "[benchmark] Building squirrel (release) ..."
cargo build --release --manifest-path "${SCRIPT_DIR}/Cargo.toml"
echo "[benchmark] squirrel binary: ${SQUIRREL_BIN}"

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Install betterleaks
# ──────────────────────────────────────────────────────────────────────────────
echo "[benchmark] Installing betterleaks ..."

BETTERLEAKS_BIN=""
if command -v betterleaks &>/dev/null; then
    BETTERLEAKS_BIN="$(command -v betterleaks)"
    echo "[benchmark] betterleaks found at: ${BETTERLEAKS_BIN}"
elif command -v go &>/dev/null; then
    echo "[benchmark] Installing betterleaks via go install ..."
    go install github.com/BetterLeaks/betterleaks@latest
    BETTERLEAKS_BIN="$(go env GOPATH)/bin/betterleaks"
    echo "[benchmark] betterleaks installed at: ${BETTERLEAKS_BIN}"
else
    # Attempt to download a pre-built binary from GitHub
    echo "[benchmark] WARNING: go not found. Attempting to download betterleaks binary ..."
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    BL_URL="https://github.com/BetterLeaks/betterleaks/releases/latest/download/betterleaks_${OS}_${ARCH}"
    BETTERLEAKS_BIN="${RESULTS_DIR}/betterleaks"
    curl -fsSL "${BL_URL}" -o "${BETTERLEAKS_BIN}" && chmod +x "${BETTERLEAKS_BIN}" || {
        echo "[benchmark] ERROR: Could not install betterleaks. Install Go and re-run."
        echo "[benchmark]   go install github.com/BetterLeaks/betterleaks@latest"
        exit 1
    }
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Clone CredData
# ──────────────────────────────────────────────────────────────────────────────
if [ ! -d "${CREDDATA_DIR}" ]; then
    echo "[benchmark] Cloning CredData ..."
    git clone --depth=1 https://github.com/Samsung/CredData.git "${CREDDATA_DIR}"
else
    echo "[benchmark] CredData already present at ${CREDDATA_DIR}"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Run squirrel
# ──────────────────────────────────────────────────────────────────────────────
SQUIRREL_OUT="${RESULTS_DIR}/squirrel_output.json"
echo "[benchmark] Running squirrel against CredData ..."
"${SQUIRREL_BIN}" detect "${CREDDATA_DIR}/data" \
    --format json \
    --output "${SQUIRREL_OUT}" \
    --severity info \
    --confidence 0.0 \
    || true   # tolerate exit 1 (findings found)
echo "[benchmark] Squirrel output: ${SQUIRREL_OUT}"

# ──────────────────────────────────────────────────────────────────────────────
# Step 5: Run betterleaks
# ──────────────────────────────────────────────────────────────────────────────
BETTERLEAKS_OUT="${RESULTS_DIR}/betterleaks_output.json"
echo "[benchmark] Running betterleaks against CredData ..."
"${BETTERLEAKS_BIN}" detect \
    --source "${CREDDATA_DIR}/data" \
    --report-format json \
    --report-path "${BETTERLEAKS_OUT}" \
    || true   # tolerate exit 1 (findings found)
echo "[benchmark] Betterleaks output: ${BETTERLEAKS_OUT}"

# ──────────────────────────────────────────────────────────────────────────────
# Step 6: Evaluate
# ──────────────────────────────────────────────────────────────────────────────
COMPARISON_OUT="${SCRIPT_DIR}/benchmark_comparison.json"
echo "[benchmark] Evaluating results ..."
python3 "${SCRIPT_DIR}/training/eval_creddata.py" \
    --squirrel    "${SQUIRREL_OUT}" \
    --betterleaks "${BETTERLEAKS_OUT}" \
    --creddata    "${CREDDATA_DIR}" \
    --save        "${COMPARISON_OUT}" \
    --tolerance   1

echo ""
echo "[benchmark] Done! Results saved to ${COMPARISON_OUT}"
