#!/usr/bin/env bash
# entrypoint.sh — Secret Squirrel GitHub Action entrypoint
#
# Reads environment variables injected by action.yml, builds the squirrel
# command, executes the scan, writes SARIF output, and sets GitHub Action
# step outputs.
#
# Environment variables (set by action.yml):
#   SQUIRREL_SCAN_MODE          diff | full | history
#   SQUIRREL_CONFIG_PATH        optional path to custom rules file
#   SQUIRREL_SEVERITY_THRESHOLD info | low | medium | high | critical
#   SQUIRREL_FAIL_ON_FINDINGS   true | false
#   SQUIRREL_VALIDATE           true | false
#   SQUIRREL_SARIF_UPLOAD       true | false
#   SQUIRREL_MODEL_TIER         default | tiny | large | enhanced | maximum
#   GITHUB_TOKEN                GitHub API token for SARIF upload
#   GITHUB_WORKSPACE            set by GitHub Actions runner (repo root)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_MODE="${SQUIRREL_SCAN_MODE:-diff}"
CONFIG_PATH="${SQUIRREL_CONFIG_PATH:-}"
SEVERITY="${SQUIRREL_SEVERITY_THRESHOLD:-medium}"
FAIL_ON_FINDINGS="${SQUIRREL_FAIL_ON_FINDINGS:-true}"
VALIDATE="${SQUIRREL_VALIDATE:-false}"
MODEL_TIER="${SQUIRREL_MODEL_TIER:-tiny}"
WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"

SARIF_PATH="${RUNNER_TEMP:-/tmp}/squirrel-results.sarif"
FINDINGS_COUNT=0

# ── Validate inputs ───────────────────────────────────────────────────────────
case "${SCAN_MODE}" in
    diff|full|history) ;;
    *)
        echo "::error::Invalid scan-mode '${SCAN_MODE}'. Must be: diff, full, or history."
        exit 1
        ;;
esac

case "${SEVERITY}" in
    info|low|medium|high|critical) ;;
    *)
        echo "::error::Invalid severity-threshold '${SEVERITY}'. Must be: info, low, medium, high, or critical."
        exit 1
        ;;
esac

# ── Print version and config ──────────────────────────────────────────────────
echo "::group::Secret Squirrel Configuration"
squirrel --version
echo "Scan mode:         ${SCAN_MODE}"
echo "Severity threshold: ${SEVERITY}"
echo "Model tier:        ${MODEL_TIER}"
echo "Validate:          ${VALIDATE}"
echo "Workspace:         ${WORKSPACE}"
if [[ -n "${CONFIG_PATH}" ]]; then
    echo "Config file:       ${CONFIG_PATH}"
fi
echo "::endgroup::"

# ── Build command arguments ───────────────────────────────────────────────────
SQUIRREL_ARGS=(
    "--severity" "${SEVERITY}"
    "--format" "sarif"
    "--output" "${SARIF_PATH}"
    "--model-tier" "${MODEL_TIER}"
)

# Scan mode flags
case "${SCAN_MODE}" in
    diff)
        # In diff mode, scan only files changed in the current PR/push.
        # We use git to find changed files and pass them explicitly.
        echo "::group::Discovering changed files"
        if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
            # Pull request: compare against base branch
            BASE_SHA=$(git rev-parse "origin/${GITHUB_BASE_REF}" 2>/dev/null || echo "HEAD~1")
            CHANGED_FILES=$(git diff --name-only "${BASE_SHA}...HEAD" 2>/dev/null || true)
        else
            # Push: compare against previous commit
            CHANGED_FILES=$(git diff --name-only HEAD~1 HEAD 2>/dev/null || true)
        fi

        if [[ -z "${CHANGED_FILES}" ]]; then
            echo "No changed files detected. Skipping scan."
            echo "::endgroup::"
            # Write empty SARIF
            cat > "${SARIF_PATH}" <<'SARIF'
{"version":"2.1.0","$schema":"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json","runs":[{"tool":{"driver":{"name":"secret-squirrel","version":"0.1.0","rules":[]}},"results":[]}]}
SARIF
            FINDINGS_COUNT=0
        else
            echo "Changed files:"
            echo "${CHANGED_FILES}"
            echo "::endgroup::"
            # Scan only changed files
            readarray -t FILES_ARRAY <<< "${CHANGED_FILES}"
            SQUIRREL_ARGS+=("scan" "--files" "${FILES_ARRAY[@]}")
        fi
        ;;
    full)
        SQUIRREL_ARGS+=("scan" "${WORKSPACE}")
        ;;
    history)
        DEPTH="${SQUIRREL_GIT_DEPTH:-0}"
        SQUIRREL_ARGS+=("scan" "--git" "--git-depth" "${DEPTH}" "${WORKSPACE}")
        ;;
esac

# Optional: custom config file
if [[ -n "${CONFIG_PATH}" ]]; then
    if [[ -f "${WORKSPACE}/${CONFIG_PATH}" ]]; then
        SQUIRREL_ARGS+=("--config" "${WORKSPACE}/${CONFIG_PATH}")
    else
        echo "::warning::Config file '${CONFIG_PATH}' not found — using embedded defaults."
    fi
fi

# Optional: active validation
if [[ "${VALIDATE}" == "true" ]]; then
    SQUIRREL_ARGS+=("--validate")
fi

# ── Run the scan ──────────────────────────────────────────────────────────────
echo "::group::Running Secret Squirrel scan"
cd "${WORKSPACE}"

set +e  # Don't exit on non-zero — we capture the exit code explicitly
squirrel "${SQUIRREL_ARGS[@]}"
SQUIRREL_EXIT=$?
set -e

echo "Exit code: ${SQUIRREL_EXIT}"
echo "::endgroup::"

# ── Parse findings count from SARIF ──────────────────────────────────────────
if [[ -f "${SARIF_PATH}" ]]; then
    FINDINGS_COUNT=$(jq '[.runs[].results | length] | add // 0' "${SARIF_PATH}" 2>/dev/null || echo "0")
    echo "Total findings: ${FINDINGS_COUNT}"
else
    echo "::warning::SARIF output file not found at ${SARIF_PATH}"
    SARIF_PATH=""
    FINDINGS_COUNT=0
fi

# ── Set GitHub Action step outputs ───────────────────────────────────────────
{
    echo "findings-count=${FINDINGS_COUNT}"
    echo "sarif-path=${SARIF_PATH}"
} >> "${GITHUB_OUTPUT:-/dev/null}"

# ── Summary ──────────────────────────────────────────────────────────────────
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "## 🐿️ Secret Squirrel Scan Results"
        echo ""
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| Scan mode | \`${SCAN_MODE}\` |"
        echo "| Severity threshold | \`${SEVERITY}\` |"
        echo "| Model tier | \`${MODEL_TIER}\` |"
        echo "| Findings | **${FINDINGS_COUNT}** |"
        if [[ "${FINDINGS_COUNT}" -gt 0 ]]; then
            echo ""
            echo "> ⚠️  **${FINDINGS_COUNT}** potential secret(s) detected."
            echo "> Review the Security tab for details."
        else
            echo ""
            echo "> ✅ No secrets detected."
        fi
    } >> "${GITHUB_STEP_SUMMARY}"
fi

# ── SARIF upload (handled by caller workflow using github/codeql-action/upload-sarif) ──
# We set the sarif-path output; the workflow decides whether to upload.
# Direct upload via API could be added here if needed.
if [[ "${SQUIRREL_SARIF_UPLOAD:-true}" == "true" && -n "${SARIF_PATH}" ]]; then
    echo "SARIF report written to: ${SARIF_PATH}"
    echo "To upload, add this step to your workflow:"
    echo "  - uses: github/codeql-action/upload-sarif@v3"
    echo "    with:"
    echo "      sarif_file: \${{ steps.scan.outputs.sarif-path }}"
fi

# ── Fail on findings ──────────────────────────────────────────────────────────
if [[ "${FAIL_ON_FINDINGS}" == "true" && "${FINDINGS_COUNT}" -gt 0 ]]; then
    echo "::error::Secret Squirrel found ${FINDINGS_COUNT} potential secret(s). \
Investigate and remediate before merging. \
Set fail-on-findings: false to report-only without blocking CI."
    exit 1
fi

# ── Propagate squirrel's own exit code ───────────────────────────────────────
# squirrel exits 0 = clean, 1 = findings, 2+ = error
if [[ "${SQUIRREL_EXIT}" -ge 2 ]]; then
    echo "::error::squirrel exited with error code ${SQUIRREL_EXIT}. Check logs above."
    exit "${SQUIRREL_EXIT}"
fi

exit 0
