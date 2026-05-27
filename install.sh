#!/usr/bin/env sh
# install.sh — Download and install the Secret Squirrel binary from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Chrysalisms/Secret-Squirrel/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/Chrysalisms/Secret-Squirrel/main/install.sh | sh -s -- --version v0.1.0
#
# Options:
#   --version <tag>   Install a specific release tag (default: latest)
#   --install-dir <dir>  Install binary to this directory (default: /usr/local/bin)
#
set -eu

REPO="Chrysalisms/Secret-Squirrel"
BINARY_NAME="squirrel"
DEFAULT_INSTALL_DIR="/usr/local/bin"

# ── Argument parsing ──────────────────────────────────────────────────────────
VERSION=""
INSTALL_DIR="${DEFAULT_INSTALL_DIR}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required command '$1' not found." >&2
    exit 1
  fi
}

need_cmd curl
need_cmd tar   # used for .tar.gz

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)
    case "${ARCH}" in
      x86_64)  TARGET="x86_64-unknown-linux-musl"  ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
      *)
        echo "Error: unsupported Linux architecture '${ARCH}'." >&2
        exit 1
        ;;
    esac
    ARCHIVE_EXT="tar.gz"
    ;;
  Darwin)
    case "${ARCH}" in
      x86_64)       TARGET="x86_64-apple-darwin"  ;;
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      *)
        echo "Error: unsupported macOS architecture '${ARCH}'." >&2
        exit 1
        ;;
    esac
    ARCHIVE_EXT="tar.gz"
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows*)
    # Running under Git Bash / WSL-like environment on Windows
    TARGET="x86_64-windows"
    ARCHIVE_EXT="zip"
    need_cmd unzip
    ;;
  *)
    echo "Error: unsupported operating system '${OS}'." >&2
    echo "For Windows, please download the .zip from https://github.com/${REPO}/releases" >&2
    exit 1
    ;;
esac

# ── Resolve version ───────────────────────────────────────────────────────────
if [ -z "${VERSION}" ]; then
  echo "Fetching latest release tag..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"

  if [ -z "${VERSION}" ]; then
    echo "Error: could not determine latest release version." >&2
    exit 1
  fi
fi

echo "Installing ${BINARY_NAME} ${VERSION} for ${TARGET}..."

# ── Build download URL ────────────────────────────────────────────────────────
if [ "${ARCHIVE_EXT}" = "zip" ]; then
  ARCHIVE_NAME="${BINARY_NAME}-${VERSION}-${TARGET}.zip"
else
  ARCHIVE_NAME="${BINARY_NAME}-${VERSION}-${TARGET}.tar.gz"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"

# ── Download ──────────────────────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading ${DOWNLOAD_URL} ..."
curl -fsSL --progress-bar "${DOWNLOAD_URL}" -o "${TMP_DIR}/${ARCHIVE_NAME}"

# ── Verify checksum (optional but recommended) ─────────────────────────────
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if curl -fsSL "${CHECKSUM_URL}" -o "${TMP_DIR}/checksums.txt" 2>/dev/null; then
  echo "Verifying SHA-256 checksum..."
  # Filter to only the line for our archive
  EXPECTED="$(grep "${ARCHIVE_NAME}" "${TMP_DIR}/checksums.txt" || true)"
  if [ -n "${EXPECTED}" ]; then
    # sha256sum on Linux, shasum -a 256 on macOS
    if command -v sha256sum >/dev/null 2>&1; then
      echo "${EXPECTED}" | (cd "${TMP_DIR}" && sha256sum --check --status)
    elif command -v shasum >/dev/null 2>&1; then
      echo "${EXPECTED}" | (cd "${TMP_DIR}" && shasum -a 256 --check --status)
    else
      echo "Warning: no sha256sum/shasum found; skipping checksum verification." >&2
    fi
    echo "Checksum OK."
  else
    echo "Warning: no checksum entry found for ${ARCHIVE_NAME}; skipping." >&2
  fi
else
  echo "Warning: could not fetch checksums.txt; skipping verification." >&2
fi

# ── Extract ───────────────────────────────────────────────────────────────────
cd "${TMP_DIR}"

if [ "${ARCHIVE_EXT}" = "zip" ]; then
  unzip -q "${ARCHIVE_NAME}"
else
  tar xzf "${ARCHIVE_NAME}"
fi

# Find the extracted binary
EXTRACTED_BIN="${TMP_DIR}/${BINARY_NAME}"
if [ ! -f "${EXTRACTED_BIN}" ]; then
  # Try with .exe suffix for Windows environments
  EXTRACTED_BIN="${TMP_DIR}/${BINARY_NAME}.exe"
fi

if [ ! -f "${EXTRACTED_BIN}" ]; then
  echo "Error: could not find '${BINARY_NAME}' in extracted archive." >&2
  exit 1
fi

chmod +x "${EXTRACTED_BIN}"

# ── Install ───────────────────────────────────────────────────────────────────
INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}"

# Create install dir if needed (requires write permission)
if [ ! -d "${INSTALL_DIR}" ]; then
  mkdir -p "${INSTALL_DIR}" 2>/dev/null || sudo mkdir -p "${INSTALL_DIR}"
fi

if [ -w "${INSTALL_DIR}" ]; then
  cp "${EXTRACTED_BIN}" "${INSTALL_PATH}"
else
  echo "Install directory ${INSTALL_DIR} requires elevated permissions. Using sudo..."
  sudo cp "${EXTRACTED_BIN}" "${INSTALL_PATH}"
fi

echo ""
echo "✓ ${BINARY_NAME} ${VERSION} installed to ${INSTALL_PATH}"
echo ""

# ── Verify installation ───────────────────────────────────────────────────────
if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
  echo "Run '${BINARY_NAME} --help' to get started."
else
  echo "Note: '${INSTALL_DIR}' may not be on your PATH."
  echo "Add it by running:  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi
