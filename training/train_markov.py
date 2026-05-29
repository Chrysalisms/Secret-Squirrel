#!/usr/bin/env python3
"""
train_markov.py — Train the 64-char trigram Markov model from CredData corpus.

Reads ground-truth secrets from CredData and builds a trigram frequency table
over the 64-character alphabet used by Secret Squirrel's MarkovScorer.

Output: training/data/markov_trigrams.json
  A flat list of 262,144 (64^3) log-probability values (f32), indexed by
  a * 64 * 64 + b * 64 + c where a,b,c are alphabet indices.

Usage:
  python3 training/train_markov.py --creddata benchmark/CredData
  python3 training/train_markov.py --creddata benchmark/CredData --output training/data/markov_trigrams.json
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Alphabet (must match Rust ALPHABET in src/scoring/markov.rs)
# ---------------------------------------------------------------------------
ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
ALPHA_SIZE = 64
TABLE_SIZE = ALPHA_SIZE ** 3

# Build char -> index lookup
CHAR_INDEX: dict[int, int] = {c: i for i, c in enumerate(ALPHABET)}

# ---------------------------------------------------------------------------
# Log-probability constants (fallback heuristics, same as Rust)
# ---------------------------------------------------------------------------
LOG_COMMON = math.log2(0.05)    # -4.322  common trigrams
LOG_MIXED  = math.log2(0.001)   # -9.966  medium frequency
LOG_RARE   = math.log2(0.0001)  # -13.288 rare / random-looking


def trigram_idx(a: int, b: int, c: int) -> int:
    return a * ALPHA_SIZE * ALPHA_SIZE + b * ALPHA_SIZE + c


def extract_trigrams(text: str) -> list[tuple[int, int, int]]:
    """Extract all valid trigrams (indices into ALPHABET) from text."""
    indices: list[int] = []
    for ch in text.encode("latin-1", errors="replace"):
        idx = CHAR_INDEX.get(ch)
        if idx is not None:
            indices.append(idx)
    return [(indices[i], indices[i+1], indices[i+2]) for i in range(len(indices) - 2)]


def load_creddata_secrets(creddata_dir: Path) -> list[str]:
    """Load ground-truth secret strings from CredData CSV files."""
    secrets: list[str] = []
    meta_dir = creddata_dir / "meta"
    data_dir = creddata_dir / "data"

    if not meta_dir.exists():
        print(f"[markov] WARNING: {meta_dir} not found — using synthetic secrets only", file=sys.stderr)
        return secrets

    for csv_file in meta_dir.glob("*.csv"):
        try:
            with csv_file.open(encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    if row.get("GroundTruth") != "T":
                        continue
                    file_path = row.get("FilePath", "")
                    line_str  = row.get("LineStart", "0")
                    try:
                        line_num = int(line_str)
                    except ValueError:
                        continue
                    if not file_path or not line_num:
                        continue

                    # Try to read the actual secret value from the file
                    source_file = data_dir / file_path.lstrip("data/")
                    if not source_file.exists():
                        source_file = creddata_dir / file_path
                    if not source_file.exists():
                        continue

                    try:
                        lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
                        if 0 < line_num <= len(lines):
                            line = lines[line_num - 1]
                            # Heuristically extract the value part (after = or :)
                            m = re.search(r'[:=]\s*["\']?([A-Za-z0-9+/\-_]{8,})', line)
                            if m:
                                secrets.append(m.group(1))
                    except Exception:
                        pass
        except Exception as e:
            print(f"[markov] WARNING: failed to read {csv_file}: {e}", file=sys.stderr)

    return secrets


def synthetic_secrets() -> list[str]:
    """Return a set of known-format synthetic secrets for training."""
    import random
    import string

    rng = random.Random(42)
    secrets: list[str] = []

    def rand_b64(n: int) -> str:
        chars = string.ascii_letters + string.digits + "+/"
        return "".join(rng.choice(chars) for _ in range(n))

    def rand_hex(n: int) -> str:
        return "".join(rng.choice("0123456789abcdef") for _ in range(n))

    def rand_alnum(n: int) -> str:
        chars = string.ascii_letters + string.digits
        return "".join(rng.choice(chars) for _ in range(n))

    # AWS Access Keys
    for _ in range(500):
        secrets.append("AKIA" + rand_alnum(16).upper())
    # AWS Secret Keys
    for _ in range(500):
        secrets.append(rand_b64(40))
    # GitHub PATs
    for _ in range(500):
        secrets.append("ghp_" + rand_alnum(36))
    # GitLab PATs
    for _ in range(200):
        secrets.append("glpat-" + rand_alnum(20))
    # Stripe keys
    for _ in range(300):
        secrets.append("sk_live_" + rand_alnum(24))
    # OpenAI keys
    for _ in range(300):
        secrets.append("sk-" + rand_alnum(48))
    # Slack tokens
    for _ in range(200):
        secrets.append("xoxb-" + rand_hex(10) + "-" + rand_hex(10) + "-" + rand_alnum(24))
    # Generic high-entropy tokens
    for _ in range(1000):
        secrets.append(rand_b64(rng.randint(20, 64)))
    for _ in range(500):
        secrets.append(rand_hex(rng.randint(20, 64)))

    return secrets


def natural_text_samples() -> list[str]:
    """Return strings that should score LOW (not secrets)."""
    return [
        "the quick brown fox jumps over the lazy dog",
        "password_field", "api_key_name", "access_token",
        "hello world", "configuration", "development",
        "localhost", "example", "placeholder", "changeme",
        "YOUR_API_KEY", "YOUR_TOKEN", "your_password",
        "true", "false", "null", "undefined",
        "function", "return", "variable", "import",
        "username", "email", "address", "database",
        "connection", "timeout", "retry", "default",
    ] * 50   # repeat so they have weight


def build_tables(
    secret_strings: list[str],
    natural_strings: list[str],
    laplace_k: float = 0.01,
) -> list[float]:
    """
    Build log-probability table from corpus.
    Returns list of TABLE_SIZE float log2-probabilities.
    """
    # Count trigrams in secrets and natural text
    secret_counts  = [0.0] * TABLE_SIZE
    natural_counts = [0.0] * TABLE_SIZE

    print(f"[markov] Extracting trigrams from {len(secret_strings)} secret samples...", file=sys.stderr)
    for s in secret_strings:
        for a, b, c in extract_trigrams(s):
            secret_counts[trigram_idx(a, b, c)] += 1.0

    print(f"[markov] Extracting trigrams from {len(natural_strings)} natural samples...", file=sys.stderr)
    for s in natural_strings:
        for a, b, c in extract_trigrams(s):
            natural_counts[trigram_idx(a, b, c)] += 1.0

    total_secret  = sum(secret_counts)  or 1.0
    total_natural = sum(natural_counts) or 1.0

    # Build log-prob table: log2(P(trigram | secret) / P(trigram | natural))
    # High positive => more likely a secret trigram
    # High negative => more likely natural text
    #
    # We want MarkovScorer to output HIGH scores for secrets, so we want the
    # log-prob in the table to be MORE NEGATIVE for secret-like trigrams
    # (because the scorer maps: very negative avg log-prob -> score near 1.0).
    # So we actually want: P(trigram | natural) values.
    table: list[float] = []
    for i in range(TABLE_SIZE):
        p_natural = (natural_counts[i] + laplace_k) / (total_natural + laplace_k * TABLE_SIZE)
        lp = math.log2(p_natural)
        # Clamp to sensible range
        lp = max(-20.0, min(-1.0, lp))
        table.append(lp)

    print(f"[markov] Table built. Range: [{min(table):.3f}, {max(table):.3f}]", file=sys.stderr)
    return table


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Markov trigram model for Secret Squirrel.")
    parser.add_argument("--creddata", type=Path, default=Path("benchmark/CredData"),
                        help="Path to CredData root directory")
    parser.add_argument("--output", type=Path, default=Path("training/data/markov_trigrams.json"),
                        help="Output path for trigram table JSON")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    # Load training data
    creddata_secrets = load_creddata_secrets(args.creddata)
    print(f"[markov] Loaded {len(creddata_secrets)} secrets from CredData", file=sys.stderr)

    synth = synthetic_secrets()
    print(f"[markov] Generated {len(synth)} synthetic secrets", file=sys.stderr)

    natural = natural_text_samples()

    all_secrets = creddata_secrets + synth

    # Build table
    table = build_tables(all_secrets, natural)

    # Write output
    with args.output.open("w") as fh:
        json.dump(table, fh, separators=(",", ":"))

    size_kb = args.output.stat().st_size / 1024
    print(f"[markov] Wrote {TABLE_SIZE} entries to {args.output} ({size_kb:.1f} KB)", file=sys.stderr)

    # Sanity check: known secrets should have low average log-prob
    test_cases = [
        ("AKIAIOSFODNN7EXAMPLE", "AWS key (should score high)"),
        ("ghp_" + "A" * 36,      "GitHub PAT (should score high)"),
        ("the quick brown fox",   "English text (should score low)"),
        ("password_field",        "Natural identifier (should score low)"),
    ]
    print("\n[markov] Sanity checks:", file=sys.stderr)
    for text, label in test_cases:
        trigrams = extract_trigrams(text)
        if not trigrams:
            continue
        avg_lp = sum(table[trigram_idx(a, b, c)] for a, b, c in trigrams) / len(trigrams)
        # Normalize same way Rust does: (avg - SCORE_MIN) / (SCORE_MAX - SCORE_MIN)
        score_min, score_max = -4.0, -14.0
        score = (avg_lp - score_min) / (score_max - score_min)
        score = max(0.0, min(1.0, score))
        print(f"  {label}: avg_lp={avg_lp:.3f}, score={score:.3f}", file=sys.stderr)


if __name__ == "__main__":
    main()
