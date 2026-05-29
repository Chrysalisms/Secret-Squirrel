#!/usr/bin/env python3
"""
eval_creddata.py — CredData benchmark evaluation for Secret Squirrel.

Compares the output of Secret Squirrel and optionally Betterleaks against
the CredData ground-truth dataset, computing precision, recall, and F1.

Usage
-----
python training/eval_creddata.py \
    --squirrel results/squirrel_output.json \
    [--betterleaks results/betterleaks_output.json] \
    [--creddata ./CredData] \
    [--save benchmark_comparison.json]

CredData ground-truth format
----------------------------
CredData/meta/cred_data_meta.json (or CredData/data/meta.json) is expected
to contain a list of findings like:

  [
    {
      "FilePath": "data/00001.py",
      "LineStart": 10,
      "CredType": "AWS"
    },
    ...
  ]

Tool output format (JSON)
--------------------------
Squirrel produces findings with at minimum:
  { "file": "...", "line": 10, "rule_id": "..." }

Betterleaks produces findings with at minimum:
  { "File": "...", "StartLine": 10, "RuleID": "..." }

Both formats are normalised to (file, line, type) tuples before comparison.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Finding(NamedTuple):
    file: str       # normalised relative path
    line: int       # 1-based line number
    kind: str       # credential type / rule id (normalised to lower-case)


# ---------------------------------------------------------------------------
# Ground-truth loaders
# ---------------------------------------------------------------------------

CREDDATA_META_CANDIDATES = [
    "meta/cred_data_meta.json",
    "data/meta.json",
    "cred_data_meta.json",
]


def load_creddata(creddata_dir: Path) -> list[Finding]:
    """Load CredData ground-truth findings."""
    meta_path: Path | None = None
    for candidate in CREDDATA_META_CANDIDATES:
        p = creddata_dir / candidate
        if p.exists():
            meta_path = p
            break

    findings: list[Finding] = []
    
    if meta_path is not None:
        with meta_path.open(encoding="utf-8") as fh:
            raw = json.load(fh)
        for item in raw:
            file_path = item.get("FilePath") or item.get("file_path") or item.get("file") or ""
            line = int(item.get("LineStart") or item.get("line_start") or item.get("line") or 0)
            kind = item.get("CredType") or item.get("cred_type") or item.get("type") or "unknown"
            if file_path and line:
                findings.append(Finding(file=_norm_path(file_path), line=line, kind=kind.lower()))
    else:
        # Load from meta/*.csv
        meta_dir = creddata_dir / "meta"
        if meta_dir.exists() and meta_dir.is_dir():
            import csv
            for csv_file in meta_dir.glob("*.csv"):
                with csv_file.open(encoding="utf-8", newline='') as fh:
                    reader = csv.DictReader(fh)
                    for row in reader:
                        if row.get("GroundTruth") != "T":
                            continue # Only count true positives
                        file_path = row.get("FilePath", "")
                        if file_path.startswith("data/"):
                            file_path = file_path[5:] # Remove "data/" prefix to match findings which have relative paths from data dir
                        line_str = row.get("LineStart", "0")
                        try:
                            line = int(line_str)
                        except ValueError:
                            line = 0
                        kind = row.get("Category", "unknown")
                        if file_path and line:
                            findings.append(Finding(file=_norm_path(file_path), line=line, kind=kind.lower()))

    if not findings:
        print(
            f"[eval] ERROR: Could not find CredData metadata in {creddata_dir}.\n"
            f"[eval] Tried: {', '.join(CREDDATA_META_CANDIDATES)} and meta/*.csv\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return findings


# ---------------------------------------------------------------------------
# Tool-output loaders
# ---------------------------------------------------------------------------

def load_squirrel(json_file: Path) -> list[Finding]:
    """Normalise Secret Squirrel JSON output."""
    with json_file.open(encoding="utf-8") as fh:
        raw = json.load(fh)

    # Squirrel may output {"findings": [...]} or directly [...]
    if isinstance(raw, dict):
        raw = raw.get("findings", [])

    findings: list[Finding] = []
    for item in raw:
        location = item.get("location", {})
        file_path = location.get("path") or item.get("file") or item.get("path") or ""
        if file_path.startswith("benchmark/CredData/data/"):
            file_path = file_path[len("benchmark/CredData/data/"):]
        elif file_path.startswith("data/"):
            file_path = file_path[5:]
        line = int(location.get("start_line") or item.get("line") or item.get("line_number") or 0)
        kind = (
            item.get("rule_id")
            or item.get("type")
            or item.get("kind")
            or "unknown"
        )
        if file_path and line:
            findings.append(Finding(
                file=_norm_path(file_path),
                line=line,
                kind=kind.lower(),
            ))
    return findings


def load_betterleaks(json_file: Path) -> list[Finding]:
    """Normalise Betterleaks JSON output."""
    with json_file.open(encoding="utf-8") as fh:
        raw = json.load(fh)

    # Betterleaks may output {"findings": [...]} or directly [...]
    if isinstance(raw, dict):
        raw = raw.get("findings", [])

    findings: list[Finding] = []
    for item in raw:
        file_path = item.get("File") or item.get("file") or ""
        line = int(item.get("StartLine") or item.get("line") or 0)
        kind = (
            item.get("RuleID")
            or item.get("rule_id")
            or item.get("Description")
            or "unknown"
        )
        if file_path and line:
            findings.append(Finding(
                file=_norm_path(file_path),
                line=line,
                kind=kind.lower(),
            ))
    return findings


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

def _norm_path(p: str) -> str:
    """Normalise a file path for cross-platform comparison."""
    return Path(p).as_posix().lstrip("/")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def match_findings(
    predicted: list[Finding],
    ground_truth: list[Finding],
    line_tolerance: int = 1,
) -> tuple[int, int, int]:
    """
    Compute TP, FP, FN.

    A predicted finding matches a ground-truth finding when:
      - The file paths are equal (after normalisation), AND
      - The line numbers are within `line_tolerance` of each other.

    Credential type is NOT required to match because different tools use
    different taxonomies.

    Returns (TP, FP, FN).
    """
    gt_set = set(ground_truth)
    matched_gt: set[Finding] = set()

    tp = 0
    fp = 0

    for pred in predicted:
        hit = False
        for gt in gt_set:
            if gt in matched_gt:
                continue
            if gt.file == pred.file and abs(gt.line - pred.line) <= line_tolerance:
                tp += 1
                matched_gt.add(gt)
                hit = True
                break
        if not hit:
            fp += 1

    fn = len(gt_set) - len(matched_gt)
    return tp, fp, fn


def prf1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_table(results: dict[str, dict]) -> None:
    col_w = 16
    header = f"{'Tool':<{col_w}} {'TP':>6} {'FP':>6} {'FN':>6}  {'Prec':>7} {'Recall':>7} {'F1':>7}"
    print()
    print(header)
    print("-" * len(header))
    for tool, m in results.items():
        print(
            f"{tool:<{col_w}} {m['TP']:>6} {m['FP']:>6} {m['FN']:>6}  "
            f"{m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}"
        )
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate credential-scanner output against CredData ground truth.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--squirrel",
        metavar="JSON",
        type=Path,
        help="Path to Secret Squirrel JSON output file.",
    )
    parser.add_argument(
        "--betterleaks",
        metavar="JSON",
        type=Path,
        help="Path to Betterleaks JSON output file.",
    )
    parser.add_argument(
        "--creddata",
        metavar="DIR",
        type=Path,
        default=Path("./CredData"),
        help="Path to the CredData repository root.",
    )
    parser.add_argument(
        "--save",
        metavar="JSON",
        type=Path,
        default=None,
        help="Save comparison results to this JSON file.",
    )
    parser.add_argument(
        "--tolerance",
        metavar="N",
        type=int,
        default=1,
        help="Line-number tolerance for a match (default: 1).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.squirrel and not args.betterleaks:
        print("[eval] ERROR: Provide at least one of --squirrel or --betterleaks.", file=sys.stderr)
        sys.exit(1)

    # Load ground truth.
    print(f"[eval] Loading CredData ground truth from {args.creddata} ...")
    gt = load_creddata(args.creddata)
    print(f"[eval] Ground-truth findings: {len(gt)}")

    results: dict[str, dict] = {}

    def _evaluate(name: str, predictions: list[Finding]) -> None:
        print(f"[eval] Evaluating {name}: {len(predictions)} predictions ...")
        tp, fp, fn = match_findings(predictions, gt, line_tolerance=args.tolerance)
        p, r, f1 = prf1(tp, fp, fn)
        results[name] = {
            "predictions": len(predictions),
            "ground_truth": len(gt),
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "precision": round(p, 6),
            "recall": round(r, 6),
            "f1": round(f1, 6),
        }

    if args.squirrel:
        if not args.squirrel.exists():
            print(f"[eval] ERROR: {args.squirrel} not found.", file=sys.stderr)
            sys.exit(1)
        _evaluate("squirrel", load_squirrel(args.squirrel))

    if args.betterleaks:
        if not args.betterleaks.exists():
            print(f"[eval] ERROR: {args.betterleaks} not found.", file=sys.stderr)
            sys.exit(1)
        _evaluate("betterleaks", load_betterleaks(args.betterleaks))

    print_table(results)

    if args.save:
        with args.save.open("w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"[eval] Results saved to {args.save}")


if __name__ == "__main__":
    main()
