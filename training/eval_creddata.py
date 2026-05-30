#!/usr/bin/env python3
"""
eval_creddata.py — CredData benchmark evaluation for Secret Squirrel.

Compares the output of Secret Squirrel and optionally Betterleaks against
the CredData ground-truth dataset, computing precision, recall, and F1.
It can also emit structured disagreement details so higher-level benchmark
drivers can explain which findings are shared or unique to each scanner.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple


class Finding(NamedTuple):
    file: str
    line: int
    kind: str


@dataclass(frozen=True)
class MatchPair:
    left: Finding
    right: Finding


@dataclass(frozen=True)
class MatchResult:
    matched_pairs: list[MatchPair]
    left_only: list[Finding]
    right_only: list[Finding]


CREDDATA_META_CANDIDATES = [
    "meta/cred_data_meta.json",
    "data/meta.json",
    "cred_data_meta.json",
]


def _norm_path(path: str) -> str:
    return Path(path).as_posix().lstrip("/")


def _normalise_file_path(file_path: str) -> str:
    normalized = _norm_path(file_path)
    normalized_lower = normalized.lower()

    # Scanner outputs may include absolute Windows/WSL paths while CredData
    # metadata is relative to the dataset root. Trim everything through the
    # dataset's data/ directory so both sides compare on the same path shape.
    markers = [
        "benchmark/creddata/data/",
        "creddata/data/",
        "./data/",
        "data/",
    ]

    for marker in markers:
        index = normalized_lower.find(marker)
        if index != -1:
            return normalized[index + len(marker) :]

    return normalized


def finding_to_dict(finding: Finding) -> dict[str, str | int]:
    return {
        "file": finding.file,
        "line": finding.line,
        "kind": finding.kind,
    }


def match_pair_to_dict(pair: MatchPair) -> dict[str, dict[str, str | int]]:
    return {
        "left": finding_to_dict(pair.left),
        "right": finding_to_dict(pair.right),
    }


def _sample_findings(findings: list[Finding], limit: int) -> list[dict[str, str | int]]:
    return [finding_to_dict(finding) for finding in findings[:limit]]


def _sample_pairs(pairs: list[MatchPair], limit: int) -> list[dict[str, dict[str, str | int]]]:
    return [match_pair_to_dict(pair) for pair in pairs[:limit]]


def _path_context(file_path: str) -> str:
    lower = file_path.lower()
    parts = [part for part in re.split(r"[\\/]+", lower) if part]
    if any(part in {"test", "tests", "testdata", "__tests__", "fixture", "fixtures"} for part in parts):
        return "test"
    if any(part in {"src", "lib", "pkg", "app", "cmd"} for part in parts):
        return "source"
    if any(part in {"config", "conf", "settings"} for part in parts):
        return "config"
    if any(part in {"docs", "doc"} for part in parts):
        return "docs"
    if any(part in {"example", "examples", "sample", "samples"} for part in parts):
        return "example"
    if any(part in {"ci", ".github", ".gitlab", ".circleci"} for part in parts):
        return "ci"
    return "other"


def _extension_bucket(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    if not suffix:
        return "<none>"
    return suffix


def _rule_family(kind: str) -> str:
    lower = kind.lower()
    if "private" in lower or "pem" in lower:
        return "private_key"
    if "jwt" in lower or "bearer" in lower:
        return "auth_token"
    if "url" in lower or "credential" in lower or "dsn" in lower:
        return "url_credentials"
    if "password" in lower or "passwd" in lower:
        return "password"
    if "api" in lower and "key" in lower:
        return "api_key"
    if "token" in lower or "secret" in lower or "oauth" in lower:
        return "token"
    if "nonce" in lower:
        return "nonce"
    return "other"


def _cluster_findings(findings: list[Finding], max_examples: int) -> dict:
    by_family = Counter()
    by_extension = Counter()
    by_context = Counter()
    combo_counts = Counter()
    combo_examples: dict[str, list[dict[str, str | int]]] = {}

    for finding in findings:
        family = _rule_family(finding.kind)
        extension = _extension_bucket(finding.file)
        context = _path_context(finding.file)
        by_family[family] += 1
        by_extension[extension] += 1
        by_context[context] += 1

        combo_key = f"{family} | {extension} | {context}"
        combo_counts[combo_key] += 1
        if len(combo_examples.setdefault(combo_key, [])) < max_examples:
            combo_examples[combo_key].append(finding_to_dict(finding))

    top_clusters = []
    for cluster, count in combo_counts.most_common(10):
        family, extension, context = cluster.split(" | ")
        top_clusters.append(
            {
                "family": family,
                "extension": extension,
                "path_context": context,
                "count": count,
                "examples": combo_examples.get(cluster, []),
            }
        )

    return {
        "by_family": dict(by_family.most_common()),
        "by_extension": dict(by_extension.most_common()),
        "by_path_context": dict(by_context.most_common()),
        "top_clusters": top_clusters,
    }


def load_creddata(creddata_dir: Path) -> list[Finding]:
    """Load CredData ground-truth findings."""
    meta_path: Path | None = None
    for candidate in CREDDATA_META_CANDIDATES:
        path = creddata_dir / candidate
        if path.exists():
            meta_path = path
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
                findings.append(
                    Finding(
                        file=_normalise_file_path(file_path),
                        line=line,
                        kind=str(kind).lower(),
                    )
                )
    else:
        meta_dir = creddata_dir / "meta"
        if meta_dir.exists() and meta_dir.is_dir():
            for csv_file in meta_dir.glob("*.csv"):
                with csv_file.open(encoding="utf-8", newline="") as fh:
                    reader = csv.DictReader(fh)
                    for row in reader:
                        if row.get("GroundTruth") != "T":
                            continue
                        file_path = row.get("FilePath", "")
                        line_str = row.get("LineStart", "0")
                        try:
                            line = int(line_str)
                        except ValueError:
                            line = 0
                        kind = row.get("Category", "unknown")
                        if file_path and line:
                            findings.append(
                                Finding(
                                    file=_normalise_file_path(file_path),
                                    line=line,
                                    kind=str(kind).lower(),
                                )
                            )

    if not findings:
        print(
            f"[eval] ERROR: Could not find CredData metadata in {creddata_dir}.\n"
            f"[eval] Tried: {', '.join(CREDDATA_META_CANDIDATES)} and meta/*.csv\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return findings


def _load_json_findings(json_file: Path) -> list[dict]:
    with json_file.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = raw.get("findings", [])
    if not isinstance(raw, list):
        raise ValueError(f"Expected a JSON array or object with 'findings' in {json_file}")
    return raw


def load_squirrel_stats(json_file: Path) -> dict:
    with json_file.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    if isinstance(raw, dict):
        stats = raw.get("stats")
        if isinstance(stats, dict):
            return stats
    return {}


def load_squirrel(json_file: Path) -> list[Finding]:
    """Normalise Secret Squirrel JSON output."""
    findings: list[Finding] = []
    for item in _load_json_findings(json_file):
        location = item.get("location", {})
        file_path = location.get("path") or item.get("file") or item.get("path") or ""
        line = int(location.get("start_line") or item.get("line") or item.get("line_number") or 0)
        kind = item.get("rule_id") or item.get("type") or item.get("kind") or "unknown"
        if file_path and line:
            findings.append(
                Finding(
                    file=_normalise_file_path(str(file_path)),
                    line=line,
                    kind=str(kind).lower(),
                )
            )
    return findings


def load_betterleaks(json_file: Path) -> list[Finding]:
    """Normalise Betterleaks JSON output."""
    findings: list[Finding] = []
    for item in _load_json_findings(json_file):
        file_path = (
            item.get("File")
            or item.get("file")
            or item.get("Path")
            or item.get("path")
            or item.get("Attributes", {}).get("path", "")
        )
        line = int(item.get("StartLine") or item.get("line") or item.get("Line") or 0)
        kind = item.get("RuleID") or item.get("rule_id") or item.get("Description") or "unknown"
        if file_path and line:
            findings.append(
                Finding(
                    file=_normalise_file_path(str(file_path)),
                    line=line,
                    kind=str(kind).lower(),
                )
            )
    return findings


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda finding: (finding.file, finding.line, finding.kind))


def match_details(
    left: list[Finding],
    right: list[Finding],
    line_tolerance: int = 1,
) -> MatchResult:
    """
    Deterministically match findings by file and line tolerance.

    The best match is the unused finding on the same file with the smallest
    line distance, then the earliest line, then lexicographic kind order.
    """
    right_sorted = _sort_findings(right)
    used_right: set[int] = set()
    matched_pairs: list[MatchPair] = []
    left_only: list[Finding] = []

    for left_finding in _sort_findings(left):
        candidate_indices = [
            index
            for index, right_finding in enumerate(right_sorted)
            if index not in used_right
            and right_finding.file == left_finding.file
            and abs(right_finding.line - left_finding.line) <= line_tolerance
        ]

        if not candidate_indices:
            left_only.append(left_finding)
            continue

        best_index = min(
            candidate_indices,
            key=lambda index: (
                abs(right_sorted[index].line - left_finding.line),
                right_sorted[index].line,
                right_sorted[index].kind,
            ),
        )
        used_right.add(best_index)
        matched_pairs.append(MatchPair(left=left_finding, right=right_sorted[best_index]))

    right_only = [
        right_finding
        for index, right_finding in enumerate(right_sorted)
        if index not in used_right
    ]

    return MatchResult(
        matched_pairs=matched_pairs,
        left_only=left_only,
        right_only=right_only,
    )


def match_findings(
    predicted: list[Finding],
    ground_truth: list[Finding],
    line_tolerance: int = 1,
) -> tuple[int, int, int]:
    result = match_details(predicted, ground_truth, line_tolerance=line_tolerance)
    return len(result.matched_pairs), len(result.left_only), len(result.right_only)


def prf1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def evaluate_predictions(
    predictions: list[Finding],
    ground_truth: list[Finding],
    line_tolerance: int = 1,
    max_examples: int = 25,
) -> tuple[dict, MatchResult]:
    details = match_details(predictions, ground_truth, line_tolerance=line_tolerance)
    tp = len(details.matched_pairs)
    fp = len(details.left_only)
    fn = len(details.right_only)
    precision, recall, f1 = prf1(tp, fp, fn)
    metrics = {
        "predictions": len(predictions),
        "ground_truth": len(ground_truth),
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "examples": {
            "true_positives": _sample_pairs(details.matched_pairs, max_examples),
            "false_positives": _sample_findings(details.left_only, max_examples),
            "false_negatives": _sample_findings(details.right_only, max_examples),
        },
        "clusters": {
            "false_positives": _cluster_findings(details.left_only, max_examples),
            "false_negatives": _cluster_findings(details.right_only, max_examples),
        },
    }
    return metrics, details


def compare_tool_outputs(
    left_name: str,
    left_findings: list[Finding],
    right_name: str,
    right_findings: list[Finding],
    line_tolerance: int = 1,
    max_examples: int = 25,
) -> dict:
    details = match_details(left_findings, right_findings, line_tolerance=line_tolerance)
    return {
        "left_tool": left_name,
        "right_tool": right_name,
        "shared_matches": len(details.matched_pairs),
        f"only_{left_name}": len(details.left_only),
        f"only_{right_name}": len(details.right_only),
        "examples": {
            "shared_matches": _sample_pairs(details.matched_pairs, max_examples),
            f"only_{left_name}": _sample_findings(details.left_only, max_examples),
            f"only_{right_name}": _sample_findings(details.right_only, max_examples),
        },
        "clusters": {
            f"only_{left_name}": _cluster_findings(details.left_only, max_examples),
            f"only_{right_name}": _cluster_findings(details.right_only, max_examples),
        },
    }


def compare_ground_truth_advantage(
    left_name: str,
    left_findings: list[Finding],
    right_name: str,
    right_findings: list[Finding],
    ground_truth: list[Finding],
    line_tolerance: int = 1,
    max_examples: int = 25,
) -> dict:
    left_vs_gt = match_details(left_findings, ground_truth, line_tolerance=line_tolerance)
    right_vs_gt = match_details(right_findings, ground_truth, line_tolerance=line_tolerance)

    left_tp = [pair.left for pair in left_vs_gt.matched_pairs]
    right_tp = [pair.left for pair in right_vs_gt.matched_pairs]
    advantage = match_details(right_tp, left_tp, line_tolerance=line_tolerance)

    return {
        "reference_ground_truth": True,
        "left_tool": left_name,
        "right_tool": right_name,
        f"{right_name}_tp_not_{left_name}": len(advantage.left_only),
        f"{left_name}_tp_not_{right_name}": len(advantage.right_only),
        "examples": {
            f"{right_name}_tp_not_{left_name}": _sample_findings(advantage.left_only, max_examples),
            f"{left_name}_tp_not_{right_name}": _sample_findings(advantage.right_only, max_examples),
        },
        "clusters": {
            f"{right_name}_tp_not_{left_name}": _cluster_findings(advantage.left_only, max_examples),
            f"{left_name}_tp_not_{right_name}": _cluster_findings(advantage.right_only, max_examples),
        },
    }


def build_report(
    ground_truth: list[Finding],
    squirrel_findings: list[Finding] | None,
    betterleaks_findings: list[Finding] | None,
    line_tolerance: int = 1,
    max_examples: int = 25,
) -> dict:
    report = {
        "parameters": {
            "line_tolerance": line_tolerance,
            "max_examples": max_examples,
        },
        "ground_truth": {
            "count": len(ground_truth),
        },
        "tools": {},
    }

    if squirrel_findings is not None:
        metrics, _ = evaluate_predictions(
            squirrel_findings,
            ground_truth,
            line_tolerance=line_tolerance,
            max_examples=max_examples,
        )
        report["tools"]["squirrel"] = metrics

    if betterleaks_findings is not None:
        metrics, _ = evaluate_predictions(
            betterleaks_findings,
            ground_truth,
            line_tolerance=line_tolerance,
            max_examples=max_examples,
        )
        report["tools"]["betterleaks"] = metrics

    if squirrel_findings is not None and betterleaks_findings is not None:
        report["tool_overlap"] = compare_tool_outputs(
            "squirrel",
            squirrel_findings,
            "betterleaks",
            betterleaks_findings,
            line_tolerance=line_tolerance,
            max_examples=max_examples,
        )
        report["ground_truth_advantage"] = compare_ground_truth_advantage(
            "squirrel",
            squirrel_findings,
            "betterleaks",
            betterleaks_findings,
            ground_truth,
            line_tolerance=line_tolerance,
            max_examples=max_examples,
        )

    return report


def _print_overlap_clusters(overlap: dict | None) -> None:
    if not overlap:
        return
    clusters = overlap.get("clusters", {}).get("only_betterleaks", {}).get("top_clusters", [])
    if not clusters:
        return
    print("Top Betterleaks-only clusters:")
    for cluster in clusters[:5]:
        print(
            f"  - {cluster['family']} | {cluster['extension']} | {cluster['path_context']}: {cluster['count']}"
        )
    print()


def _print_ground_truth_advantage(report: dict) -> None:
    advantage = report.get("ground_truth_advantage")
    if not advantage:
        return
    clusters = (
        advantage.get("clusters", {})
        .get("betterleaks_tp_not_squirrel", {})
        .get("top_clusters", [])
    )
    if not clusters:
        return
    print("Top GT-aligned Betterleaks wins over Secret-Squirrel:")
    for cluster in clusters[:5]:
        print(
            f"  - {cluster['family']} | {cluster['extension']} | {cluster['path_context']}: {cluster['count']}"
        )
    print()


def print_table(results: dict[str, dict]) -> None:
    col_w = 16
    header = f"{'Tool':<{col_w}} {'TP':>6} {'FP':>6} {'FN':>6}  {'Prec':>7} {'Recall':>7} {'F1':>7}"
    print()
    print(header)
    print("-" * len(header))
    for tool, metrics in results.items():
        print(
            f"{tool:<{col_w}} {metrics['TP']:>6} {metrics['FP']:>6} {metrics['FN']:>6}  "
            f"{metrics['precision']:>7.4f} {metrics['recall']:>7.4f} {metrics['f1']:>7.4f}"
        )
    print()


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
        help="Save the compact metrics summary to this JSON file.",
    )
    parser.add_argument(
        "--save-details",
        metavar="JSON",
        type=Path,
        default=None,
        help="Save detailed metrics, examples, and tool overlap to this JSON file.",
    )
    parser.add_argument(
        "--tolerance",
        metavar="N",
        type=int,
        default=1,
        help="Line-number tolerance for a match.",
    )
    parser.add_argument(
        "--max-examples",
        metavar="N",
        type=int,
        default=25,
        help="Maximum example findings to retain per category in detailed output.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.squirrel and not args.betterleaks:
        print("[eval] ERROR: Provide at least one of --squirrel or --betterleaks.", file=sys.stderr)
        sys.exit(1)

    print(f"[eval] Loading CredData ground truth from {args.creddata} ...")
    ground_truth = load_creddata(args.creddata)
    print(f"[eval] Ground-truth findings: {len(ground_truth)}")

    squirrel_findings: list[Finding] | None = None
    betterleaks_findings: list[Finding] | None = None

    if args.squirrel:
        if not args.squirrel.exists():
            print(f"[eval] ERROR: {args.squirrel} not found.", file=sys.stderr)
            sys.exit(1)
        squirrel_findings = load_squirrel(args.squirrel)
        print(f"[eval] Evaluating squirrel: {len(squirrel_findings)} predictions ...")

    if args.betterleaks:
        if not args.betterleaks.exists():
            print(f"[eval] ERROR: {args.betterleaks} not found.", file=sys.stderr)
            sys.exit(1)
        betterleaks_findings = load_betterleaks(args.betterleaks)
        print(f"[eval] Evaluating betterleaks: {len(betterleaks_findings)} predictions ...")

    report = build_report(
        ground_truth,
        squirrel_findings,
        betterleaks_findings,
        line_tolerance=args.tolerance,
        max_examples=args.max_examples,
    )
    results = report["tools"]
    print_table(results)
    _print_overlap_clusters(report.get("tool_overlap"))
    _print_ground_truth_advantage(report)

    if args.save:
        compact = {
            tool_name: {
                key: value
                for key, value in metrics.items()
                if key != "examples"
            }
            for tool_name, metrics in results.items()
        }
        with args.save.open("w", encoding="utf-8") as fh:
            json.dump(compact, fh, indent=2)
        print(f"[eval] Results saved to {args.save}")

    if args.save_details:
        with args.save_details.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[eval] Detailed results saved to {args.save_details}")


if __name__ == "__main__":
    main()
