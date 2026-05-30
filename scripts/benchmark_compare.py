#!/usr/bin/env python3
"""
Cross-platform benchmark runner for Secret-Squirrel vs Betterleaks.

This driver keeps benchmark execution separate from fuzzing so accuracy and
throughput comparisons are easier to rerun and inspect.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]


DEFAULT_RESULTS_ROOT = Path("artifacts") / "benchmarks"
DEFAULT_CRED_DATA_URL = "https://github.com/Samsung/CredData.git"
DEFAULT_SQUIRREL_FEATURES = "cli,cpu-simd"
DEFAULT_SQUIRREL_SEVERITY = "low"
DEFAULT_SQUIRREL_CONFIDENCE = 0.5
DEFAULT_SQUIRREL_PROFILE = "fast"
DEFAULT_SQUIRREL_FAIL_ON = "critical"
DEFAULT_LINE_TOLERANCE = 1
DEFAULT_MAX_EXAMPLES = 25
DEFAULT_CORPUS_MANIFEST = Path("docs") / "benchmark_repo_corpus.toml"


@dataclass
class CommandResult:
    command: list[str]
    cwd: str
    exit_code: int
    elapsed_ms: int
    stdout_log: str
    stderr_log: str


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_eval_module():
    eval_path = repo_root() / "training" / "eval_creddata.py"
    spec = importlib.util.spec_from_file_location("benchmark_eval_creddata", eval_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to import evaluator from {eval_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def default_squirrel_binary() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    cargo_target_dir = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target_dir:
        return Path(cargo_target_dir) / "release" / f"squirrel{suffix}"
    return repo_root() / "target" / "release" / f"squirrel{suffix}"


def run_command(
    command: list[str],
    cwd: Path,
    log_prefix: Path,
    allowed_exit_codes: set[int] | None = None,
) -> CommandResult:
    allowed = allowed_exit_codes or {0}
    start = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    stdout_log = log_prefix.with_suffix(".stdout.log")
    stderr_log = log_prefix.with_suffix(".stderr.log")
    stdout_log.write_text(completed.stdout, encoding="utf-8")
    stderr_log.write_text(completed.stderr, encoding="utf-8")

    if completed.returncode not in allowed:
        raise RuntimeError(
            f"Command failed with exit code {completed.returncode}: {' '.join(command)}\n"
            f"stdout: {stdout_log}\n"
            f"stderr: {stderr_log}"
        )

    return CommandResult(
        command=command,
        cwd=str(cwd),
        exit_code=completed.returncode,
        elapsed_ms=elapsed_ms,
        stdout_log=str(stdout_log),
        stderr_log=str(stderr_log),
    )


def probe_version(binary: str | Path, version_args: list[str], cwd: Path, log_prefix: Path) -> dict:
    command = [str(binary), *version_args]
    try:
        result = run_command(command, cwd, log_prefix, allowed_exit_codes={0})
        stdout_text = Path(result.stdout_log).read_text(encoding="utf-8").strip()
        stderr_text = Path(result.stderr_log).read_text(encoding="utf-8").strip()
        version_text = stdout_text or stderr_text or "unknown"
        return {
            "command": command,
            "version": version_text.splitlines()[0] if version_text else "unknown",
            "stdout_log": result.stdout_log,
            "stderr_log": result.stderr_log,
        }
    except Exception as exc:  # pragma: no cover - version probing is best effort
        return {
            "command": command,
            "version": f"unavailable ({exc})",
        }


def write_json(path: Path, data: dict | list) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_markdown(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def ensure_creddata(
    creddata_dir: Path,
    clone_if_missing: bool,
    work_dir: Path,
    logs_dir: Path,
) -> Path:
    if creddata_dir.exists():
        return creddata_dir
    if not clone_if_missing:
        raise FileNotFoundError(
            f"CredData not found at {creddata_dir}. Pass --clone-creddata to fetch it."
        )
    ensure_directory(creddata_dir.parent)
    run_command(
        ["git", "clone", "--depth=1", DEFAULT_CRED_DATA_URL, str(creddata_dir)],
        cwd=work_dir,
        log_prefix=logs_dir / "clone_creddata",
    )
    return creddata_dir


def build_squirrel(
    binary: Path,
    features: str,
    work_dir: Path,
    no_default_features: bool,
    logs_dir: Path,
) -> None:
    command = ["cargo", "build", "--release", "--bin", "squirrel"]
    if no_default_features:
        command.append("--no-default-features")
    if features:
        command.extend(["--features", features])
    run_command(
        command,
        cwd=work_dir,
        log_prefix=logs_dir / "cargo_build_squirrel",
    )
    if not binary.exists():
        raise FileNotFoundError(f"Squirrel binary was not produced at {binary}")


def ensure_creddata_dataset(creddata_dir: Path, logs_dir: Path) -> Path:
    scan_root = creddata_dir / "data"
    if scan_root.exists():
        return scan_root

    run_command(
        [sys.executable, "download_data.py", "--data_dir", "data"],
        cwd=creddata_dir,
        log_prefix=logs_dir / "creddata_generate_dataset",
    )

    if not scan_root.exists():
        raise FileNotFoundError(
            f"CredData data directory does not exist after generation: {scan_root}"
        )
    return scan_root


def squirrel_scan_command(
    binary: Path,
    target_path: Path,
    output_path: Path,
    severity: str,
    confidence: float,
    profile: str,
    fail_on: str,
) -> list[str]:
    return [
        str(binary),
        "detect",
        str(target_path),
        "--severity",
        severity,
        "--confidence",
        str(confidence),
        "--profile",
        profile,
        "--fail-on",
        fail_on,
        "--format",
        "json",
        "--output",
        str(output_path),
    ]


def betterleaks_scan_command(
    binary: str | Path,
    target_path: Path,
    output_path: Path,
) -> list[str]:
    return [
        str(binary),
        "dir",
        str(target_path),
        "-f",
        "json",
        "-r",
        str(output_path),
        "--exit-code",
        "0",
    ]


def write_creddata_summary(
    path: Path,
    report: dict,
    run_metadata: dict,
    config: dict,
) -> None:
    tools = report["tools"]
    overlap = report.get("tool_overlap")

    lines = [
        "# CredData Benchmark Summary",
        "",
        "## Configuration",
        "",
        f"- `Secret-Squirrel` build: `{config['squirrel_build']}`",
        f"- `Secret-Squirrel` detect flags: `{config['squirrel_detect']}`",
        f"- `Betterleaks` detect flags: `{config['betterleaks_detect']}`",
        f"- Line tolerance: `{report['parameters']['line_tolerance']}`",
        "",
        "## Accuracy",
        "",
        "| Tool | Predictions | TP | FP | FN | Precision | Recall | F1 | Runtime (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for tool_name in ("squirrel", "betterleaks"):
        if tool_name not in tools:
            continue
        metrics = tools[tool_name]
        runtime_ms = run_metadata["scans"][tool_name]["elapsed_ms"]
        lines.append(
            f"| {tool_name} | {metrics['predictions']} | {metrics['TP']} | {metrics['FP']} | "
            f"{metrics['FN']} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
            f"{metrics['f1']:.4f} | {runtime_ms} |"
        )

    if overlap:
        lines.extend(
            [
                "",
                "## Tool Overlap",
                "",
                f"- Shared matches: `{overlap['shared_matches']}`",
                f"- Only `Secret-Squirrel`: `{overlap['only_squirrel']}`",
                f"- Only `Betterleaks`: `{overlap['only_betterleaks']}`",
            ]
        )
        betterleaks_only_clusters = (
            overlap.get("clusters", {})
            .get("only_betterleaks", {})
            .get("top_clusters", [])
        )
        if betterleaks_only_clusters:
            lines.extend(
                [
                    "",
                    "## Betterleaks-only Clusters",
                    "",
                    "| Family | Extension | Path Context | Count |",
                    "| --- | --- | --- | ---: |",
                ]
            )
            for cluster in betterleaks_only_clusters[:5]:
                lines.append(
                    f"| {cluster['family']} | {cluster['extension']} | {cluster['path_context']} | {cluster['count']} |"
                )

    gt_advantage = report.get("ground_truth_advantage")
    if gt_advantage:
        betterleaks_gt_clusters = (
            gt_advantage.get("clusters", {})
            .get("betterleaks_tp_not_squirrel", {})
            .get("top_clusters", [])
        )
        lines.extend(
            [
                "",
                "## Ground-truth Betterleaks Advantage",
                "",
                f"- Betterleaks true positives missed by `Secret-Squirrel`: `{gt_advantage['betterleaks_tp_not_squirrel']}`",
                f"- `Secret-Squirrel` true positives missed by Betterleaks: `{gt_advantage['squirrel_tp_not_betterleaks']}`",
            ]
        )
        if betterleaks_gt_clusters:
            lines.extend(
                [
                    "",
                    "| Family | Extension | Path Context | Count |",
                    "| --- | --- | --- | ---: |",
                ]
            )
            for cluster in betterleaks_gt_clusters[:5]:
                lines.append(
                    f"| {cluster['family']} | {cluster['extension']} | {cluster['path_context']} | {cluster['count']} |"
                )

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Summary JSON: `{run_metadata['artifacts']['summary_json']}`",
            f"- Detailed JSON: `{run_metadata['artifacts']['details_json']}`",
            f"- Raw `Secret-Squirrel` findings: `{run_metadata['artifacts']['squirrel_json']}`",
            f"- Raw `Betterleaks` findings: `{run_metadata['artifacts']['betterleaks_json']}`",
        ]
    )

    write_markdown(path, "\n".join(lines))


def run_creddata(args: argparse.Namespace) -> None:
    work_dir = repo_root()
    eval_module = load_eval_module()

    results_dir = ensure_directory((args.results_dir / "creddata" / timestamp()).resolve())
    logs_dir = ensure_directory(results_dir / "logs")
    creddata_dir = ensure_creddata(args.creddata_dir, args.clone_creddata, work_dir, logs_dir)

    squirrel_binary = args.squirrel_binary
    if not args.skip_build:
        build_squirrel(
            squirrel_binary,
            args.squirrel_features,
            work_dir,
            no_default_features=not args.use_default_features,
            logs_dir=logs_dir,
        )

    scan_root = ensure_creddata_dataset(creddata_dir, logs_dir)

    squirrel_output = (results_dir / "squirrel_creddata.json").resolve()
    betterleaks_output = (results_dir / "betterleaks_creddata.json").resolve()
    summary_json = (results_dir / "benchmark_summary.json").resolve()
    details_json = (results_dir / "benchmark_details.json").resolve()
    summary_md = (results_dir / "benchmark_summary.md").resolve()

    squirrel_scan = run_command(
        squirrel_scan_command(
            squirrel_binary,
            scan_root,
            squirrel_output,
            severity=args.squirrel_severity,
            confidence=args.squirrel_confidence,
            profile=args.squirrel_profile,
            fail_on=args.squirrel_fail_on,
        ),
        cwd=creddata_dir,
        log_prefix=logs_dir / "squirrel_creddata",
        allowed_exit_codes={0, 1},
    )
    if not squirrel_output.exists():
        raise FileNotFoundError(f"Secret-Squirrel scan did not create {squirrel_output}")

    betterleaks_scan = run_command(
        betterleaks_scan_command(args.betterleaks_binary, scan_root, betterleaks_output),
        cwd=creddata_dir,
        log_prefix=logs_dir / "betterleaks_creddata",
        allowed_exit_codes={0, 1},
    )
    if not betterleaks_output.exists():
        raise FileNotFoundError(f"Betterleaks scan did not create {betterleaks_output}")

    ground_truth = eval_module.load_creddata(creddata_dir)
    squirrel_findings = eval_module.load_squirrel(squirrel_output)
    squirrel_stats = eval_module.load_squirrel_stats(squirrel_output)
    betterleaks_findings = eval_module.load_betterleaks(betterleaks_output)
    report = eval_module.build_report(
        ground_truth,
        squirrel_findings,
        betterleaks_findings,
        line_tolerance=args.line_tolerance,
        max_examples=args.max_examples,
    )

    compact = {
        tool_name: {
            key: value
            for key, value in metrics.items()
            if key != "examples"
        }
        for tool_name, metrics in report["tools"].items()
    }
    write_json(summary_json, compact)
    write_json(details_json, report)

    run_metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "creddata_dir": str(creddata_dir),
        "scan_root": str(scan_root),
        "versions": {
            "squirrel": probe_version(squirrel_binary, ["--version"], work_dir, logs_dir / "squirrel_version"),
            "betterleaks": probe_version(
                args.betterleaks_binary,
                ["--version"],
                work_dir,
                logs_dir / "betterleaks_version",
            ),
        },
        "build": {
            "skip_build": args.skip_build,
            "squirrel_binary": str(squirrel_binary),
            "no_default_features": not args.use_default_features,
            "features": args.squirrel_features,
        },
        "scans": {
            "squirrel": squirrel_scan.__dict__,
            "betterleaks": betterleaks_scan.__dict__,
        },
        "pipeline_stats": {
            "squirrel": squirrel_stats,
        },
        "artifacts": {
            "summary_json": str(summary_json),
            "details_json": str(details_json),
            "summary_md": str(summary_md),
            "squirrel_json": str(squirrel_output),
            "betterleaks_json": str(betterleaks_output),
        },
    }
    write_json(results_dir / "run_metadata.json", run_metadata)

    config = {
        "squirrel_build": "cargo build --release --bin squirrel --no-default-features --features cli,cpu-simd"
        if not args.use_default_features
        else f"cargo build --release --bin squirrel --features {args.squirrel_features}",
        "squirrel_detect": " ".join(
            squirrel_scan_command(
                squirrel_binary,
                Path("<scan_root>"),
                Path("<output_json>"),
                severity=args.squirrel_severity,
                confidence=args.squirrel_confidence,
                profile=args.squirrel_profile,
                fail_on=args.squirrel_fail_on,
            )[1:]
        ),
        "betterleaks_detect": " ".join(
            betterleaks_scan_command(args.betterleaks_binary, Path("<scan_root>"), Path("<output_json>"))
        ),
    }
    write_creddata_summary(summary_md, report, run_metadata, config)

    print(f"[benchmark] CredData benchmark complete: {results_dir}")


def load_corpus_manifest(path: Path) -> dict:
    if tomllib is None:
        raise RuntimeError("Python 3.11+ is required to read the TOML corpus manifest.")
    with path.open("rb") as fh:
        return tomllib.load(fh)


def ensure_repo_checkout(
    repo_entry: dict,
    checkout_root: Path,
    clone_missing: bool,
    logs_dir: Path,
) -> Path:
    repo_path = checkout_root / repo_entry["id"]
    if repo_path.exists():
        return repo_path
    if not clone_missing:
        raise FileNotFoundError(
            f"Repo checkout missing for {repo_entry['id']} at {repo_path}. "
            "Populate the checkout root or rerun with --clone-missing."
        )
    ensure_directory(checkout_root)
    run_command(
        ["git", "clone", repo_entry["repo_url"], str(repo_path)],
        cwd=repo_root(),
        log_prefix=logs_dir / f"clone_{repo_entry['id']}",
    )
    run_command(
        ["git", "checkout", repo_entry["ref"]],
        cwd=repo_path,
        log_prefix=logs_dir / f"checkout_{repo_entry['id']}",
    )
    return repo_path


def write_repo_summary(path: Path, repo_entry: dict, overlap: dict, run_metadata: dict) -> None:
    lines = [
        f"# Repo Benchmark Summary: {repo_entry['name']}",
        "",
        f"- Repo URL: `{repo_entry['repo_url']}`",
        f"- Ref: `{repo_entry['ref']}`",
        f"- Scan path: `{repo_entry['scan_path']}`",
        "",
        "## Overlap",
        "",
        f"- Shared matches: `{overlap['shared_matches']}`",
        f"- Only `Secret-Squirrel`: `{overlap['only_squirrel']}`",
        f"- Only `Betterleaks`: `{overlap['only_betterleaks']}`",
        "",
        "## Runtime",
        "",
        f"- `Secret-Squirrel`: `{run_metadata['scans']['squirrel']['elapsed_ms']}` ms",
        f"- `Betterleaks`: `{run_metadata['scans']['betterleaks']['elapsed_ms']}` ms",
    ]
    write_markdown(path, "\n".join(lines))


def write_corpus_summary(path: Path, manifest: dict, aggregate: dict, results_dir: Path) -> None:
    lines = [
        f"# Repository Tree Benchmark Summary",
        "",
        f"- Corpus: `{manifest['corpus']['name']}`",
        f"- Description: {manifest['corpus']['description']}",
        "",
        "| Repo | Shared | Only Squirrel | Only Betterleaks | Squirrel ms | Betterleaks ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for repo_result in aggregate["repos"]:
        lines.append(
            f"| {repo_result['name']} | {repo_result['overlap']['shared_matches']} | "
            f"{repo_result['overlap']['only_squirrel']} | {repo_result['overlap']['only_betterleaks']} | "
            f"{repo_result['runtime_ms']['squirrel']} | {repo_result['runtime_ms']['betterleaks']} |"
        )
    lines.extend(
        [
            "",
            "## Outputs",
            "",
            f"- Aggregate JSON: `{results_dir / 'corpus_summary.json'}`",
            f"- Repo summaries: `{results_dir}`",
        ]
    )
    write_markdown(path, "\n".join(lines))


def run_corpus(args: argparse.Namespace) -> None:
    work_dir = repo_root()
    eval_module = load_eval_module()
    manifest = load_corpus_manifest(args.manifest)

    results_dir = ensure_directory((args.results_dir / "corpus" / timestamp()).resolve())
    logs_dir = ensure_directory(results_dir / "logs")

    squirrel_binary = args.squirrel_binary
    if not args.skip_build:
        build_squirrel(
            squirrel_binary,
            args.squirrel_features,
            work_dir,
            no_default_features=not args.use_default_features,
            logs_dir=logs_dir,
        )

    aggregate = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "manifest": str(args.manifest),
        "repos": [],
    }

    for repo_entry in manifest.get("repos", []):
        repo_dir = ensure_repo_checkout(repo_entry, args.checkout_root, args.clone_missing, logs_dir)
        scan_path = repo_dir / repo_entry.get("scan_path", ".")
        repo_results_dir = ensure_directory((results_dir / repo_entry["id"]).resolve())
        repo_logs_dir = ensure_directory(repo_results_dir / "logs")

        squirrel_output = (repo_results_dir / "squirrel.json").resolve()
        betterleaks_output = (repo_results_dir / "betterleaks.json").resolve()

        squirrel_scan = run_command(
            squirrel_scan_command(
                squirrel_binary,
                scan_path,
                squirrel_output,
                severity=args.squirrel_severity,
                confidence=args.squirrel_confidence,
                profile=args.squirrel_profile,
                fail_on=args.squirrel_fail_on,
            ),
            cwd=repo_dir,
            log_prefix=repo_logs_dir / "squirrel",
            allowed_exit_codes={0, 1},
        )
        betterleaks_scan = run_command(
            betterleaks_scan_command(args.betterleaks_binary, scan_path, betterleaks_output),
            cwd=repo_dir,
            log_prefix=repo_logs_dir / "betterleaks",
            allowed_exit_codes={0, 1},
        )

        squirrel_findings = eval_module.load_squirrel(squirrel_output)
        squirrel_stats = eval_module.load_squirrel_stats(squirrel_output)
        betterleaks_findings = eval_module.load_betterleaks(betterleaks_output)
        overlap = eval_module.compare_tool_outputs(
            "squirrel",
            squirrel_findings,
            "betterleaks",
            betterleaks_findings,
            line_tolerance=args.line_tolerance,
            max_examples=args.max_examples,
        )

        overlap_path = (repo_results_dir / "overlap.json").resolve()
        summary_path = (repo_results_dir / "summary.md").resolve()
        metadata_path = (repo_results_dir / "run_metadata.json").resolve()

        run_metadata = {
            "repo_id": repo_entry["id"],
            "repo_path": str(repo_dir),
            "scan_path": str(scan_path),
            "scans": {
                "squirrel": squirrel_scan.__dict__,
                "betterleaks": betterleaks_scan.__dict__,
            },
            "pipeline_stats": {
                "squirrel": squirrel_stats,
            },
        }
        write_json(overlap_path, overlap)
        write_json(metadata_path, run_metadata)
        write_repo_summary(summary_path, repo_entry, overlap, run_metadata)

        aggregate["repos"].append(
            {
                "id": repo_entry["id"],
                "name": repo_entry["name"],
                "repo_url": repo_entry["repo_url"],
                "ref": repo_entry["ref"],
                "scan_path": repo_entry.get("scan_path", "."),
                "overlap": {
                    "shared_matches": overlap["shared_matches"],
                    "only_squirrel": overlap["only_squirrel"],
                    "only_betterleaks": overlap["only_betterleaks"],
                },
                "runtime_ms": {
                    "squirrel": squirrel_scan.elapsed_ms,
                    "betterleaks": betterleaks_scan.elapsed_ms,
                },
                "pipeline_stats": {
                    "squirrel": squirrel_stats,
                },
                "artifacts": {
                    "squirrel_json": str(squirrel_output),
                    "betterleaks_json": str(betterleaks_output),
                    "overlap_json": str(overlap_path),
                    "summary_md": str(summary_path),
                },
            }
        )

    write_json((results_dir / "corpus_summary.json").resolve(), aggregate)
    write_corpus_summary((results_dir / "corpus_summary.md").resolve(), manifest, aggregate, results_dir)
    print(f"[benchmark] Repository-tree benchmark complete: {results_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark Secret-Squirrel against Betterleaks on shared datasets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_ROOT,
        help="Root directory for benchmark artifacts.",
    )
    parser.add_argument(
        "--squirrel-binary",
        type=Path,
        default=default_squirrel_binary(),
        help="Path to the Secret-Squirrel binary.",
    )
    parser.add_argument(
        "--betterleaks-binary",
        default=shutil.which("betterleaks") or "betterleaks",
        help="Betterleaks binary or command name.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip rebuilding Secret-Squirrel before scanning.",
    )
    parser.add_argument(
        "--use-default-features",
        action="store_true",
        help="Build Secret-Squirrel with its default features instead of the pinned CPU benchmark build.",
    )
    parser.add_argument(
        "--squirrel-features",
        default=DEFAULT_SQUIRREL_FEATURES,
        help="Comma-separated feature list for Secret-Squirrel builds.",
    )
    parser.add_argument(
        "--squirrel-severity",
        default=DEFAULT_SQUIRREL_SEVERITY,
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity reported by Secret-Squirrel during benchmark scans.",
    )
    parser.add_argument(
        "--squirrel-confidence",
        type=float,
        default=DEFAULT_SQUIRREL_CONFIDENCE,
        help="Confidence threshold for Secret-Squirrel benchmark scans.",
    )
    parser.add_argument(
        "--squirrel-profile",
        default=DEFAULT_SQUIRREL_PROFILE,
        choices=["fast", "deep"],
        help="Execution profile for Secret-Squirrel benchmark scans.",
    )
    parser.add_argument(
        "--squirrel-fail-on",
        default=DEFAULT_SQUIRREL_FAIL_ON,
        choices=["low", "medium", "high", "critical"],
        help="Severity level that triggers Secret-Squirrel exit code 1.",
    )
    parser.add_argument(
        "--line-tolerance",
        type=int,
        default=DEFAULT_LINE_TOLERANCE,
        help="Line-distance tolerance when matching findings.",
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=DEFAULT_MAX_EXAMPLES,
        help="Maximum example findings saved per category.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    creddata = subparsers.add_parser(
        "creddata",
        help="Run the labeled accuracy benchmark against Samsung/CredData.",
    )
    creddata.add_argument(
        "--creddata-dir",
        type=Path,
        default=repo_root() / "benchmark" / "CredData",
        help="Path to the CredData checkout.",
    )
    creddata.add_argument(
        "--clone-creddata",
        action="store_true",
        help="Clone CredData into --creddata-dir when it does not already exist.",
    )
    creddata.set_defaults(func=run_creddata)

    corpus = subparsers.add_parser(
        "corpus",
        help="Run the repository-tree comparison benchmark using a pinned manifest.",
    )
    corpus.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_CORPUS_MANIFEST,
        help="TOML manifest describing pinned repositories for corpus benchmarking.",
    )
    corpus.add_argument(
        "--checkout-root",
        type=Path,
        default=repo_root() / "benchmark" / "repo-corpus",
        help="Directory containing repo checkouts keyed by repo id.",
    )
    corpus.add_argument(
        "--clone-missing",
        action="store_true",
        help="Clone any missing repositories listed in the manifest.",
    )
    corpus.set_defaults(func=run_corpus)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"[benchmark] ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
