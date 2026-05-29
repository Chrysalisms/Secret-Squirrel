#!/usr/bin/env python3
"""
Synthetic credential benchmark — no external download required.

Creates a controlled set of test files with:
  - Real-looking secrets (ground truth: TRUE positive)
  - Placeholder/example strings (ground truth: FALSE positive)

Then runs Secret Squirrel, Gitleaks, and BetterLeaks against the files and
computes precision/recall/F1 for each tool.

This gives an immediate, reproducible benchmark while the full CredData
corpus downloads in the background.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Ground truth dataset
# Each entry: (label, description, file_content_lines)
#   label = "T" (real secret, should be detected) or "F" (FP, should be suppressed)
# ──────────────────────────────────────────────────────────────────────────────

TRUE_POSITIVES = [
    # AWS
    ("aws-key-env",        'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'),
    ("aws-key-code",       'access_key = "AKIAJ5H4X3ZUX3BVXH2W"\nsecret = "iV5gQ/7e4sGlB2T3oP9dN1kRmXuWvA2cYhEzFq"\n'),
    # GitHub PAT
    ("github-pat",         'token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB"\n'),
    ("github-pat-v2",      'GITHUB_TOKEN=github_pat_11ABCDE_0yZxWvUt3RqPoNmLkJiHgFeDcBaZyXwVuTsSrQpOnMlKjIhGfEdCbAaZyX\n'),
    # Stripe
    ("stripe-secret",      'stripe_secret_key = "sk_live_51HNXVpILxT3GQRkxD4YoXILsrJIQqZgTnGaOIxfEdEfD1234"\n'),
    # Google API
    ("google-api",         'google_api_key = "AIzaSyB4H9x2k7F3P1DqRtLmNvWE0XcUoYsJiKl"\n'),
    # Generic DB password
    ("db-password",        'DATABASE_URL=postgresql://admin:Sup3rS3cr3tP@ss!@prod-db.internal:5432/app_db\n'),
    # JWT secret
    ("jwt-secret",         'JWT_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgH\n'),
    # Private key (PEM)
    ("rsa-private-key",    '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Ygef3dCCd4hNDMNMPNuBrR\n-----END RSA PRIVATE KEY-----\n'),
    # Slack webhook
    ("slack-webhook",      'slack_webhook = "https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/xYzAbCdEfGhIjKlMnOpQrStUv"\n'),
    # Twilio
    ("twilio-auth",        'TWILIO_AUTH_TOKEN=3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a\n'),
    # Mailgun
    ("mailgun-key",        'MAILGUN_API_KEY=key-3ax6xnjp29jd6fds4gc373sgvjxteol0\n'),
    # SendGrid
    ("sendgrid-key",       'SENDGRID_API_KEY=SG.ngeVfQFYQlKU0ufo8x5d1A.TwL09arlADpk7XWiW8N1vXC-xYzA\n'),
    # Azure SAS
    ("azure-sas",          'AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=dGhpcyBpcyBhIGZha2UgYmFzZTY0IGVuY29kZWQga2V5IHN0cmluZyBmb3IgdGVzdGluZyBvbmx5\n'),
    # Docker Hub
    ("dockerhub-pw",       'DOCKER_PASSWORD=sPecIaL_P@ssw0rd_2024\n'),
    # Telegram Bot
    ("telegram-bot",       'TELEGRAM_BOT_TOKEN=5432167890:AAHdqTcvCH1vGWJxfSeofSh0riYsFfsGE9U\n'),
    # NPM token
    ("npm-token",          'NPM_TOKEN=npm_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\n'),
    # Hashicorp Vault
    ("vault-token",        'VAULT_TOKEN=s.aBcDeFgHiJkLmNoPqRsTuVwXy\n'),
    # SSH private key
    ("ssh-private-key",    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQ\n-----END OPENSSH PRIVATE KEY-----\n'),
    # Generic high-entropy env var
    ("generic-secret-env", 'SECRET_KEY=qK9#mP2$nL5@hJ7&wR4!vT8*xN1^zM6\n'),
]

FALSE_POSITIVES = [
    # Explicit placeholders
    ("fp-your-key",        'api_key = "YOUR_API_KEY_HERE"\n'),
    ("fp-example",         'token = "example_token_replace_me"\n'),
    ("fp-xxx",             'password = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'),
    ("fp-test-cred",       'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n# This is a test credential from AWS documentation\n'),
    # Repeated chars
    ("fp-aaa",             'secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'),
    ("fp-12345",           'token = "123456789012345678901234567890123456"\n'),
    # Template variables
    ("fp-template",        'DATABASE_URL = "${DATABASE_PASSWORD}"\n'),
    ("fp-mustache",        'api_key: "{{API_KEY}}"\n'),
    ("fp-envvar-ref",      'SECRET_KEY = "$SECRET_KEY"\n'),
    # Comment/doc references
    ("fp-commented-url",   '# API key: https://example.com/api?key=your-api-key\n'),
    ("fp-fake-in-comment", '// Example: token = "some_fake_token_for_demo"\n'),
    # Test fixtures
    ("fp-test-fixture",    'AWS_ACCESS_KEY = "AKIATEST00000000TEST"\n# Used in unit tests only\n'),
    ("fp-mock",            'const mockApiKey = "mock_key_for_testing_12345"\n'),
    # Null/empty
    ("fp-null",            'SECRET=\nAPI_KEY=null\nTOKEN=undefined\n'),
    # Low-entropy strings
    ("fp-low-entropy",     'password = "password123"\ntoken = "testtoken"\n'),
    # Known example values from docs
    ("fp-aws-docs",        '# From AWS docs: AKIAIOSFODNN7EXAMPLE is an example access key ID\n'),
    ("fp-changeme",        'DB_PASS=changeme\nADMIN_PASSWORD=change_me_please\n'),
    # README
    ("fp-readme",          '## Configuration\nSet API_KEY to your actual key (e.g., `sk_live_xxx...`)\n'),
    # CI/CD secret references (not literal values)
    ("fp-ci-ref",          'GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\nAWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n'),
    # Sample/demo values
    ("fp-sample-key",      'sample_key = "SampleKey123456789012345678901234"\n'),
]


def write_test_corpus(corpus_dir: Path) -> dict:
    """Write test files and return ground truth dict keyed by (file_name, line)."""
    gt = {}
    tp_dir = corpus_dir / "true_positives"
    fp_dir = corpus_dir / "false_positives"
    tp_dir.mkdir(parents=True, exist_ok=True)
    fp_dir.mkdir(parents=True, exist_ok=True)

    for name, content in TRUE_POSITIVES:
        fpath = tp_dir / f"{name}.env"
        fpath.write_text(content)
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip():
                gt[(str(fpath), i)] = "T"

    for name, content in FALSE_POSITIVES:
        fpath = fp_dir / f"{name}.env"
        fpath.write_text(content)
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip():
                gt[(str(fpath), i)] = "F"

    return gt


def tool_version(bin_path: str, version_arg: str = "--version") -> str:
    try:
        r = subprocess.run([bin_path, version_arg], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).strip().split("\n")[0]
    except Exception:
        return "unknown"


def run_squirrel(bin_path: str, scan_path: str, timeout: int = 120) -> tuple:
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            [bin_path, "detect", "--format", "json", "--confidence", "0.3", scan_path],
            capture_output=True, text=True, timeout=timeout,
        )
        elapsed = time.monotonic() - t0
        findings = json.loads(r.stdout or "[]")
        hits = set()
        for f in findings:
            path = f.get("location", {}).get("path", "")
            line = f.get("location", {}).get("start_line", 0)
            hits.add((path, line))
        return hits, elapsed
    except Exception as e:
        return set(), time.monotonic() - t0


def run_gitleaks(bin_path: str, scan_path: str, timeout: int = 120) -> tuple:
    t0 = time.monotonic()
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            report = tf.name
        subprocess.run(
            [bin_path, "detect", "--no-git", "--source", scan_path,
             "--report-format", "json", "--report-path", report, "--exit-code", "0"],
            capture_output=True, text=True, timeout=timeout,
        )
        elapsed = time.monotonic() - t0
        raw = Path(report).read_text().strip() if Path(report).exists() else ""
        Path(report).unlink(missing_ok=True)
        if not raw or raw == "null":
            return set(), elapsed
        findings = json.loads(raw)
        return {(f.get("File", ""), f.get("StartLine", 0)) for f in findings}, elapsed
    except Exception:
        return set(), time.monotonic() - t0


def run_betterleaks(bin_path: str, scan_path: str, timeout: int = 120) -> tuple:
    t0 = time.monotonic()
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            report = tf.name
        subprocess.run(
            [bin_path, "dir", scan_path,
             "--report-format", "json", "--report-path", report],
            capture_output=True, text=True, timeout=timeout,
        )
        elapsed = time.monotonic() - t0
        raw = Path(report).read_text().strip() if Path(report).exists() else ""
        Path(report).unlink(missing_ok=True)
        if not raw or raw in ("null", "[]"):
            return set(), elapsed
        findings = json.loads(raw)
        return {(f.get("File", ""), f.get("StartLine", 0)) for f in findings}, elapsed
    except Exception:
        return set(), time.monotonic() - t0


def evaluate(detections: set, ground_truth: dict, scan_path: str) -> dict:
    """
    Compute TP/FP/FN.
    A detection at (abs_path, line) matches ground truth if the path ends with
    the same filename and line is within ±3 of the labeled line.
    """
    from collections import defaultdict
    gt_by_file = defaultdict(list)
    for (fpath, line), label in ground_truth.items():
        gt_by_file[str(Path(fpath))].append((line, label))

    tp = fp = fn = 0
    matched_gt = set()

    for (det_path, det_line) in detections:
        # Normalise: try as absolute, else join with scan_path
        abs_det = det_path if Path(det_path).is_absolute() else str(Path(scan_path) / det_path)
        entries = gt_by_file.get(abs_det, [])
        matched = False
        for gt_line, label in entries:
            if abs(gt_line - det_line) <= 3:  # widen to ±3
                if label == "T":
                    tp += 1
                else:
                    fp += 1
                matched_gt.add((abs_det, gt_line))
                matched = True
                break
        if not matched:
            # Detection not in our GT window → check if file is in corpus
            if abs_det in gt_by_file:
                fp += 1
            # If file not in corpus at all, ignore (could be a support/meta file)

    for (fpath, line), label in ground_truth.items():
        if label == "T" and (fpath, line) not in matched_gt:
            fn += 1

    return {"tp": tp, "fp": fp, "fn": fn}


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2*p*r / (p+r) if p+r else 0.0
    return p, r, f


def main():
    ap = argparse.ArgumentParser(description="Synthetic 3-way credential scanner benchmark")
    ap.add_argument("--squirrel",    default="./target/release/squirrel")
    ap.add_argument("--gitleaks",    default="gitleaks")
    ap.add_argument("--betterleaks", default="betterleaks")
    ap.add_argument("--out",         default="benchmark_synthetic_results.json")
    ap.add_argument("--keep",        action="store_true", help="Keep test corpus after run")
    args = ap.parse_args()

    corpus_dir = Path(tempfile.mkdtemp(prefix="squirrel_bench_"))
    print(f"Writing test corpus to {corpus_dir} ...")
    gt = write_test_corpus(corpus_dir)

    total_t = sum(1 for v in gt.values() if v == "T")
    total_f = sum(1 for v in gt.values() if v == "F")
    print(f"  {len(TRUE_POSITIVES)} TP files ({total_t} labeled lines)")
    print(f"  {len(FALSE_POSITIVES)} FP files ({total_f} labeled lines)")
    print()

    tools = [
        ("Secret Squirrel", "squirrel", args.squirrel, run_squirrel),
        ("Gitleaks v8",     "gitleaks", args.gitleaks, run_gitleaks),
        ("BetterLeaks",     "betterleaks", args.betterleaks, run_betterleaks),
    ]

    results = {}
    for display_name, key, bin_path, runner in tools:
        ver = tool_version(bin_path)
        print(f"Running {display_name} ({ver}) ...", flush=True)
        hits, elapsed = runner(bin_path, str(corpus_dir))
        m = evaluate(hits, gt, str(corpus_dir))
        p, r, f = prf(**m)
        results[key] = {
            "tool": display_name,
            "version": ver,
            "precision": round(p, 4),
            "recall":    round(r, 4),
            "f1":        round(f, 4),
            "tp": m["tp"], "fp": m["fp"], "fn": m["fn"],
            "detections": len(hits),
            "time_s": round(elapsed, 2),
        }
        print(f"  TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  "
              f"P={p:.3f}  R={r:.3f}  F1={f:.3f}  ({elapsed:.1f}s)")

    # ── Print comparison table ────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("BENCHMARK RESULTS  —  Synthetic credential corpus")
    print(f"  {total_t} true positive lines  |  {total_f} false positive lines")
    print("=" * 72)

    col = 16
    names = [(d, k) for d, k, _, _ in tools]
    header = f"{'Metric':<22}" + "".join(f"{n:>{col}}" for n, _ in names)
    print(header)
    print("-" * len(header))

    rows = [
        ("Precision",       [f"{results[k]['precision']:.4f}" for _, k in names]),
        ("Recall",          [f"{results[k]['recall']:.4f}"    for _, k in names]),
        ("F1 Score ★",      [f"{results[k]['f1']:.4f}"        for _, k in names]),
        ("True Positives",  [f"{results[k]['tp']}"            for _, k in names]),
        ("False Positives", [f"{results[k]['fp']}"            for _, k in names]),
        ("False Negatives", [f"{results[k]['fn']}"            for _, k in names]),
        ("Detections",      [f"{results[k]['detections']}"    for _, k in names]),
        ("Time (s)",        [f"{results[k]['time_s']}"        for _, k in names]),
    ]
    for label, vals in rows:
        print(f"{label:<22}" + "".join(f"{v:>{col}}" for v in vals))

    f1s = [(results[k]["f1"], n) for n, k in names]
    winner_f1, winner = max(f1s)
    print(f"\n🏆  Best F1: {winner}  ({winner_f1:.4f})")

    # ── Save JSON ─────────────────────────────────────────────────────────────
    out = {
        "corpus": {
            "type": "synthetic",
            "tp_files": len(TRUE_POSITIVES),
            "fp_files": len(FALSE_POSITIVES),
            "total_labeled_lines": len(gt),
            "true_positive_lines": total_t,
            "false_positive_lines": total_f,
        },
        "results": results,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nDetailed results → {args.out}")

    if not args.keep:
        import shutil
        shutil.rmtree(corpus_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
