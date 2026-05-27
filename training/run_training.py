#!/usr/bin/env python3
"""
run_training.py — End-to-end training orchestrator.

Runs the full pipeline:
  1. Build dataset (synthetic + optional CredData)
  2. Train Tiny model
  3. Train Large model
  4. Export both to ONNX FP32
  5. Run final evaluation
  6. Print summary

Usage:
    uv run python run_training.py
    uv run python run_training.py --epochs-tiny 15 --epochs-large 25
    uv run python run_training.py --skip-large   # Only train Tiny
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent


def run(cmd: list[str], desc: str) -> int:
    """Run a subprocess, streaming output. Returns exit code."""
    print(f"\n{'='*70}")
    print(f"  STEP: {desc}")
    print(f"{'='*70}")
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable] + cmd,
        cwd=ROOT,
    )
    elapsed = time.time() - t0
    status = "[OK]" if proc.returncode == 0 else f"[FAILED] (exit {proc.returncode})"
    print(f"\n  {status}  [{elapsed:.1f}s]")
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(description="Secret Squirrel end-to-end training")
    parser.add_argument("--epochs-tiny",  type=int, default=20)
    parser.add_argument("--epochs-large", type=int, default=25)
    parser.add_argument("--batch-size",   type=int, default=256)
    parser.add_argument("--skip-dataset", action="store_true",
                        help="Skip dataset generation (use existing data/)")
    parser.add_argument("--skip-large",   action="store_true",
                        help="Only train the Tiny model")
    parser.add_argument("--no-verify",    action="store_true",
                        help="Skip ONNX verification step")
    args = parser.parse_args()

    start = time.time()
    failures = []

    # ── Step 1: Build dataset ──────────────────────────────────────────────
    if not args.skip_dataset:
        rc = run(["dataset_builder.py"], "Build training corpus")
        if rc != 0:
            print("Dataset build failed — aborting.")
            sys.exit(1)
    else:
        print("\n[Skipping dataset generation]")

    # ── Step 2: Train Tiny ─────────────────────────────────────────────────
    rc = run(
        [
            "train.py",
            "--tier", "tiny",
            "--epochs", str(args.epochs_tiny),
            "--batch-size", str(args.batch_size),
        ],
        f"Train TINY model ({args.epochs_tiny} epochs)"
    )
    if rc != 0:
        failures.append("train tiny")

    # ── Step 3: Train Large ────────────────────────────────────────────────
    if not args.skip_large:
        rc = run(
            [
                "train.py",
                "--tier", "large",
                "--epochs", str(args.epochs_large),
                "--batch-size", str(args.batch_size),
            ],
            f"Train LARGE model ({args.epochs_large} epochs)"
        )
        if rc != 0:
            failures.append("train large")

    # ── Step 4: Export ONNX ────────────────────────────────────────────────
    export_args = ["export_onnx.py"]
    if args.skip_large:
        export_args += ["--tier", "tiny"]
    if args.no_verify:
        export_args += ["--no-verify"]

    rc = run(export_args, "Export to ONNX FP32")
    if rc != 0:
        failures.append("onnx export")

    # ── Summary ───────────────────────────────────────────────────────────
    total = time.time() - start
    print(f"\n{'='*70}")
    print(f"  TRAINING COMPLETE  [{total/60:.1f} min]")
    print(f"{'='*70}")

    model_dir = ROOT.parent / "models"
    for f in sorted(model_dir.glob("*.onnx")):
        size = f.stat().st_size / 1_048_576
        print(f"  {f.name:<40} {size:6.2f} MB")

    if failures:
        print(f"\n  [WARN] Failed steps: {', '.join(failures)}")
        sys.exit(1)
    print("\n  [OK] All steps succeeded!")
    print("\n  Next: upload models to GitHub Releases:")
    print("    gh release create v0.1.0 models/*.onnx")


if __name__ == "__main__":
    main()
