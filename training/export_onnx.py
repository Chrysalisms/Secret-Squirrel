#!/usr/bin/env python3
"""
export_onnx.py — Export trained PyTorch checkpoints to ONNX FP32.

Produces:
  models/squirrel-tiny-fp32.onnx
  models/squirrel-large-fp32.onnx

The exported model contract:
  Input:  "input_ids"  — int64 [1, seq_len]
  Output: "logits"     — float32 [1, 2]   (logits for [benign, secret])

Usage:
    uv run python export_onnx.py --tier tiny
    uv run python export_onnx.py --tier large
    uv run python export_onnx.py --tier tiny --verify
"""

import argparse
import hashlib
import json
from pathlib import Path

import torch
import onnx
import onnxruntime as ort
import numpy as np

from models import build_tiny, build_large, ALPHABET_SIZE
from train import tokenize  # reuse exact tokenizer

ROOT      = Path(__file__).parent
CKPT_DIR  = ROOT / "checkpoints"
MODEL_DIR = ROOT.parent / "models"
MODEL_DIR.mkdir(exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def export(tier: str, verify: bool = True) -> Path:
    # ── 1. Rebuild model architecture ─────────────────────────────────────
    if tier == "tiny":
        model = build_tiny(max_seq_len=256)
        seq_len = 256
        onnx_name = "squirrel-tiny-fp32.onnx"
    else:
        model = build_large(max_seq_len=256)
        seq_len = 256
        onnx_name = "squirrel-large-fp32.onnx"

    # ── 2. Load best checkpoint ────────────────────────────────────────────
    ckpt_path = CKPT_DIR / f"squirrel-{tier}-best.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(
            f"Checkpoint not found: {ckpt_path}\n"
            f"Run:  uv run python train.py --tier {tier}"
        )

    ckpt = torch.load(ckpt_path, map_location="cpu")
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    print(f"Loaded checkpoint from epoch {ckpt['epoch']} "
          f"(val_f1={ckpt.get('val_f1', 'N/A'):.4f})")

    # ── 3. Create dummy input for tracing ─────────────────────────────────
    dummy_input = torch.zeros(1, seq_len, dtype=torch.long)

    # ── 4. Export to ONNX ─────────────────────────────────────────────────
    onnx_path = MODEL_DIR / onnx_name
    print(f"Exporting to {onnx_path}...")

    torch.onnx.export(
        model,
        dummy_input,
        str(onnx_path),
        export_params=True,
        opset_version=17,               # broad compatibility
        do_constant_folding=True,       # optimize constant sub-graphs
        input_names=["input_ids"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "logits":    {0: "batch_size"},
        },
        verbose=False,
        dynamo=False,                   # use legacy jit-trace exporter (supports adaptive_max_pool1d)
    )
    print(f"  Export complete → {onnx_path}")

    # ── 5. Validate ONNX model structure ──────────────────────────────────
    print("Validating ONNX model structure...")
    onnx_model = onnx.load(str(onnx_path))
    onnx.checker.check_model(onnx_model)
    print("  ✓ ONNX model is valid")

    # Print input/output info
    for inp in onnx_model.graph.input:
        shape = [d.dim_value if d.dim_value > 0 else d.dim_param
                 for d in inp.type.tensor_type.shape.dim]
        dtype = inp.type.tensor_type.elem_type
        print(f"  Input  '{inp.name}': shape={shape}, dtype={dtype}")
    for out in onnx_model.graph.output:
        shape = [d.dim_value if d.dim_value > 0 else d.dim_param
                 for d in out.type.tensor_type.shape.dim]
        dtype = out.type.tensor_type.elem_type
        print(f"  Output '{out.name}': shape={shape}, dtype={dtype}")

    # ── 6. ORT inference verification ─────────────────────────────────────
    if verify:
        print("\nRunning ORT inference verification...")
        sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])

        # Test cases: (text, expected_label)
        test_cases = [
            ("AKIAIOSFODNN7EXAMPLE",                         1),  # AWS access key
            ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",   1),  # AWS secret
            ("ghp_16C7e42F292c6912E7710c838347Ae178B4a",     1),  # GitHub PAT
            ("sk_live_4eC39HqLyjWDarjtT1zdp7dc",             1),  # Stripe SK
            ("hello world",                                   0),  # benign
            ("config_path",                                   0),  # benign
            ("https://example.com/api/v1",                   0),  # benign URL
            ("1.2.3.4",                                       0),  # IP address
            ("d41d8cd98f00b204e9800998ecf8427e",              0),  # MD5 hash (benign)
        ]

        correct = 0
        print(f"  {'Text':<48} {'Expected':>8} {'Pred':>6} {'P(secret)':>10}")
        print(f"  {'-'*48} {'-'*8} {'-'*6} {'-'*10}")
        for text, expected in test_cases:
            tokens = np.array([tokenize(text, seq_len)], dtype=np.int64)
            outputs = sess.run(["logits"], {"input_ids": tokens})
            logits = outputs[0][0]
            exp_s = np.exp(logits[1] - max(logits))
            exp_b = np.exp(logits[0] - max(logits))
            p_secret = exp_s / (exp_s + exp_b)
            pred = 1 if p_secret > 0.5 else 0
            ok = "✓" if pred == expected else "✗"
            print(f"  {ok} {text[:46]:<46} {expected:>8} {pred:>6} {p_secret:>10.4f}")
            if pred == expected:
                correct += 1

        acc = correct / len(test_cases)
        print(f"\n  Verification accuracy: {correct}/{len(test_cases)} = {acc:.1%}")
        if acc < 0.7:
            print("  ⚠ Low verification accuracy — model may need more training")
        else:
            print("  ✓ Verification passed")

    # ── 7. File size + SHA-256 ─────────────────────────────────────────────
    size_mb = onnx_path.stat().st_size / 1_048_576
    sha = sha256_file(onnx_path)
    print(f"\n  File:   {onnx_name}")
    print(f"  Size:   {size_mb:.2f} MB")
    print(f"  SHA256: {sha}")

    # Save manifest
    manifest = {
        "filename": onnx_name,
        "tier": tier,
        "size_bytes": onnx_path.stat().st_size,
        "size_mb": round(size_mb, 3),
        "sha256": sha,
        "opset_version": 17,
        "seq_len": seq_len,
        "vocab_size": ALPHABET_SIZE,
        "input_names": ["input_ids"],
        "output_names": ["logits"],
        "checkpoint_epoch": ckpt["epoch"],
        "val_f1": float(ckpt.get("val_f1", 0.0)),
    }
    manifest_path = MODEL_DIR / f"{tier}-manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"  Manifest: {manifest_path}")

    return onnx_path


def main():
    parser = argparse.ArgumentParser(description="Export Secret Squirrel model to ONNX")
    parser.add_argument("--tier", choices=["tiny", "large", "both"], default="both",
                        help="Which tier to export")
    parser.add_argument("--verify", action="store_true", default=True,
                        help="Run ORT verification after export")
    parser.add_argument("--no-verify", dest="verify", action="store_false")
    args = parser.parse_args()

    tiers = ["tiny", "large"] if args.tier == "both" else [args.tier]

    for tier in tiers:
        print(f"\n{'='*60}")
        print(f"  Exporting {tier.upper()} model")
        print(f"{'='*60}")
        try:
            path = export(tier, verify=args.verify)
            print(f"\n  ✓ {tier.upper()} → {path}")
        except FileNotFoundError as e:
            print(f"\n  ✗ Skipping {tier}: {e}")

    print(f"\nAll models in: {MODEL_DIR}/")
    print("Upload to GitHub Releases with:")
    print("  gh release create v0.1.0 models/*.onnx --title 'v0.1.0 Models'")


if __name__ == "__main__":
    main()
