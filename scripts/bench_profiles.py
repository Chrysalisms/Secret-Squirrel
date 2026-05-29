#!/usr/bin/env python3
import csv
import json
import os
import subprocess
import time
from pathlib import Path
import argparse

def load_ground_truth(gt_file):
    with open(gt_file, "r") as f:
        return json.load(f)

def run_squirrel(bin_path, scan_path, profile="fast"):
    cmd = [bin_path, "detect", "--profile", profile, "--format", "json", "--confidence", "0.3", scan_path]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        findings = json.loads(r.stdout or "[]")
    except subprocess.TimeoutExpired:
        print(f"  Secret Squirrel ({profile}) timed out!")
        return set(), 60.0
    dt = time.time() - t0
    
    detections = set()
    for f in findings:
        path = f["location"]["path"]
        if scan_path in path:
            path = path.split(scan_path)[1].lstrip("\\/")
        detections.add(path.replace("\\", "/"))
    return detections, dt

def run_betterleaks(bin_path, scan_path):
    out_file = "/tmp/bl_ext.json"
    cmd = [bin_path, "dir", "--report-format", "json", "--report-path", out_file, scan_path]
    t0 = time.time()
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("  BetterLeaks timed out!")
        return set(), 180.0
    dt = time.time() - t0
    
    try:
        with open(out_file) as f:
            findings = json.load(f)
    except FileNotFoundError:
        findings = []
        
    detections = set()
    for f in findings:
        path = f.get("File") or f.get("file_path") or ""
        if scan_path in path:
            path = path.split(scan_path)[1].lstrip("\\/")
        detections.add(path.replace("\\", "/"))
    return detections, dt

def evaluate(detections, ground_truth):
    tp = fp = fn = 0
    matched_t = set()

    for det_path in detections:
        det_path = det_path.replace("\\", "/").lstrip("./")
        
        label = ground_truth.get(det_path)
        if label == "T":
            tp += 1
            matched_t.add(det_path)
        elif label == "F":
            fp += 1
        else:
            matched = False
            for k, v in ground_truth.items():
                if det_path.endswith(k):
                    if v == "T":
                        tp += 1
                        matched_t.add(k)
                    elif v == "F":
                        fp += 1
                    matched = True
                    break
            if not matched:
                fp += 1

    for path, label in ground_truth.items():
        if label == "T" and path not in matched_t:
            fn += 1

    return {"tp": tp, "fp": fp, "fn": fn}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus_dir", help="Directory containing true_positives and false_positives")
    parser.add_argument("--squirrel", default="/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel/target/release/squirrel")
    parser.add_argument("--betterleaks", default="betterleaks")
    args = parser.parse_args()

    corpus_dir = Path(args.corpus_dir).resolve()
    gt_file = corpus_dir / "ground_truth.json"

    print(f"Loading ground truth from {gt_file}...")
    ground_truth = load_ground_truth(gt_file)
    print(f"Loaded {len(ground_truth)} labeled files.")

    print(f"\nRunning Secret Squirrel Fast ...")
    sq_fast_det, sq_fast_time = run_squirrel(args.squirrel, str(corpus_dir), "fast")
    sq_fast_res = evaluate(sq_fast_det, ground_truth)
    print(f"  TP={sq_fast_res['tp']}  FP={sq_fast_res['fp']}  FN={sq_fast_res['fn']}  ({sq_fast_time:.1f}s)")

    print(f"Running Secret Squirrel Deep ...")
    sq_deep_det, sq_deep_time = run_squirrel(args.squirrel, str(corpus_dir), "deep")
    sq_deep_res = evaluate(sq_deep_det, ground_truth)
    print(f"  TP={sq_deep_res['tp']}  FP={sq_deep_res['fp']}  FN={sq_deep_res['fn']}  ({sq_deep_time:.1f}s)")

    print(f"Running BetterLeaks ({args.betterleaks}) ...")
    bl_det, bl_time = run_betterleaks(args.betterleaks, str(corpus_dir))
    bl_res = evaluate(bl_det, ground_truth)
    print(f"  TP={bl_res['tp']}  FP={bl_res['fp']}  FN={bl_res['fn']}  ({bl_time:.1f}s)")

    print("\n========================================================================")
    print(f"BENCHMARK RESULTS  —  {corpus_dir.name.upper()}")
    print("========================================================================")
    print(f"{'Metric':<22} {'Secret Squirrel (Fast)':<24} {'Secret Squirrel (Deep)':<24} {'BetterLeaks':<15}")
    print("-" * 88)

    def calc_metrics(res):
        p = res["tp"] / (res["tp"] + res["fp"]) if (res["tp"] + res["fp"]) > 0 else 0
        r = res["tp"] / (res["tp"] + res["fn"]) if (res["tp"] + res["fn"]) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        return p, r, f1

    sqf_p, sqf_r, sqf_f1 = calc_metrics(sq_fast_res)
    sqd_p, sqd_r, sqd_f1 = calc_metrics(sq_deep_res)
    bl_p, bl_r, bl_f1 = calc_metrics(bl_res)

    print(f"{'Precision':<22} {sqf_p:<24.4f} {sqd_p:<24.4f} {bl_p:<15.4f}")
    print(f"{'Recall':<22} {sqf_r:<24.4f} {sqd_r:<24.4f} {bl_r:<15.4f}")
    print(f"{'F1 Score \u2605':<22} {sqf_f1:<24.4f} {sqd_f1:<24.4f} {bl_f1:<15.4f}")
    print(f"{'True Positives':<22} {sq_fast_res['tp']:<24} {sq_deep_res['tp']:<24} {bl_res['tp']:<15}")
    print(f"{'False Positives':<22} {sq_fast_res['fp']:<24} {sq_deep_res['fp']:<24} {bl_res['fp']:<15}")
    print(f"{'False Negatives':<22} {sq_fast_res['fn']:<24} {sq_deep_res['fn']:<24} {bl_res['fn']:<15}")
    print(f"{'Time (s)':<22} {sq_fast_time:<24.2f} {sq_deep_time:<24.2f} {bl_time:<15.2f}")

    best_f1 = max(sqf_f1, sqd_f1, bl_f1)
    winner = "Secret Squirrel Deep" if best_f1 == sqd_f1 else "Secret Squirrel Fast" if best_f1 == sqf_f1 else "BetterLeaks"
    print(f"\n🏆  Best F1: {winner}  ({best_f1:.4f})")

if __name__ == "__main__":
    main()
