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

def run_squirrel(bin_path, scan_path):
    cmd = [bin_path, "detect", "--format", "json", "--confidence", "0.3", scan_path]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        findings = json.loads(r.stdout or "[]")
    except subprocess.TimeoutExpired:
        print("  Secret Squirrel timed out!")
        return set(), 60.0
    dt = time.time() - t0
    
    detections = set()
    for f in findings:
        path = f["location"]["path"]
        if scan_path in path:
            path = path.split(scan_path)[1].lstrip("\\/")
        detections.add(path.replace("\\", "/"))
    return detections, dt

def run_gitleaks(bin_path, scan_path):
    out_file = "/tmp/gl_ext.json"
    cmd = [bin_path, "detect", "--no-git", "--report-format", "json", "--report-path", out_file, scan_path]
    t0 = time.time()
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("  Gitleaks timed out!")
        return set(), 180.0
    dt = time.time() - t0
    
    try:
        with open(out_file) as f:
            findings = json.load(f)
    except FileNotFoundError:
        findings = []
        
    detections = set()
    for f in findings:
        path = f["File"]
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
        # Check if det_path matches a key in ground_truth
        # Sometimes tools report absolute paths or prepend ./
        det_path = det_path.replace("\\", "/").lstrip("./")
        
        label = ground_truth.get(det_path)
        if label == "T":
            tp += 1
            matched_t.add(det_path)
        elif label == "F":
            fp += 1
        else:
            # If a tool finds something in an unlabelled file, what does that mean?
            # In our benchmark corpus, EVERY file has a label (it's either a TP or FP).
            # If it's not in ground_truth, it might be path formatting mismatch.
            # Let's check for suffix match just in case
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
    parser.add_argument("--squirrel", default="./target/release/squirrel")
    parser.add_argument("--gitleaks", default="gitleaks")
    parser.add_argument("--betterleaks", default="betterleaks")
    args = parser.parse_args()

    corpus_dir = Path(args.corpus_dir).resolve()
    gt_file = corpus_dir / "ground_truth.json"

    print(f"Loading ground truth from {gt_file}...")
    ground_truth = load_ground_truth(gt_file)
    print(f"Loaded {len(ground_truth)} labeled files.")

    print(f"\nRunning Secret Squirrel ({args.squirrel}) ...")
    sq_det, sq_time = run_squirrel(args.squirrel, str(corpus_dir))
    sq_res = evaluate(sq_det, ground_truth)
    print(f"  TP={sq_res['tp']}  FP={sq_res['fp']}  FN={sq_res['fn']}  ({sq_time:.1f}s)")

    print(f"Running Gitleaks ({args.gitleaks}) ...")
    gl_det, gl_time = run_gitleaks(args.gitleaks, str(corpus_dir))
    gl_res = evaluate(gl_det, ground_truth)
    print(f"  TP={gl_res['tp']}  FP={gl_res['fp']}  FN={gl_res['fn']}  ({gl_time:.1f}s)")

    print(f"Running BetterLeaks ({args.betterleaks}) ...")
    bl_det, bl_time = run_betterleaks(args.betterleaks, str(corpus_dir))
    bl_res = evaluate(bl_det, ground_truth)
    print(f"  TP={bl_res['tp']}  FP={bl_res['fp']}  FN={bl_res['fn']}  ({bl_time:.1f}s)")

    print("\n========================================================================")
    print(f"BENCHMARK RESULTS  —  {args.corpus_dir.upper()}")
    print("========================================================================")
    print(f"{'Metric':<22} {'Secret Squirrel':<19} {'Gitleaks v8':<15} {'BetterLeaks':<15}")
    print("-" * 70)

    def calc_metrics(res):
        p = res["tp"] / (res["tp"] + res["fp"]) if (res["tp"] + res["fp"]) > 0 else 0
        r = res["tp"] / (res["tp"] + res["fn"]) if (res["tp"] + res["fn"]) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        return p, r, f1

    sq_p, sq_r, sq_f1 = calc_metrics(sq_res)
    gl_p, gl_r, gl_f1 = calc_metrics(gl_res)
    bl_p, bl_r, bl_f1 = calc_metrics(bl_res)

    print(f"{'Precision':<22} {sq_p:<19.4f} {gl_p:<15.4f} {bl_p:<15.4f}")
    print(f"{'Recall':<22} {sq_r:<19.4f} {gl_r:<15.4f} {bl_r:<15.4f}")
    print(f"{'F1 Score \u2605':<22} {sq_f1:<19.4f} {gl_f1:<15.4f} {bl_f1:<15.4f}")
    print(f"{'True Positives':<22} {sq_res['tp']:<19} {gl_res['tp']:<15} {bl_res['tp']:<15}")
    print(f"{'False Positives':<22} {sq_res['fp']:<19} {gl_res['fp']:<15} {bl_res['fp']:<15}")
    print(f"{'False Negatives':<22} {sq_res['fn']:<19} {gl_res['fn']:<15} {bl_res['fn']:<15}")
    print(f"{'Time (s)':<22} {sq_time:<19.2f} {gl_time:<15.2f} {bl_time:<15.2f}")

    best_f1 = max(sq_f1, gl_f1, bl_f1)
    winner = "Secret Squirrel" if best_f1 == sq_f1 else "Gitleaks v8" if best_f1 == gl_f1 else "BetterLeaks"
    print(f"\n🏆  Best F1: {winner}  ({best_f1:.4f})")

if __name__ == "__main__":
    main()
