#!/usr/bin/env python3
import csv
import json
import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path
import argparse

def load_ground_truth(meta_dir, data_dir):
    """Load labels from CredData CSVs, but only for files we actually downloaded."""
    ground_truth = defaultdict(list)
    t_count = 0
    f_count = 0
    for csv_file in Path(meta_dir).glob("*.csv"):
        with open(csv_file, newline="") as f:
            for row in csv.DictReader(f):
                file_path = row["FilePath"]
                if not (Path(data_dir).parent / file_path).exists():
                    continue  # skip if we didn't fetch this file
                
                line = int(row["LineStart"])
                label = row["GroundTruth"]
                ground_truth[file_path].append((line, label))
                if label == "T":
                    t_count += 1
                elif label == "F":
                    f_count += 1
    
    print(f"Loaded ground truth: {t_count} TP labels, {f_count} FP labels across downloaded files.")
    return ground_truth

def run_squirrel(bin_path, scan_path):
    cmd = [bin_path, "detect", "--format", "json", "--confidence", "0.3", scan_path]
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    dt = time.time() - t0
    findings = json.loads(r.stdout or "[]")
    
    detections = set()
    for f in findings:
        path = f["location"]["path"]
        # Normalise to "data/reponame/sample/file" format if needed
        if "CredData/data" in path:
            path = "data" + path.split("CredData/data")[1]
        elif path.startswith("data/"):
            pass
        detections.add((path, f["location"]["start_line"]))
    return detections, dt

def run_gitleaks(bin_path, scan_path):
    out_file = "/tmp/gl_creddata.json"
    cmd = [bin_path, "detect", "--no-git", "--report-format", "json", "--report-path", out_file, scan_path]
    t0 = time.time()
    subprocess.run(cmd, capture_output=True, text=True)
    dt = time.time() - t0
    
    try:
        with open(out_file) as f:
            findings = json.load(f)
    except FileNotFoundError:
        findings = []
        
    detections = set()
    for f in findings:
        path = f["File"]
        if "CredData/data" in path:
            path = "data" + path.split("CredData/data")[1]
        detections.add((path, f["StartLine"]))
    return detections, dt

def run_betterleaks(bin_path, scan_path):
    out_file = "/tmp/bl_creddata.json"
    cmd = [bin_path, scan_path, "-o", out_file]
    t0 = time.time()
    subprocess.run(cmd, capture_output=True, text=True)
    dt = time.time() - t0
    
    try:
        with open(out_file) as f:
            findings = json.load(f)
    except FileNotFoundError:
        findings = []
        
    detections = set()
    for f in findings:
        path = f["file_path"]
        if "CredData/data" in path:
            path = "data" + path.split("CredData/data")[1]
        detections.add((path, f["line_number"]))
    return detections, dt

def evaluate(detections, ground_truth):
    tp = fp = fn = unlabeled = 0
    matched_t = set()

    for det_path, det_line in detections:
        # Match with ±3 line window
        labels = ground_truth.get(det_path, [])
        matched = False
        for gt_line, label in labels:
            if abs(gt_line - det_line) <= 3:
                if label == "T":
                    tp += 1
                    matched_t.add((det_path, gt_line))
                else:
                    fp += 1
                matched = True
                break
        if not matched:
            unlabeled += 1

    for path, labels in ground_truth.items():
        for line, label in labels:
            if label == "T" and (path, line) not in matched_t:
                fn += 1

    return {"tp": tp, "fp": fp, "fn": fn, "unlabeled": unlabeled}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--squirrel", default="./target/release/squirrel")
    parser.add_argument("--gitleaks", default="gitleaks")
    parser.add_argument("--betterleaks", default="betterleaks")
    args = parser.parse_args()

    cred_dir = Path(os.path.expanduser("~/CredData"))
    meta_dir = cred_dir / "meta"
    data_dir = cred_dir / "data"

    print("Loading CredData ground truth...")
    ground_truth = load_ground_truth(meta_dir, data_dir)

    print(f"\nRunning Secret Squirrel ({args.squirrel}) ...")
    sq_det, sq_time = run_squirrel(args.squirrel, str(data_dir))
    sq_res = evaluate(sq_det, ground_truth)
    print(f"  TP={sq_res['tp']}  FP={sq_res['fp']}  FN={sq_res['fn']}  Unlabeled={sq_res['unlabeled']}  ({sq_time:.1f}s)")

    print(f"Running Gitleaks ({args.gitleaks}) ...")
    gl_det, gl_time = run_gitleaks(args.gitleaks, str(data_dir))
    gl_res = evaluate(gl_det, ground_truth)
    print(f"  TP={gl_res['tp']}  FP={gl_res['fp']}  FN={gl_res['fn']}  Unlabeled={gl_res['unlabeled']}  ({gl_time:.1f}s)")

    print(f"Running BetterLeaks ({args.betterleaks}) ...")
    bl_det, bl_time = run_betterleaks(args.betterleaks, str(data_dir))
    bl_res = evaluate(bl_det, ground_truth)
    print(f"  TP={bl_res['tp']}  FP={bl_res['fp']}  FN={bl_res['fn']}  Unlabeled={bl_res['unlabeled']}  ({bl_time:.1f}s)")

    print("\n========================================================================")
    print("BENCHMARK RESULTS  —  CredData Sub-Sample")
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
    print(f"{'False Positives (Labeled)':<22} {sq_res['fp']:<19} {gl_res['fp']:<15} {bl_res['fp']:<15}")
    print(f"{'False Negatives':<22} {sq_res['fn']:<19} {gl_res['fn']:<15} {bl_res['fn']:<15}")
    print(f"{'Unlabeled Detections':<22} {sq_res['unlabeled']:<19} {gl_res['unlabeled']:<15} {bl_res['unlabeled']:<15}")
    print(f"{'Time (s)':<22} {sq_time:<19.2f} {gl_time:<15.2f} {bl_time:<15.2f}")

    best_f1 = max(sq_f1, gl_f1, bl_f1)
    winner = "Secret Squirrel" if best_f1 == sq_f1 else "Gitleaks v8" if best_f1 == gl_f1 else "BetterLeaks"
    print(f"\n🏆  Best F1: {winner}  ({best_f1:.4f})")

if __name__ == "__main__":
    main()
