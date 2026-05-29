import subprocess
import time
import os

def run_cmd(cmd):
    start = time.time()
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
    except Exception as e:
        res = type('obj', (object,), {'stdout': str(e), 'stderr': ''})()
    duration = time.time() - start
    return duration, res.stdout, res.stderr

print("--- Running BetterLeaks on WSL ---")
bl_cmd = '/usr/bin/time -v betterleaks dir /root/test_suites/ 2>&1'
bl_duration, bl_out, bl_err = run_cmd(bl_cmd)

print("--- Running Secret Squirrel (FAST) on WSL ---")
ss_fast_cmd = '/usr/bin/time -v /mnt/c/Users/vbode/OneDrive/Desktop/Coding\\ Space/Secret-Squirrel/target/release/squirrel detect --profile fast /root/test_suites/ 2>&1'
ssf_duration, ssf_out, ssf_err = run_cmd(ss_fast_cmd)

print("--- Running Secret Squirrel (DEEP) on WSL ---")
ss_deep_cmd = '/usr/bin/time -v /mnt/c/Users/vbode/OneDrive/Desktop/Coding\\ Space/Secret-Squirrel/target/release/squirrel detect --profile deep /root/test_suites/ 2>&1'
ssd_duration, ssd_out, ssd_err = run_cmd(ss_deep_cmd)

def extract_utilization(out):
    lines = []
    for line in out.splitlines():
        if "Maximum resident set size" in line or "Percent of CPU" in line or "User time" in line or "System time" in line:
            lines.append(line.strip())
    return "\n".join(lines)

with open('/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel/benchmark_wsl_results.txt', 'w') as f:
    f.write("BENCHMARK RESULTS (WSL NATIVE)\n====================================\n\n")
    
    f.write(f"BetterLeaks Time: {bl_duration:.2f}s\n")
    f.write("Utilization:\n" + extract_utilization(bl_out) + "\n\n")
    
    f.write(f"Secret Squirrel (FAST) Time: {ssf_duration:.2f}s\n")
    f.write("Utilization:\n" + extract_utilization(ssf_out) + "\n\n")
    
    f.write(f"Secret Squirrel (DEEP) Time: {ssd_duration:.2f}s\n")
    f.write("Utilization:\n" + extract_utilization(ssd_out) + "\n\n")

print("Done. Results in benchmark_wsl_results.txt")
