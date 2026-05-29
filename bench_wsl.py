import subprocess
import time
import json
import os

def run_cmd(cmd):
    start = time.time()
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
    except Exception as e:
        res = type('obj', (object,), {'stdout': str(e), 'stderr': ''})()
    duration = time.time() - start
    return duration, res.stdout, res.stderr

print("Building Secret Squirrel natively for Linux in WSL...")
# We build in WSL. It might be slow due to 9p but the resulting binary will be native.
build_cmd = 'wsl.exe -e bash -c "cd \'/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel\' && /root/.cargo/bin/cargo build --release"'
run_cmd(build_cmd)

print("\n--- Running BetterLeaks on WSL Native File System ---")
bl_cmd = 'wsl.exe -e bash -c "/usr/bin/time -v betterleaks dir /root/test_suites/ 2>&1"'
bl_duration, bl_out, bl_err = run_cmd(bl_cmd)
print(f"Total Wall Time: {bl_duration:.2f}s")
print("System Utilization (BetterLeaks):")
for line in bl_out.splitlines():
    if "Maximum resident set size" in line or "Percent of CPU" in line or "User time" in line or "System time" in line:
        print("  " + line.strip())

print("\n--- Running Secret Squirrel on WSL Native File System ---")
ss_cmd = 'wsl.exe -e bash -c "/usr/bin/time -v \'/mnt/c/Users/vbode/OneDrive/Desktop/Coding Space/Secret-Squirrel/target/release/squirrel\' /root/test_suites/ 2>&1"'
ss_duration, ss_out, ss_err = run_cmd(ss_cmd)
print(f"Total Wall Time: {ss_duration:.2f}s")
print("System Utilization (Secret Squirrel):")
for line in ss_out.splitlines():
    if "Maximum resident set size" in line or "Percent of CPU" in line or "User time" in line or "System time" in line:
        print("  " + line.strip())

with open('benchmark_wsl_results.txt', 'w') as f:
    f.write("BENCHMARK RESULTS (WSL NATIVE)\n====================================\n\n")
    f.write(f"BetterLeaks Time: {bl_duration:.2f}s\n")
    f.write(f"Secret Squirrel Time: {ss_duration:.2f}s\n")
