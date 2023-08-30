#!/usr/bin/env python3
# Requires Python 3.6+.
# Author: Chris Ball <chris@printf.net>
# Ported from Marc "van Hauser" Heuse's "benchmark.sh".
import os
import subprocess
import shutil
import re
import sys

def colon_value_or_none(filename: str, searchKey: str) -> str | None:
    with open(filename, "r") as fh:
        for line in fh:
            kv = line.split(": ", 1)
            if kv and len(kv) == 2:
                (key, value) = kv
                key = key.strip()
                value = value.strip()
                if key == searchKey:
                    return value
        return None


# Check if the necessary files exist and are executable
if not (
    os.access("../afl-fuzz", os.X_OK)
    and os.access("../afl-cc", os.X_OK)
    and os.path.exists("../SanitizerCoveragePCGUARD.so")
):
    print(
        "Error: you need to compile AFL++ first, we need afl-fuzz, afl-clang-fast and SanitizerCoveragePCGUARD.so built."
    )
    exit(1)

print("Preparing environment")

# Unset AFL_* environment variables
for e in list(os.environ.keys()):
    if e.startswith("AFL_"):
        os.environ.pop(e)

AFL_PATH = os.path.abspath("../")
os.environ["PATH"] = AFL_PATH + ":" + os.environ["PATH"]

# Compile test-instr.c
with open("afl.log", "w") as f:
    process = subprocess.run(
        ["../afl-cc", "-o", "test-instr", "../test-instr.c"],
        stdout=f,
        stderr=subprocess.STDOUT,
        env={"AFL_INSTRUMENT": "PCGUARD"}
    )
    if process.returncode != 0:
        print("Error: afl-cc is unable to compile")
        exit(1)

# Create input directory and file
os.makedirs("in", exist_ok=True)
with open("in/in.txt", "wb") as f:
    f.write(b"\x00" * 10240)

print("Ready, starting benchmark - this will take approx 20-30 seconds ...")

# Run afl-fuzz
env_vars = {
    "AFL_DISABLE_TRIM": "1",
    "AFL_NO_UI": "1",
    "AFL_TRY_AFFINITY": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    "AFL_BENCH_JUST_ONE": "1",
}
with open("afl.log", "a") as f:
    process = subprocess.run(
        [
            "afl-fuzz",
            "-i",
            "in",
            "-o",
            "out",
            "-s",
            "123",
            "-D",
            "./test-instr",
        ],
        stdout=f,
        stderr=subprocess.STDOUT,
        env={**os.environ, **env_vars},
    )

print("Analysis:")

# Extract CPUID from afl.log
with open("afl.log", "r") as f:
    match = re.search(r".*try binding to.*#(\d+)", f.read())
    if not match:
        sys.exit("Couldn't see which CPU# was used in afl.log", 1)
    cpuid = match.group(1)
    print(cpuid)

# Print CPU model
model = colon_value_or_none("/proc/cpuinfo", "model name")
if model:
    print(" CPU:", model)

# Print CPU frequency
cpu_speed = None
with open("/proc/cpuinfo", "r") as fh:
    current_cpu = None
    for line in fh:
        kv = line.split(": ", 1)
        if kv and len(kv) == 2:
            (key, value) = kv
            key = key.strip()
            value = value.strip()
            if key == "processor":
                current_cpu = value
            elif key == "cpu MHz" and current_cpu == cpuid:
                cpu_speed = value
if cpu_speed:
    print(" Mhz:", cpu_speed)

# Print execs_per_sec from fuzzer_stats
execs = colon_value_or_none("out/default/fuzzer_stats", "execs_per_sec")
if execs:
    print(" execs/s:", execs)

print("\nComparison: (note that values can change by 10-15% per run)")
with open("COMPARISON", "r") as f:
    print(f.read())

# Clean up
shutil.rmtree("in")
shutil.rmtree("out")
os.remove("test-instr")
os.remove("afl.log")
