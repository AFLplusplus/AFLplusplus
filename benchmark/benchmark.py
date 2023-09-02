#!/usr/bin/env python3
# Requires Python 3.6+.
# Author: Chris Ball <chris@printf.net>
# Ported from Marc "van Hauser" Heuse's "benchmark.sh".
import argparse
import asyncio
import glob
import json
import multiprocessing
import os
import shutil
import sys
from collections import defaultdict
from decimal import Decimal

reset = "\033[0m"
blue  = lambda text: f"\033[1;94m{text}{reset}"
gray  = lambda text: f"\033[1;90m{text}{reset}"
green = lambda text: f"\033[0;32m{text}{reset}"
red   = lambda text: f"\033[0;31m{text}{reset}"

targets = [
    {"source": "../test-instr.c", "binary": "test-instr"},
    {"source": "../utils/persistent_mode/test-instr.c", "binary": "test-instr-persistent-shmem"},
]
modes = ["single-core", "multi-core"]
tree = lambda: defaultdict(tree) # recursive (arbitrary-depth) defaultdict!
results = tree()
between_tests = False
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action="store_true")
args = parser.parse_args()

async def clean_up() -> None:
    """Remove temporary files."""
    shutil.rmtree("in")
    for target in targets:
        os.remove(target["binary"])
        for mode in modes:
            for outdir in glob.glob(f"/tmp/out-{mode}-{target['binary']}*"):
                shutil.rmtree(outdir)

async def check_deps() -> None:
    """Check if the necessary files exist and are executable."""
    if not (os.access("../afl-fuzz", os.X_OK) and os.access("../afl-cc", os.X_OK) and os.path.exists("../SanitizerCoveragePCGUARD.so")):
        sys.exit(f'{red(" [*] Error: you need to compile AFL++ first, we need afl-fuzz, afl-clang-fast and SanitizerCoveragePCGUARD.so built.")}')

async def prep_env() -> dict:
    # Unset AFL_* environment variables
    for e in list(os.environ.keys()):
        if e.startswith("AFL_"):
            os.environ.pop(e)
    # Create input directory and file
    os.makedirs("in", exist_ok=True)
    with open("in/in.txt", "wb") as f:
        f.write(b"\x00" * 10240)
    # Rest of env
    AFL_PATH = os.path.abspath("../")
    os.environ["PATH"] = AFL_PATH + ":" + os.environ["PATH"]
    return {
        "AFL_BENCH_JUST_ONE": "1",
        "AFL_DISABLE_TRIM": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_UI": "1",
        "AFL_TRY_AFFINITY": "1",
        "PATH": f"{AFL_PATH}:{os.environ['PATH']}",
    }

async def compile_target(source: str, binary: str) -> None:
    (returncode, stdout, stderr) = await run_command(
        ["afl-cc", "-o", binary, source],
        env={"AFL_INSTRUMENT": "PCGUARD", "PATH": os.environ["PATH"]},
    )
    if returncode != 0:
        sys.exit(f'{red(f" [*] Error: afl-cc is unable to compile: {stderr} {stdout}")}')

async def cool_down() -> None:
    """Avoid the next test run's results being contaminated by e.g. thermal limits hit on this one."""
    global between_tests
    if between_tests:
        print(f'{blue("Taking a five second break to stay cool between tests.")}')
        await asyncio.sleep(10)
    else:
        between_tests = True

async def run_command(cmd, env) -> (int | None, bytes, bytes):
    if args.debug:
        print(blue(f"Launching command: {cmd} with env {env}"))
    p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    stdout, stderr = await p.communicate()
    return (p.returncode, stdout, stderr)

async def colon_value_or_none(filename: str, searchKey: str) -> str | None:
    """Read a value (e.g. 'cpu MHz         : 4976.109') given its filename and key."""
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

async def save_benchmark_results() -> None:
    """We want a consistent JSON file, so read in the existing one, append, and replace."""
    with open("benchmark-results.json", "r+") as jsonfile:
        current_benchmarks = json.load(jsonfile)
        current_benchmarks.append(results)
        jsonfile.seek(0)
        jsonfile.write(json.dumps(current_benchmarks, indent=2))
        jsonfile.truncate()
        print(json.dumps(results, indent=2))


async def main() -> None:
    print(f'{gray(" [*] Preparing environment")}')
    # Remove stale files, if necessary.
    try:
        await clean_up()
    except FileNotFoundError:
        pass
    await check_deps()
    env_vars = await prep_env()
    cpu_count = multiprocessing.cpu_count()
    results["cpu_model"] = await colon_value_or_none("/proc/cpuinfo", "model name")
    results["cpu_mhz"]   = await colon_value_or_none("/proc/cpuinfo", "cpu MHz")

    print(f'{gray(" [*] Ready, starting benchmark - this will take approx 1-2 minutes...")}')
    for target in targets:
        await compile_target(target["source"], target["binary"])
        for mode in modes:
            await cool_down()
            print(f" [*] {mode} {target['binary']} benchmark starting, execs/s: ", end="", flush=True)
            if mode == "single-core":
                cpus = [0]
            elif mode == "multi-core":
                cpus = range(0, cpu_count)
            basedir = f"/tmp/out-{mode}-{target['binary']}-"
            cmd = [["afl-fuzz", "-i", "in", "-o", f"{basedir}{cpu}", "-M", f"{cpu}", "-s", "123", "-D", f"./{target['binary']}"] for cpu in cpus]

            # Here's where we schedule the tasks, and then block waiting for them to finish.
            tasks = [run_command(cmd[cpu], env_vars) for cpu in cpus]
            output = await asyncio.gather(*tasks)

            if args.debug:
                for (_, stdout, stderr) in output:
                    print(blue(f"Output: {stdout.decode()} {stderr.decode()}"))
            execs = sum([Decimal(await colon_value_or_none(f"{basedir}{cpu}/{cpu}/fuzzer_stats", "execs_per_sec")) for cpu in cpus])
            print(green(execs))
            results["targets"][target["binary"]][mode]["execs_per_second"] = str(execs)
            results["targets"][target["binary"]][mode]["cores_used"] = len(cpus)

    print("\nComparison: (note that values can change by 10-20% per run)")
    with open("COMPARISON", "r") as f:
        print(f.read())
    await clean_up()
    await save_benchmark_results()

if __name__ == "__main__":
    asyncio.run(main())