#!/usr/bin/env python3
# Requires Python 3.6+.
# Author: Chris Ball <chris@printf.net>
# Ported from Marc "van Hauser" Heuse's "benchmark.sh".
import asyncio
import glob
import json
import multiprocessing
import os
import shutil
import sys
from decimal import Decimal

debug = False

targets = [
    {"source": "../test-instr.c", "binary": "test-instr"},
    {"source": "../utils/persistent_mode/test-instr.c", "binary": "test-instr-persistent-shmem"},
]
modes = ["single-core", "multi-core"]
results = {}

colors = {
    "blue": "\033[1;94m",
    "gray": "\033[1;90m",
    "green": "\033[0;32m",
    "red": "\033[0;31m",
    "reset": "\033[0m",
}

async def clean_up() -> None:
    """Remove temporary files."""
    shutil.rmtree("in")
    for target in targets:
        # os.remove(target["binary"])
        for mode in modes:
            for outdir in glob.glob(f"/tmp/out-{mode}-{target['binary']}*"):
                shutil.rmtree(outdir)

async def check_deps() -> None:
    """Check if the necessary files exist and are executable."""
    if not (os.access("../afl-fuzz", os.X_OK) and os.access("../afl-cc", os.X_OK) and os.path.exists("../SanitizerCoveragePCGUARD.so")):
        sys.exit(f"{colors['red']}Error: you need to compile AFL++ first, we need afl-fuzz, afl-clang-fast and SanitizerCoveragePCGUARD.so built.{colors['reset']}")

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
        sys.exit(f"{colors['red']} [*] Error: afl-cc is unable to compile: {stderr} {stdout}{colors['reset']}")

async def cool_down() -> None:
    """Avoid the next test run's results being contaminated by e.g. thermal limits hit on this one."""
    print(f"{colors['blue']}Taking a five second break to stay cool.{colors['reset']}")
    await asyncio.sleep(10)

async def run_command(args, env) -> (int | None, bytes, bytes):
    if debug:
        print(f"\n{colors['blue']}Launching command: {args} with env {env}{colors['reset']}")
    p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
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

async def main() -> None:
    # Remove stale files, if necessary.
    try:
        await clean_up()
    except FileNotFoundError:
        pass

    await check_deps()
    env_vars = await prep_env()
    cpu_count = multiprocessing.cpu_count()
    print(f"{colors['gray']} [*] Preparing environment{colors['reset']}")
    print(f"{colors['gray']} [*] Ready, starting benchmark - this will take approx 1-2 minutes...{colors['reset']}")
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
            args = [["afl-fuzz", "-i", "in", "-o", f"{basedir}{cpu}", "-M", f"{cpu}", "-s", "123", "-D", f"./{target['binary']}"] for cpu in cpus]
            tasks = [run_command(args[cpu], env_vars) for cpu in cpus]
            output = await asyncio.gather(*tasks)
            if debug:
                for _, (_, stdout, stderr) in enumerate(output):
                    print(f"{colors['blue']}Output: {stdout} {stderr}{colors['reset']}")
            execs = sum([Decimal(await colon_value_or_none(f"{basedir}{cpu}/{cpu}/fuzzer_stats", "execs_per_sec")) for cpu in cpus])
            print(f"{colors['green']}{execs}{colors['reset']}")

    print("\nComparison: (note that values can change by 10-20% per run)")
    with open("COMPARISON", "r") as f:
        print(f.read())
    await clean_up()

if __name__ == "__main__":
    asyncio.run(main())