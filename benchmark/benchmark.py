#!/usr/bin/env python3
# Part of the aflplusplus project, requires Python 3.9+.
# Author: Chris Ball <chris@printf.net>, ported from Marc "van Hauser" Heuse's "benchmark.sh".
import argparse, asyncio, datetime, json, multiprocessing, os, platform, re, shutil, sys
from dataclasses import asdict, dataclass
from decimal import Decimal
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Union

blue   = lambda text: f"\033[1;94m{text}\033[0m"; gray = lambda text: f"\033[1;90m{text}\033[0m"
green  = lambda text: f"\033[0;32m{text}\033[0m"; red  = lambda text: f"\033[0;31m{text}\033[0m"
yellow = lambda text: f"\033[0;33m{text}\033[0m"

class Mode(Enum):
    multicore  = auto()
    singlecore = auto()

@dataclass
class Target:
    source: Path
    binary: Path

@dataclass
class Run:
    afl_execs_per_sec: float
    afl_execs_total: float
    fuzzers_used: int
    run_end: str
    run_start: str
    total_execs_per_sec: float
    total_run_time: float

@dataclass
class Config:
    afl_persistent_config: bool
    afl_system_config: bool
    afl_version: Optional[str]
    comment: str
    compiler: str
    target_arch: str

@dataclass
class Hardware:
    cpu_fastest_core_mhz: Optional[float]
    cpu_model: Optional[str]
    cpu_threads: int

@dataclass
class Results:
    config: Optional[Config]
    hardware: Optional[Hardware]
    targets: dict[str, dict[str, Optional[Run]]]

all_modes = [Mode.singlecore, Mode.multicore]
all_targets = [
    Target(source=Path("../utils/persistent_mode/test-instr.c").resolve(), binary=Path("test-instr-persist-shmem")),
    Target(source=Path("../test-instr.c").resolve(), binary=Path("test-instr"))
]
mode_names = [mode.name for mode in all_modes]
target_names = [str(target.binary) for target in all_targets]
cpu_count = multiprocessing.cpu_count()

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-b", "--basedir", help="directory to use for temp files", type=str, default="/tmp/aflpp-benchmark")
parser.add_argument("-d", "--debug", help="show verbose debugging output", action="store_true")
parser.add_argument("-r", "--runs", help="how many runs to average results over", type=int, default=5)
parser.add_argument("-f", "--fuzzers", help="how many afl-fuzz workers to use", type=int, default=cpu_count)
parser.add_argument("-m", "--mode", help="pick modes", action="append", default=["multicore"], choices=mode_names)
parser.add_argument("-c", "--comment", help="add a comment about your setup", type=str, default="")
parser.add_argument(
    "-t", "--target", help="pick targets", action="append", default=["test-instr-persist-shmem"], choices=target_names
)
args = parser.parse_args()
# Really unsatisfying argparse behavior: we want a default and to allow multiple choices, but if there's a manual choice
# it should override the default.  Seems like we have to remove the default to get that and have correct help text?
if len(args.target) > 1: args.target = args.target[1:]
if len(args.mode) > 1: args.mode = args.mode[1:]

targets = [target for target in all_targets if str(target.binary) in args.target]
modes = [mode for mode in all_modes if mode.name in args.mode]
results = Results(config=None, hardware=None, targets={str(t.binary): {m.name: None for m in modes} for t in targets})
debug = lambda text: args.debug and print(blue(text))
if Mode.multicore in modes:
    print(blue(f" [*] Using {args.fuzzers} fuzzers for multicore fuzzing "), end="")
    print(blue("(use --fuzzers to override)" if args.fuzzers == cpu_count else f"(the default is {cpu_count})"))

async def clean_up_tempfiles() -> None:
    shutil.rmtree(f"{args.basedir}/in")
    for target in targets:
        target.binary.unlink()
        for mode in modes:
            shutil.rmtree(f"{args.basedir}/out-{mode.name}-{str(target.binary)}")

async def check_afl_persistent() -> bool:
    with open("/proc/cmdline", "r") as cpuinfo:
        return "mitigations=off" in cpuinfo.read().split(" ")

async def check_afl_system() -> bool:
    sysctl = next((s for s in ["sysctl", "/sbin/sysctl"] if shutil.which(s)), None)
    if sysctl:
        (returncode, stdout, _) = await run_command([sysctl, "kernel.randomize_va_space"], None)
        return returncode == 0 and stdout.decode().rstrip().split(" = ")[1] == "0"
    return False

async def prep_env() -> dict:
    Path(f"{args.basedir}/in").mkdir(exist_ok=True, parents=True)
    with open(f"{args.basedir}/in/in.txt", "wb") as seed: seed.write(b"\x00" * 10240)
    return {
        "AFL_BENCH_JUST_ONE": "1", "AFL_DISABLE_TRIM": "1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_UI": "1", "AFL_TRY_AFFINITY": "1", "PATH": str(Path("../").resolve()),
    }

async def compile_target(source: Path, binary: Path) -> None:
    print(f" [*] Compiling the {binary} fuzzing harness for the benchmark to use.")
    (returncode, stdout, stderr) = await run_command(
        [str(Path("../afl-clang-lto").resolve()), "-o", str(Path(binary.resolve())), str(Path(source).resolve())],
        env={"AFL_LLVM_INSTRUMENT": "PCGUARD"},
    )
    if returncode != 0:
        print(yellow(f" [*] afl-clang-lto was unable to compile; falling back to afl-cc."))

    (returncode, stdout, stderr) = await run_command(
        [str(Path("../afl-cc").resolve()), "-o", str(Path(binary.resolve())), str(Path(source).resolve())],
        env={"AFL_LLVM_INSTRUMENT": "PCGUARD"},
    )
    if returncode != 0:
        sys.exit(red(f" [*] Error: afl-cc is unable to compile: {stderr.decode()} {stdout.decode()}"))

async def run_command(cmd: list[str], env: Union[dict, None]) -> tuple[Union[int, None], bytes, bytes]:
    debug(f"Launching command: {cmd} with env {env}")
    p = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    stdout, stderr = await p.communicate()
    debug(f"Output: {stdout.decode()} {stderr.decode()}")
    return (p.returncode, stdout, stderr)

async def check_deps() -> None:
    if not (plat := platform.system()) == "Linux": sys.exit(red(f" [*] {plat} is not supported by this script yet."))
    if not os.access(Path("../afl-fuzz").resolve(), os.X_OK) and os.access(Path("../afl-cc").resolve(), os.X_OK) and (
        os.path.exists(Path("../SanitizerCoveragePCGUARD.so").resolve())):
        sys.exit(red(" [*] Compile AFL++: we need afl-fuzz, afl-clang-fast and SanitizerCoveragePCGUARD.so built."))

    (returncode, stdout, stderr) = await run_command([str(Path("../afl-cc").resolve()), "-v"], env={})
    if returncode != 0:
        sys.exit(red(f" [*] Error: afl-cc -v returned: {stderr.decode()} {stdout.decode()}"))
    compiler = ""
    target_arch = ""
    for line in stderr.decode().split("\n"):
        if m := re.match(r"^(clang version .*)", line):
            compiler = m.group(1)
        elif m := re.match(r"^Target: (.*)", line):
            target_arch = m.group(1)

    # Pick some sample settings from afl-{persistent,system}-config to try to see whether they were run.
    afl_pc = await check_afl_persistent()
    afl_sc = await check_afl_system()
    if not afl_pc:
        print(yellow(f" [*] afl-persistent-config did not run; run it to improve performance (and decrease security)."))
    if not afl_sc:
        print(yellow(f" [*] afl-system-config did not run; run it to improve performance (and decrease security)."))

    results.config = Config(afl_persistent_config=afl_pc, afl_system_config=afl_sc, afl_version="",
                            comment=args.comment, compiler=compiler, target_arch=target_arch)

async def colon_values(filename: str, searchKey: str) -> list[str]:
    """Return a colon-separated value given a key in a file, e.g. 'cpu MHz         : 4976.109')"""
    with open(filename, "r") as fh:
        kv_pairs = (line.split(": ", 1) for line in fh if ": " in line)
        v_list = [v.rstrip() for k, v in kv_pairs if k.rstrip() == searchKey]
        return v_list

async def save_benchmark_results() -> None:
    """Append a single row to the benchmark results in JSON Lines format (which is simple to write and diff)."""
    with open("benchmark-results.jsonl", "a") as jsonfile:
        json.dump(asdict(results), jsonfile, sort_keys=True)
        jsonfile.write("\n")
        print(blue(f" [*] Results have been written to {jsonfile.name}"))


async def main() -> None:
    try:
        await clean_up_tempfiles()
    except FileNotFoundError:
        pass
    await check_deps()
    cpu_mhz_str = await colon_values("/proc/cpuinfo", "cpu MHz")
    cpu_mhz = max([float(c) for c in cpu_mhz_str]) # use the fastest CPU MHz for now
    cpu_model = await colon_values("/proc/cpuinfo", "model name")
    # Only record the first core's speed for now, even though it can vary between cores.
    results.hardware = Hardware(cpu_fastest_core_mhz=cpu_mhz, cpu_model=cpu_model[0], cpu_threads=cpu_count)
    env_vars = await prep_env()
    print(f" [*] Ready, starting benchmark...")
    for target in targets:
        await compile_target(target.source, target.binary)
        binary = str(target.binary)
        for mode in modes:
            afl_execs_per_sec, execs_total, run_time_total = ([] for _ in range(3))
            for run_idx in range(0, args.runs):
                print(gray(f" [*] {mode.name} {binary} run {run_idx+1} of {args.runs}, execs/s: "), end="", flush=True)
                fuzzers = range(0, args.fuzzers if mode == Mode.multicore else 1)
                outdir = f"{args.basedir}/out-{mode.name}-{binary}"
                cmds = []
                for fuzzer_idx, afl in enumerate(fuzzers):
                    name = ["-o", outdir, "-M" if fuzzer_idx == 0 else "-S", str(afl)]
                    cmds.append(["afl-fuzz", "-i", f"{args.basedir}/in"] + name + ["-s", "123", "-D", f"./{binary}"])

                # Prepare the afl-fuzz tasks, and then block while waiting for them to finish.
                fuzztasks = [run_command(cmds[cpu], env_vars) for cpu in fuzzers]
                start_time = datetime.datetime.now()
                await asyncio.gather(*fuzztasks)
                end_time = datetime.datetime.now()
                afl_versions = await colon_values(f"{outdir}/0/fuzzer_stats", "afl_version")
                if results.config:
                    results.config.afl_version = afl_versions[0]

                # Our score is the sum of all execs_per_sec entries in fuzzer_stats files for the run.
                sectasks = [colon_values(f"{outdir}/{afl}/fuzzer_stats", "execs_per_sec") for afl in fuzzers]
                all_execs_per_sec = await asyncio.gather(*sectasks)
                execs = sum([Decimal(count[0]) for count in all_execs_per_sec])
                print(green(execs))
                afl_execs_per_sec.append(execs)

                # Also gather execs_total and total_run_time for this run.
                exectasks = [colon_values(f"{outdir}/{afl}/fuzzer_stats", "execs_done") for afl in fuzzers]
                all_execs_total = await asyncio.gather(*exectasks)
                execs_total.append(sum([Decimal(count[0]) for count in all_execs_total]))
                run_time_total.append((end_time - start_time).total_seconds())

            # (Using float() because Decimal() is not JSON-serializable.)
            avg_afl_execs_per_sec = round(Decimal(sum(afl_execs_per_sec) / len(afl_execs_per_sec)), 2)
            afl_execs_total = int(sum([Decimal(execs) for execs in execs_total]))
            total_run_time = float(round(Decimal(sum(run_time_total)), 2))
            total_execs_per_sec = float(round(Decimal(afl_execs_total / total_run_time), 2))
            run = Run(afl_execs_per_sec=float(avg_afl_execs_per_sec), afl_execs_total=afl_execs_total,
                      fuzzers_used=len(fuzzers), run_end=str(end_time), run_start=str(start_time),
                      total_execs_per_sec=total_execs_per_sec, total_run_time=total_run_time)
            results.targets[binary][mode.name] = run

            print(f" [*] Average AFL execs/sec for this test across all runs was: {green(avg_afl_execs_per_sec)}")
            print(f" [*] Average total execs/sec for this test across all runs was: {green(total_execs_per_sec)}")
            if (((max(afl_execs_per_sec) - min(afl_execs_per_sec)) / avg_afl_execs_per_sec) * 100) > 15:
                print(yellow(" [*] The difference between your slowest and fastest runs was >15%, maybe try again?"))

    await clean_up_tempfiles()
    await save_benchmark_results()

if __name__ == "__main__":
    asyncio.run(main())

