#!/usr/bin/env python3
# Part of the aflplusplus project, requires Python 3.8+.
# Author: Chris Ball <chris@printf.net>, ported from Marc "van Hauser" Heuse's "benchmark.sh".
import argparse, asyncio, json, multiprocessing, os, platform, re, shutil, sys
from dataclasses import asdict, dataclass
from decimal import Decimal
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
    execs_per_sec: float
    execs_total: float
    fuzzers_used: int

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
    cpu_fastest_core_mhz: float
    cpu_model: str
    cpu_threads: int

@dataclass
class Results:
    config: Optional[Config]
    hardware: Optional[Hardware]
    targets: Dict[str, Dict[str, Optional[Run]]]

all_modes = [Mode.singlecore, Mode.multicore]
all_targets = [
    Target(source=Path("../utils/persistent_mode/test-instr.c").resolve(), binary=Path("test-instr-persist-shmem")),
    Target(source=Path("../test-instr.c").resolve(), binary=Path("test-instr"))
]
modes = [mode.name for mode in all_modes]
targets = [str(target.binary) for target in all_targets]
cpu_count = multiprocessing.cpu_count()
env_vars = {
    "AFL_DISABLE_TRIM": "1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_FAST_CAL": "1",
    "AFL_NO_UI": "1", "AFL_TRY_AFFINITY": "1", "PATH": f'{str(Path("../").resolve())}:{os.environ["PATH"]}',
}

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-b", "--basedir", help="directory to use for temp files", type=str, default="/tmp/aflpp-benchmark")
parser.add_argument("-d", "--debug", help="show verbose debugging output", action="store_true")
parser.add_argument("-r", "--runs", help="how many runs to average results over", type=int, default=3)
parser.add_argument("-f", "--fuzzers", help="how many afl-fuzz workers to use", type=int, default=cpu_count)
parser.add_argument("-m", "--mode", help="pick modes", action="append", default=modes, choices=modes)
parser.add_argument("-c", "--comment", help="add a comment about your setup", type=str, default="")
parser.add_argument("--cpu", help="override the detected CPU model name", type=str, default="")
parser.add_argument("--mhz", help="override the detected CPU MHz", type=str, default="")
parser.add_argument(
    "-t", "--target", help="pick targets", action="append", default=["test-instr-persist-shmem"], choices=targets
)
args = parser.parse_args()
# Really unsatisfying argparse behavior: we want a default and to allow multiple choices, but if there's a manual choice
# it should override the default.  Seems like we have to remove the default to get that and have correct help text?
if len(args.target) > 1:
    args.target = args.target[1:]
if len(args.mode) > 2:
    args.mode = args.mode[2:]

chosen_modes = [mode for mode in all_modes if mode.name in args.mode]
chosen_targets = [target for target in all_targets if str(target.binary) in args.target]
results = Results(config=None, hardware=None, targets={
    str(t.binary): {m.name: None for m in chosen_modes} for t in chosen_targets}
)
debug = lambda text: args.debug and print(blue(text))

async def clean_up_tempfiles() -> None:
    shutil.rmtree(f"{args.basedir}/in")
    for target in chosen_targets:
        target.binary.unlink()
        for mode in chosen_modes:
            shutil.rmtree(f"{args.basedir}/out-{mode.name}-{str(target.binary)}")

async def check_afl_persistent() -> bool:
    with open("/proc/cmdline", "r") as cmdline:
        return "mitigations=off" in cmdline.read().strip().split(" ")

async def check_afl_system() -> bool:
    sysctl = next((s for s in ["sysctl", "/sbin/sysctl"] if shutil.which(s)), None)
    if sysctl:
        (returncode, stdout, _) = await run_command([sysctl, "kernel.randomize_va_space"])
        return returncode == 0 and stdout.decode().rstrip().split(" = ")[1] == "0"
    return False

async def prep_env() -> None:
    Path(f"{args.basedir}/in").mkdir(exist_ok=True, parents=True)
    with open(f"{args.basedir}/in/in.txt", "wb") as seed:
        seed.write(b"\x00" * 10240)

async def compile_target(source: Path, binary: Path) -> None:
    print(f" [*] Compiling the {binary} fuzzing harness for the benchmark to use.")
    (returncode, stdout, stderr) = await run_command(
        [str(Path("../afl-clang-lto").resolve()), "-o", str(Path(binary.resolve())), str(Path(source).resolve())]
    )
    if returncode == 0:
        return
    print(yellow(f" [*] afl-clang-lto was unable to compile; falling back to afl-cc."))
    (returncode, stdout, stderr) = await run_command(
        [str(Path("../afl-cc").resolve()), "-o", str(Path(binary.resolve())), str(Path(source).resolve())]
    )
    if returncode != 0:
        sys.exit(red(f" [*] Error: afl-cc is unable to compile: {stderr.decode()} {stdout.decode()}"))

async def run_command(cmd: List[str]) -> Tuple[Optional[int], bytes, bytes]:
    debug(f"Launching command: {cmd} with env {env_vars}")
    p = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env_vars
    )
    stdout, stderr = await p.communicate()
    debug(f"Output: {stdout.decode()} {stderr.decode()}")
    return (p.returncode, stdout, stderr)

async def check_deps() -> None:
    if not (plat := platform.system()) == "Linux": sys.exit(red(f" [*] {plat} is not supported by this script yet."))
    if not os.access(Path("../afl-fuzz").resolve(), os.X_OK) and os.access(Path("../afl-cc").resolve(), os.X_OK) and (
        os.path.exists(Path("../SanitizerCoveragePCGUARD.so").resolve())):
        sys.exit(red(" [*] Compile AFL++: we need afl-fuzz, afl-clang-fast and SanitizerCoveragePCGUARD.so built."))

    (returncode, stdout, stderr) = await run_command([str(Path("../afl-cc").resolve()), "-v"])
    if returncode != 0:
        sys.exit(red(f" [*] Error: afl-cc -v returned: {stderr.decode()} {stdout.decode()}"))
    compiler = ""
    target_arch = ""
    for line in stderr.decode().split("\n"):
        if "clang version" in line:
            compiler = line
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

async def colon_values(filename: str, searchKey: str) -> List[str]:
    """Return a colon-separated value given a key in a file, e.g. 'cpu MHz         : 4976.109')"""
    with open(filename, "r") as fh:
        kv_pairs = (line.split(": ", 1) for line in fh if ": " in line)
        v_list = [v.rstrip() for k, v in kv_pairs if k.rstrip() == searchKey]
        return v_list

async def describe_afl_config() -> str:
   if results.config is None:
       return "unknown"
   elif results.config.afl_persistent_config and results.config.afl_system_config:
       return "both"
   elif results.config.afl_persistent_config:
       return "persistent"
   elif results.config.afl_system_config:
       return "system"
   else:
       return "none"

async def save_benchmark_results() -> None:
    """Append a single row to the benchmark results in JSON Lines format (which is simple to write and diff)."""
    with open("benchmark-results.jsonl", "a") as jsonfile:
        json.dump(asdict(results), jsonfile, sort_keys=True)
        jsonfile.write("\n")
        print(blue(f" [*] Results have been written to the {jsonfile.name} file."))
    with open("COMPARISON.md", "r+") as comparisonfile:
        described_config = await describe_afl_config()
        aflconfig = described_config.ljust(12)
        if results.hardware is None:
            return
        cpu_model = results.hardware.cpu_model.ljust(51)
        if cpu_model in comparisonfile.read():
            print(blue(f" [*] Results have not been written to the COMPARISON.md file; this CPU is already present."))
            return
        cpu_mhz = str(round(results.hardware.cpu_fastest_core_mhz)).ljust(5)
        if not "test-instr-persist-shmem" in results.targets or \
           not "multicore" in results.targets["test-instr-persist-shmem"] or \
           not "singlecore" in results.targets["test-instr-persist-shmem"] or \
           results.targets["test-instr-persist-shmem"]["singlecore"] is None or \
           results.targets["test-instr-persist-shmem"]["multicore"] is None:
            return
        single = str(round(results.targets["test-instr-persist-shmem"]["singlecore"].execs_per_sec)).ljust(10)
        multi = str(round(results.targets["test-instr-persist-shmem"]["multicore"].execs_per_sec)).ljust(9)
        cores = str(args.fuzzers).ljust(7)
        comparisonfile.write(f"|{cpu_model} | {cpu_mhz} | {cores} | {single} | {multi} | {aflconfig} |\n")
        print(blue(f" [*] Results have been written to the COMPARISON.md file."))
    with open("COMPARISON.md", "r") as comparisonfile:
        print(comparisonfile.read())


async def main() -> None:
    try:
        await clean_up_tempfiles()
    except FileNotFoundError:
        pass
    await check_deps()
    if args.mhz:
        cpu_mhz = float(args.mhz)
    else:
        cpu_mhz_str = await colon_values("/proc/cpuinfo", "cpu MHz")
        if len(cpu_mhz_str) == 0:
            cpu_mhz_str.append("0")
        cpu_mhz = max([float(c) for c in cpu_mhz_str]) # use the fastest CPU MHz for now
    if args.cpu:
        cpu_model = [args.cpu]
    else:
        cpu_model = await colon_values("/proc/cpuinfo", "model name") or [""]
    results.hardware = Hardware(cpu_fastest_core_mhz=cpu_mhz, cpu_model=cpu_model[0], cpu_threads=cpu_count)
    await prep_env()
    print(f" [*] Ready, starting benchmark...")
    for target in chosen_targets:
        await compile_target(target.source, target.binary)
        binary = str(target.binary)
        for mode in chosen_modes:
            if mode == Mode.multicore:
                print(blue(f" [*] Using {args.fuzzers} fuzzers for multicore fuzzing "), end="")
                print(blue("(use --fuzzers to override)." if args.fuzzers == cpu_count else f"(the default is {cpu_count})"))
            execs_per_sec, execs_total = ([] for _ in range(2))
            for run_idx in range(0, args.runs):
                print(gray(f" [*] {mode.name} {binary} run {run_idx+1} of {args.runs}, execs/s: "), end="", flush=True)
                fuzzers = range(0, args.fuzzers if mode == Mode.multicore else 1)
                outdir = f"{args.basedir}/out-{mode.name}-{binary}"
                cmds = []
                for fuzzer_idx, afl in enumerate(fuzzers):
                    name = ["-o", outdir, "-M" if fuzzer_idx == 0 else "-S", str(afl)]
                    cmds.append(["afl-fuzz", "-i", f"{args.basedir}/in"] + name + ["-s", "123", "-V10", "-D", f"./{binary}"])
                # Prepare the afl-fuzz tasks, and then block while waiting for them to finish.
                fuzztasks = [run_command(cmds[cpu]) for cpu in fuzzers]
                await asyncio.gather(*fuzztasks)
                afl_versions = await colon_values(f"{outdir}/0/fuzzer_stats", "afl_version")
                if results.config:
                    results.config.afl_version = afl_versions[0]
                # Our score is the sum of all execs_per_sec entries in fuzzer_stats files for the run.
                sectasks = [colon_values(f"{outdir}/{afl}/fuzzer_stats", "execs_per_sec") for afl in fuzzers]
                all_execs_per_sec = await asyncio.gather(*sectasks)
                execs = sum([Decimal(count[0]) for count in all_execs_per_sec])
                print(green(execs))
                execs_per_sec.append(execs)
                # Also gather execs_total and total_run_time for this run.
                exectasks = [colon_values(f"{outdir}/{afl}/fuzzer_stats", "execs_done") for afl in fuzzers]
                all_execs_total = await asyncio.gather(*exectasks)
                execs_total.append(sum([Decimal(count[0]) for count in all_execs_total]))

            # (Using float() because Decimal() is not JSON-serializable.)
            avg_afl_execs_per_sec = round(Decimal(sum(execs_per_sec) / len(execs_per_sec)), 2)
            afl_execs_total = int(sum([Decimal(execs) for execs in execs_total]))
            run = Run(execs_per_sec=float(avg_afl_execs_per_sec), execs_total=afl_execs_total, fuzzers_used=len(fuzzers))
            results.targets[binary][mode.name] = run
            print(f" [*] Average execs/sec for this test across all runs was: {green(avg_afl_execs_per_sec)}")
            if (((max(execs_per_sec) - min(execs_per_sec)) / avg_afl_execs_per_sec) * 100) > 15:
                print(yellow(" [*] The difference between your slowest and fastest runs was >15%, maybe try again?"))

    await clean_up_tempfiles()
    await save_benchmark_results()

if __name__ == "__main__":
    asyncio.run(main())

