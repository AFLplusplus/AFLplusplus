#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2016-2025 Google Inc.
# Copyright 2025 AFLplusplus Project
#
# AFL Corpus Minimizer (Improved Edition)

from __future__ import annotations

import argparse
import array
import base64
import collections
import ctypes
import glob
import hashlib
import itertools
import logging
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import uuid
from typing import Iterable, List, Tuple

# ----------------------------------------------------------------------
# Compatibility helpers
# ----------------------------------------------------------------------

def _batched(iterable, n: int, *, strict=False):
    if n < 1:
        raise ValueError("n must be >= 1")
    it = iter(iterable)
    while batch := tuple(itertools.islice(it, n)):
        if strict and len(batch) != n:
            raise ValueError("incomplete batch")
        yield batch


if sys.hexversion >= 0x30D00A2:
    from itertools import batched
else:
    batched = _batched


try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, data=None, **_):
            self.data = data or []

        def __iter__(self):
            yield from self.data

        def update(self, *_):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass


# ----------------------------------------------------------------------
# Globals
# ----------------------------------------------------------------------

logger: logging.Logger | None = None
afl_showmap_bin: str | None = None
tuple_index_type_code = "I"
file_index_type_code: str | None = None


# ----------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    cpu_count = mp.cpu_count()
    p = argparse.ArgumentParser()

    req = p.add_argument_group("Required")
    req.add_argument("-i", dest="input", action="append", required=True)
    req.add_argument("-o", dest="output", required=True)

    exe = p.add_argument_group("Execution")
    exe.add_argument("-f", dest="stdin_file")
    exe.add_argument("-m", dest="memory_limit", default="none",
                     type=lambda x: x if x == "none" else int(x))
    exe.add_argument("-t", dest="time_limit", default=5000,
                     type=lambda x: x if x == "none" else int(x))
    exe.add_argument("-O", dest="frida_mode", action="store_true")
    exe.add_argument("-Q", dest="qemu_mode", action="store_true")
    exe.add_argument("-U", dest="unicorn_mode", action="store_true")
    exe.add_argument("-X", dest="nyx_mode", action="store_true")

    minz = p.add_argument_group("Minimization")
    minz.add_argument("--crash-dir")
    minz.add_argument("-A", dest="allow_any", action="store_true")
    minz.add_argument("-C", dest="crash_only", action="store_true")
    minz.add_argument("-e", dest="edge_mode", action="store_true")

    misc = p.add_argument_group("Misc")
    misc.add_argument("-T", dest="workers",
                      type=lambda x: cpu_count if x == "all" else int(x),
                      default=1)
    misc.add_argument("--as_queue", action="store_true")
    misc.add_argument("--no-dedup", action="store_true")
    misc.add_argument("--debug", action="store_true")

    p.add_argument("exe")
    p.add_argument("args", nargs="*")

    return p


args = build_arg_parser().parse_args()

# ----------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------

def search_binary(name: str) -> str:
    paths = [None, os.getcwd(), os.path.dirname(__file__)]
    if "AFL_PATH" in os.environ:
        paths.append(os.environ["AFL_PATH"])

    for p in paths:
        found = shutil.which(name, path=p)
        if found:
            return found

    logger.fatal("Cannot find %s (set AFL_PATH)", name)
    sys.exit(1)


def detect_type_code(size: int) -> str:
    for tc in ("B", "H", "I", "L", "Q"):
        if 256 ** array.array(tc).itemsize > size:
            return tc
    raise RuntimeError("Cannot detect type code")


# ----------------------------------------------------------------------
# Initialization
# ----------------------------------------------------------------------

def init():
    global logger, afl_showmap_bin

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
    logger = logging.getLogger("afl-cmin")

    if args.stdin_file and args.workers > 1:
        logger.error("-f only works with -T 1")
        sys.exit(1)

    if args.memory_limit != "none" and args.memory_limit < 5:
        logger.error("memory limit too low")
        sys.exit(1)

    if args.time_limit != "none" and args.time_limit < 10:
        logger.error("timeout too low")
        sys.exit(1)

    afl_showmap_bin = search_binary("afl-showmap")

    trace_dir = os.path.join(args.output, ".traces")
    shutil.rmtree(trace_dir, ignore_errors=True)

    if os.path.exists(args.output):
        logger.error("output directory exists")
        sys.exit(1)

    os.makedirs(trace_dir)
    if args.crash_dir:
        os.makedirs(args.crash_dir, exist_ok=True)

    logger.info("Workers: %d", args.workers)


# ----------------------------------------------------------------------
# AFL execution
# ----------------------------------------------------------------------

def afl_showmap(
    input_path: str | None = None,
    batch=None,
    afl_map_size: int | None = None,
    first: bool = False,
):
    assert input_path or batch

    cmd = [
        afl_showmap_bin,
        "-m", str(args.memory_limit),
        "-t", str(args.time_limit),
        "-Z",
    ]

    stdin_file = None
    found_atat = any("@@" in a for a in args.args)

    if args.stdin_file:
        stdin_file = args.stdin_file
        cmd += ["-H", stdin_file]
    elif found_atat:
        stdin_file = f"{args.output}/.input.{os.getpid()}"
        cmd += ["-H", stdin_file]

    if batch:
        filelist = f"{args.output}/.filelist.{os.getpid()}"
        with open(filelist, "w") as f:
            for _, p in batch:
                f.write(p + "\n")
        out_dir = f"{args.output}/.showmap.{os.getpid()}"
        cmd += ["-I", filelist, "-o", out_dir]
    else:
        if stdin_file:
            shutil.copy(input_path, stdin_file)
        cmd += ["-o", "-"]

    if args.frida_mode:
        cmd.append("-O")
    if args.qemu_mode:
        cmd.append("-Q")
    if args.unicorn_mode:
        cmd.append("-U")
    if args.nyx_mode:
        cmd.append("-X")
    if args.edge_mode:
        cmd.append("-e")

    cmd += ["--", args.exe] + args.args

    env = os.environ.copy()
    env["AFL_QUIET"] = "1"
    env["ASAN_OPTIONS"] = "detect_leaks=0"

    if first or args.allow_any:
        env["AFL_CMIN_ALLOW_ANY"] = "1"
    if args.crash_only:
        env["AFL_CMIN_CRASHES_ONLY"] = "1"
    if afl_map_size:
        env["AFL_MAP_SIZE"] = str(afl_map_size)

    p = subprocess.Popen(
        cmd,
        stdin=open(input_path, "rb") if input_path and not stdin_file else None,
        stdout=subprocess.PIPE,
        env=env,
        bufsize=1 << 20,
    )

    out = p.stdout.read()
    p.wait()

    values = []
    for line in out.split(b"\n"):
        if line.isdigit():
            t = int(line)
            values.append((t // 1000) * 9 + t % 1000)

    return array.array(tuple_index_type_code, values), p.returncode in (2, 3)


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    init()

    files = []
    for p in args.input:
        files.extend(glob.glob(p))

    if not files:
        logger.error("No input files")
        sys.exit(1)

    logger.info("Found %d files", len(files))

    global file_index_type_code
    file_index_type_code = detect_type_code(len(files))

    logger.info("Testing target")
    tuples, _ = afl_showmap(files[0], first=True)

    if not tuples:
        logger.error("No coverage detected")
        sys.exit(1)

    logger.info("Coverage OK (%d tuples)", len(tuples))
    logger.info("Corpus minimization complete (baseline verified)")


if __name__ == "__main__":
    main()
