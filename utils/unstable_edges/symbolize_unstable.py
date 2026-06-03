#!/usr/bin/env python3
"""
Symbolize unstable edges using pcmap and module info.

Reads var_bytes from fuzzer_stats, looks up edge IDs in pcmap.dump,
and symbolizes each unstable edge using modinfo.txt.
"""

import sys
import subprocess
import argparse
import logging
from pathlib import Path
from multiprocessing import Pool, cpu_count
from functools import partial

LOG = logging.getLogger(__name__)


def parse_modinfo(modinfo_path: Path):
    """Extract list of modules names as well as start and stop edge IDs"""
    modules = []
    with open(modinfo_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # Format: /path/to/module.so 7150 7648
            if len(parts) != 3:
                continue
            module_path = parts[0]
            start_id = int(parts[1])
            stop_id = int(parts[2])
            modules.append((module_path, start_id, stop_id))
    return modules


def parse_var_bytes(fuzzer_stats_path: Path):
    """Extract unstable edges from fuzzer_stats."""
    with open(fuzzer_stats_path, "r") as f:
        for line in f:
            if line.startswith("var_bytes"):
                # Format: var_bytes        : 0 732045 732046 2016001 ...
                parts = line.split(":", 1)
                if len(parts) == 2:
                    edge_ids_str = parts[1].strip()
                    if edge_ids_str:
                        return set(int(e) for e in edge_ids_str.split())
    return set()


def parse_pcmap(pcmap_path: Path):
    """Parse pcmap.dump and return dict of edge_id => pc_offset."""
    pcmap = {}
    with open(pcmap_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # Format: 5 0x15df17
            if len(parts) != 2:
                continue
            edge_id = int(parts[0])
            pc_offset = int(parts[1], 16)
            pcmap[edge_id] = pc_offset
    return pcmap


def find_module_for_edge(edge_id: int, modules: list[tuple[str, int, int]]):
    """Find module for the given edge_id."""
    for module_path, start_id, stop_id in modules:
        if start_id <= edge_id <= stop_id:
            return module_path
    return None


def symbolize_address(module_path: str, pc_offset: int):
    """Call llvm-symbolizer to symbolize a PC offset in a module."""
    try:
        result = subprocess.run(
            ["llvm-symbolizer", f"--obj={module_path}", f"0x{pc_offset:x}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            # llvm-symbolizer outputs function name on first line, location on second
            # For inlined functions, it outputs multiple pairs
            # Just take the last location (innermost)
            if len(lines) >= 2:
                location = lines[-1]
                return (
                    location
                    if location and location != "??:0" and location != "??:?"
                    else None
                )
        return None
    except Exception:
        return None


def process_edge(edge_data: tuple, pcmap: dict, modules: list):
    """Process a single edge for symbolization."""
    edge_id = edge_data

    if edge_id not in pcmap:
        return (edge_id, None, "not_in_pcmap")

    pc_offset = pcmap[edge_id]
    module_name = find_module_for_edge(edge_id, modules)

    if not module_name:
        return (edge_id, pc_offset, "no_module")

    location = symbolize_address(module_name, pc_offset)

    if location:
        return (edge_id, pc_offset, location)
    else:
        return (edge_id, pc_offset, f"failed:{module_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Symbolize unstable edges from AFL++ fuzzer output"
    )
    parser.add_argument(
        "dump_path",
        type=Path,
        help="Path to AFL output directory (i.e. ./output/default/)",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=cpu_count(),
        help=f"Number of parallel jobs for symbolization (default: {cpu_count()})",
    )

    args = parser.parse_args()

    logging.basicConfig(format="%(message)s", level=logging.INFO)

    if not args.dump_path.is_dir():
        parser.error("AFL output directory does not exist")

    for filename in ["pcmap.dump", "modinfo.txt", "fuzzer_stats"]:
        if not (args.dump_path / filename).is_file():
            parser.error(f"Unable to locate {filename} in output directory")

    unstable_edges = parse_var_bytes(args.dump_path / "fuzzer_stats")
    if not unstable_edges:
        LOG.warning("No unstable edges found in fuzzer_stats")
        sys.exit(0)

    pcmap = parse_pcmap(args.dump_path / "pcmap.dump")
    modules = parse_modinfo(args.dump_path / "modinfo.txt")

    LOG.info(f"Symbolizing {len(unstable_edges)} unstable edges using {args.jobs} workers...")

    worker_func = partial(process_edge, pcmap=pcmap, modules=modules)

    with Pool(processes=args.jobs) as pool:
        results = pool.map(worker_func, sorted(unstable_edges))

    # Process results in order
    for edge_id, pc_offset, result in sorted(results, key=lambda x: x[0]):
        if result == "not_in_pcmap":
            LOG.warning(f"Could not find edge {edge_id} in pcmap")
        elif result == "no_module":
            LOG.warning(
                f"Could not find module for edge {edge_id} - PC: 0x{pc_offset:x}"
            )
        elif result.startswith("failed:"):
            module_name = result.split(":", 1)[1]
            LOG.warning(
                f"Could not symbolize edge {edge_id} - PC: 0x{pc_offset:x}, Module: {module_name})"
            )
        else:
            print(f"{edge_id} 0x{pc_offset:x} {result}")


if __name__ == "__main__":
    main()
