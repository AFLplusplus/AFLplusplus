"""AFL++ MCP Server tools implementation."""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from .models import (
    FuzzingStats,
    QueueEntry,
    CrashInfo,
    Strategy,
    CoverageInfo,
)


def _resolve_output_dir(output_dir: Optional[str]) -> str:
    """Resolve the AFL++ output directory."""
    if output_dir:
        return output_dir
    env = os.environ.get("AFL_OUTPUT_DIR")
    if env:
        return env
    raise ValueError(
        "output_dir is required: pass it explicitly or set AFL_OUTPUT_DIR"
    )


def _parse_queue_filename(filename: str) -> Dict[str, Any]:
    """Parse an AFL++ queue filename into its components.

    Format: id:NNNNNN,time:NNNN,orig:NAME[,op:OP,src:NNNNNN]
    Or SIMPLE_FILES: id_NNNNNN
    """
    info: Dict[str, Any] = {"filename": filename}
    if filename.startswith("id:"):
        parts = filename.split(",")
        for part in parts:
            if ":" in part:
                k, _, v = part.partition(":")
                if k == "id":
                    info["id"] = int(v)
                elif k == "time":
                    info["time"] = int(v)
                elif k == "orig":
                    info["is_original"] = True
                    info["original_name"] = v
                elif k == "src":
                    info["parent_id"] = int(v)
                elif k == "op":
                    info["op"] = v
    elif filename.startswith("id_"):
        try:
            info["id"] = int(filename.split("_")[1].split(",")[0])
        except (IndexError, ValueError):
            pass
    return info


def _parse_crash_filename(filename: str) -> Dict[str, Any]:
    """Parse an AFL++ crash filename into its components.

    Format: id:NNNNNN,sig:NN,src:NNNNNN,time:NNNN,op:OP,rep:NN
    """
    info: Dict[str, Any] = {"filename": filename}
    if not filename.startswith("id:") and not filename.startswith("id_"):
        return info
    parts = filename.split(",")
    for part in parts:
        if ":" not in part:
            continue
        k, _, v = part.partition(":")
        if k == "id":
            info["id"] = int(v)
        elif k == "sig":
            info["signal"] = int(v)
        elif k == "src":
            info["source_id"] = int(v)
        elif k == "time":
            info["time"] = int(v)
        elif k == "op":
            info["op"] = v
        elif k == "rep":
            info["rep"] = int(v)
    return info


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def get_stats(output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Get current fuzzing statistics by parsing fuzzer_stats.

    Returns a dict mirroring FuzzingStats fields.
    """
    out = _resolve_output_dir(output_dir)
    stats_path = Path(out) / "fuzzer_stats"
    if not stats_path.exists():
        raise FileNotFoundError(f"fuzzer_stats not found at {stats_path}")
    content = stats_path.read_text(errors="replace")
    stats = FuzzingStats.from_stats_file(content)
    return stats.to_dict()


def list_queue(
    output_dir: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List test cases in the queue/ directory."""
    out = _resolve_output_dir(output_dir)
    queue_dir = Path(out) / "queue"
    if not queue_dir.exists():
        raise FileNotFoundError(f"queue directory not found at {queue_dir}")

    entries: List[Dict[str, Any]] = []
    files = sorted(queue_dir.iterdir())
    for fpath in files:
        if not fpath.is_file():
            continue
        parsed = _parse_queue_filename(fpath.name)
        entry = QueueEntry(
            path=str(fpath),
            filename=fpath.name,
            size=fpath.stat().st_size,
            is_original=parsed.get("is_original", False),
            parent_id=parsed.get("parent_id"),
        )
        entries.append(entry.to_dict())

    total = len(entries)
    page = entries[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "entries": page}


def analyze_queue(output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Analyze queue characteristics: size distribution, origins, etc."""
    out = _resolve_output_dir(output_dir)
    queue_dir = Path(out) / "queue"
    if not queue_dir.exists():
        raise FileNotFoundError(f"queue directory not found at {queue_dir}")

    sizes: List[int] = []
    originals = 0
    mutations = 0
    for fpath in queue_dir.iterdir():
        if not fpath.is_file():
            continue
        sizes.append(fpath.stat().st_size)
        parsed = _parse_queue_filename(fpath.name)
        if parsed.get("is_original"):
            originals += 1
        else:
            mutations += 1

    if not sizes:
        return {
            "count": 0,
            "originals": 0,
            "mutations": 0,
            "size_min": 0,
            "size_max": 0,
            "size_avg": 0.0,
            "size_median": 0,
        }

    sizes_sorted = sorted(sizes)
    n = len(sizes_sorted)
    median = (
        sizes_sorted[n // 2]
        if n % 2
        else (sizes_sorted[n // 2 - 1] + sizes_sorted[n // 2]) / 2
    )
    return {
        "count": n,
        "originals": originals,
        "mutations": mutations,
        "size_min": min(sizes),
        "size_max": max(sizes),
        "size_avg": sum(sizes) / n,
        "size_median": median,
    }


def list_crashes(
    output_dir: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List crash samples in the crashes/ directory."""
    out = _resolve_output_dir(output_dir)
    crashes_dir = Path(out) / "crashes"
    if not crashes_dir.exists():
        raise FileNotFoundError(f"crashes directory not found at {crashes_dir}")

    entries: List[Dict[str, Any]] = []
    for fpath in sorted(crashes_dir.iterdir()):
        if not fpath.is_file():
            continue
        if fpath.name == "README.txt":
            continue
        parsed = _parse_crash_filename(fpath.name)
        info = CrashInfo(
            path=str(fpath),
            filename=fpath.name,
            signal=parsed.get("signal", 0),
            source_id=parsed.get("source_id"),
            time=parsed.get("time"),
            op=parsed.get("op", ""),
            rep=parsed.get("rep"),
            size=fpath.stat().st_size,
        )
        entries.append(info.to_dict())

    total = len(entries)
    page = entries[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "crashes": page}


def analyze_crash(
    crash_path: str,
    target_binary: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze a single crash sample.

    If target_binary is provided, runs it under the binary to capture the
    signal and stderr output. Otherwise, only reports file metadata.
    """
    p = Path(crash_path)
    if not p.exists():
        raise FileNotFoundError(f"crash file not found: {crash_path}")

    parsed = _parse_crash_filename(p.name)
    info: Dict[str, Any] = {
        "path": str(p),
        "filename": p.name,
        "size": p.stat().st_size,
        "signal": parsed.get("signal", 0),
        "source_id": parsed.get("source_id"),
        "op": parsed.get("op", ""),
    }

    if target_binary and shutil.which(target_binary):
        try:
            result = subprocess.run(
                [target_binary, crash_path],
                input=p.read_bytes(),
                capture_output=True,
                timeout=10,
            )
            info["exit_code"] = result.returncode
            info["stderr_tail"] = result.stderr.decode(errors="replace")[-1024:]
            if result.returncode < 0:
                info["observed_signal"] = -result.returncode
        except subprocess.TimeoutExpired:
            info["error"] = "timeout running target binary"
        except Exception as e:
            info["error"] = str(e)

    return info


def minimize_crash(
    crash_path: str,
    output_dir: Optional[str] = None,
    target_binary: Optional[str] = None,
) -> Dict[str, Any]:
    """Minimize a crash sample using afl-tmin if available.

    Returns the path to the minimized crash and size reduction info.
    """
    out = _resolve_output_dir(output_dir)
    crash_p = Path(crash_path)
    if not crash_p.exists():
        raise FileNotFoundError(f"crash file not found: {crash_path}")

    if not target_binary:
        raise ValueError("target_binary is required for crash minimization")

    afl_tmin = shutil.which("afl-tmin")
    if not afl_tmin:
        raise RuntimeError(
            "afl-tmin not found in PATH; install AFL++ or provide path"
        )

    minimized = Path(out) / "crashes" / f"{crash_p.name}.minimized"
    original_size = crash_p.stat().st_size

    try:
        result = subprocess.run(
            [
                afl_tmin,
                "-i",
                str(crash_p),
                "-o",
                str(minimized),
                "-t",
                "5000",
                "--",
                target_binary,
            ],
            capture_output=True,
            timeout=120,
            text=True,
        )
        if minimized.exists():
            new_size = minimized.stat().st_size
            return {
                "original_path": str(crash_p),
                "minimized_path": str(minimized),
                "original_size": original_size,
                "minimized_size": new_size,
                "reduction_bytes": original_size - new_size,
                "reduction_percent": (
                    (original_size - new_size) / original_size * 100
                    if original_size
                    else 0
                ),
                "afl_tmin_stderr": result.stderr[-2048:],
            }
        return {
            "error": "afl-tmin did not produce output",
            "stderr": result.stderr[-2048:],
        }
    except subprocess.TimeoutExpired:
        return {"error": "afl-tmin timed out"}
    except Exception as e:
        return {"error": str(e)}


def get_coverage(output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Get coverage information from fuzzer_stats and bitmap."""
    stats = get_stats(output_dir)
    edges_found = stats.get("edges_found", 0)
    total_edges = stats.get("total_edges", 0)
    bitmap_cvg = stats.get("bitmap_cvg", 0.0)
    stability = stats.get("stability", 0.0)
    var_byte_count = stats.get("var_byte_count", 0)

    count_coverage = 0.0
    if edges_found:
        count_coverage = (total_edges * 8) / edges_found

    cov = CoverageInfo(
        edges_found=edges_found,
        total_edges=total_edges,
        bitmap_cvg=bitmap_cvg,
        stability=stability,
        var_byte_count=var_byte_count,
        count_coverage=count_coverage,
    )
    return cov.to_dict()


def recommend_strategy(output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Recommend fuzzing strategies based on current statistics.

    Heuristics mirror common AFL++ tuning advice:
    - Low stability -> suggest AFL_DISABLE_TRIM or longer timeout
    - Low exec/s -> suggest AFL_FAST_CAL or persistent mode
    - Coverage plateau -> suggest dictionary, radamsa, or custom mutator
    - Many crashes -> suggest crash triage workflow
    - Few finds -> suggest -D deterministic mode or longer run
    """
    stats = get_stats(output_dir)
    strategies: List[Dict[str, Any]] = []

    execs_per_sec = stats.get("execs_per_sec", 0)
    stability = stats.get("stability", 100.0)
    bitmap_cvg = stats.get("bitmap_cvg", 0.0)
    saved_crashes = stats.get("saved_crashes", 0)
    cycles_wo_finds = stats.get("cycles_wo_finds", 0)
    pending_total = stats.get("pending_total", 0)
    corpus_count = stats.get("corpus_count", 0)

    # Speed recommendation
    if execs_per_sec < 50:
        strategies.append(
            Strategy(
                name="enable_persistent_mode",
                type="config",
                parameters={"env": {"AFL_FAST_CAL": "1"}},
                rationale=(
                    f"exec/s is {execs_per_sec:.1f}, which is very slow. "
                    "Persistent mode or AFL_FAST_CAL can speed things up."
                ),
                expected_effect="10x-100x speedup if target supports it",
                priority=2,
            ).to_dict()
        )

    # Stability recommendation
    if stability < 90.0 and stats.get("var_byte_count", 0) > 40:
        strategies.append(
            Strategy(
                name="improve_stability",
                type="config",
                parameters={"env": {"AFL_DISABLE_TRIM": "1"}},
                rationale=(
                    f"stability is {stability:.1f}%. Unstable bits may be "
                    "causing noise. Disable trim or increase timeout."
                ),
                expected_effect="cleaner coverage signals, fewer wasted execs",
                priority=1,
            ).to_dict()
        )

    # Coverage plateau
    if cycles_wo_finds > 5 and bitmap_cvg < 30.0:
        strategies.append(
            Strategy(
                name="add_dictionary",
                type="dictionary",
                parameters={"action": "provide a dictionary with -x"},
                rationale=(
                    "Coverage has stalled with many cycles without finds. "
                    "A dictionary can help break through magic-value checks."
                ),
                expected_effect="new edges past string/integer comparisons",
                priority=2,
            ).to_dict()
        )

    if cycles_wo_finds > 10:
        strategies.append(
            Strategy(
                name="try_radamsa_or_custom_mutator",
                type="mutation",
                parameters={
                    "option_a": "AFL_CUSTOM_MUTATOR_LIBRARY=radamsa",
                    "option_b": "use a grammar-based custom mutator",
                },
                rationale=(
                    "Long plateau with no new finds. Structural mutators "
                    "may explore deeper paths."
                ),
                expected_effect="new coverage for structured inputs",
                priority=1,
            ).to_dict()
        )

    # Pending entries
    if pending_total > corpus_count * 2 and corpus_count > 0:
        strategies.append(
            Strategy(
                name="reduce_pending_queue",
                type="config",
                parameters={
                    "action": "let the fuzzer run longer or trim corpus"
                },
                rationale=(
                    f"pending_total={pending_total} is much larger than "
                    f"corpus_count={corpus_count}. The fuzzer has a lot "
                    "of work queued."
                ),
                expected_effect="faster cycle completion",
                priority=0,
            ).to_dict()
        )

    # Crashes found
    if saved_crashes > 0:
        strategies.append(
            Strategy(
                name="triage_crashes",
                type="triage",
                parameters={
                    "action": "use analyze_crash on each crash in crashes/"
                },
                rationale=f"{saved_crashes} crashes saved; triage for unique bugs.",
                expected_effect="identify unique vulnerabilities",
                priority=2,
            ).to_dict()
        )

    # Default: keep going
    if not strategies:
        strategies.append(
            Strategy(
                name="continue_fuzzing",
                type="config",
                parameters={},
                rationale="Current metrics look healthy. Keep fuzzing.",
                expected_effect="continued coverage growth",
                priority=0,
            ).to_dict()
        )

    strategies.sort(key=lambda s: s.get("priority", 0), reverse=True)
    return {"strategies": strategies}
