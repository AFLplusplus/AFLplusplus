"""Data models for AFL++ MCP Server."""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import json


@dataclass
class FuzzingStats:
    """Fuzzing statistics parsed from fuzzer_stats file.

    Mirrors the key=value format written by write_stats_file() in
    src/afl-fuzz-stats.c.
    """

    start_time: int = 0
    last_update: int = 0
    run_time: int = 0
    fuzzer_pid: int = 0
    cycles_done: int = 0
    cycles_wo_finds: int = 0
    time_wo_finds: int = 0
    fuzz_time: int = 0
    calibration_time: int = 0
    cmplog_time: int = 0
    sync_time: int = 0
    trim_time: int = 0
    execs_done: int = 0
    execs_per_sec: float = 0.0
    execs_ps_last_min: float = 0.0
    corpus_count: int = 0
    corpus_favored: int = 0
    corpus_found: int = 0
    corpus_imported: int = 0
    corpus_variable: int = 0
    max_depth: int = 0
    cur_item: int = 0
    pending_favs: int = 0
    pending_total: int = 0
    stability: float = 0.0
    bitmap_cvg: float = 0.0
    saved_crashes: int = 0
    saved_hangs: int = 0
    total_tmout: int = 0
    last_find: int = 0
    last_crash: int = 0
    last_hang: int = 0
    execs_since_crash: int = 0
    exec_timeout: int = 0
    slowest_exec_ms: int = 0
    peak_rss_mb: int = 0
    cpu_affinity: int = -1
    edges_found: int = 0
    total_edges: int = 0
    var_byte_count: int = 0
    havoc_expansion: int = 0
    auto_dict_entries: int = 0
    testcache_size: int = 0
    testcache_count: int = 0
    testcache_evict: int = 0
    afl_banner: str = ""
    afl_version: str = ""
    target_mode: str = ""
    command_line: str = ""

    @classmethod
    def from_stats_file(cls, content: str) -> "FuzzingStats":
        """Parse fuzzer_stats file content into FuzzingStats.

        The file format is lines of `key : value` or `key: value`.
        Percent signs are stripped from numeric values (e.g. `99.50%`).
        """
        stats = cls()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip().rstrip("%")
            field_names = {f.name for f in cls.__dataclass_fields__.values()}
            if key not in field_names:
                continue
            expected = cls.__dataclass_fields__[key].type
            try:
                if expected is float:
                    setattr(stats, key, float(value))
                elif expected is int:
                    setattr(stats, key, int(float(value)))
                else:
                    setattr(stats, key, value)
            except (ValueError, TypeError):
                continue
        return stats

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QueueEntry:
    """A single entry in the AFL++ queue/ directory.

    Queue files are named like `id:000000,time:0,orig:input0` (non-simple)
    or `id_000000` (SIMPLE_FILES). The file contents are the test case bytes.
    """

    path: str = ""
    filename: str = ""
    size: int = 0
    exec_count: int = 0
    coverage: int = 0
    favored: bool = False
    disabled: bool = False
    depth: int = 0
    is_original: bool = False
    parent_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrashInfo:
    """A crash sample from the crashes/ directory.

    Crash filenames encode signal and metadata, e.g.
    `id:000000,sig:06,src:000123,time:12345,op:havoc,rep:2`.
    """

    path: str = ""
    filename: str = ""
    signal: int = 0
    source_id: Optional[int] = None
    time: Optional[int] = None
    op: str = ""
    rep: Optional[int] = None
    size: int = 0
    unique: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Strategy:
    """Recommended fuzzing strategy."""

    name: str = ""
    type: str = ""  # e.g. "power_schedule", "mutation", "dictionary", "config"
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    expected_effect: str = ""
    priority: int = 0  # 0=low, 1=medium, 2=high

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageInfo:
    """Coverage information parsed from bitmap and stats."""

    edges_found: int = 0
    total_edges: int = 0
    bitmap_cvg: float = 0.0
    stability: float = 0.0
    var_byte_count: int = 0
    count_coverage: float = 0.0  # bits/tuple

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
