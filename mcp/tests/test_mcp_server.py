"""Tests for AFL++ MCP Server."""

import json
import tempfile
import pytest
from pathlib import Path

from mcp import tools, models


@pytest.fixture
def mock_afl_output(tmp_path):
    """Create a mock AFL++ output directory structure."""
    # Create fuzzer_stats
    stats_content = """start_time        : 1704067200
last_update       : 1704070800
run_time          : 3600
fuzzer_pid        : 12345
cycles_done       : 5
cycles_wo_finds   : 2
execs_done        : 1000000
execs_per_sec     : 277.78
corpus_count      : 50
corpus_favored    : 10
corpus_found      : 40
max_depth         : 8
pending_favs      : 5
pending_total     : 15
stability         : 95.50%
bitmap_cvg        : 12.34%
saved_crashes     : 3
saved_hangs       : 1
edges_found       : 1234
total_edges       : 65536
var_byte_count    : 20
afl_banner        : test_target
afl_version       : 4.00c
target_mode       : default
command_line      : afl-fuzz -i input -o output ./target
"""
    (tmp_path / "fuzzer_stats").write_text(stats_content)

    # Create queue directory
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()

    # Original input
    (queue_dir / "id:000000,time:0,orig:input0").write_bytes(b"original input")

    # Mutated inputs
    (queue_dir / "id:000001,time:100,src:000000,op:havoc").write_bytes(b"mutated1")
    (queue_dir / "id:000002,time:200,src:000001,op:splice").write_bytes(b"mutated2" * 10)
    (queue_dir / "id:000003,time:300,src:000000,op:havoc").write_bytes(b"m3")

    # Create crashes directory
    crashes_dir = tmp_path / "crashes"
    crashes_dir.mkdir()

    # Crash samples
    (crashes_dir / "id:000000,sig:11,src:000001,time:500,op:havoc,rep:2").write_bytes(
        b"crash1" * 20
    )
    (crashes_dir / "id:000001,sig:06,src:000002,time:600,op:splice,rep:1").write_bytes(
        b"crash2"
    )
    (crashes_dir / "README.txt").write_text("This is a readme")

    return tmp_path


def test_parse_stats_file(mock_afl_output):
    """Test parsing fuzzer_stats file."""
    stats_path = mock_afl_output / "fuzzer_stats"
    content = stats_path.read_text()
    stats = models.FuzzingStats.from_stats_file(content)

    assert stats.start_time == 1704067200
    assert stats.run_time == 3600
    assert stats.execs_done == 1000000
    assert stats.execs_per_sec == 277.78
    assert stats.corpus_count == 50
    assert stats.stability == 95.50
    assert stats.bitmap_cvg == 12.34
    assert stats.saved_crashes == 3
    assert stats.edges_found == 1234
    assert stats.afl_version == "4.00c"


def test_get_stats(mock_afl_output):
    """Test get_stats tool."""
    result = tools.get_stats(str(mock_afl_output))

    assert result["start_time"] == 1704067200
    assert result["execs_done"] == 1000000
    assert result["execs_per_sec"] == 277.78
    assert result["corpus_count"] == 50
    assert result["saved_crashes"] == 3


def test_list_queue(mock_afl_output):
    """Test list_queue tool."""
    result = tools.list_queue(str(mock_afl_output))

    assert result["total"] == 4
    assert len(result["entries"]) == 4

    # Check first entry (original)
    first = result["entries"][0]
    assert first["filename"] == "id:000000,time:0,orig:input0"
    assert first["is_original"] is True
    assert first["size"] == 14  # len("original input")

    # Check mutated entry
    second = result["entries"][1]
    assert second["filename"] == "id:000001,time:100,src:000000,op:havoc"
    assert second["is_original"] is False
    assert second["parent_id"] == 0


def test_list_queue_pagination(mock_afl_output):
    """Test list_queue with pagination."""
    result = tools.list_queue(str(mock_afl_output), limit=2, offset=0)
    assert len(result["entries"]) == 2
    assert result["total"] == 4

    result = tools.list_queue(str(mock_afl_output), limit=2, offset=2)
    assert len(result["entries"]) == 2


def test_analyze_queue(mock_afl_output):
    """Test analyze_queue tool."""
    result = tools.analyze_queue(str(mock_afl_output))

    assert result["count"] == 4
    assert result["originals"] == 1
    assert result["mutations"] == 3
    assert result["size_min"] == 2  # "m3"
    assert result["size_max"] == 120  # "crash2" * 10 would be wrong, it's "mutated2" * 10 = 80
    # Actually: "mutated2" * 10 = 80 bytes
    assert result["size_max"] == 80
    assert result["size_avg"] > 0
    assert result["size_median"] > 0


def test_list_crashes(mock_afl_output):
    """Test list_crashes tool."""
    result = tools.list_crashes(str(mock_afl_output))

    assert result["total"] == 2  # README.txt is excluded
    assert len(result["crashes"]) == 2

    first = result["crashes"][0]
    assert first["filename"] == "id:000000,sig:11,src:000001,time:500,op:havoc,rep:2"
    assert first["signal"] == 11
    assert first["source_id"] == 1
    assert first["op"] == "havoc"
    assert first["rep"] == 2
    assert first["size"] == 120  # "crash1" * 20


def test_analyze_crash(mock_afl_output):
    """Test analyze_crash tool."""
    crash_path = str(mock_afl_output / "crashes" / "id:000000,sig:11,src:000001,time:500,op:havoc,rep:2")
    result = tools.analyze_crash(crash_path)

    assert result["path"] == crash_path
    assert result["signal"] == 11
    assert result["source_id"] == 1
    assert result["op"] == "havoc"
    assert result["size"] == 120


def test_get_coverage(mock_afl_output):
    """Test get_coverage tool."""
    result = tools.get_coverage(str(mock_afl_output))

    assert result["edges_found"] == 1234
    assert result["total_edges"] == 65536
    assert result["bitmap_cvg"] == 12.34
    assert result["stability"] == 95.50
    assert result["var_byte_count"] == 20
    # count_coverage = (65536 * 8) / 1234 = 424.78
    assert result["count_coverage"] > 0


def test_recommend_strategy_slow(mock_afl_output):
    """Test recommend_strategy with slow execution."""
    # Modify stats to have low exec/s
    stats_path = mock_afl_output / "fuzzer_stats"
    content = stats_path.read_text()
    content = content.replace("execs_per_sec     : 277.78", "execs_per_sec     : 10.00")
    stats_path.write_text(content)

    result = tools.recommend_strategy(str(mock_afl_output))

    assert "strategies" in result
    strategies = result["strategies"]
    assert len(strategies) > 0

    # Should recommend persistent mode for slow exec/s
    found = any(s["name"] == "enable_persistent_mode" for s in strategies)
    assert found, "Should recommend persistent mode for slow execution"


def test_recommend_strategy_crashes(mock_afl_output):
    """Test recommend_strategy with crashes."""
    result = tools.recommend_strategy(str(mock_afl_output))

    strategies = result["strategies"]
    # Should recommend triage since we have crashes
    found = any(s["name"] == "triage_crashes" for s in strategies)
    assert found, "Should recommend crash triage when crashes exist"


def test_recommend_strategy_healthy(mock_afl_output):
    """Test recommend_strategy with healthy metrics."""
    # Modify stats to look healthy
    stats_path = mock_afl_output / "fuzzer_stats"
    content = stats_path.read_text()
    content = content.replace("execs_per_sec     : 277.78", "execs_per_sec     : 500.00")
    content = content.replace("saved_crashes     : 3", "saved_crashes     : 0")
    content = content.replace("cycles_wo_finds   : 2", "cycles_wo_finds   : 0")
    stats_path.write_text(content)

    result = tools.recommend_strategy(str(mock_afl_output))

    strategies = result["strategies"]
    # Should recommend continuing
    found = any(s["name"] == "continue_fuzzing" for s in strategies)
    assert found, "Should recommend continuing when metrics are healthy"


def test_parse_queue_filename():
    """Test queue filename parsing."""
    # Original input
    result = tools._parse_queue_filename("id:000000,time:0,orig:input0")
    assert result["id"] == 0
    assert result["is_original"] is True
    assert result["original_name"] == "input0"

    # Mutated input
    result = tools._parse_queue_filename("id:000123,time:5000,src:000042,op:havoc")
    assert result["id"] == 123
    assert result["time"] == 5000
    assert result["parent_id"] == 42
    assert result["op"] == "havoc"
    assert result["is_original"] is False

    # SIMPLE_FILES format
    result = tools._parse_queue_filename("id_000456")
    assert result["id"] == 456


def test_parse_crash_filename():
    """Test crash filename parsing."""
    result = tools._parse_crash_filename(
        "id:000005,sig:11,src:000123,time:45678,op:havoc,rep:3"
    )
    assert result["id"] == 5
    assert result["signal"] == 11
    assert result["source_id"] == 123
    assert result["time"] == 45678
    assert result["op"] == "havoc"
    assert result["rep"] == 3


def test_missing_output_dir():
    """Test error when output_dir is missing."""
    with pytest.raises(ValueError, match="output_dir is required"):
        tools.get_stats(None)


def test_missing_stats_file(tmp_path):
    """Test error when fuzzer_stats doesn't exist."""
    with pytest.raises(FileNotFoundError, match="fuzzer_stats not found"):
        tools.get_stats(str(tmp_path))


def test_missing_queue_dir(tmp_path):
    """Test error when queue directory doesn't exist."""
    # Create stats file but no queue
    (tmp_path / "fuzzer_stats").write_text("start_time: 0\n")

    with pytest.raises(FileNotFoundError, match="queue directory not found"):
        tools.list_queue(str(tmp_path))


def test_missing_crashes_dir(tmp_path):
    """Test error when crashes directory doesn't exist."""
    # Create stats file but no crashes
    (tmp_path / "fuzzer_stats").write_text("start_time: 0\n")

    with pytest.raises(FileNotFoundError, match="crashes directory not found"):
        tools.list_crashes(str(tmp_path))


def test_empty_queue(tmp_path):
    """Test analyze_queue with empty queue."""
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()
    (tmp_path / "fuzzer_stats").write_text("start_time: 0\n")

    result = tools.analyze_queue(str(tmp_path))
    assert result["count"] == 0
    assert result["originals"] == 0
    assert result["mutations"] == 0


def test_models_to_dict():
    """Test dataclass to_dict methods."""
    stats = models.FuzzingStats(
        start_time=1000,
        execs_done=5000,
        stability=98.5,
    )
    d = stats.to_dict()
    assert d["start_time"] == 1000
    assert d["execs_done"] == 5000
    assert d["stability"] == 98.5

    entry = models.QueueEntry(
        path="/tmp/queue/id:000000",
        filename="id:000000",
        size=100,
        favored=True,
    )
    d = entry.to_dict()
    assert d["path"] == "/tmp/queue/id:000000"
    assert d["size"] == 100
    assert d["favored"] is True

    crash = models.CrashInfo(
        path="/tmp/crashes/id:000000,sig:11",
        signal=11,
        unique=True,
    )
    d = crash.to_dict()
    assert d["signal"] == 11
    assert d["unique"] is True

    strategy = models.Strategy(
        name="test",
        type="config",
        priority=2,
    )
    d = strategy.to_dict()
    assert d["name"] == "test"
    assert d["priority"] == 2


def test_coverage_info_model():
    """Test CoverageInfo model."""
    cov = models.CoverageInfo(
        edges_found=1000,
        total_edges=65536,
        bitmap_cvg=15.26,
        stability=99.0,
    )
    d = cov.to_dict()
    assert d["edges_found"] == 1000
    assert d["bitmap_cvg"] == 15.26
    assert d["stability"] == 99.0
