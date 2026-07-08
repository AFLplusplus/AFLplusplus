# AFL++ MCP Server

Model Context Protocol (MCP) server for AFL++ fuzzing analysis. Provides AI agents with programmatic access to AFL++ fuzzing statistics, queue analysis, crash investigation, and strategy recommendations.

## Features

- **Fuzzing Statistics**: Parse and analyze `fuzzer_stats` file
- **Queue Analysis**: List and analyze test case queue characteristics
- **Crash Investigation**: List, analyze, and minimize crash samples
- **Coverage Metrics**: Extract coverage information from bitmap data
- **Strategy Recommendations**: Get intelligent recommendations based on current fuzzing metrics
- **Multiple Transports**: Support for stdio, SSE, and HTTP transports

## Installation

```bash
# Install from source
cd ctf-mcp-repos/aflpp/mcp
pip install -e .

# Or install dependencies directly
pip install mcp starlette uvicorn pytest
```

## Quick Start

### Using as a Library

```python
from mcp import tools

# Get fuzzing statistics
stats = tools.get_stats("/path/to/afl/output")
print(f"Exec/s: {stats['execs_per_sec']}")
print(f"Coverage: {stats['bitmap_cvg']}%")
print(f"Crashes: {stats['saved_crashes']}")

# List queue entries
queue = tools.list_queue("/path/to/afl/output")
print(f"Total entries: {queue['total']}")

# Analyze queue characteristics
analysis = tools.analyze_queue("/path/to/afl/output")
print(f"Size range: {analysis['size_min']} - {analysis['size_max']}")

# List crashes
crashes = tools.list_crashes("/path/to/afl/output")
for crash in crashes['crashes']:
    print(f"Signal {crash['signal']}: {crash['filename']}")

# Get coverage info
coverage = tools.get_coverage("/path/to/afl/output")
print(f"Edges found: {coverage['edges_found']}")
print(f"Stability: {coverage['stability']}%")

# Get strategy recommendations
strategies = tools.recommend_strategy("/path/to/afl/output")
for strategy in strategies['strategies']:
    print(f"{strategy['name']}: {strategy['rationale']}")
```

### Running as MCP Server

#### Stdio Transport (for local AI agents)

```bash
python -m mcp.server --transport stdio
```

#### SSE/HTTP Transport (for remote AI agents)

```bash
python -m mcp.server --transport sse --host 0.0.0.0 --port 8000
```

The server will be available at:
- SSE endpoint: `http://localhost:8000/sse`
- Messages endpoint: `http://localhost:8000/messages/`

## Available Tools

### get_stats

Get current fuzzing statistics from the `fuzzer_stats` file.

**Parameters:**
- `output_dir` (optional): Path to AFL++ output directory

**Returns:**
```json
{
  "start_time": 1704067200,
  "run_time": 3600,
  "execs_done": 1000000,
  "execs_per_sec": 277.78,
  "corpus_count": 50,
  "bitmap_cvg": 12.34,
  "stability": 95.50,
  "saved_crashes": 3,
  "edges_found": 1234,
  ...
}
```

### list_queue

List test cases in the queue directory.

**Parameters:**
- `output_dir` (optional): Path to AFL++ output directory
- `limit` (default: 100): Maximum number of entries to return
- `offset` (default: 0): Offset for pagination

**Returns:**
```json
{
  "total": 50,
  "offset": 0,
  "limit": 100,
  "entries": [
    {
      "path": "/path/to/queue/id:000000,time:0,orig:input0",
      "filename": "id:000000,time:0,orig:input0",
      "size": 14,
      "is_original": true,
      "parent_id": null,
      ...
    }
  ]
}
```

### analyze_queue

Analyze queue characteristics including size distribution and mutation statistics.

**Parameters:**
- `output_dir` (optional): Path to AFL++ output directory

**Returns:**
```json
{
  "count": 50,
  "originals": 5,
  "mutations": 45,
  "size_min": 2,
  "size_max": 1024,
  "size_avg": 128.5,
  "size_median": 96
}
```

### list_crashes

List crash samples in the crashes directory.

**Parameters:**
- `output_dir` (optional): Path to AFL++ output directory
- `limit` (default: 100): Maximum number of entries to return
- `offset` (default: 0): Offset for pagination

**Returns:**
```json
{
  "total": 3,
  "offset": 0,
  "limit": 100,
  "crashes": [
    {
      "path": "/path/to/crashes/id:000000,sig:11,src:000001,time:500,op:havoc,rep:2",
      "filename": "id:000000,sig:11,src:000001,time:500,op:havoc,rep:2",
      "signal": 11,
      "source_id": 1,
      "time": 500,
      "op": "havoc",
      "rep": 2,
      "size": 120
    }
  ]
}
```

### analyze_crash

Analyze a single crash sample. Optionally run the target binary to capture signal information.

**Parameters:**
- `crash_path`: Path to the crash file
- `target_binary` (optional): Path to the target binary for live analysis

**Returns:**
```json
{
  "path": "/path/to/crash",
  "filename": "id:000000,sig:11,...",
  "size": 120,
  "signal": 11,
  "source_id": 1,
  "op": "havoc",
  "exit_code": -11,
  "stderr_tail": "..."
}
```

### minimize_crash

Minimize a crash sample using `afl-tmin`.

**Parameters:**
- `crash_path`: Path to the crash file
- `output_dir` (optional): Path to AFL++ output directory
- `target_binary`: Path to the target binary (required)

**Returns:**
```json
{
  "original_path": "/path/to/crash",
  "minimized_path": "/path/to/crash.minimized",
  "original_size": 120,
  "minimized_size": 45,
  "reduction_bytes": 75,
  "reduction_percent": 62.5,
  "afl_tmin_stderr": "..."
}
```

### get_coverage

Get coverage information from fuzzing statistics.

**Parameters:**
- `output_dir` (optional): Path to AFL++ output directory

**Returns:**
```json
{
  "edges_found": 1234,
  "total_edges": 65536,
  "bitmap_cvg": 12.34,
  "stability": 95.50,
  "var_byte_count": 20,
  "count_coverage": 424.78
}
```

### recommend_strategy

Recommend fuzzing strategies based on current statistics.

**Parameters:**
- `output_dir` (optional): Path to AFL++ output directory

**Returns:**
```json
{
  "strategies": [
    {
      "name": "enable_persistent_mode",
      "type": "config",
      "parameters": {"env": {"AFL_FAST_CAL": "1"}},
      "rationale": "exec/s is 10.0, which is very slow...",
      "expected_effect": "10x-100x speedup if target supports it",
      "priority": 2
    }
  ]
}
```

## AI Agent Integration

### Claude Desktop Configuration

Add to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "aflpp": {
      "command": "python",
      "args": ["-m", "mcp.server", "--transport", "stdio"],
      "env": {
        "AFL_OUTPUT_DIR": "/path/to/your/afl/output"
      }
    }
  }
}
```

### Example AI Agent Prompts

**Analyze fuzzing progress:**
```
Check the current fuzzing statistics and tell me if we're making good progress.
```

**Investigate crashes:**
```
List all crashes and analyze the most recent one. What signal did it trigger?
```

**Get optimization recommendations:**
```
Our fuzzing seems slow. What strategies do you recommend to improve performance?
```

**Queue analysis:**
```
Analyze the test case queue. Are there any patterns in the file sizes?
```

## Testing

```bash
# Run all tests
pytest mcp/tests/

# Run with verbose output
pytest mcp/tests/ -v

# Run specific test
pytest mcp/tests/test_mcp_server.py::test_get_stats
```

## Architecture

The server is organized into three main modules:

- **models.py**: Data models for fuzzing statistics, queue entries, crashes, and strategies
- **tools.py**: Core tool implementations that parse AFL++ output files
- **server.py**: MCP server wrapper with stdio/SSE/HTTP transport support

### File Format Parsing

The server parses AFL++ output files directly:

- **fuzzer_stats**: Key-value pairs separated by `:` (see `src/afl-fuzz-stats.c:write_stats_file`)
- **queue/ files**: Filenames encode metadata like `id:NNNNNN,time:NNNN,orig:NAME` or `id:NNNNNN,time:NNNN,src:NNNNNN,op:OP`
- **crashes/ files**: Filenames encode metadata like `id:NNNNNN,sig:NN,src:NNNNNN,time:NNNN,op:OP,rep:NN`

## Requirements

- Python 3.8+
- AFL++ (for crash minimization tools)
- Optional: `mcp`, `starlette`, `uvicorn` (for MCP server functionality)

## License

Apache-2.0 (same as AFL++)

## References

- AFL++ source: `src/afl-fuzz-stats.c`, `src/afl-fuzz-queue.c`
- MCP specification: https://modelcontextprotocol.io
- AFL++ documentation: https://aflplus.plus/docs/
