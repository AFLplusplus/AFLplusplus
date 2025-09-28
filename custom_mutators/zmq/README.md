# AFL++ ZMQ Consumer Mutator with Shared Memory Support

This custom mutator is copied from AIXCC Team Atlanta.

This is a custom mutator for AFL++ that receives seed IDs from a ZMQ router and reads actual seed content from shared memory pools.

## Features

- Connects to a ZMQ router as a dealer
- Receives JSON bundles containing seed IDs and shared memory names
- Reads actual seed content from shared memory pools (`/dev/shm/<shm_name>`)
- Background thread handles all network and shared memory operations
- Large circular buffer (100MB) maintains seeds for instant access
- Completely non-blocking fuzzing function
- Sends periodic heartbeats to maintain connection
- Thread-safe shared memory consumer management
- Returns nothing when no seeds are available (no fallback mutations)
- Configurable via environment variables

## Architecture

The mutator implements a sophisticated architecture:

1. **ZMQ Communication**: Receives seed metadata (IDs and shared memory names) via ZMQ
2. **Shared Memory Reading**: Reads actual seed content from shared memory pools
3. **Background Processing**: Network thread handles all I/O operations
4. **Circular Buffer**: Large buffer ensures seeds are instantly available for fuzzing

### Shared Memory Layout

The shared memory pools follow this layout:
```
Header (8 bytes):
  - item_size (4 bytes, uint32, little-endian)
  - item_num (4 bytes, uint32, little-endian)

Items (item_size * item_num bytes):
  Each item:
    - data_len (4 bytes, uint32)
    - payload (data_len bytes)
```

## Building

Prerequisites:
- ZeroMQ library (libzmq-dev)
- AFL++ with custom mutator support
- pthread support
- Shared memory support (POSIX)

```bash
make libzmqmutator.so
```

## Usage

Set the custom mutator library when running AFL++:

```bash
AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/libzmqmutator.so afl-fuzz [options]
```

## Configuration

The mutator can be configured via environment variables:

- `AFL_ZMQ_ROUTER`: ZMQ router address (default: "ipc:///tmp/haha")
- `AFL_ZMQ_HARNESS`: Harness name to identify this fuzzer (optional)

The harness name is determined in the following priority order:
1. Binary name from AFL++ (extracted from argv[0] if available)
2. Binary name from `/proc/self/exe` (Linux only)
3. `AFL_ZMQ_HARNESS` environment variable
4. Default: "AFL"

The mutator will automatically extract just the binary name from full paths (e.g., `/usr/bin/target` becomes `target`).

Example:
```bash
export AFL_ZMQ_ROUTER="tcp://127.0.0.1:5555"
export AFL_ZMQ_HARNESS="MyTarget"  # Optional, will auto-detect if not set
AFL_CUSTOM_MUTATOR_LIBRARY=./libzmqmutator.so afl-fuzz -i in -o out ./target @@
```

## Protocol

The mutator implements the following protocol:

1. **Heartbeat**: Sent every 5 seconds
   - Frame 0: "HEARTBEAT"
   - Frame 1: harness name

2. **Seed Reception**: 
   - Frame 0: "SEED"
   - Frame 1: message ID
   - Frame 2: JSON bundle

3. **Acknowledgment**:
   - Frame 0: "ACK"
   - Frame 1: message ID
   - Frame 2: original bundle data

## JSON Bundle Format

The seed bundle contains references to seeds in shared memory:

```json
{
  "script_id": 123,
  "harness_name": "MyTarget",
  "shm_name": "seed_pool_001",
  "seed_ids": [0, 1, 2, 3, 4]
}
```

- `shm_name`: Name of the shared memory pool in `/dev/shm/`
- `seed_ids`: Array of seed indices within the shared memory pool

## Behavior

- **When seeds are available**: Returns seeds from the circular buffer
- **When no seeds are available**: Returns 0 (no mutation)
- **No fallback**: The mutator does not generate random mutations

This design ensures that fuzzing only occurs with seeds from the ZMQ router, maintaining full control over the fuzzing inputs.

## Performance

- Circular buffer: 100MB
- Maximum seed size: 1MB
- Non-blocking design ensures no fuzzing delays
- Shared memory access is direct and efficient
- Multiple shared memory pools supported concurrently
- Background thread maintains buffer fill level

## Statistics

The mutator tracks and reports:
- Buffer utilization percentage
- Total seeds processed
- Seeds used for fuzzing
- Total bytes received
- Total mutations performed
- Active shared memory consumers

## Implementation Details

1. **Shared Memory Consumers**: Created on-demand when new `shm_name` is encountered
2. **Memory Mapping**: Shared memory is mapped read-only for safety
3. **Thread Safety**: Separate mutexes for buffer and shared memory operations
4. **JSON Parsing**: Currently uses simplified parsing (production should use cJSON)
5. **Error Handling**: Graceful handling of corrupted or missing shared memory

## Limitations

- Simplified JSON parsing (production code should use proper JSON library)
- Fixed buffer size (could be made configurable)
- Maximum 10 concurrent shared memory pools (configurable in source)

## Future Improvements

1. Proper JSON parsing library integration (cJSON or json-c)
2. Support for sending interesting test cases back to router
3. Dynamic buffer sizing based on seed rate
4. Compression support for seeds
5. Shared memory pool statistics and monitoring
6. Support for seed prioritization based on metadata
7. Hash verification for seed integrity 
