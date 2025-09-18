# IJON Full Implementation

This is a complete implementation of all IJON features for source code instrumentation in AFL++.

Based on the research paper: [IJON: Exploring Deep State Spaces via Fuzzing](https://nyx-fuzz.com/papers/ijon.pdf)

Test data and benchmarks available at: [IJON Data Repository](https://github.com/RUB-SysSec/ijon-data/tree/master/ijon-data)

---

## IJON API Reference

### Core Value Tracking Macros

#### `IJON_MAX(...)`

#### `IJON_MIN(...)`

#### `IJON_SET(x)`

#### `IJON_INC(x)`

### State Management Macros

#### `IJON_STATE(n)`

#### `IJON_CTX(x)`

### Distance and Comparison Macros

#### `IJON_STRDIST(x, y)`

#### `IJON_DIST(x, y)`

#### `IJON_CMP(x, y)`

#### `IJON_BITS(x)`

### Stack-Aware Macros

#### `IJON_STACK_MAX(x)`

#### `IJON_STACK_MIN(x)`

---

## Implementation Details

### Memory Layout

This implementation uses a unified dynamic shared memory layout that works for all map sizes:

```
Dynamic Shared Memory Layout (All Map Sizes):

Base Address    ┌─────────────────────────────────────┐
                │ AFL++ Shared Memory Region          │
                │ (Total: variable size)              │
                │                                     │
+0              ├─────────────────────────────────────┤ <- __afl_area_ptr
                │ Coverage Bitmap                     │   (fuzzer: trace_bits)
                │ Size: coverage_size bytes           │   (target: __afl_area_ptr)
                │ Type: u8[coverage_size]             │   (variable: 65536, 262144, etc.)
                │                                     │
                │ [0x0000] = edge_hits[0]             │
                │ [0x0001] = edge_hits[1]             │
                │ ...                                 │
                │ [coverage_size-1] = edge_hits[N]    │
                │                                     │
+coverage_size  ├─────────────────────────────────────┤
                │ IJON Set/Inc/State Area             │
                │ Size: 65,536 bytes                  │
                │ Type: u8[65536]                     │
                │                                     │
                │                                     │
+coverage_size  ├─────────────────────────────────────┤ <- __afl_ijon_bits
+65536          │ IJON Max Values                     │   (fuzzer: ijon_bits)
                │ Size: 4,096 bytes (512 × 8)         │   (target: __afl_ijon_bits)
                │ Type: u64[512]                      │   Dynamic Offset: calculated
                │                                     │
                │ [0] = max_value_slot_0              │
                │ [1] = max_value_slot_1              │
                │ ...                                 │
                │ [25] = 15240170669                  │ <- Tracked value
                │ ...                                 │
                │ [351] = 520011065792645             │ <- Tracked value  
                │ ...                                 │
                │ [458] = 964077327750                │ <- Tracked value
                │ ...                                 │
                │ [511] = max_value_slot_511          │
                │                                     │
+coverage_size  └─────────────────────────────────────┘
+69632
```

**Key Features:**
- **Unified Design**: Works for all map sizes (65k, 256k, 1M+)
- **Dynamic Offsets**: IJON offset calculated at runtime based on actual coverage size
- **Consistent Layout**: Same memory organization regardless of target size
- **Fastresume Support**: IJON offsets preserved across fuzzing sessions

### IJON Statistics

AFL++ displays IJON effectiveness statistics in the fuzzer UI:

**Format:**
- **Active IJON**: `21.67% (13/60)` - Shows percentage of successful IJON max updates vs total IJON executions
- **Inactive IJON**: `0/0` - Shows updates/entries when no IJON executions yet

**Interpretation:**
- **High percentage (>10%)**: IJON is effectively finding new maximums
- **Low percentage (<1%)**: May indicate saturation or need for different IJON instrumentation
- **Zero executions**: Target not calling IJON functions or IJON disabled

---

## Usage Instructions

### Building AFL++ with IJON

```bash
make clean
make LLVM_CONFIG=llvm-config-18 source-only
```

### Compiling Target Programs

When using IJON instrumentation in AFL++, it is required to invoke `__AFL_INIT()` at the beginning of your target program’s `main()` function:
```c
int main(int argc, char **argv) {
    __AFL_INIT();
    // Your code here
}
```
Adding `__AFL_INIT()` ensures:
- Proper initialization of the AFL++ runtime environment
- Correct setup of the coverage bitmap and IJON feedback regions
- Improved compatibility across targets

Set the environment variables during compilation:
```bash
AFL_LLVM_IJON=1 CC=afl-clang-fast CXX=afl-clang-fast++ make
```

### Fuzzing Configuration

#### Basic Fuzzing
```bash
AFL_IJON=1 AFL_IJON_HISTORY_LIMIT=1000 afl-fuzz -i input_dir -o output_dir -- ./target
```

#### For Large Targets (bitmap > 65k)
```bash
echo test > test_input.txt && AFL_DUMP_MAP_SIZE=1 ./target

AFL_MAP_SIZE=10000 AFL_IJON_HISTORY_LIMIT=1000 AFL_IJON=1 afl-fuzz -S worker -i input_dir -o output_dir -- ./target
```

### Environment Variables

- **`AFL_LLVM_IJON=1`**: Enables IJON instrumentation during compilation
- **`AFL_IJON=1`**: Enables IJON feedback during fuzzing  
- **`AFL_IJON_HISTORY_LIMIT=N`**: Sets the maximum number of IJON max-value inputs stored on the host (default: 20)
- **`AFL_MAP_SIZE=N`**: Sets a custom coverage map size for large targets (bitmap > 65k)

---

## Performance (Super Mario Bros. Level 1.1, ijon_max(pos_y/16, world_pos))

Test environment: Ubuntu 20.04, 16 GB RAM, 8 cores


| Run | IJON AFL | IJON AFL++ |
| ---- | -------- | ---------- |
| 1 | 1 h 19 min | 15 min |
| 2 | 50 min | 20 min |
| 3 | 31 min | 21 min |
| 4 | 1 h 22 min | 23 min |
| 5 | 2 h 14 min | 25 min |
| AVG | 1 h 16 min | 20.8 min |

Overall, IJON AFL++ is ~3.7x faster on average (76.0 min -> 20.8 min).

## Performance (Maze, IJON_SET(ijon_hashint(x, y)))

Test environment: Ubuntu 20.04, 16 GB RAM, 8 cores

| Run | Easy Small (AFL ijon) | Easy Small (AFL++ ijon) | Easy Big (AFL ijon) | Easy Big (AFL++ ijon) | Hard Small (AFL ijon) | Hard Small (AFL++ ijon) | Hard Big (AFL ijon) | Hard Big (AFL++ ijon) |
| --- | ------------------------ | -------------------------- | ---------------------- | ------------------------ | ----------------------- | ------------------------- | --------------------- | ----------------------- |
| 1 | 1 min 56 s | 26 s | 15 min 32 s | 54 s | 40 s | 8 s | 22 s | 35 s |
| 2 | 1 min 21 s | 11 s | 10 min 56 s | 2 min 13 s | 25 s | 14 s | 11 min 6 s | 19 s |
| 3 | 1 min 53 s | 42 s | 18 min 18 s | 48 s | 5 min 8 s | 11 s | 10 min 33 s | 53 s |
| 4 | 3 min 25 s | 24 s | 29 min 32 s | 1 min 20 s | 1 min 12 s | 10 s | 2 min 11 s | 20 s |
| 5 | 2 min 28 s | 21 s | 10 min 34 s | 49 s | 19 s | 9 s | 4 min 29 s | 26 s |
| 6 | 2 min 30 s | 24 s | 11 min 49 s | 1 min 24 s | 2 min 37 s | 12 s | 11 min 16 s | 33 s |
| 7 | 1 min 5 s | 22 s | 12 min 18 s | 4 min 6 s | 38 s | 8 s | 10 min 9 s | 32 s |
| 8 | 42 s | 14 s | 11 min 41 s | 56 s | 52 s | 9 s | 5 min 47 s | 18 s |
| 9 | 12 min 18 s | 37 s | 9 min 36 s | 2 min 36 s | 56 s | 9 s | 5 min 24 s | 19 s |
| 10 | 1 min 32 s | 15 s | 12 min 7 s | 47 s | 1 min 5 s | 15 s | 17 min 10 s | 24 s |
| AVG | 2 min 55 s | 23.6 s (x7.42) | 14 min 14 s | 1 min 35 s (x9) | 1 min 23 s | 10.5 s (x7.9) | 7 min 50 s | 27.9 s (x16.85) |
