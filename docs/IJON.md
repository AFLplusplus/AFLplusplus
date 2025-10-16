# IJON – Guided Fuzzing with Annotations

IJON is an **annotation mechanism** for AFL++ fuzzers that lets analysts guide fuzzing by exposing *state information* or *progress indicators* directly to the fuzzer.  
With small code annotations (often a single line), you can help AFL++ explore deep program states that are otherwise unreachable.

IJON makes it possible to:
- Guide fuzzers through complex state machines.
- Explore large state spaces (e.g., games, protocol handlers).
- Solve "unsolvable" fuzzing challenges such as:
  - Completing Super Mario Bros. levels automatically.
  - Handling structured input formats (PNG, WAV, TPM messages).
  - Resolving complex hash map lookups.

This is a complete implementation of all IJON features for source code instrumentation in AFL++.
Based on the research paper: [IJON: Exploring Deep State Spaces via Fuzzing](https://nyx-fuzz.com/papers/ijon.pdf)
Test data and benchmarks available at: [IJON Data Repository](https://github.com/RUB-SysSec/ijon-data/tree/master/ijon-data)

**NOTE** There is also an IJON implemenation for qemu_mode, see [qemu_mode/README.md](../qemu_mode/README.md)

## IMPORTANT: Linker parameters

If your compiler does not use ld.bfd or lld or the linker is called directly by your build environment then linking the target binary will fail:

```
/usr/bin/ld: b.o:(.data+0x0): multiple definition of `__afl_ijon_enabled'; a.o:(.data+0x0): first defined here
```

For lld and ld.bfd this can be usually solved with defining the necessary linking parameter:
```
export LD_FLAGS=--allow-multiple-definition
```

If you use a different linker than find out what the necessary linker flag is to allow multiple strong definitions, e.g.
`-z muldefs` for gold, and then set the build environment up accordingly, e.g.:
```
export C_FLAGS="-Wl,-z,muldefs"
export CXX_FLAGS="-Wl,-z,muldefs"
export CPP_FLAGS="-Wl,-z,muldefs"
export LD_FLAGS="-z muldefs"
```

## IJON API Reference

### Core Value Tracking Macros

#### `IJON_MAX(x)`
Tell the fuzzer to **maximize** the value `x`.  
Useful when the state space is too large to enumerate and you want to guide exploration toward progress.  
Example: in Super Mario Bros., `IJON_MAX(player_x)` makes the fuzzer try to push Mario as far right as possible.

#### `IJON_MIN(x)`
Tell the fuzzer to **minimize** the value `x`.  
Implemented by maximizing the negated value.  
Example: `IJON_MIN(latency)` rewards inputs that reduce latency.

#### `IJON_SET(x)`
Mark the value `x` as a new coverage event.  
Each distinct value of `x` will be treated like a new branch by AFL.  
Example: `IJON_SET(hash_int(x, y))` rewards visiting new (x,y) positions in a maze.

#### `IJON_INC(x)`
Increment the coverage map entry for value `x`.  
Unlike `IJON_SET`, this rewards **how often** different values occur.  
Example: `IJON_INC(packet_type)` makes AFL explore many different packet types.

### State Management Macros

#### `IJON_STATE(n)`
Extend AFL’s edge coverage with a **virtual state component**.  
The same code paths will count as different coverage depending on the value of `n`.  
Use sparingly—too many states may cause state explosion.  
Example: `IJON_STATE(has_hello + has_login)` distinguishes protocol states.

#### `IJON_CTX(x)`
Scoped state hashing: temporarily incorporates variable `x` into the state hash.  
Useful for distinguishing behavior based on execution context.  
Example: `IJON_CTX(function_id)` makes AFL track the same code differently depending on the active function.

### Distance and Comparison Macros

#### `IJON_STRDIST(x, y)`
Reward inputs that increase the **common prefix length** of two strings.  
Example: `IJON_STRDIST(input, "bootloader")` helps AFL solve string comparisons inside hash maps.

#### `IJON_DIST(x, y)`
Reward fuzzing inputs that minimize the **absolute distance** between `x` and `y`.  
Example: `IJON_DIST(checksum, expected)` guides the fuzzer toward valid checksums.

#### `IJON_CMP(x, y)`
Reward closeness of two integers by counting differing bits.  
Example: `IJON_CMP(input_val, magic_val)` helps the fuzzer solve integer equality checks.

#### `IJON_BITS(x)`
Return the number of leading zero bits in `x`.  
Can be used to measure how “close” a value is to zero or a power of two.  
Example: `IJON_BITS(mask)` for inputs where alignment matters.

### Stack-Aware Macros

#### `IJON_STACK_MAX(x)`
Like `IJON_MAX(x)`, but the maximization is **scoped to the current call stack**.  
This allows maximizing the same value differently in different call contexts.  
Example: `IJON_STACK_MAX(buffer_len)` rewards progress in different parsing functions independently.

#### `IJON_STACK_MIN(x)`
Like `IJON_MIN(x)`, but scoped to the current call stack.  
Example: `IJON_STACK_MIN(depth)` rewards reaching shallower recursion in one context, deeper in another.

## Example Usage

### Maze example

In a maze we want to trigger coverage on new locations in the maze, we can simply use `IJON_SET`:

```c
while (true) {
    ox = x; oy = y;
    switch (input[i]) {
        case 'w': y--; break;
        case 's': y++; break;
        case 'a': x--; break;
        case 'd': x++; break;
    }
    IJON_SET(hash_int(x, y)); // new position = new coverage
}
```

### Protocol example

When we fuzz a protocol, we want to reward different message types and states:

```c
msg = parse_msg();
state_log = (state_log << 8) + msg.type;
IJON_STATE(state_log); // reward new message sequences
```

## Usage Instructions

### Building AFL++ with IJON

```bash
make clean
make LLVM_CONFIG=llvm-config-18 source-only
```

### IJON mode debug build for afl-fuzz

Note that this does not affect any ijon functionality, it just creates an extra file.

```bash
make clean
CFLAGS="-DDUMP_IJON_STATE" make afl-fuzz
```

This will output non-zero values to the default/ijon_max/cur_state file whenever 
the ijon max bitmap is updated. By looking at this file, you can see the maximum values
of your max/min annotations so far, which can help you understand the current fuzzing progress. 

For example, you can check Mario's current maximum y-axis position.

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
AFL_IJON_HISTORY_LIMIT=1000 afl-fuzz -i input_dir -o output_dir -- ./target
```

#### For Large Targets (bitmap > 65k)
```bash
echo test > test_input.txt && AFL_DUMP_MAP_SIZE=1 ./target

AFL_IJON_HISTORY_LIMIT=1000 afl-fuzz -S worker -i input_dir -o output_dir -- ./target
```

### Environment Variables

- **`AFL_LLVM_IJON=1`**: Enables IJON instrumentation during compilation
- **`AFL_IJON_HISTORY_LIMIT=N`**: Sets the maximum number of IJON max-value inputs stored on the host (default: 20)

## Performance (Super Mario Bros. Level 1.1, ijon_max(pos_y/16, world_pos))

Test environment: Ubuntu 20.04, 16 GB RAM, 8 cores

| Run | IJON AFL | IJON AFL++ |
| ---- | -------- | ---------- |
| 1 | 1 h 19 min | 30 min |
| 2 | 50 min | 34 min |
| 3 | 31 min | 36 min |
| 4 | 1 h 22 min | 28 min |
| 5 | 2 h 14 min | 28 min |
| AVG | 1 h 16 min | 31.2 min |

Overall, IJON AFL++ is ~2.4x faster on average (76.0 min -> 31.2 min).

## Performance (Maze, IJON_SET(ijon_hashint(x, y)))

Test environment: Ubuntu 20.04, 16 GB RAM, 8 cores

| Run | Easy Small (AFL ijon) | Easy Small (AFL++ ijon) | Easy Big (AFL ijon) | Easy Big (AFL++ ijon) | Hard Small (AFL ijon) | Hard Small (AFL++ ijon) | Hard Big (AFL ijon) | Hard Big (AFL++ ijon) |
| --- | ------------------------ | -------------------------- | ---------------------- | ------------------------ | ----------------------- | ------------------------- | --------------------- | ----------------------- |
| 1 | 1 min 56 s |  2 min 24 s | 15 min 32 s |  5 min 30 s | 40 s       | 16 s  | 22 s       |  1 min 40 s |
| 2 | 1 min 21 s |  1 min 30 s | 10 min 56 s |  6 min 40 s | 25 s       | 18 s  | 11 min 6 s |  1 min 30 s |
| 3 | 1 min 53 s |  2 min 10 s | 18 min 18 s |  9 min 44 s | 5 min 8 s  | 40 s  | 10 min 33 s|  59 s |
| 4 | 3 min 25 s |  1 min 1 s  | 29 min 32 s |  6 min 3 s  | 1 min 12 s | 23 s  | 2 min 11 s |  1 min 5 s |
| 5 | 2 min 28 s |  1 min 3 s  | 10 min 34 s |  11 min 6 s | 19 s       | 15 s  | 4 min 29 s |  2 min 23 s |
| 6 | 2 min 30 s |  1 min 51 s | 11 min 49 s |  5 min 27 s | 2 min 37 s | 22 s  | 11 min 16 s|  1 min 32 s |
| 7 | 1 min 5 s  |  1 min 49 s | 12 min 18 s |  6 min 10 s | 38 s       | 17 s  | 10 min 9 s |  1 min 12 s |
| 8 | 42 s       |  1 min 12 s | 11 min 41 s |  6 min 30 s | 52 s       | 24 s  | 5 min 47 s |  2 min 28 s |
| 9 | 12 min 18 s|  1 min 49 s | 9 min 36 s  |  8 min 36 s | 56 s       | 20 s  | 5 min 24 s |  1 min 57 s |
| 10 | 1 min 32 s|  2 min 32 s | 12 min 7 s  |  11 min 50 s| 1 min 5 s  | 24 s  | 17 min 10 s|  1 min 42 s |
| AVG| 2 min 55 s| 1 min 44 s (1.68x) | 14 min 14 s | 7 min 46 s (1.83x) | 1 min 23 s | 21.9 s (3.8x) | 7 min 51 s | 1 min 39 s (4.75x) |

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


