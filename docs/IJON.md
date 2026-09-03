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

Two properties of the default mode surprise harness authors, and both have been
found in the wild:

- **It accumulates by exclusive-or.** The register is `state ^= n`, so passing a
  raw identifier each time makes the register a digest of the *route* taken
  rather than the *situation* the target is in. To report a situation, pass the
  delta against what you reported last:
  `IJON_STATE(prev ^ cur); prev = cur;` — and reset `prev` at the start of every
  execution, or the first annotation of one input inherits the last state of the
  previous one.
- **It is reduced modulo 65536**, so every bit from 16 upwards is discarded
  silently. An identifier built by setting one bit per condition runs out of
  room at 16 conditions; fold it yourself first, e.g.
  `n = ((n >> 16) ^ n) & 0xffff;`, so the high conditions still affect the
  result instead of vanishing.

`AFL_LLVM_IJON_STATE_MAX` (below) removes both problems, at the cost of
requiring you to declare how many states there are.

#### Declared state regions — `AFL_LLVM_IJON_STATE_MAX=N`

Compile with `AFL_LLVM_IJON_STATE_MAX=N` and `IJON_STATE()` stops folding the
state into the edge index. Instead each state gets **its own copy of the whole
coverage map**: the edge index becomes `state * cov_size + edge` and the map
becomes `cov_size * (N + 1)`. Region 0 is byte-for-byte the plain build's map,
so a run with the state never leaving 0 is directly comparable to an
unannotated build.

In this mode the argument **is** the state, not something to mix in. It is
assigned, not exclusive-ored, so no delta trick and no folding is needed, and a
value above `N` aborts the run with a message rather than wrapping — a modulo
there would reintroduce exactly the aliasing the mode exists to remove.

The rule for what may be a state id is stricter than in the default mode, and
the abort is there to enforce it: **a state id must be a position in the
protocol's progress** — pre-auth, keys exchanged, authenticated, channel open,
rekeyed — and never a configuration (cipher choice, dialect, whether signing is
on), never a resource count, and never a slot or handle bitmask. Those belong in
`IJON_SET`/`IJON_INC` or in the ordinary coverage signal. Real protocols need
well under 32 such positions; the pass refuses anything above 255.

The map expansion is cheaper than it looks, because AFL's per-execution map work
is small next to a real protocol target's execution. Measured on Samba's SMB2
server harness, whose coverage map is 403,392 bytes, seven declared positions
take the map to 2,893,376 bytes — a 6.1× expansion for **4.3 % of throughput**.

Before reaching for it, consider `IJON_MAX_AT(slot + position, work_done)` on
the same position ladder: it needs no rebuild flag, no map expansion and no
declaration, and on an nginx QUIC/HTTP-3 harness it drove inputs measurably
further into the protocol than declared regions did for the same cost. Declared
regions are the tool when you need states genuinely *separated* — so that the
same edge in two states can never alias — rather than merely rewarded.

#### `IJON_CTX(x)`
Scoped state hashing: temporarily incorporates variable `x` into the state hash.  
Useful for distinguishing behavior based on execution context.  
Example: `IJON_CTX(function_id)` makes AFL track the same code differently depending on the active function.

`AFL_STATE_ACTION()` and `AFL_HOT_REGION()` were removed along with the
state-transition map and aimed havoc they fed; both measured at or below the
baseline. A harness still carrying them will not compile against this header —
delete the calls.

### Relationship to state fuzzing mode

`IJON_STATE()` mixes the state into the edge hash, which makes state and
coverage one signal. That is the whole mechanism now: the separate
state-transition map `-Js` used to keep was measured to cost without paying and
was removed. See
[fuzzing_stateful_targets.md](fuzzing_stateful_targets.md).

### Distance and Comparison Macros

#### `IJON_STRDIST(x, y)`
Reward inputs that increase the **common prefix length** of two strings.  
Example: `IJON_STRDIST(input, "bootloader")` helps AFL solve string comparisons inside hash maps.

#### `IJON_DIST(x, y)`
Reward fuzzing inputs that share the most beginning bytes.
(note that this changed to original IJON behaviour, it is not the absolute distance anymore.)
Max length is defined in instrumentation/afl-compiler-rt.o.c and is set to 1024.
Example: `IJON_DIST(buf, expected)` guides the fuzzer toward the expected byte values.

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

### Retiring completed max targets

Use `IJON_MAX_UNTIL(x, limit)` when an IJON max objective has a known upper
bound and continuing to schedule its seed after that point is no longer useful:

```c
IJON_MAX_UNTIL(depth, 100);
IJON_MAX_UNTIL_AT(0x1234, score, target_score);
```

The fuzzer keeps guiding `x` upward while `x < limit`. When `x >= limit`, the
slot writes the terminal value `UINT64_MAX`. If `AFL_IJON_RETIRE_MAX` is set
during fuzzing, AFL++ removes that IJON max input from the IJON scheduling pool.

Stored maximum-reaching inputs are validated and loaded again when AFL++ starts.
The scheduler replays them round-robin after every 15 normal scheduler turns,
so IJON replay occupies at most one of every 16 scheduling opportunities. New
coverage found during replay enters the queue as an independent root entry.
`AFL_IJON_REPLAY_INTERVAL=N` changes that share: 4 replays every fourth turn, 1
every turn, 0 switches replay off. `ijon_max_vars` and `ijon_max_updates` in
`fuzzer_stats` say how many slots are live and how often one improved.

### `IJON_MAX` does not always win its own objective

Worth knowing before annotating a quantity: on a stateful QUIC server harness
with one `IJON_MAX` over total bytes delivered — an explicit *more is better*
objective — the arms **without** the annotation grew that quantity 20 to 50
times better (mean 8.52 bytes per input and a maximum of 13,670 against 0.35 and
207 for the annotated arms). Plain coverage feedback found the byte-moving code
paths and the `IJON_MAX` arms did not.

The mechanism is the queue, not the objective. `IJON_MAX` gets a fixed share of
the scheduling turns and one stored input per slot, while `IJON_SET`/`IJON_INC`
in the same harness create queue entries without any bound (below), so the
corpus grows 15-fold with state churn and every entry's share of the energy —
including the one holding the byte-moving path — shrinks with it. Two knobs
address that from opposite ends: `AFL_IJON_REPLAY_INTERVAL` raises the max
channel's share, `AFL_IJON_ADMIT_PCT` bounds the set channel's queue growth.

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

### Map layout and the three sizes that get reported

An IJON build shares one region with the fuzzer, laid out as

```
[ coverage | IJON_MAP (64 KB) | IJON_BYTES (4 KB) ]
   edges     IJON_SET/_INC      IJON_MAX/_MIN slots
```

`IJON_SET` and `IJON_INC` write into the 64 KB middle area, and the fuzzer
deliberately treats that area as part of its bitmap — that is how a set bit
becomes a new find. Only the trailing 4 KB of `IJON_MAX` slots is outside it.
So three different numbers describe one map, and all three are correct:

* `AFL_DUMP_MAP_SIZE` prints the **whole** region, IJON areas included. With
  IJON compiled in, the breakdown also goes to **stderr**
  (`148288 = coverage 78656 + ijon 65536 + ijon max 4096`) while stdout keeps
  the single parsable number.
* `afl-fuzz`'s `Target map size:` line is the same whole-region size as
  reported by the forkserver, and its `IJON map: coverage bytes ...` line is
  the coverage area alone.
* `total_edges` in `fuzzer_stats` is coverage + the 64 KB IJON area, because
  that is what the fuzzer tracks for novelty. It is therefore larger than the
  coverage region, and `bitmap_cvg` is computed over it.

Comparing an IJON build against a plain one by map size only works on the
coverage figure, not on `AFL_DUMP_MAP_SIZE` or `total_edges`.

### `edges_found` is not coverage on an IJON build — read `cov_edges_found`

`edges_found` counts set bytes over the whole map, and on an IJON build the map
also holds the 64 KB `IJON_SET`/`IJON_INC` area. Those writes are *meant* to
register as coverage, so they land in the same count as real edges. The effect
is not marginal. A target with nine reachable edges and one
`IJON_SET(b[0] << 8 | b[1])`:

```
edges_found       : 15397
cov_edges_found   : 9
total_edges       : 65600
```

`cov_edges_found` counts the coverage area only — `real_map_size` minus the
IJON map — and is the figure to compare against a plain build or between two
IJON builds. `edges_found` is kept unchanged so existing tooling and plot files
are unaffected.

One caveat: with `AFL_LLVM_IJON_STATE_MAX=N` the coverage area is itself `N + 1`
copies of the map, and `cov_edges_found` spans all of them. It is therefore
still not comparable between two builds with different `N`, or against a plain
build. When comparing arms that differ in `N`, replay the corpora through one
common build instead of reading either figure.

### What bounds each IJON channel

The three channels are saved and bounded in three different ways, and the
natural assumption — that the state-fuzzing knobs cover all of them — is wrong:

| Channel | Where it lands | What bounds it |
|---|---|---|
| `IJON_MAX` / `IJON_MIN` | 4 KB of `u64` slots outside the fuzzer's map, one stored input per slot in `<out>/ijon_max/` | one slot per variable, replayed every `AFL_IJON_REPLAY_INTERVAL` turns; `AFL_IJON_RETIRE_MAX` drops slots that reached an `IJON_MAX_UNTIL` limit |
| `IJON_SET` / `IJON_INC` | inside the coverage bitmap, on purpose | nothing, by default — `AFL_IJON_ADMIT_PCT` |
| `IJON_STATE` | the edge hash | unbounded by design. `AFL_LLVM_IJON_STATE_MAX` replaces the hash with one map region per state, which bounds the aliasing instead of the saving |

A byte written by `IJON_SET` or `IJON_INC` **has** to register as new coverage —
that is the whole mechanism — so such a find travels the ordinary save path and
none of the `AFL_STATE_*` knobs, nor `AFL_IJON_RETIRE_MAX`, can slow it down. In
an ablation on a stateful harness the annotated arms saved roughly 7.7 times as
many queue entries per execution as the plain arms, and no user-facing knob
changed that. On a small annotated target 206 of 267 entries came from this
channel alone.

`AFL_IJON_ADMIT_PCT=N` is the bound for it: once the queue holds at least 200
entries and novelty that is *only* an `IJON_SET`/`IJON_INC` write has created
more than N% of them, that novelty stops saving inputs for the rest of the run.
The channel keeps writing into the map and keeps being reported; only saving
stops. Unlike the state channel there is no yield licence that lifts the bound
again — `ijon_only_paid` is reported so the share can be judged, not to reopen
the gate — and the bound is off unless set, because a coverage find that is
dropped is dropped for good.

`fuzzer_stats` reports the channel whenever the target is an IJON build:

- `ijon_max_vars` — `IJON_MAX`/`IJON_MIN` slots holding a stored input
- `ijon_max_updates` — times a slot improved
- `ijon_only_saves` — queue entries saved for an `IJON_SET`/`IJON_INC` write alone
- `ijon_only_paid` — of those, the ones that went on to mother a find of its own
- `ijon_admit_off` — 1 once the channel lost its licence to save
- `ijon_replay_int` — the `IJON_MAX` replay interval in force

To check statically whether a binary carries IJON instrumentation, look for the
strong symbol the pass emits — `strings` cannot tell, because the runtime is
linked into every `afl-cc` target:

```sh
nm ./target | grep __afl_ijon_enabled     # "D" = instrumented, "V" = weak default
```

### Environment Variables

- **`AFL_LLVM_IJON=1`**: Enables IJON instrumentation during compilation
- **`AFL_LLVM_IJON_STATE_MAX=N`**: Compile-time. Give each of the `N + 1` declared states its own copy of the coverage map instead of folding the state into the edge index — see [Declared state regions](#declared-state-regions--afl_llvm_ijon_state_maxn). Requires `AFL_LLVM_IJON=1`. Refused above 255; real protocols need well under 32
- **`AFL_IJON_RETIRE_MAX=1`**: Treats `UINT64_MAX` IJON max values as completed targets and stops scheduling their stored IJON input
- **`AFL_IJON_ADMIT_PCT=N`**: Largest share of the queue, in percent, that `IJON_SET`/`IJON_INC` may create on its own (default 0, no bound) — see above
- **`AFL_IJON_REPLAY_INTERVAL=N`**: Scheduling turns between two `IJON_MAX` replays (default 16, 0 switches replay off)
- **`AFL_IJON_HISTORY_LIMIT=N`**: Size of the rolling `finding_*.dat` history in `<out>/ijon_max/` (default 0, history off)

`AFL_IJON_HISTORY_LIMIT` is a **file budget, not a bound on anything the fuzzer
saves**: every improvement of any `IJON_MAX`/`IJON_MIN` slot is also written to
`finding_%0*d.dat` in the IJON max directory, as one global ring of N files that
wraps. It does not change what enters the queue, how often IJON inputs are
replayed, or how many slots are live.

N below the number of live IJON variables is legal and only warns once. It
cannot be validated up front, because the live variable count is not known up
front: a slot counts as live the first time its `IJON_MAX` is reached, so a
harness with five annotations can be at four variables in the first second and
six a few minutes later. A limit under that count means the ring wraps within
one round of variables, so one variable's newest finding can evict another's —
the stored maximum-reaching inputs in `<out>/ijon_max/<slot>` are unaffected,
only the history is. Leaving it unset writes no history at all.

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

### The other tools

`afl-showmap`, `afl-cmin`, `afl-tmin` and `afl-analyze` see the same map
afl-fuzz does: coverage plus the 64 KB `IJON_SET`/`IJON_INC` area, with the
4 KB of `IJON_MAX` slots (and a bug-pass map, if the target has one) excluded,
because those hold wide values rather than hit counts and would otherwise be
reported as tuples, minimised against, or bucket-classified in place. So an
`afl-showmap` dump of an IJON target lists tuples above the coverage size, and
two inputs that differ only in an `IJON_SET` value are two different traces —
which is what makes `afl-cmin` keep both, exactly as afl-fuzz would.

The IJON channels need a map to write into: a bare `./target` run leaves them
alone, while a run under any of these tools has one. Nothing has to be passed
for that.
