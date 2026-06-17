# High-performance binary-only instrumentation for afl-fuzz (Qemu Mode)

For the general instruction manual, see [docs/README.md](../docs/README.md).

## 0) qemu_mode vs qemu_bridge - which one to use?

If qemu_mode works for your target then use qemu_mode. It is quite faster
for normal targets, and slightly faster for persistent targets.

If you have a target that does not work for whatever reason (eg Risc-V), then
use qemu_bridge. As this is WIP some features might be implemented yet.
Plus you have access to the plugin system of a modern Qemu.
Note that this mode is work in progress!


## 1) Introduction

The code in this directory builds a standalone tool, based on QEMU "user
emulation" mode, that produces edge-coverage instrumentation for black-box,
closed-source binaries. afl-fuzz uses it to stress-test targets that cannot be
rebuilt with afl-cc.

The usual performance cost is 2-5x. The idea and initial implementation come
from Andrew Griffiths; the current QEMU port (shipped as qemuafl) is from Andrea
Fioraldi, with TCG chaining re-enabled by abiondo.

## 2) Building and using QEMU mode

QEMU mode is a patched QEMU. Build it with `./build_qemu_support.sh`, which
downloads, configures, and compiles the binary. QEMU is large, so this takes a
while and needs a few dependencies (most notably `libtool` and `glib2-devel`).

Once built, pass `-Q` to afl-fuzz and the related utilities to use it.

This build produces `afl-qemu-trace`. When `-Q` is given, afl-fuzz and the
related utilities (afl-showmap, afl-tmin, afl-analyze, afl-cmin) launch
`afl-qemu-trace` if it is present, and otherwise fall back to the newer
`afl-qemu-bridge` backend (see [qemu_bridge/README.md](../qemu_bridge/README.md)).
Set `AFL_QEMU_MODE=bridge` to force the bridge, or `AFL_QEMU_MODE=trace` to force
this qemuafl backend. The full path of the binary actually used is printed at
start-up.

Build variables:

- `CPU_TARGET` — build for a non-native architecture, e.g. `CPU_TARGET=arm`,
  `CPU_TARGET=aarch64`, or `CPU_TARGET=i386` (also required to run 32-bit
  binaries on a 64-bit host).
- `HOST` — cross-compiler prefix, e.g. `HOST=arm-linux-gnueabi` to use
  `arm-linux-gnueabi-gcc`.
- `STATIC=1` — produce statically-linked binaries, useful when building on a
  different system than the one running the fuzzer (often paired with `HOST`).
- `QEMU_LD_PREFIX` — library path for foreign-architecture binaries (e.g.
  running an arm64 binary on x86_64).

If you want the QEMU helper installed system-wide, build it before running
`make install` in the parent directory.

When targeting i386, the forkserver handshake can fail on some binaries due to a
lack of reserved memory. Work around it with:

```
export QEMU_RESERVED_VA=0x1000000
```

## 3) Edge coverage and map size

QEMU mode records **edge coverage**: every control-flow edge (source block ->
destination block) increments a counter in the shared coverage map. Counters
saturate and never wrap back to zero (NeverZero) on all architectures.

By default, edges are assigned **collision-free** IDs from a shared table, so
distinct edges never share a counter. This is more faithful than the classic
hashed scheme and recovers edges that hashing would have merged.

The map defaults to 65536 bytes (64 KB), which QEMU reports to afl-fuzz during
the forkserver handshake. A target that exercises more than 65536 distinct edges
will wrap and start colliding; raise the map to keep coverage collision-free:

```
export AFL_QEMU_MAP_SIZE=262144      # bytes; allowed range 8 .. 2^29
```

`AFL_QEMU_OLD_COVERAGE=1` restores the legacy coverage scheme (`prev_loc XOR
cur_loc` hashed into a fixed 64 KB map). Use it only to reproduce older results
or for compatibility; it loses edges to hash collisions.

To instrument only part of the address space, see *Partial instrumentation*
below.

## 4) Deferred initialization

Like LLVM mode (see
[instrumentation/README.llvm.md](../instrumentation/README.llvm.md)), QEMU mode
supports deferred initialization. Set `AFL_ENTRYPOINT` to move the forkserver to
a later address — for example just before the input file is opened, after
command-line parsing and config loading. This can be a large speed improvement.

For an example, see
[README.deferred_initialization_example.md](README.deferred_initialization_example.md).

`AFL_EXITPOINT` sets an address that terminates the forked instance once the
block containing it is reached.

## 5) Persistent mode

QEMU mode supports persistent mode on x86, x86_64, arm, and aarch64. It speeds
up fuzzing by several factors and is well worth the setup effort.

afl-fuzz and the persistent child synchronize each iteration over a shared futex
word rather than `SIGSTOP`/`SIGCONT` signals, which roughly doubles persistent
throughput. This is automatic when supported; set `AFL_OLD_CHILD_SYNC=1` to
force the legacy signal-based path.

For setup details, see [README.persistent.md](README.persistent.md).

## 6) Snapshot mode

As an extension of persistent mode, QEMU mode can snapshot and restore the
writable memory pages and `brk()`. Enable it with `AFL_QEMU_SNAPSHOT=<hex addr>`,
where the address is the snapshot entry point.

Restoring all writable pages is typically slower than `fork()` but scales better
across cores. If the AFL++ snapshot kernel module is loaded, QEMU mode uses it,
which is both faster than `fork()` and better-scaling. See
[README.persistent.md](README.persistent.md) for details.

## 7) Partial instrumentation

To instrument only part of the address space, set:

```
AFL_QEMU_INST_RANGES=A,B,C...
```

Each item is either an address range like `0x123-0x321` or a module name like
`module.so` (matched against the mapped object's filename).

To exclude part of the address space instead, set `AFL_QEMU_EXCLUDE_RANGES` with
the same format. Exclusions take priority over any included ranges or
`AFL_INST_LIBS`.

## 8) CompareCoverage

CompareCoverage is a sub-instrumentation with effects similar to laf-intel.
Preload `libcompcov.so` and select a level:

```
AFL_PRELOAD=/path/to/libcompcov.so AFL_COMPCOV_LEVEL=2 ...
```

- `AFL_COMPCOV_LEVEL=1` — comparisons with immediate values / read-only memory.
- `AFL_COMPCOV_LEVEL=2` — all comparison instructions and memory-comparison
  functions (with libcompcov preloaded).
- `AFL_COMPCOV_LEVEL=3` — as level 2, plus floating-point comparisons on x86 and
  x86_64 (experimental).

Integer comparison instrumentation is available on x86, x86_64, arm, and
aarch64. Recommended, but not as effective as CMPLOG mode.

## 9) CMPLOG mode

CMPLOG, based on the Redqueen project, learns the immediates in CMP instructions
into a dynamic dictionary and applies them at the input locations that reached
each CMP, trying to solve and pass it. It is very effective and available on
x86, x86_64, arm, and aarch64.

Enable it by passing the target to afl-fuzz with `-c`:

```
-c /path/to/your/target
```

## 10) IJON mode

IJON lets the target transmit information about variable changes to AFL++.
Different IJON methods indicate the semantic meaning of the changed value.
Enable it with:

```
AFL_QEMU_IJON=/full/path/to/test.conf
```

The config file tells QEMU: when execution reaches an instruction address
(`code_addr`), read the given register or memory location and pass the bytes to
the chosen IJON method. One rule per line; comments (`#`) and blank lines are
allowed; fields are comma-separated (surrounding spaces allowed):

```
# code_addr, ijon_method, memory_addr_or_register, data_len
0x40000012c8, ijon_set, rdx, 8
0x40000012c8, ijon_set, r10d, 4
```

- `code_addr` — instruction address that triggers capture, hex (`0x...`) or
  decimal. The target instruction may be relocated when loaded into QEMU, so the
  effective address must be determined in advance.
- `ijon_method` — one of `ijon_set`, `ijon_inc`, `ijon_min`, `ijon_max`.
- `memory_addr_or_register` — a register name (e.g. `rax`/`eax`/`r8d` on x86,
  `r0` on ARM32, `x0`/`w0` on aarch64; case-insensitive) or an absolute virtual
  memory address (e.g. `0x601050`).
- `data_len` — number of bytes to read, 1 .. 8.

To find effective addresses, set `AFL_QEMU_DEBUG_MAPS=1` (with `AFL_DEBUG=1`) to
print the memory layout after the target loads, then compute
`load_base + file_offset`. With `AFL_DEBUG=1`, a triggered rule also logs the
value read and the method called.

For a description of the methods, see [IJON.md](../docs/IJON.md). For examples,
see [ijon-maze](../test/ijon-maze.c).

## 11) Wine mode

QEMU mode can use Wine to fuzz Win32 PE binaries via the `-W` flag of afl-fuzz.
Some binaries require GUI interaction and must be patched. For examples, see
[WineAFLplusplusDEMO](https://github.com/andreafioraldi/WineAFLplusplusDEMO).

## 12) Notes on linking

QEMU mode is supported only on Linux. Supporting BSD would mean porting the
changes in `linux-user/elfload.c` to `bsd-user/elfload.c`.

Instrumentation follows only the `.text` section of the first ELF binary in the
linking process; it does not trace shared libraries. In practice:

- Libraries you want to analyze *must* be linked statically into the executed
  ELF (usually already the case for closed-source apps).
- Standard C libraries and other code that is wasteful to instrument should be
  linked dynamically.

Set `AFL_INST_LIBS=1` to bypass the `.text` detection and instrument every basic
block encountered.

## 13) Exporting coverage (Drcov)

A run's coverage can be exported with a QEMU user-mode plugin enabled at runtime.
The `drcov.c` plugin writes coverage in the Drcov format, loadable by tools such
as [lighthouse](https://github.com/gaasedelen/lighthouse),
[lightkeeper](https://github.com/WorksButNotTested/lightkeeper), or
[Cartographer](https://github.com/nccgroup/Cartographer).

Build the plugins from the `qemuafl` directory:

```
make plugins
```

Load a plugin with the `QEMU_PLUGIN` environment variable or the `-plugin`
option:

```
afl-qemu-trace -plugin qemuafl/build/contrib/plugins/libdrcov.so,arg=filename=/tmp/target.drcov.trace <target> <args>
```

## 14) Benchmarking

To compare QEMU instrumentation against afl-clang-fast on the same target, build
the non-instrumented binary with the optimization flags afl-clang-fast normally
injects, and statically link the bits under test:

```
CFLAGS="-O3 -funroll-loops" ./configure --disable-shared
make clean all
```

Comparisons are meaningless if the optimization levels or instrumentation scopes
don't match.

## 15) Other environment variables

- `AFL_QEMU_MODE` — choose the QEMU backend binary. `AFL_QEMU_MODE=bridge`
  forces `afl-qemu-bridge`; `AFL_QEMU_MODE=trace` (alias `qemuafl`) forces this
  `afl-qemu-trace`. When unset, afl-fuzz uses `afl-qemu-trace` if present and
  falls back to `afl-qemu-bridge`. The full path of the selected binary is
  printed at start-up. This applies to afl-fuzz, afl-showmap, afl-tmin,
  afl-analyze, and afl-cmin alike.
- `AFL_QEMU_FORCE_DFL` — make QEMU ignore the target's registered signal
  handlers.
- `AFL_QEMU_DEBUG_MAPS` — print the target's memory layout after loading (pair
  with `AFL_DEBUG=1`).

## 16) Gotchas, feedback, bugs

If you need to fix up checksums or otherwise clean up mutated test cases, see
`afl_custom_post_process` in `custom_mutators/examples/example.c`.

Do not mix QEMU mode with ASAN, MSAN, or similar; QEMU does not appreciate the
sanitizers' "shadow VM" trick and will likely run out of memory.

User emulation is *not* a security boundary — the binary can freely interact
with the host OS. To fuzz an untrusted binary, sandbox it first.

QEMU does not support every CPU feature a target may use (notably, AVX2/FMA3
support is incomplete). Using binaries for older CPUs, or recompiling with
`-march=core2`, can help.

## 17) Alternatives: static rewriting

Rewriting a binary once, instead of translating it at run time, can be faster —
but static rewriting is fraught with peril, since it depends on fully modeling
control flow without executing every path. For more, see
[docs/fuzzing_binary-only_targets.md](../docs/fuzzing_binary-only_targets.md).
