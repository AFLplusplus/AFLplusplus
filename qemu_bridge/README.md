# High-performance binary-only instrumentation for afl-fuzz (QEMU bridge) - WIP!

For the general instruction manual, see [docs/README.md](../docs/README.md).

## 0) qemu_mode vs qemu_bridge - which one to use?

If qemu_mode works for your target then use qemu_mode. It is quite faster
for normal targets, and slightly faster for persistent targets.

If you have a target that does not work for whatever reason (eg Risc-V), then
use qemu_bridge. As this is WIP some features might be implemented yet.
Plus you have access to the plugin system of a modern Qemu.
Note that this mode is work in progress!


## 1) Introduction

`qemu_bridge` lets afl-fuzz instrument and fuzz **black-box, closed-source
binaries** by running them under QEMU "user emulation" mode. You get edge
coverage, comparison logging, and lightweight sanitization for targets that
cannot be rebuilt with `afl-cc`.

The backend is a fork of **qemu-libafl-bridge** (based on **QEMU 10.2**) — the
same modern QEMU fork that powers LibAFL's `libafl_qemu`. It replaces the older
**qemuafl** backend (a fork of QEMU 5.2). All AFL-specific code is additive and
compiled behind the `CONFIG_AFL` flag (enabled by the `--afl` configure switch),
so the same tree keeps building cleanly as `libafl_qemu`.

Why the bridge:

- **Modern QEMU 10.2** instead of 5.2 — years of upstream CPU, target, and
  syscall fixes, and far better coverage of recent instruction sets.
- **Shared lineage with `libafl_qemu`**, so AFL++ and LibAFL track the same QEMU
  fork.
- **Dynamic, collision-free edge coverage** instead of the fixed XOR-hash map.

The typical performance cost is the usual QEMU-mode 2-5x over native execution.
Fork mode is competitive with qemuafl; **persistent mode** is dramatically
faster (see §7).

## 2) Building

The backend builds to the repository-root `afl-qemu-bridge`, alongside the
companion libraries `libqasan.so` and `libcompcov.so`. (The legacy qemuafl
backend in `qemu_mode/` builds a separate `afl-qemu-trace`, so the two no longer
collide on disk.)

```sh
make                              # build the AFL++ core first
cd qemu_bridge
./build_qemu_bridge_support.sh
```

or, from the repository root, as part of the normal binary-only build:

```sh
make binary-only
```

QEMU is a large project, so the first build takes a while and needs the usual
QEMU build dependencies (a C toolchain, `ninja`, `python3`,
`glib2`/`pkg-config`).

Build-time environment variables for `build_qemu_bridge_support.sh`:

- `CPU_TARGET` — guest architecture to build (`x86_64` by default; also `i386`,
  `arm`, `aarch64`, `mips`, `ppc`). Set this to run non-native or 32-bit
  binaries (e.g. `CPU_TARGET=i386` to fuzz 32-bit guests on a 64-bit host, or
  `CPU_TARGET=aarch64`).
- `HOST=<prefix>` — cross-compiler prefix when building QEMU itself for another
  host architecture (e.g. `HOST=aarch64-linux-gnu`).
- `STATIC=1` — build a statically-linked, non-PIE `afl-qemu-bridge` (useful with
  `HOST` when the build and run machines differ).
- `DEBUG=1` — build QEMU with debug info / assertions.
- `NO_CHECKOUT=1` — skip the submodule checkout/pin step and build whatever is
  currently checked out in `qemu_bridge/qemu-libafl-bridge`.

The bridge QEMU source is the `qemu_bridge/qemu-libafl-bridge` submodule, pinned
by `qemu_bridge/QEMU_BRIDGE_VERSION`. To exclude the bridge from the top-level
build, pass `NO_QEMU=1` to `make`.

If you want the helper installed system-wide, build it before running
`make install` in the parent directory.

To run a guest whose libraries live elsewhere (e.g. an aarch64 root on an
x86_64 host) set `QEMU_LD_PREFIX=/path/to/sysroot`.

Note: when targeting i386, some binaries fail the forkserver handshake for lack
of reserved memory. Fix it with:

```sh
export QEMU_RESERVED_VA=0x1000000
```

## 3) Choosing the backend (bridge vs legacy qemuafl)

The two backends now build to **distinct binaries** — the bridge to
`afl-qemu-bridge`, the legacy qemuafl to `afl-qemu-trace` — so they no longer
overwrite each other on disk.

When you pass `-Q`, afl-fuzz and the related utilities (afl-showmap, afl-tmin,
afl-analyze, afl-cmin) pick the binary like this:

- If `afl-qemu-trace` is present, it is used.
- Otherwise `afl-qemu-bridge` is used.
- `AFL_QEMU_MODE=bridge` forces `afl-qemu-bridge` regardless of what else is
  present; `AFL_QEMU_MODE=trace` (alias `qemuafl`) forces `afl-qemu-trace`.

The full path of the binary actually used is printed at start-up, e.g.
`Using QEMU binary: /path/to/afl-qemu-bridge`. So if you have only built the
bridge, `-Q` selects it automatically; build both and the legacy qemuafl wins by
default unless you set `AFL_QEMU_MODE=bridge`.

Binaries are searched via `AFL_PATH`, then next to the AFL++ tool, then the
install dir, then `PATH` — point `AFL_PATH` at a specific directory to override
which `afl-qemu-bridge`/`afl-qemu-trace` is used.

A separate, lower-level knob selects the forkserver *protocol* rather than the
binary: `AFL_QEMU_BACKEND=legacy` switches to the old qemuafl forkserver
handshake (needed only for an old qemuafl `afl-qemu-trace` that predates the
shared forkserver protocol). The default (`bridge`) is correct for both the
bridge and a current qemuafl build.

## 4) Running

Build the backend, then invoke afl-fuzz (and the related utilities such as
`afl-showmap`) with `-Q`:

```sh
afl-fuzz -Q -i in -o out -- ./target @@
```

The target is run unmodified; no recompilation or source is required.

## 5) Coverage map and `AFL_QEMU_MAP_SIZE`

The bridge emits **dynamic, collision-free** edge coverage. Each newly-seen edge
`(src_block, dst_block)` is assigned the next free slot in the shared coverage
map at translation time, recorded in a shared edge-ID table so the IDs stay
stable across forked children. This avoids the edge collisions inherent to the
legacy fixed-size XOR-hash map.

### Sizing the map: `AFL_QEMU_MAP_SIZE`

The coverage map has a fixed upper bound, chosen **once** at forkserver startup.
That bound is the number of distinct edges the run can record collision-free,
and it is also the number of bytes afl-fuzz scans and clears **on every single
execution** — so it directly affects throughput.

```sh
AFL_QEMU_MAP_SIZE=<bytes>
```

- **Default: 65536 (64 KB)** — `MAP_SIZE`, the same default as the rest of
  AFL++. This is collision-free for up to 64K distinct edges, which is plenty
  for the large majority of targets, and keeps the per-execution map-processing
  cost small.
- **Raise it for large targets.** If your target exercises more than ~64K
  distinct edges you will start to see edge folding (collisions) above the
  bound; raise `AFL_QEMU_MAP_SIZE` (e.g. `262144`, `1048576`) to stay
  collision-free. The cost is a larger map for afl-fuzz to scan each run, so set
  it to roughly the edge count you expect, not arbitrarily large.
- Accepted range: `8 .. 2^29-1` bytes.

Why a dedicated variable: afl-fuzz uses `AFL_MAP_SIZE` internally to negotiate
the shared-memory *allocation* with dynamic-map targets, so it is not a reliable
way to request a specific bridge map size. `AFL_QEMU_MAP_SIZE` controls the
bridge's collision-free bound unambiguously. You can inspect the negotiated size
in the afl-fuzz banner ("Target map size: …").

## 6) Deferred initialization (entry / exit points)

Like LLVM mode (see
[instrumentation/README.llvm.md](../instrumentation/README.llvm.md)), the bridge
supports deferred forkserver initialization.

- `AFL_ENTRYPOINT=0x<addr>` moves the forkserver to a chosen instruction
  address — ideally just before the input is consumed, after expensive one-time
  setup (argument parsing, config loading, etc.). This can be a large speed-up.
  The default entry point is the executable's own ELF entry (after the dynamic
  linker has run), so coverage and the forkserver start at the program proper,
  not inside `ld.so`.
- `AFL_EXITPOINT=0x<addr>` terminates the forked instance when the block
  containing that address is reached (when the *block*, not the exact
  instruction, is executed).

For PIE/PIC targets these are loaded addresses, not raw `nm` addresses — see the
note in §7.1.

## 7) Persistent mode

Persistent mode loops the target between two points *in-process* instead of
fork+exec per input. It is the single biggest throughput win available — often
an order of magnitude or more — and is well worth the setup effort.

Internally the bridge drives the loop through a TCG instruction hook and
synchronizes with afl-fuzz over a fast shared-memory **futex** channel rather
than fork/pipe, since no per-iteration fork is needed.

Persistent mode is currently supported on **x86 / x86_64**. (arm/aarch64/mips/
ppc require per-architecture loop-back support that is not yet implemented; they
run in fork mode.)

### 7.1) The START address — `AFL_QEMU_PERSISTENT_ADDR`

Set the start of the persistent loop:

```sh
AFL_QEMU_PERSISTENT_ADDR=0x<addr>
```

This is usually the address of a function. If START points at a function entry
and neither `RET` nor `EXITS` is set (see below), QEMU patches the return
address so the function returns to START on each iteration (WinAFL-style).

*PIE/PIC note:* QEMU loads position-independent executables at a fixed base. For
amd64 add `0x4000000000` (9 zeroes) to the `nm` address; for 32-bit add
`0x40000000` (7 zeroes). To discover the actual base on your setup, run

```sh
AFL_DEBUG=1 afl-qemu-bridge ./target
```

and read the printed instrument range / entry point. If the address is invalid,
afl-fuzz reports that the forkserver could not be found.

### 7.2) The RET address — `AFL_QEMU_PERSISTENT_RET`

`AFL_QEMU_PERSISTENT_RET=0x<addr>` marks the last instruction of the loop; the
emulator jumps back to START when it reaches this address. Use it when the loop
should end before the natural end of the function START is in. Apply the same
PIE base offset as for START.

### 7.3) The stack offset — `AFL_QEMU_PERSISTENT_RETADDR_OFFSET`

x86/x86_64 only. If START is *not* a function entry and no `RET` is set, QEMU
needs the offset from the stack pointer to the saved return address it should
patch. Set it with `AFL_QEMU_PERSISTENT_RETADDR_OFFSET=<n>`.

To find the offset with gdb: break at `main` (so PIE addresses are resolved),
run, break at the function containing START and at START itself, note `$sp` at
each, and take the difference.

### 7.4) Restoring registers — `AFL_QEMU_PERSISTENT_GPR`

Almost always set `AFL_QEMU_PERSISTENT_GPR=1`. It saves the general-purpose
register state on the first iteration and restores it on each subsequent one.
Without it, register-passed state (e.g. `argc`/`argv` for a `main()`-based loop)
is lost after the first iteration. The bridge also restores the stack pointer
each iteration so the stack does not drift over long runs.

### 7.5) Restoring memory — `AFL_QEMU_PERSISTENT_MEM`

`AFL_QEMU_PERSISTENT_MEM=1` restores the writable memory pages to their START
snapshot on every iteration. Use it when the loop body mutates global/heap state
that must be reset between inputs. It is more expensive than register-only reset,
so enable it only when needed.

### 7.6) Reset on exit() — `AFL_QEMU_PERSISTENT_EXITS`

`AFL_QEMU_PERSISTENT_EXITS=1` makes QEMU treat the `exit`/`exit_group` syscall as
the end of a loop iteration (jumping back to START) instead of terminating the
process.

### 7.7) Loop count — `AFL_QEMU_PERSISTENT_CNT`

The number of iterations before a real fork happens, resetting accumulated
process state. The more stable your loop, the higher you can set it. A low value
is ~100, the maximum ~10000; the default is 1000. This mirrors `__AFL_LOOP()` in
LLVM persistent mode.

```sh
AFL_QEMU_PERSISTENT_CNT=1000
```

### 7.8) Snapshot entry — `AFL_QEMU_SNAPSHOT`

`AFL_QEMU_SNAPSHOT=0x<addr>` is a convenience alias that enables persistent mode
with memory restoration at the given entry address (equivalent to setting
`AFL_QEMU_PERSISTENT_ADDR` together with `AFL_QEMU_PERSISTENT_MEM`).

## 8) Partial instrumentation

By default only the `.text` of the main executable is instrumented; shared
libraries (libc, etc.) are not, which keeps coverage focused and fast.

- `AFL_INST_LIBS=1` — instrument every basic block encountered, including shared
  libraries.
- `AFL_QEMU_INST_RANGES=A,B,C…` — instrument only these ranges. Each item is
  either an address range `0x123-0x321` or a module name `module.so` (matched
  against the mapped object filename).
- `AFL_QEMU_EXCLUDE_RANGES=A,B,C…` — exclude these ranges from instrumentation.
  Same item format; exclusion takes priority over any inclusion and over
  `AFL_INST_LIBS`.
- `AFL_CODE_START=0x<addr>` / `AFL_CODE_END=0x<addr>` — override the default
  instrumented address window directly.
- `AFL_INST_RATIO=<1-100>` — instrument only a random fraction of blocks.

## 9) CompCov (comparison coverage)

CompCov is sub-instrumentation similar to laf-intel: it splits multi-byte
comparisons so the fuzzer can solve them progressively.

On the bridge, CompCov is generated by the in-QEMU TCG hooks — **you do not need
to `AFL_PRELOAD` `libcompcov.so`**. Just set the level:

- `AFL_COMPCOV_LEVEL=1` (or `AFL_QEMU_COMPCOV=1`) — instrument comparisons with
  immediate / read-only-memory operands.
- `AFL_COMPCOV_LEVEL=2` — instrument all integer comparison instructions.

Integer-comparison instrumentation is available on x86, x86_64, arm, aarch64,
and riscv. It is **not** available on mips/ppc (the bridge does not yet emit the
compare hook for those targets). CompCov is useful, but CMPLOG (below) is
generally more effective.

## 10) CMPLOG mode

CMPLOG (Redqueen-style) records the operands of comparison instructions into a
dynamic dictionary and replays them at the matching input positions. Enable it
by passing the target a second time with `-c`:

```sh
afl-fuzz -Q -c 0 -i in -o out -- ./target @@
```

- Instruction-level CMPLOG is available on x86, x86_64, arm, aarch64, and riscv
  (not mips/ppc — same compare-hook limitation as CompCov).
- Routine/argument CMPLOG (RTN — capturing function-call argument buffers) is
  currently **x86_64 only**.
- `AFL_QEMU_CMPLOG_NO_RTN=1` disables the RTN pass (instruction CMPLOG only).

## 11) QASan (QEMU AddressSanitizer)

QASan adds heap-overflow detection to uninstrumented binaries via a shadow-memory
engine inside QEMU plus a guest-side allocator interposer.

```sh
AFL_USE_QASAN=1 afl-fuzz -Q -i in -o out -- ./target @@
```

`AFL_USE_QASAN=1` automatically loads `libqasan.so` into the guest (discovered
via `AFL_PATH` or next to `afl-qemu-bridge`) and enables the in-QEMU shadow — no
manual `AFL_PRELOAD` is needed. Overflow **detection** works on all
architectures; the report's PC/BP/SP context and backtraces are populated on
x86/x86_64, arm, aarch64, and riscv.

Current limitations versus a full ASan build:

- Only the allocator is interposed. libc string/memory routines are not yet
  shadowed, so glibc SIMD string functions can occasionally over-read small heap
  buffers (a known QASan false positive without string interposition).
- Symbolized allocation/free backtraces are not yet available.

## 12) IJON

IJON lets the target push semantic state values into a secondary feedback map to
guide exploration (mazes, state machines, etc.). Enable the secondary map with:

```sh
AFL_QEMU_IJON=1
```

The bridge implements the LibAFL-style IJON secondary map; values are fed via the
source-level IJON annotation API. See [docs/IJON.md](../docs/IJON.md) for the
annotation methods (`ijon_set`, `ijon_inc`, `ijon_min`, `ijon_max`, …) and
[test/ijon-maze.c](../test/ijon-maze.c) for an example.

## 13) Architecture and feature support

HOST (the machine running the fuzzer) and TARGET (the guest binary's
architecture) are independent: on any supported host you can fuzz any supported
target with that target's feature set.

| Feature                          | x86_64 | i386 | arm | aarch64 | mips | ppc | riscv |
|----------------------------------|:------:|:----:|:---:|:-------:|:----:|:---:|:-----:|
| Edge coverage                    |  yes   | yes  | yes |  yes    | yes  | yes | yes   |
| Range / entry / exit filtering   |  yes   | yes  | yes |  yes    | yes  | yes | yes   |
| IJON                             |  yes   | yes  | yes |  yes    | yes  | yes | yes   |
| CompCov                          |  yes   | yes  | yes |  yes    |  no  | no  | yes   |
| CMPLOG (instructions)            |  yes   | yes  | yes |  yes    |  no  | no  | yes   |
| CMPLOG (routines / RTN)          |  yes   |  no  | no  |   no    |  no  | no  | no    |
| Persistent mode + futex sync     |  yes   | yes  | no  |   no    |  no  | no  | no    |
| QASan — overflow detection       |  yes   | yes  | yes |  yes    | yes  | yes | yes   |
| QASan — report context           |  yes   | yes  | yes |  yes    |  no  | no  | yes   |

x86_64 is the primary, fully-supported target. The HOST is fully supported on
x86_64; other hosts (e.g. aarch64) are expected to work via QEMU's native TCG
backends but are not yet validated.

## 14) Performance notes

- **Map size dominates per-execution overhead.** afl-fuzz scans and clears the
  whole coverage map every run, so keep `AFL_QEMU_MAP_SIZE` close to your
  target's real edge count (§5). The 64 KB default is a good balance.
- **Fork mode** caches translated code in the forkserver parent so children do
  not re-translate the guest on every run; throughput is competitive with
  qemuafl. QEMU 10.2 has a larger address space than 5.2, so the per-fork
  copy-on-write cost is slightly higher — most visible on trivially small
  targets where almost no work happens per execution.
- **Persistent mode** (§7) avoids the per-execution fork entirely and is far
  faster — use it whenever you can identify a clean loop in the target.
- For an apples-to-apples comparison against `afl-clang-fast`, build the
  reference binary with matching optimization flags and statically link the code
  under test; otherwise speed/coverage numbers are not comparable.

## 15) Debugging

- `AFL_DEBUG=1` prints the instrumented address range, entry/exit points, and
  resolved configuration at startup — use it to find load bases for persistent
  mode and to confirm range filtering.
- QEMU's own logging is available via the `-d` flag / `QEMU_LOG` (e.g.
  `QEMU_LOG=out_asm` to dump generated code) when running `afl-qemu-bridge`
  directly.

## 16) Not yet ported from qemuafl

These qemuafl features are not (yet) available on the bridge:

- **Persistent-hook ABI** (`AFL_QEMU_PERSISTENT_HOOK=<hook.so>` for custom
  in-memory input placement). Existing hook `.so` files will not load.
- **Generic `AFL_PRELOAD` → guest passthrough.** Only the QASan `libqasan.so`
  auto-load is wired; CompCov is driven by `AFL_COMPCOV_LEVEL`, not by preloading
  `libcompcov.so`.
- **libqasan** string/memory interposition and the dlmalloc backend (see §11).
- **The hooking-bridge** user-instrumentation mechanism.
- **Automatic use of the AFL snapshot LKM**; persistent memory reset uses the
  userspace page-backup path.
- **Wine / Win32 PE fuzzing** (`-W`) is not validated on the bridge.

## 17) Gotchas, limitations, security

- Do not combine QEMU mode with ASan/MSAN-built targets; QEMU does not get along
  with the sanitizers' shadow-VM trick and tends to run out of memory. Use QASan
  (§11) for heap-overflow detection under emulation instead.
- User-emulation mode is **not** a security boundary — the guest interacts
  freely with the host OS. Sandbox untrusted targets.
- QEMU may not implement every CPU feature your target uses (notably some
  AVX2/FMA3 paths). Targets built for older CPUs or with `-march=core2` avoid
  this.
- If you need to fix checksums or otherwise post-process mutated inputs, see
  `afl_custom_post_process` in `custom_mutators/examples/example.c`.

## 18) Alternatives

Static binary rewriting can be faster than run-time translation but is harder to
get right. See
[docs/fuzzing_binary-only_targets.md](../docs/fuzzing_binary-only_targets.md) for
the trade-offs and other binary-only options.
