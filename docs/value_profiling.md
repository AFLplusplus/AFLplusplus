# Value Profiling

Value profiling (VP) adds a distance signal on top of normal edge coverage.
Instead of only asking whether a comparison was reached, AFL++ also tracks how
close the observed operands are to a match. This helps on transformed compares
where direct solve attempts are weak or impossible.

## Activation

Value profiling currently uses runtime VP instrumentation in the main target.
Compile the target with `AFL_LLVM_VALUE_PROFILE=1`.

VP and CmpLog are alternative compare-observer instrumentation modes for a
single compile. A target compiled with `AFL_LLVM_VALUE_PROFILE=1` emits VP hooks
for the compare-observer passes instead of CmpLog hooks. Use a separate
CmpLog-compiled `-c` binary if you want AFL++'s CmpLog workflow in the same
fuzzing session.

- `-r0`: enable value profiling from startup
- `-rN`: enable value profiling after `N` seconds without new edge coverage,
  then keep it enabled for the rest of the run

Without `-r`, value profiling stays disabled.

Runtime VP currently requires an LLVM-instrumented main target compiled with
`AFL_LLVM_VALUE_PROFILE=1`. It is not supported with `-n`, QEMU, Frida,
Unicorn, CoreSight, Nyx, or `AFL_NO_FORKSRV` execution modes.

Runtime value profiling tracks eight runtime slots per assigned compare site.

Stagnation mode is edge-coverage based: `-rN` activates after `N` seconds since
the last new edge-coverage discovery. It is not based on total queue growth.
When stagnation mode activates, AFL++ synchronously replays the existing queue
once so the VP frontier also reflects already-discovered inputs. This replay
processes enabled queue entries only. Inputs disabled before activation, such as
coverage-duplicate seeds, are not reconsidered for VP.

## Frontier

VP maintains a frontier of the best known distances for `(site, slot)` pairs.
Queue entries owning frontier slots are favored for more fuzzing.

Inputs admitted only through VP are marked with `,+vp` in their queue filename
and with state files under `.state/vp_only`. If a VP-only entry later owns no
frontier slots, AFL++ disables it after a one-cycle grace period. VP-only queue
admission is intentionally strict-distance-only: equal-distance cost
improvements do not admit a new queue entry by themselves, although cost still
breaks ties among already-admitted frontier owners.

For scalar and routine compares, each dynamic hit ordinal selects one adjacent
slot pair, with the two metrics stored in that pair. Once an execution observes
more hits than the four pairs can represent, later hits wrap around and update
the same pairs.

The physical site namespace has 65,536 entries (`VP_MAP_W`), organized as
16,384 four-way sets. A logical site token selects two candidate sets and a
preferred way in each. An existing tag is reused; otherwise the runtime claims
a free way in the primary set and then the secondary set. Assignments remain
stable for the lifetime of the runtime map. If all eight candidate ways are
occupied by other tags, the new logical site is omitted instead of sharing or
evicting an existing site's state.

## Mutation Scope

VP currently guides which queue entries are kept and favored. It does not yet
guide byte-level mutation positions. Havoc and deterministic mutations still use
the regular AFL++ mutation machinery over the input buffer.

## Overhead

The fixed eight-slot setting allocates roughly:

- ~8 MiB for the fuzzer-side frontier (`65536 * 8` entries)
- 2,498,576 bytes (about 2.38 MiB) for the runtime VP shared-memory map

On a 64-bit build, the practical fixed-map overhead is about 10.4 MiB.
