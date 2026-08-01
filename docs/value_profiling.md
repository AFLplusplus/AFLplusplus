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

A distance of zero on a frontier slot that no queue entry owns yet does not
by itself admit a new queue entry: the constraint is already satisfied, so
there is no gradient left to follow. Entries admitted for any other reason
still take and hold such slots, which keeps the solved constraint anchored.

Routine-compare sites are restricted to functions with recognised comparison or
search semantics (the `memcmp`, `strcmp`, `strncmp`, `strstr`, `memmem` and
`std::string` families). CmpLog's broader "any two same-typed pointer arguments"
heuristic is deliberately not applied under value profiling: a non-comparison
call such as `strcpy` would otherwise contribute a synthetic gradient that can
admit and permanently favour queue entries.

Routine-compare VP features record separate matched-prefix and whole-buffer
hamming-distance signals. Substring routines (`strstr`, `strcasestr`, `memmem`
and similar) record the minimum of both metrics over every candidate offset in
the haystack, so a successful match records distance 0.

All routine hooks read at most 32 bytes per operand, the same bound CmpLog
uses, which caps the substring scan at 32 x 32 byte comparisons per call. A
match that only starts beyond the first 32 haystack bytes is therefore recorded
as a non-zero distance even though the call itself succeeds; the gradient over
the scanned window stays valid, the constraint just never reports as solved.

Floating-point compares are modelled for `float`, `double`, `_Float16` and
`__bf16` (the last two are widened to `float`, which is exact). `long double`,
`__float128` and PowerPC double-double compares are not instrumented, because
their encodings have no exact widening target and an integer-encoding distance
would contradict floating-point comparison semantics.

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

## Stats

VP-only queue entries are counted in `value_profile_finds` and in
`corpus_count`, but they deliberately do not update `last_find_time`. The
"no new finds" clock that drives `AFL_EXIT_ON_TIME`, the explore/exploit
switch and the `time_wo_finds` display stays coverage-based, matching the
`last_cov_find_time` clock that `-rN` stagnation mode uses.

Note that `cycles_wo_finds`, and the havoc escalation gated on it, count
queue growth rather than the find clock, so VP-only entries do still reset
them.

## Mutation Scope

VP currently guides which queue entries are kept and favored. It does not yet
guide byte-level mutation positions. Havoc and deterministic mutations still use
the regular AFL++ mutation machinery over the input buffer.

## Overhead

The fixed eight-slot setting allocates roughly:

- ~8 MiB for the fuzzer-side frontier (`65536 * 8` entries)
- 2,498,576 bytes (about 2.38 MiB) for the runtime VP shared-memory map

On a 64-bit build, the practical fixed-map overhead is about 10.4 MiB.
