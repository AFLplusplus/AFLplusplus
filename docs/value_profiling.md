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
- `-r -1`: enable value profiling once the queue is starved and no new edge has
  been found for `2 * STARVE_EDGE_EXECS` executions, then keep it enabled for
  the rest of the run. With `AFL_STARVED_MINIMIZE_QUEUE` the threshold is
  `3 * STARVE_EDGE_EXECS` so that the starved queue minimization runs first

Without `-r`, value profiling stays disabled.

Runtime VP currently requires an LLVM-instrumented main target compiled with
`AFL_LLVM_VALUE_PROFILE=1`. It is not supported with `-n`, QEMU, Frida,
Unicorn, CoreSight, Nyx, or `AFL_NO_FORKSRV` execution modes.

Runtime value profiling tracks eight runtime slots per assigned compare site.

Stagnation mode is edge-coverage based: `-rN` activates after `N` seconds since
the last new edge-coverage discovery. It is not based on total queue growth.
Starve mode (`-r -1`) uses the same edge-coverage signal but counts executions
instead of seconds, and additionally waits until the fuzzer has entered starve
mode, meaning no unfuzzed queue entry is left.
When either mode activates, AFL++ synchronously replays the existing queue
once so the VP frontier also reflects already-discovered inputs. This replay
processes enabled queue entries only. Inputs disabled before activation, such as
coverage-duplicate seeds, are not reconsidered for VP.

## Frontier

VP maintains a frontier of the best known distances for `(site, slot)` pairs.
Queue entries owning frontier slots are favored for more fuzzing.

Being favored is not enough on its own. The favored set is the minimal set of
queue entries covering every known edge, and on a small target that set alone
already fills it, so an entry owning the gradient the campaign is following
ends up with the same share of air time as an entry that only represents an
edge some other input covers too. Entries owning an unresolved frontier slot
therefore also get their queue-selection weight multiplied by
`VP_FRONTIER_WEIGHT_MULT` in `config.h` (16), which is roughly what it takes to
put them on par with the coverage favorites rather than behind them.

Inputs admitted only through VP are marked with `,+vp` in their queue filename
and with state files under `.state/vp_only`. If a VP-only entry later owns no
frontier slots, AFL++ disables it after a one-cycle grace period. VP-only queue
admission is intentionally strict-distance-only: equal-distance cost
improvements do not admit a new queue entry by themselves, although cost still
breaks ties among already-admitted frontier owners.

A distance of zero on a frontier slot that no queue entry owns yet does not
by itself admit a new queue entry: the constraint is already satisfied, so
there is no gradient left to follow. A solved slot stays closed for the rest
of the campaign whether or not a queue entry holds it, so AFL++ hands it back
at the next queue-cycle boundary. That lets a VP-only entry whose slots are all
solved retire on schedule instead of staying alive - and competing for air time
- for a gradient it can no longer produce.

VP-only entries do not compete for the coverage favorites either. They add no
coverage of their own, so letting one win a `top_rated` slot would displace a
real coverage find from the favored set and pin the VP-only entry alive through
its trace reference long after its gradient was exhausted.

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

Both signals span the whole compared window. For the nul-terminated families
the comparison ends only where *both* operands are nul: a nul in one operand
alone is a mismatch like any other, and every byte behind it still has to be
made equal. Stopping the hamming sum at the first nul in either operand would
report a near-solved distance for an input that is nowhere near matching, and
because that distance can never reach zero the false minimum would hold its
frontier slot - and keep its queue entry favored - for the rest of the run. For
the same reason the `strcmp` and `strcasecmp` families size their window from
the *longer* operand, so a short input is scored on the bytes it still has to
grow, not only on the ones it already has.

A compare against the *result* of one of these routines - the `if (strncmp(a,
b, n))` idiom - is not value-profiled. The routine's own hook already carries
the operand distance, while the returned integer only encodes equal-or-not and
in which direction: a return of `-1` is one byte away from a match but has
maximal hamming weight against `0`, so scoring it would add an inverted
gradient that admits and permanently favours queue entries.

All routine hooks read at most 32 bytes per operand, the same bound CmpLog
uses, which caps the substring scan at 32 x 32 byte comparisons per call. A
match that only starts beyond the first 32 haystack bytes is therefore recorded
as a non-zero distance even though the call itself succeeds; the gradient over
the scanned window stays valid, the constraint just never reports as solved.

Floating-point compares are modelled for `float`, `double`, `_Float16` and
`__bf16` (the last two are widened to `float`, which is exact). `long double`,
`__float128` and PowerPC double-double have no exact widening target, so they
are scored on their bit encoding through the 128-bit integer hooks. The
encoding is mapped to a radix-sort key first, so that its unsigned order
matches floating-point order instead of contradicting it. On 32-bit hosts,
where the 128-bit hooks do not exist, these types stay uninstrumented.

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

## Focus Set

The cost of a runtime hit is set by how many distinct sites are live, not by
how the map is packed: about 6 ns at a few thousand live sites and about 18 ns
at 60,000, because each live site adds another random cache line to touch.
AFL++ therefore caps how many sites may record at once, in a focus set rebuilt
at every queue-cycle boundary.

`VP_FOCUS_TARGET_SITES` in `config.h` (4,096) is the ceiling on how many sites
a rebuild admits. Owning a frontier slot is not scarce - a site owns its own
slots, so nearly every recorded site owns one - so the ceiling, not ownership,
is what bounds the live set.

Three quarters of the budget rotate over the sites that own a frontier slot
whose distance is still above zero, which is where the gradient the campaign
is following lives. The remaining quarter rotates over everything else, so
constraints outside the current focus are still discovered over time. Either
tier hands its unused share to the other. Each tier keeps its own cursor, so
neither starves the other.

Sites outside the focus set bail out of the hook before touching their slot
state, which is the second random cache line a recorded hit would cost. This
is also what makes retirement cheap, so filtering stays on whenever the
*assigned* namespace exceeds the budget, even when retirement has taken the
number of recording sites below it. Only a map with few assigned sites in
total lifts the restriction; there, every site records and the rotation costs
nothing.

Logical sites the runtime has never seen can still claim a physical key while
the focus set is in force, otherwise newly reached code could never enter the
rotation. They just record nothing until a rotation admits them. This is also
why the ceiling holds between rebuilds: a site discovered mid-cycle cannot
record until a rotation admits it.

While filtering is off, though, newly discovered sites do record immediately,
so the live set can outgrow the budget before the next queue-cycle boundary.
`control_len` reports how many distinct sites recorded in the previous
execution, and a rebuild is scheduled for the next queue entry as soon as that
count passes the budget. The overshoot is therefore bounded by one queue
entry, not one queue cycle.

## Site Retirement

The same pass retires sites that have stopped paying for themselves:

- A site whose frontier slots are *all* owned and solved has no gradient left
  to offer.
- A site that owns no unresolved slot and has recorded for
  `VP_IDLE_RETIRE_CYCLES` focus cycles without changing anything on the
  frontier is not worth its hook cost.

An empty frontier slot is a dynamic hit ordinal the site has not been observed
at yet, not a solved one. A site is hit repeatedly within one execution, and
each hit ordinal maps to its own slot pair, so solving the first occurrence
says nothing about occurrences that have never been reached. Retiring on the
owned slots alone would hide those later occurrences until a frontier reset,
which is why full solving requires every slot and why the idle rule gives an
unobserved ordinal `VP_IDLE_RETIRE_CYCLES` focus cycles to appear.

A site that owns an unresolved slot is never retired for going quiet; it
rotates like every other site instead, so it can still be improved on and
released, and the queue entry holding it never ends up favored for a site
AFL++ has stopped measuring.

Retirement is one flag bit per site in the runtime map, so it costs nothing in
memory, and it shrinks the live set exactly when the map is fullest, late in a
campaign. A retired site records nothing even when the focus set is not in
force.

Retirement is undone by a frontier reset, so a site retired early can always
come back. A solved site stays retired when its owner goes away, because the
slot stays closed without one.

The idle clock counts only cycles in which the site was actually allowed to
record, and it restarts whenever the site claims a slot, improves a distance,
or loses an owner. A site is never retired for failing to improve during
cycles it sat outside the focus set, nor immediately after its owner
disappears.

Sandboxed observation, used by the trim guard, temporarily lifts retirement on
the sites it observes, so a trim guard never reads its own signal as lost.

## Instrumented Compares

Beyond skipping canonical loop-control compares, the instructions pass drops
compares whose operands are not transitively derived from a load or a function
argument. With no input dependence there is no solvable constraint, so the
site would be pure overhead. The analysis is conservative in one direction
only: anything it cannot see through - a call result, inline asm, a def-use
chain deeper than 32 steps - counts as input dependent and keeps its site.

This cuts sites at compile time rather than at runtime, and because every site
also carries a guard, it improves the default-off path as well. Coverage
instrumentation is untouched: a VP build has the same number of coverage
points as a plain build.

Switch and routine compares are not filtered this way.

## Stats

VP-only queue entries are counted in `value_profile_finds` and in
`corpus_count`, but they deliberately do not update `last_find_time`. The
"no new finds" clock that drives `AFL_EXIT_ON_TIME`, the explore/exploit
switch and the `time_wo_finds` display stays coverage-based, matching the
`last_edge_find` clock that `-rN` stagnation mode uses.

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
- 216 KiB for the fuzzer-side focus bitmaps and per-site counters

On a 64-bit build, the practical fixed-map overhead is about 10.6 MiB.
