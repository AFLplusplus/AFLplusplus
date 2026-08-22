# State fuzzing (`-J`)

State fuzzing means testing programs that remember things.

A picture viewer forgets everything after each file. A TLS server, a database
or a filesystem does not: what you send now only makes sense after what you
sent before. AFL++ is built for the forgetful case. `-J` turns that around.

Everything here is off by default. Without `-J`, `afl-fuzz` behaves exactly as
it did before.

## Quick start

```bash
afl-fuzz -J -i seeds -o out -- ./target @@
```

That enables the three parts that were measured to pay for themselves. To
enable others as well:

```bash
afl-fuzz -Jdcbs -i seeds -o out -- ./target @@
```

| Letter | Turns on | In bare `-J` |
|---|---|---|
| `d` | deep-input shelf, so long inputs stop losing | yes |
| `c` | harness self-check at startup | yes |
| `b` | one-shot execution cost benchmark | yes |
| `g` | double-run gate before saving a find | no |
| `p` | per-input stability and the repeat probe | no |
| `r` | rare-edge scoring | no |
| `s` | state map from IJON annotations | no |
| `h` | aimed havoc, from a harness annotation | no |
| `m` | hit-count high-water channel | no |
| `i` | rare-edge signature state id | no |
| `a` | ballast-adjusted scoring | no |
| `w` | hang watchdog inside the target, needs a compile-time opt-in | no |

The letters are case-insensitive and must be **attached** to `-J`: `-Jgpr`
works, `-J gpr` does not, because `-J` takes an optional argument. Plain `-J`
selects `dcb`; everything else has to be asked for by letter. A second `-J` on
the same command line is an error.

Why only three: see [what the letters were measured to
do](#what-the-letters-were-measured-to-do) below. The short version is that the
shelf is the only part that improved the search on either target measured, `c`
and `b` are one-shot diagnostics that cannot steer it, and every other letter
came out at or below the baseline.

The ballast share is always on under `-J`. Time accounting is separate from
`-J` entirely and is switched on with `AFL_TIME_ACCOUNTING=1`, with or without
state fuzzing mode.

To find out whether the `afl-fuzz` at hand has this mode at all, capture the
help screen first and search the capture. `-h` exits non-zero, so a pipeline
that greps it directly fails under `set -o pipefail`:

```sh
help=$(afl-fuzz -h 2>&1 || true)
case "$help" in *"state fuzzing mode"*) echo yes ;; *) echo no ;; esac
```

The version string is no help here: a build with `-J` and one without report
the same version.

Some parts need more than a letter:

* `s` needs a target built with a matching `afl-clang-fast`/`afl-gcc-fast`,
  built with `AFL_LLVM_IJON=1` in the environment, **and** at least one
  `IJON_STATE()` call in the harness — or a custom mutator that describes state
  instead. Miss the variable and the annotations compile to nothing.
* `h`'s `AFL_HOT_REGION()` annotation travels through the state map's shared
  memory, so it needs `s` as well: use `-Jhs` or plain `-J`. `-Jh` on its own
  only gets the CmpLog fallback.
* `w` needs `AFL_TARGET_WATCHDOG` uncommented in `include/config.h` and both
  `afl-fuzz` and the target rebuilt.

---

## What each part does, and why

### Time accounting — where the budget actually goes

Switched on with `AFL_TIME_ACCOUNTING=1`, independently of `-J`.

`afl-fuzz` then reports how much of the wall clock is spent inside the target
and how much is spent everywhere else. On one measured harness the target
could do 2,800 runs/s on its own while `afl-fuzz` reached only a few hundred:
80–90% of the budget was spent outside the target. If that is your situation,
fixing it beats every other item here.

Stats: `target_time_us`, `target_time_pct`, `us_per_exec_target`,
`us_per_exec_total`. UI: the `tgt/tot` field.

Cost: two `clock_gettime` calls per execution, and only when asked for.

### Ballast — the share of the map that tells you nothing

An edge that fires on *every* input carries zero information, but AFL++ counts
it exactly like an edge that fires once in a million. Measured ballast was
**51–89% of the map** on four different harnesses; on one, a single typical
execution already produced 89.3% of what the entire corpus produced.

`ballast_pct` is the share of discovered map bytes that every calibrated input
hits. Read it as "this fraction of my coverage signal is dead weight".

### `g` — the double-run gate

A new input only enters the queue if a second run reproduces the new edges it
claimed. One measured run reported 1,905 edges of which only 1,643 came back
on replay. Ghost edges pull the whole search off course, and they are not
free: once claimed, that coverage is marked as discovered and no later input
can claim it.

AFL++ already hands coverage back when calibration *fails*
(`virgin_undo_rollback()`), and already retires an edge caught wobbling
(`var_bytes`). Neither fires for an input whose new edge simply never comes
back. The gate closes that hole.

Behaviour: every claimed map position that the second run does not reproduce
is handed back to the virgin map. If none reproduce, the input is discarded
and never enters the queue. If some reproduce, the input is kept — it did
prove those — and only the ghosts are returned.

Two limits on handing coverage back: a position already known to wobble
(`var_bytes`) is left alone, and a position can only be reclaimed
`CAL_RECLAIM_MAX` times, so a byte cannot be handed back without bound.

Cost: one extra execution per *saved* input, which is a tiny share of all
executions — unless the campaign is saving constantly, which is itself the
symptom of a state signal that is too fine (see `s` below).

What the gate checks is *reproducibility*, not *stability*: an edge that fires
half the time passes half the time.

A worked example of what it catches, from this repository's own end-to-end
target: on a target whose `stability` reads 100.00%, the gate still rejected 4
of 72 candidates. Every rejection was the same map byte, claimed with hit count
1 and absent on replay — a one-time initialisation edge (lazy symbol
resolution, allocator arena setup) that a persistent-mode child only ever fires
on its *first* iteration after a restart. Any input that happens to run as that
first iteration claims those edges and can never reproduce them. Nothing in
AFL++ noticed this before, because `stability` is computed from calibration of
inputs that already made it into the queue — and these never should have.

Stats: `gate_checked`, `gate_rejected`, `gate_partial`.

### `p` — a stability number per input, and a real repeat probe

The `stability` figure AFL++ has always shown is

```
100 - (all map bytes ever seen to vary, over every input) / (all bytes found)
```

That is a statement about the whole corpus, and people read it as "will this
one input reproduce". Three consequences, all measured:

* It moves as the corpus grows. The same harness reads 95.0% with one input
  and 92.5% with four. Two runs of different sizes are not comparable.
* It is too low for a clean input, because other inputs' flaky edges are
  counted in — and too high overall, because a check of 3 to 12 runs misses an
  edge that flickers once in fifty. It disagreed with the repeat probe by
  up to **23 points, in both directions**.
* "this loop ran 7 times instead of 8" and "this edge sometimes does not fire"
  set the same bit. The first is usually harmless; the second means a saved
  input no longer describes what it does.

`-Jp` adds two things and removes nothing:

**Per-input stability.** During calibration, each entry's *own* varying edges
are counted, split into edges that appeared or disappeared and edges whose hit
count merely wobbled. `input_stab_avg` and `input_stab_min` report the corpus
mean and worst case. The old cumulative `stability` line stays exactly where
it was; the two numbers answer different questions and both are worth seeing.

**The repeat probe.** One input, 100 back-to-back executions, reported as
`probe_pct` (runs whose whole trace matched run 1) and `probe_edge_pct` (edges
present in every run, over edges present in any run). It runs once at startup
and at most once a minute thereafter, on a randomly chosen favored entry.

Two things to know about when and what it measures. It only re-runs *when a new
queue entry has just been saved*, so on a campaign that has plateaued the
reading stops updating. And for a persistent-mode target the 100 runs are
consecutive iterations of the same child, so what you get is
iteration-to-iteration repeatability; for a non-persistent target they are 100
fresh processes.

The run count is the whole game, because an edge that fires in a fraction `p`
of runs only shows up as varying if `N` runs catch it both ways, which happens
with probability `1 - p^N - (1-p)^N`. Measured against a target with 64 edges
of known flicker rate, where 67.3% is the true answer:

| runs | reported `probe_edge_pct` at p=2% | at p=5% | at p=10% |
|---|---|---|---|
| 8 | 95.7% | 85.6% | 80.9% |
| 30 | 85.1% | 73.1% | 68.2% |
| 100 | **70.4%** | **67.7%** | **67.3%** |
| 200 | 67.3% | 67.3% | 67.3% |

30 runs overstate a 2%-flicker target by 18 points — the same size of error
this probe exists to correct in the `stability` line. 100 runs is the default
because it is the point where the estimate stops moving for the rates that
actually occur, and it still costs only one burst per minute.

Tune with `AFL_STATE_PROBE_RUNS`. The cost is `N` executions per probe
interval, so lower it on targets slower than roughly 50 executions per second
and raise it if you suspect flicker rarer than one run in fifty.

`probe_pct` is a whole-trace statistic: with more than a handful of
independent flaky edges it collapses toward zero for any `N`, so read
`probe_edge_pct` when you want a number that grades a target.

Stats: `probe_pct`, `probe_edge_pct`, `probe_runs`, `input_stab_avg`,
`input_stab_min`.

### `r` — rare edges score higher than common ones

Each edge is weighted by `-log2 p(edge)` instead of counting as 1, where
`p(edge)` is the share of calibrated corpus entries that hit it. A ballast edge
present in every entry contributes about 0; an edge seen once in a corpus of
4,096 contributes 12. The resulting `info_score` replaces raw edge count in the
alias-table weight.

This changes how inputs are *scored*, not what is *saved*: admission is
untouched.

Known approximation: `info_score` is computed at calibration time from the
counts known then. Entries that still hold a `trace_mini` — the top-rated ones,
which is what scheduling cares about — are recomputed when the queue is culled;
the rest keep their calibration value. In practice this is mild, because
ballast edges are ballast from the first few inputs onward and rare edges stay
rare, but it is a real approximation.

A second, smaller one: the per-edge frequency is counted once per *calibration*,
so an entry that is calibrated more than once inflates the frequency of its own
edges.

Stat: `info_score_avg`.

### `d` — the deep-input shelf

This is the part that matters most for state fuzzing.

```c
fav_factor = q->exec_us * q->len;      /* src/afl-fuzz-queue.c */
```

Longer and slower always loses, and a deep input is longer and slower by
construction. This single product explains a measured result that looks
paradoxical: a deeper starting image gave **+10.8 points** of coverage at the
start and then **lost by 1.9 points** after an hour, because it halved the
number of executions. Depth is not being rejected on merit; it is being priced
out.

`-Jd` sorts entries into cells by `(depth, cost, state)` — 8 buckets each,
512 cells — and changes two things:

* **Comparison happens inside the cell.** The alias-table weight normalises
  `exec_us`, `len` and information against the entry's own cell mean, not the
  global mean, whenever that cell holds at least two entries. A slow deep input
  is compared against other slow deep inputs.
* **Each cell keeps four witnesses**, not one: the shortest, the fastest, the
  most reliable, and the one with the broadest coverage — the last of which is
  usually a different route to the same state. Witnesses join the favored set
  alongside the usual set-cover winners.

The per-edge winner selection (`fav_factor`) is deliberately left alone. It is
a much larger blast radius than this needs, and the two changes above already
let a deep input survive without beating a tiny fast one.

Three things worth knowing about the buckets:

* The "most reliable" witness needs per-input stability, so it only differs
  from the "broadest coverage" one when `p` is enabled too. `-Jd` on its own
  effectively keeps three witnesses per cell.
* The state bucket is the low three bits of the state id, and it is only used
  once the state signal is trusted (or a custom mutator supplied an operation
  count). Without `s`, the shelf is `(depth, cost)` — 64 usable cells — which
  is still the part that fixes the pricing problem.
* When the utility test changes its verdict, every cell is re-keyed, because
  leaving the old ones in place would mix two different partitions in one shelf.

Stats: `shelf_cells_used`, `shelf_members`.

### `s` — the state map

`IJON_STATE(n)` already lets a harness tell AFL++ what state it is in — the
cheapest and most reliable state source there is. Today that state is XORed
into the edge hash, so state and coverage are one signal and cannot be told
apart.

`-Js` adds a **separate** map, in its own shared-memory segment, keyed by
`(previous state, current state, action)`. Two steps of context is the
compromise: `INIT→AUTH→READY` and `INIT→AUTH→ERROR→AUTH→READY` end in the same
place but are different, while keeping full histories explodes the corpus.

The map is 64 KB, one hit counter per hashed triple, so different triples can
collide — the same trade AFL++ already makes with edge collisions.
`state_map_density` is reported in hundredths of a percent, because a real
target reaching 169 of 65536 slots would otherwise read 0%.

It costs a handful of slots per execution, not 64 KB. The target keeps a list of
the slots it actually touched, and both sides clear and scan only those; that is
what took `-Js` from roughly 15× slower to 5–15% overhead on a fast target. A
target that touches more than 512 distinct slots in one execution, or one built
before the list existed, falls back to the full walk.

Four requirements, all of which are easy to miss:

* **The build needs `AFL_LLVM_IJON=1`.** `afl-cc` only puts `afl-ijon-min.h` in
  front of the source when that variable is set. Without it, a harness whose own
  header defines fallback no-op macros behind `__has_include` — the usual
  pattern — compiles every annotation away, and nothing says so: the runtime is
  linked either way, so every `ijon_*` symbol is still in the binary and only the
  call sites are gone. `objdump -d target | grep -c ijon_xor_state` reads 0.
* The map lives in the instrumentation runtime, so the target must be built with
  a matching `afl-clang-fast` or `afl-gcc-fast`. Binary-only modes (QEMU, Frida,
  Unicorn, Nyx) have no state map and `state_signal` reads `unsupported`.
* **A harness with no `IJON_STATE()` calls produces no transitions at all.** The
  segment is attached and stays empty. The custom mutator route below is the
  alternative that needs no annotation.
* `AFL_NO_STATE_MAP` switches it off from either side — the fuzzer will not
  create the segment, and an instrumented target will not attach to one.

To tell an already-built binary apart from a plain one, do not grep it for
`__AFL_STATE_SHM_ID` or `__afl_ijon`: both strings live in
`afl-compiler-rt.o`, which every `afl-cc` target links, so they match
everything. The one static difference is the symbol the IJON pass emits:

```sh
nm ./target | grep __afl_ijon_enabled     # "D" = annotated and instrumented,
                                          # "V" = the runtime's weak default
```

That works only on an unstripped binary. The reliable check either way is the
run: `afl-fuzz` prints `Using state map.` and `state_transitions` climbs above
zero.

One thing to know before annotating anything: **the state map is only as good
as how coarse the state is.** `IJON_STATE(n)` takes whatever number the harness
hands it, and if that number carries any of the input's history — a rolling hash
of the operations, a path digest — then almost every execution reaches a state
nothing reached before, almost every execution is a find, and the queue fills
with everything. Measured on this repository's own end-to-end target, whose
`state_log` keeps eight steps of history: **14,280 queue entries in 45 seconds
against 176 without the state map**, for 22% of the state map consumed and no
more coverage.

So report a *situation*, not a route: which handles are open, which flags are
set, what phase the protocol is in. If two inputs would behave the same from
here on, they are in the same state and must produce the same number.

AFL++ bounds the damage rather than trusting the annotation. Once the queue
holds at least 200 entries and the state signal has created more than
`AFL_STATE_ADMIT_PCT` of them (default 25%) on its own, it stops saving inputs
and goes back to being a note — unless its entries are demonstrably paying for
themselves, which `AFL_STATE_YIELD_PCT` decides from `state_only_saves` and
`state_only_paid` once there are at least 50 of them. An entry has paid when
something mutated from it was saved for a reason of its own; a state-only child
does not count for a state-only parent, so a runaway signal cannot vouch for
itself. On the same target the bound brought those 14,280 entries down to 317.

The switch-off is one-way for the rest of the run, and it covers both state
channels — the instrumentation one and the custom mutator one below.
`AFL_STATE_ADMIT_PCT=0` disables the bound entirely.

What the bound deliberately does *not* do is try a coarser resolution first.
Folding the map was measured against both alternatives and came last: it still
admitted ~145 entries that never found anything, and it dropped the share of the
corpus reaching the target's deep states from 40% to **16%** — worse than never
enabling the signal. A fine, expensive signal and no signal are both defensible;
half a signal is not. `AFL_STATE_COARSE` still folds by hand for anyone who
wants to measure that themselves.

Any existing `IJON_STATE()` harness gets this for free — no source change.
Two optional annotations sharpen it:

```c
AFL_STATE_ACTION(op);            /* name the operation about to run   */
AFL_HOT_REGION(offset, length);  /* mark the bytes that matter (-Jh)  */
```

With no `AFL_STATE_ACTION`, the action is 0 and the map degrades to
`(previous, current)` pairs — still strictly more than today.

Stats: `state_signal`, `state_transitions`, `state_map_density`,
`state_only_saves`, `state_only_paid`, `state_admit_off`, `state_coarse_fold`,
`state_sit_report`, `state_situations`, `state_depth_max`, `state_depth_avg`,
`state_depth_hist`.
Note that `state_transitions` counts both instrumentation transitions and the
mutator-reported state classes below, in one number, while the four situation
fields count only what `IJON_STATE()` reported from inside the target.

The bound above governs the **state map**, and only the state map. `IJON_SET()`
and `IJON_INC()` write into an area that deliberately sits inside the coverage
bitmap, so a write there is an ordinary coverage find on the normal path:
`AFL_STATE_ADMIT_PCT`, `AFL_STATE_YIELD_PCT` and `AFL_IJON_RETIRE_MAX` never
see it, and none of them can slow down how fast an annotated build fills the
queue. That channel has a bound of its own, `AFL_IJON_ADMIT_PCT`, off by
default. `ijon_only_saves` in `fuzzer_stats` says how much of the queue it
created; on a small annotated target 206 of 267 entries came from it. See
[IJON.md](IJON.md).

### `s` — without touching the target at all

A state number does not have to come from the target. A custom mutator that
understands the input format already knows what a program does and where it
ends up, and it can say so through `afl_custom_describe_state()` (see
[custom_mutators.md](custom_mutators.md)). It reports two numbers per queue
entry: how many operations the input performs, and an id for the state it ends
in.

This is the cheaper half of the state idea and worth trying first:

* It needs no annotation, no instrumentation and no rebuild of the target.
* It does not fold the state into the edge hash, so coverage stays coverage.
  `IJON_STATE()` cannot avoid that — the same call that records a transition
  also perturbs every later edge index — which is why a state-annotated build
  reports a coverage map that is not comparable with a plain one.
* The operation count is what the depth bucket of `-Jd` always wanted. `depth`
  counts mutation generations from a seed, which is only a proxy for how much
  work an input does; an operation count is the thing itself.

By default the reported state only affects *scheduling* — which cell an entry
competes in, and how inputs are grouped for the utility test — and can
therefore not explode anything. `AFL_STATE_PLUGIN_ADMIT=1` additionally lets a
new state class justify saving an input, under the same
`AFL_STATE_ADMIT_PCT` bound.

Note that this channel is not gated on `-J`: a mutator that implements the hook
is asked about every queue entry in any run, and `AFL_STATE_PLUGIN_ADMIT=1`
changes admission with or without `-J`. Only the scheduling effects need `-Jd`.

`custom_mutators/state_records/` implements the hook, with
`STATE_RECORDS_DIGEST` selecting how much goes into the id — from "which slots
are open" (the default) up to "a hash of the whole opcode sequence", which
exists to be wrong on purpose so the failure mode can be measured.

Stats: `plugin_described`, `plugin_ops_avg`, `plugin_ops_max`.

### `s` — and the test that decides whether to believe it

**Nobody has ever published an error rate for any automatic state detection
method.** So `-Js` does not trust its own state signal until it has been
tested on your target.

The test: take two inputs AFL++ thinks are in the same state, apply the same
next action to both, and see whether they behave the same. If inputs the state
definition calls identical keep behaving differently, the definition has
merged two real states and needs one more field.

The action is built once per test and used unchanged on both members of every
pair, so every pair is asked about the same next action, and every pair is
first run without it. A pair only counts when the probe made both targets walk
*further* through the state machine than their own bytes did. Without that
check the test would pass for free on any target that ignores the probe — two
inputs that both ignore it agree trivially, and a vacuous 100% is exactly the
false pass this gate exists to prevent. Pairs whose probe changed nothing are
dropped, and if too few pairs survive AFL++ says so instead of reporting a
verdict.

Where the action comes from matters, because a probe the target does not act on
makes the gate unreachable rather than merely strict:

* **With a format-aware custom mutator loaded**, the mutator builds it, capped
  at 512 bytes: `afl_custom_state_probe` if it has one, otherwise
  `afl_custom_fuzz` called on an empty buffer, and only for a mutator that also
  implements `afl_custom_describe_state` — a mutator that never opted into the
  state protocol is not called outside the mutation loop. So a mutator that
  speaks the input format hands over a well-formed operation, which is the case
  this gate is aimed at.
* **Without one**, the probe is 1–32 random bytes. That is a valid action only
  for a format in which a bare byte string parses as a *new* operation. It is
  not one for any encoding that frames records with a separator, or that ends
  its last record at the end of the buffer: the bytes are read as more payload
  for the record already there, no operation is added, and the pair is
  dropped. Note that this includes the format
  `custom_mutators/state_records/` recommends — with that mutator loaded the
  probe is well-formed, without it the same corpus reaches no verdict at all.

The probe is tried behind the input first and then in front of it, and the
pair counts if either placement performed an action. A target whose input is
not a concatenation of operations — a fixed-size struct, a single
length-prefixed frame — ignores it in both positions and no verdict is ever
reached. That is the intended outcome: the signal stays a note. `state_util_ignored`
in `fuzzer_stats` counts the pairs that were dropped this way, so a
`state_util_pairs : 0` can be read from the stats file alone.

`state_util_pairs : 0` has three different causes and `state_util_status` names
the one in force, because they call for different answers:

| `state_util_status` | meaning | what to do |
|---|---|---|
| `untested` | the gate has not run yet | nothing, wait |
| `too few state entries` | fewer than 20 queue entries carry a non-zero state id | give "nothing open yet" an id of its own, or wait for the corpus to grow |
| `too few same-state pairs` | entries have state ids but almost none share one | the state definition separates every input; drop a field from it |
| `probe ignored` | pairs formed, the probe performed no action | a format problem — load a format-aware mutator, see above |
| `verdict reached` | `state_utility_pct` is meaningful | read the verdict |

The first two also print a warning, once, when they first become the reason.

Only entries with a **non-zero** state id are paired up: id 0 means "no state"
throughout, so a harness that encodes "nothing open yet" as `IJON_STATE(0)`
loses those entries from the test. Give that situation an id of its own.

Pairs are drawn from entries with the same state id, preferring partners whose
coverage traces differ, because a pair of near-identical inputs proves nothing.

Behaving the same means: ending in the same state, terminating the same way
(both fine, both crashing, both timing out), and giving the same answer to
"did this run reach coverage nobody had reached before".

Until the test passes, new state transitions are recorded, counted and
reported, and change nothing about which inputs are saved. `state_signal` reads
`observing`. Once agreement reaches the threshold (default 80%, set with
`AFL_STATE_UTILITY_THRESHOLD`), it reads `trusted` and a new state transition
becomes a reason to save an input on its own. `unsupported` means the target has
no state map at all — see the three requirements above. `unmeasurable` means the
probe was ignored: the signal cannot be measured on this target as it is being
fuzzed, which is a different thing from "not yet measured" and is the value to
watch for, because nothing later in the run will change it.

The transitions seen while the signal is still observational are *not* spent.
Reporting and admission use separate maps, so a transition first met during
the observational phase can still justify saving an input once the signal
becomes trusted.

Stats: `state_utility_pct`, `state_util_pairs`, `state_util_runs`,
`state_util_ignored`, `state_util_cands`, `state_util_status`.

The test samples at most 32 pairs, so on a target with few state groups the
figure is noisy — this repository's own end-to-end target has been observed at
53% on one run and 100% on another. The gate is one-sided on purpose: a noisy
estimate errs toward *not* trusting the signal, which costs nothing but a
missed opportunity, whereas trusting a bad state definition corrupts every
decision downstream. The test therefore repeats, so that a signal that is
genuinely good gets more chances as the corpus grows: at most once a minute
(`AFL_STATE_UTILITY_RETRY`) and never within 4,096 executions of the last
attempt, so that the test — at most 6 runs per pair — cannot cost more than
about 5% of the fuzzing. Beyond that it needs new material: one more entry
carrying a state id while there is no verdict yet, 20 more once there is one,
or a queue cycled 8 times. The queue cycle alone is not enough of a clock, because a
corpus that grows faster than it is fuzzed never finishes its first cycle, and
that cycle ends while the queue is still too small to hold two entries in the
same state.
`state_util_runs` in `fuzzer_stats` counts the attempts and `state_util_cands`
reports how many entries the last one had to draw from. Repeated attempts stay
quiet: a verdict is printed when it is first reached and when it changes, and
a no-verdict cause when it changes.

Adding `AFL_STATE_ACTION()` to a harness usually moves this number a long way,
because most of the disagreement comes from the state definition merging
transitions that differ only in which operation caused them.

Never report "number of states found" as a success metric. A broken observer
that hashes the clock finds millions.

### `c` — the harness self-check

In a state harness, most first-time crashes are bugs in the harness, not the
target. One measured case: **15 out of 15 crashes were the harness's fault.**

At startup, `-Jc` runs one input as execution #1 of a fresh process and then
again as execution #2 of the same process, and compares the coverage. Any
difference means something is not being reset between iterations — a static, a
cached fd, a global parser context, a leaked allocation. It says so loudly,
because the alternative is a week of confusion.

This is a **persistent-mode** check. For a target that forks fresh for every
execution there is nothing to reset, and the check degenerates into a two-run
determinism test — it will still flag general nondeterminism, but it cannot find
the bug it is aimed at.

It runs once, on the first fuzzable queue entry, with that one input. A fail is
close to proof; a pass is not a clean bill of health, because a reset bug that
first shows on the third iteration, or only for some inputs, is not covered.

Stats: `contract_check` (`pass`, `fail` or `skipped`), `contract_diff`.

### `b` — the execution cost benchmark

Is it cheaper to rebuild the state or to fork a fresh process? The right answer
swings by **30×** between targets. QEMU gained 3.8× from snapshots; libssh lost
26×. There is no default that is right for everyone, so `-Jb` measures both
once and prints a recommendation. It does not switch anything on.

The second half of the measurement starts the target as its own process,
outside the forkserver. Each of those runs has a deadline of ten times the
larger of the execution and hang timeouts, and at least one second; a run that
exceeds it is killed and the benchmark reports over the runs that finished. A
target that only terminates under the forkserver therefore delays startup by
one deadline instead of hanging the campaign, and if no standalone run finishes
at all the benchmark is skipped with a warning.

It measures 200 forkserver runs and up to 20 process starts of **one** input,
once, at startup. On a target whose cost depends strongly on the input, that is
a number for that input. Read the ratio, not the two absolute timings — the
standalone child does not get the exact environment the forkserver provides.

Stats: `cost_fork_us`, `cost_setup_us`.

### `h` — aimed havoc

Havoc picks byte offsets uniformly, so a region of *k* bytes in an *n*-byte
input receives *k/n* of all mutations. On one target the 42 interesting bytes
inside a 262 KB input got **0.016% of the mutation budget** while carrying
roughly **80% of the value**.

With `-Jh`, a harness can mark the region that matters:

```c
AFL_HOT_REGION(header_offset, header_len);
```

70% of havoc offsets then land inside it (`AFL_HOT_BIAS`). The other 30% stay
uniform on purpose — plain byte mutation still finds parser and memory bugs, and
the annotation can be wrong.

**The annotation needs `-Js` as well as `-Jh`**, because it travels through the
state map's shared memory. Use `-Jhs`, or plain `-J`.

Harnesses without the annotation get a fallback: when CmpLog colorization
finds taint ranges for an input, the largest range that is smaller than the
whole input becomes that input's hot region. On this repository's own state
machine target, built *without* `AFL_HOT_REGION`, `afl-fuzz -Jh -c 0` gave 77
of 80 queue entries a hot region; the same run without `-c` gave none. A
harness annotation always wins over the CmpLog guess.

What gets aimed: the in-place edits (bit flip, interesting 8/16/32 values in
both byte orders, every arithmetic variant, random byte, byte add and subtract,
byte flip, ascii-number rewrite), both ends of the byte switch, the *destination*
of the clone and insert operators, and the position of an inserted ascii number.

What stays uniform: deletion, shuffle, block overwrite, the *source* offset of a
clone, dictionary and auto-dictionary insert and overwrite, the in-havoc splice
operators, and the separate splice stage.

What matters here is *useful* mutations per second, not raw mutations per
second.

Stat: `hot_region_hits` — how many queue entries carry a region.

### `w` — the hang watchdog

This one is **off at compile time**. Arming and disarming a timer costs a
branch inside the persistent-mode loop, which every target pays whether or not
the watchdog is ever used, so it is not worth carrying by default. To get it,
uncomment `AFL_TARGET_WATCHDOG` in `include/config.h` and rebuild both
`afl-fuzz` and the target. Without that, `-Jw` prints a warning and does
nothing, and `-J` on its own does not select it.

One measured run spent **20 minutes at 99% CPU** while the fuzzer sat waiting
and never noticed. Every AFL++ timeout is enforced from the outside, by the
fuzzer killing the child; when that does not happen, nothing happens at all.

`-Jw` arms a timer *inside the target*: on expiry the target calls `abort()`.

The default is deliberately **above** the fuzzer's own timeout
(`max(1000 ms, 2 × exec timeout)`), not below it. Below it, every merely-slow
execution would become a fabricated crash. Above it, ordinary hangs keep their
current `hangs/` behaviour unchanged, and the watchdog only fires when the
fuzzer's own mechanism failed to work at all — which is the case this exists
for.

The result is a `SIGABRT` crash with a live stack that **reproduces
standalone**: rerun the saved input with the same `AFL_WATCHDOG_MS`, outside
`afl-fuzz`, under a debugger. Killing the child from the fuzzer could never
give you that.

Set `AFL_WATCHDOG_MS` yourself to override; it is read by the *target*, so it
has to be in the target's environment. The timer is armed at the start of every
execution and disarmed at the top of the persistent loop.

Two caveats. A target that installs its own `setitimer(ITIMER_REAL)` or its own
`SIGALRM` handler clobbers the watchdog. And the limit is wall clock, not CPU
time, so a target legitimately blocked on I/O for longer than the limit will
abort.

---

## The fast loop and the slow loop

Rich observation is valuable and too slow to do a million times a second. So
the work is split, and the split is enforced by where the code lives.

**Every execution:** the coverage map, the state map (only the slots the target
says it touched), the exit status, and — only under time accounting — two clock
reads. Nothing else.

**Candidates and intervals only:**

| Work | When | Cost |
|---|---|---|
| double-run gate | per input saved to the queue | 1 exec |
| per-input stability, ballast, info score | per calibration | map scans on an already-running path |
| repeat probe | startup, then on a save, at most once a minute | 100 execs |
| harness self-check | startup, once | 2 execs, up to 17 in persistent mode |
| cost benchmark | startup, once | ~220 execs, plus up to one deadline |
| state utility test | ≥20 state-carrying entries, then every 8 cycles | ≤192 execs |

`slow_path_execs` and `slow_path_pct` report exactly how much of your budget
this feature set consumed, so the overhead is visible rather than assumed.

Read that table in *executions*, not in percent. The letters that re-run inputs
— `g` (one extra run per saved input), `p` (100 runs per probe) and `c` — cost a
fraction of your own cost-per-execution, so the same letters that measure
`slow_path_pct 0.05%` on a microsecond-scale demo target measure a few percent
on a target that spends milliseconds per execution. Budget them by
cost-per-exec: on a 2.5 ms target, `-Jgprdcb` has been measured at
`slow_path_pct 2.57%`. If throughput matters more than the observation, drop the
re-running letters first and keep the ones that only read maps (`r`, `d`, `s`).

Memory, on top of the usual maps: one map-sized array for ballast and one for
calibration variance, two more with `p`, one `u32` per map byte with `r` (four
times the map size, so 32 MB for the 8 MB default map), 64 KB each for the two
state maps and the shared segment with `s`, and about 20 KB of shelf
bookkeeping with `d`.

---

## Reading the numbers

Every field this mode adds to `fuzzer_stats` is listed and explained in
[afl-fuzz_approach.md](afl-fuzz_approach.md). A field appears only when the part
that produces it is enabled.

The UI adds two lines below the grid whenever `-J` or time accounting is active,
which is why the minimum terminal height rises from 24 to 26 rows. The first
line carries `tgt/tot`, `ballast`, `probe` and `in-stab`; the second carries
`gate` (rejected/checked), `info`, `shelf` (cells/witnesses), `trans` with the
signal verdict, and `slow`. Both are padded to a fixed width, so a value that
shrinks leaves no leftover characters behind.

`stability` is unchanged and still means what it always meant — the cumulative
union of every map byte ever seen to vary, over the whole corpus. It is not
comparable between runs with different corpus sizes. `input_stab_avg` and
`input_stab_min` are the per-input numbers people usually mean when they read
`stability`, and both are shown so the difference is visible.

`stability` also carries **no red flag under `-Jp`**: the cumulative figure
degrades for reasons that say nothing about the harness (see the IJON note
below), so once the repeat probe has measured a per-input stability of 95% or
better, the field is no longer painted red. Judge the harness by `input_stab_*`
and the alarm colour by nothing at all.

It is also **not comparable across an IJON boundary**. `IJON_STATE` mixes the
situation into every later edge index, so the same harness annotated and
unannotated produces different cumulative figures — annotated arms of one
ablation read 83–93% where the plain arms read 99.4–99.8%, for harnesses whose
per-input stability was indistinguishable. On top of that, the fuzzer's map in an
IJON build includes the 64 KB `IJON_SET`/`IJON_INC` area, so `total_edges` and
every percentage derived from it (`bitmap_cvg`, `stability`) are computed over a
larger map than the coverage region alone. When comparing an annotated build
against a plain one, compare `input_stab_avg` and `input_stab_min`.

### Judging `-Js` and IJON: not by coverage

Coverage answers the wrong question here, and it answers it in the wrong
direction. Measured on a stateful QUIC server harness, four arms replayed
through one common `llvm-cov` build: the annotated arms covered *fewer* regions
in the target subsystem than the plain ones (11,939 and 11,965 against 11,989
and 12,038) with 15 times the corpus, and led in 0 of 41 files at equal N. A
user who judges the annotation by `edges_found` or by a coverage report will
conclude it hurt.

On the objective the annotation is actually for, the same corpora invert the
result — 3,086 and 3,044 distinct situations reached against 876 and 1,051, and
a mean deepest situation per input of 12.0 against 7.0, from *shorter* inputs.
Set difference over the whole corpora: 2,086 situations only the annotated arms
reached, against 9 only the plain arms did.

Four fields report that objective, all of them under `-Js` and all of them fed
by `IJON_STATE()` calls **in the target**: a state a custom mutator reports
through `afl_custom_describe_state` groups queue entries but does not enter the
situation list, so a run can show a rising `state_transitions` with all four
fields at zero. They also need a target rebuilt with a runtime that maintains
the list; `state_sit_report` says whether the target at hand does, and a target
that counts transitions without one is warned about once.

* `state_situations` — distinct `IJON_STATE()` values the campaign ever
  reached. This is the count to compare arms on. `state_transitions` is not:
  it counts *(previous, current, action)* triples, so one situation reached from
  four predecessors counts four times.
* `state_depth_max` — the longest chain of situations one execution went
  through.
* `state_depth_avg` — the mean of that chain length over all executions, which
  is the "how deep does a typical input get" number.
* `state_depth_hist` — distinct situations by the depth they were first reached
  at, in log2 buckets, as `1:8 2:16 4:120 8:1251`. A campaign whose situations
  all sit in the low buckets is going wide, not deep.

The UI carries the first and third as `sit <count>/d<avg>` on the second state
line. `STATE_TOUCHED_MAX` in `include/config.h` caps how many situations of one
execution are recorded by value, so past that the chain still counts towards the
depth but stops contributing new distinct situations.

---

## Inputs as programs, not byte strings

A stateful target does not want a flat byte string. It wants a list of
operations — *open this, write that, close it* — where operations can use each
other's results. Making them do so was part of a **+6,895 newly covered lines**
gain on Mbed TLS.

`custom_mutators/state_records/` ships a reference record format, a mutator
that speaks records instead of bytes, a matching harness template, and a
record-granular trimmer. See its README for the format and the two framing
rules it exists to obey:

* **Never put a length or item count at the front.** One inserted byte at
  position 0 left only **1.2%** of such an input intact.
* **Do not use a bare length field as the only separator.** After an insertion
  it recovered only **4.8%** of the time — and 59% of havoc rounds insert or
  delete something.

`AFL_CUSTOM_MUTATOR_ONLY` is deliberately not implied by `-J`. Plain byte
mutation still finds parser and memory bugs.

---

## Bug detectors

Crashes are the wrong detector for state bugs. Of ten issues filed on one
target, five came from fuzzing and five from reading the code — and the only
medium-severity one came from reading.

`utils/state_oracles/` ships optional helpers:

* **Round-trip check** — save → load → save must produce identical bytes, and
  the loader must refuse anything the saver would never write.
* **Allocation-failure injection** — makes error-handling code run at all. Off
  by default, self-disarming after one shot, so exactly one error path runs per
  execution and the failure is attributable.
* **Uninitialised-memory probe** — one input at four different
  `MALLOC_PERTURB_` values, outputs compared. This found a real bug writing
  **15,475 uninitialised bytes** to disk.
* **Exact-size buffers** — allocate exactly what the API promises to touch,
  with a guard page immediately after. A generous buffer hides real overflows.

Every detector ships with a deliberately broken example it must flag, built at
`-O0` with `-fno-builtin` and routing the defect through `volatile`. This is
not ceremony: a leak self-test once reported "clean" at `-O1` because the
compiler had deleted the leak. **A detector you have never seen fire is not
known to work.**

---

## Proving it works

`utils/state_fuzzing/run_ablation.sh` runs the experiment that decides whether
any of this paid, changing one thing at a time:

```
A  normal coverage, normal executor
B  normal coverage, improved executor      -> B minus A = engineering wins
C  improved executor + record mutator
D  improved executor + state signal        -> D minus B = state wins
E  improved executor + records + state
```

Every existing published comparison changes the executor and the state model at
the same time, so nobody can tell which one helped.

**Do not compare `edges_found` between arms.** It counts bytes of a coverage
map, and the map is not the same object in two binaries: arms C and E run a
different target, and folding a state hash into the edge index — which
`IJON_STATE()` does — changes what one edge even means. On lwext4 the arm with
*fewer* `edges_found` had *more* covered regions. So `replay_coverage.sh`
replays every arm's final corpus through **one** llvm-cov build and scores the
lines and regions of the code under test, which is a common unit. It also
handles two traps that cost real time to find: one input that kills the process
discards the profile of every input in the same invocation (so a dying chunk is
bisected and the offender quarantined and printed, never silently dropped), and
a corpus reliably contains inputs that never terminate under coverage
instrumentation, which has no forkserver of its own (so every invocation is
wrapped in `timeout`).

`analyze_ablation.py` reports **three** numbers, not one: results per
wall-clock second, per execution, and per operation. Once one input byte can
drive a thousand writes, executions per second is no longer comparable across
arms. It refuses to compare arms whose coverage builds disagree on how much code
exists, prints the min–max spread next to every median, and refuses to let a
contrast look meaningful when it falls inside that spread. Five repetitions per
arm is the default because run-to-run variance routinely exceeds the effect
sizes involved.

---

## What the letters were measured to do

Every letter was compared against `-Jd` alone, one letter at a time, on two
targets: an OpenSSL 3.5 QUIC server harness with `IJON_STATE()` annotations and
lwext4's `fuzz_ops`. Independent replicates, each instance on its own `-o` with
no syncing, 2 h per instance. Depth comes from an external probe compiled
without AFL that reports what one execution achieved; coverage is a union over
an equal-N sample per arm replayed through one common build; bugs are crashes
reproduced standalone and deduplicated on assertion text with values stripped.

QUIC, distinct situations reached and the tail of the depth distribution,
n=18 per arm:

| arm | situations | depth >= 8 | depth >= 10 | depth >= 12 | slow path |
|---|---|---|---|---|---|
| `-Jdg` | 0.92x (p=0.002) | 0.90x (p=0.003) | 0.90x (p=0.008) | 0.90x | 1.67% |
| `-Jdp` | 1.00x | 1.00x | 1.02x | 1.06x | 1.00% |
| `-Jdr` | 0.98x | 0.98x | 0.99x | 1.00x | 0.00% |
| `-Jds` | 0.96x | 0.95x | 0.94x | 0.95x | 0.66% |
| `-Jdsh` | 0.95x | 0.94x | 0.95x | 0.96x | 0.66% |
| `-J` | 0.85x (p=0.0001) | 0.83x (p=0.0001) | 0.83x (p=0.0006) | 0.83x (p=0.010) | 3.51% |

lwext4, operations retired and I/O done per input, n=11 per arm:

| arm | mean ops | p95 ops | ops >= 64 | ops >= 128 | work >= 1e5 |
|---|---|---|---|---|---|
| `-Jdg` | 0.88x | 0.89x | 0.82x | 0.68x | 1.02x |
| `-Jdp` | 0.91x | 0.89x | 0.84x | 0.67x | 0.89x (p=0.014) |
| `-Jdr` | 0.95x | 0.95x | 0.87x | 0.86x | 0.94x |
| `-Jds` | 0.86x (p=0.014) | 0.85x (p=0.013) | 0.78x (p=0.042) | 0.53x (p=0.007) | 0.95x |
| `-J` | 0.87x | 0.93x | 0.77x (p=0.038) | 0.83x | 0.84x (p=0.0009) |

Read those p-values as nominally significant and uncorrected: seven correlated
metrics were tested per arm. What is worth trusting is not any single cell but
that **no letter came out above 1.00x on both targets**, and that the two
targets agree on bare `-J`.

Coverage moved the same way and barely: on QUIC every arm ended within 0.5% of
`-Jd`, and for every single arm the edges only `-Jd` found outnumbered the edges
only that arm found. On lwext4, bare `-J` lost `edges_found` at p=0.049. Bugs
did not move at all — 31.6 to 32.4 distinct sites per replicate across every
arm, union 33 to 35.

### `g`, and why a stability number can go the wrong way

`g` is the one letter measured actively harmful. The mechanism fits: the gate
drops a find whose new edges do not reproduce, QUIC runs at about 62%
stability, and on an unstable target the inputs that reach furthest are exactly
the ones with wobbly coverage. lwext4 runs at 99.9% stability and there the
gate is neutral, which is the same explanation seen from the other side.

Its one flattering number is a trap. `-Jdg` reports stability 1.34-1.41x higher
than `-Jd` (p=0.0004), while coverage and depth do not move and the corpus grows
11%. It is not making the queue better; it is keeping the entries that drag the
average down out of it. The gate rejects 0.15-0.42% of finds for 1.67% of the
execution budget.

### `s` without annotations is not free either

On lwext4, with no `IJON_STATE()` call anywhere, `-Js` reports zero transitions
and zero extra executions, and it still moved the depth distribution down. Part
of that is length - it produced shorter inputs (0.87x, p=0.021) - but a residue
survives inside equal-length bands. The mechanism was not identified: the shelf's
state bucket stays 0 without a trusted signal, so it is not the shelf keying.
Treat "inert without annotations" as unproven and ask for `s` only when the
harness actually has annotations.

---

## Not built yet

A **snapshot pool** — several parked children, each stopped after a different
program prefix, so that "append one operation to this program" costs the one
operation instead of the whole program. It is the only planned item still
missing, and it is deliberately last: whether it pays is a per-target question
with a measured spread of 30×, `-Jb` is the go/no-go measurement, and moving the
snapshot point past the harness's own init means every child inherits whatever
the parent holds. See `TODO.md`.

---

## Environment variables

| Variable | Effect |
|---|---|
| `AFL_TIME_ACCOUNTING` | time accounting, independent of `-J` |
| `AFL_STATE_PROBE_RUNS` | repeat-probe run count (default 100, minimum 2) |
| `AFL_STATE_UTILITY_THRESHOLD` | percent agreement the state signal must reach (default 80) |
| `AFL_STATE_UTILITY_RETRY` | seconds between two runs of the state utility test (default 60) |
| `AFL_STATE_ADMIT_PCT` | largest share of the queue the state signal may create (default 25, 0 = no bound) |
| `AFL_STATE_YIELD_PCT` | percent of state-only entries that must have mothered a find to keep the licence (default 10) |
| `AFL_STATE_COARSE` | fold the state index by N bits by hand, 0–8 (default 0) |
| `AFL_STATE_PLUGIN_ADMIT` | let a mutator-reported state class justify saving an input |
| `AFL_IJON_ADMIT_PCT` | largest share of the queue `IJON_SET`/`IJON_INC` may create (default 0 = no bound) |
| `AFL_IJON_REPLAY_INTERVAL` | scheduling turns between two `IJON_MAX` replays (default 16, 0 = no replay) |
| `AFL_HOT_BIAS` | percent of havoc offsets aimed at the hot region (default 70) |
| `AFL_NO_STATE_MAP` | kill switch for the state map, honoured by both fuzzer and target |
| `AFL_WATCHDOG_MS` | target-side watchdog, `abort()` after N ms (needs `AFL_TARGET_WATCHDOG`) |

`include/config.h` holds the compile-time defaults behind these, plus
`STATE_MAP_SIZE`, `STATE_TOUCHED_MAX`, `STATE_PROBE_INTERVAL_MS`, the benchmark
run counts, the admission minimums and `AFL_TARGET_WATCHDOG` itself.

---

## Measured to lose — do not try these

All of the following were tried and measured. They lost. They are listed so
nobody spends the effort again.

| Idea | What happened |
|---|---|
| Start from a deep saved state ("golden image") | +10.8 points at first, then **−1.9 points** after an hour. It halved the executions. |
| Keep state between executions to save time | Stability fell from 100% to **62%** at worst. Saved crashes stopped reproducing. |
| Persistent mode with a small loop count as a compromise | At loop count 2, **half of all runs already start dirty**. Not tunable — structural. |
| Pin a deep prefix into the snapshot | Worse on every axis: fewer edges, 7.4 points less stability. |
| Fold the state map coarser when it turns out too fine | Kept the corpus cost, lost the benefit: deep-state share fell from 40% to **16%**, below no state signal at all. |
| Raise the operation-depth limit | A 64× larger budget moved coverage by 1.2 points. The real limit is the queue, not the cap. |
| Turn off trimming (`AFL_DISABLE_TRIM=1`) | No depth gain, slightly worse coverage. |
| Use threads for the peer side of a protocol | Stability 71–81% falling to 59%, and 5.5× slower. Turn-taking beat it on every axis. |
| Corrupt bytes protected by a signature or MAC | **0 of 321 target lines** over 1,470 attempts. The record is thrown away before any parser sees it. |
| Clever state-picking schedulers | Multiple published algorithms landed within noise of plain random. |
| More coverage instrumentation | More edges means more ballast. Write passes for state or fault injection instead. |

## See also

* [IJON.md](IJON.md) — the state annotation API
* [custom_mutators.md](custom_mutators.md) — the mutator API `state_records` uses
* [afl-fuzz_approach.md](afl-fuzz_approach.md) — every `fuzzer_stats` field
* [env_variables.md](env_variables.md) — every `AFL_*` variable
* [../custom_mutators/state_records/README.md](../custom_mutators/state_records/README.md)
  — the record format and its two framing rules
* [../utils/state_oracles/README.md](../utils/state_oracles/README.md) — the bug
  detectors and their self-tests
* [../utils/state_fuzzing/README.md](../utils/state_fuzzing/README.md) — the
  ablation experiment
