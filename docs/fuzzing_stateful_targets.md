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

That enables every part. To enable only some:

```bash
afl-fuzz -Jgpr -i seeds -o out -- ./target @@
```

| Letter | Turns on |
|---|---|
| `g` | double-run gate before saving a find |
| `p` | per-input stability and the repeat probe |
| `r` | rare-edge scoring |
| `d` | deep-input shelf, so long inputs stop losing |
| `s` | state map from IJON annotations |
| `c` | harness self-check at startup |
| `b` | one-shot execution cost benchmark |
| `h` | aimed havoc, from a harness annotation |
| `w` | hang watchdog inside the target, needs a compile-time opt-in |

The ballast share is always on under `-J`. Time accounting is separate from
`-J` entirely and is switched on with `AFL_TIME_ACCOUNTING=1`, with or without
state fuzzing mode.

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

Cost: one extra execution per *saved* input, which is a tiny share of all
executions.

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

**The repeat probe.** One input, 100 runs from a clean start, reported as
`probe_pct` (runs whose whole trace matched run 1) and `probe_edge_pct` (edges
present in every run, over edges present in any run). It runs once at startup
and at most once a minute thereafter, on a randomly chosen favored entry.

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

AFL++ bounds the damage rather than trusting the annotation. When the state
signal has created more than `AFL_STATE_ADMIT_PCT` of the queue (default 25%)
on its own, it stops saving inputs and goes back to being a note — unless its
entries are demonstrably paying for themselves, which `AFL_STATE_YIELD_PCT`
decides from `state_only_saves` and `state_only_paid`. On the same target the
bound brought those 14,280 entries down to 317.

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

Stats: `state_transitions`, `state_map_density`, `state_signal`,
`state_only_saves`, `state_coarse_fold`, `state_coarse_steps`.

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

Stats: `plugin_described`, `plugin_ops_avg`, `plugin_ops_max`.

### `s` — and the test that decides whether to believe it

**Nobody has ever published an error rate for any automatic state detection
method.** So `-Js` does not trust its own state signal until it has been
tested on your target.

The test: take two inputs AFL++ thinks are in the same state, apply the same
next action to both, and see whether they behave the same. If inputs the state
definition calls identical keep behaving differently, the definition has
merged two real states and needs one more field.

The action is a short random byte string appended to both inputs, so every
pair is first run without it. A pair only counts when the appended bytes made
both targets walk *further* through the state machine than their own bytes
did. Without that check the test would pass for free on any target that
ignores trailing bytes — two inputs that both ignore their suffix agree
trivially, and a vacuous 100% is exactly the false pass this gate exists to
prevent. Pairs whose probe changed nothing are dropped, and if too few pairs
survive AFL++ says so instead of reporting a verdict.

Behaving the same means: ending in the same state, terminating the same way
(both fine, both crashing, both timing out), and giving the same answer to
"did this run reach coverage nobody had reached before".

Until the test passes, new state transitions are recorded, counted and
reported, and change nothing about which inputs are saved. `state_signal` reads
`observing`. Once agreement reaches the threshold (default 80%, set with
`AFL_STATE_UTILITY_THRESHOLD`), it reads `trusted` and a new state transition
becomes a reason to save an input on its own.

The transitions seen while the signal is still observational are *not* spent.
Reporting and admission use separate maps, so a transition first met during
the observational phase can still justify saving an input once the signal
becomes trusted.

Stats: `state_utility_pct`, `state_util_pairs`.

The test samples at most 32 pairs, so on a target with few state groups the
figure is noisy — this repository's own end-to-end target has been observed at
53% on one run and 100% on another. The gate is one-sided on purpose: a noisy
estimate errs toward *not* trusting the signal, which costs nothing but a
missed opportunity, whereas trusting a bad state definition corrupts every
decision downstream. Re-checking every 8 queue cycles means a signal that is
genuinely good gets more chances as the corpus grows.

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

Stats: `contract_check`, `contract_diff`.

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
one deadline instead of hanging the campaign.

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

70% of single-byte havoc mutations then land inside it (`AFL_HOT_BIAS`). The
other 30% stay uniform on purpose — plain byte mutation still finds parser and
memory bugs, and the annotation can be wrong.

Harnesses without the annotation get a fallback: when CmpLog colorization
finds taint ranges for an input, the largest range that is smaller than the
whole input becomes that input's hot region. On this repository's own state
machine target, built *without* `AFL_HOT_REGION`, `afl-fuzz -Jh -c 0` gave 77
of 80 queue entries a hot region; the same run without `-c` gave none. A
harness annotation always wins over the CmpLog guess.

Length-changing operators keep uniform offsets, and the splice stage is
untouched.

What matters here is *useful* mutations per second, not raw mutations per
second.

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

Set `AFL_WATCHDOG_MS` yourself to override. Note that a target which installs
its own `setitimer(ITIMER_REAL)` will clobber the watchdog.

---

## The fast loop and the slow loop

Rich observation is valuable and too slow to do a million times a second. So
the work is split, and the split is enforced by where the code lives.

**Every execution:** the coverage map, the state map, the exit status, and —
only under time accounting — two clock reads. Nothing else.

**Candidates and intervals only:**

| Work | When | Cost |
|---|---|---|
| double-run gate | per input saved to the queue | 1 exec |
| per-input stability, ballast, info score | per calibration | map scans on an already-running path |
| repeat probe | startup, then at most once a minute | 100 execs |
| harness self-check | startup, once | ~4 execs |
| cost benchmark | startup, once | 220 execs |
| state utility test | ≥20 state-carrying entries, then every 8 cycles | ≤128 execs |

`slow_path_execs` and `slow_path_pct` report exactly how much of your budget
this feature set consumed, so the overhead is visible rather than assumed.

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

`analyze_ablation.py` reports **three** numbers, not one: results per
wall-clock second, per execution, and per operation. Once one input byte can
drive a thousand writes, executions per second is no longer comparable across
arms.

---

## Environment variables

| Variable | Effect |
|---|---|
| `AFL_TIME_ACCOUNTING` | time accounting, independent of `-J` |
| `AFL_STATE_PROBE_RUNS` | repeat-probe run count (default 100) |
| `AFL_STATE_UTILITY_THRESHOLD` | percent agreement the state signal must reach (default 80) |
| `AFL_HOT_BIAS` | percent of havoc offsets aimed at the hot region (default 70) |
| `AFL_NO_STATE_MAP` | target-side kill switch for the state map |
| `AFL_WATCHDOG_MS` | target-side watchdog, `abort()` after N ms (needs `AFL_TARGET_WATCHDOG`) |

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
| Raise the operation-depth limit | A 64× larger budget moved coverage by 1.2 points. The real limit is the queue, not the cap. |
| Turn off trimming (`AFL_DISABLE_TRIM=1`) | No depth gain, slightly worse coverage. |
| Use threads for the peer side of a protocol | Stability 71–81% falling to 59%, and 5.5× slower. Turn-taking beat it on every axis. |
| Corrupt bytes protected by a signature or MAC | **0 of 321 target lines** over 1,470 attempts. The record is thrown away before any parser sees it. |
| Clever state-picking schedulers | Multiple published algorithms landed within noise of plain random. |
| More coverage instrumentation | More edges means more ballast. Write passes for state or fault injection instead. |

## See also

* [IJON.md](IJON.md) — the state annotation API
* [custom_mutators.md](custom_mutators.md) — the mutator API `state_records` uses
* [env_variables.md](env_variables.md) — every `AFL_*` variable
