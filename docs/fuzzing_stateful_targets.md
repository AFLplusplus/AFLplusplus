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

That enables the three parts in the default set. The launch line the
measurements favour adds the high-water channel:

```bash
afl-fuzz -Jdm -i seeds -o out -- ./target @@
```

| Letter | Turns on | In bare `-J` |
|---|---|---|
| `d` | deep-input shelf, so long inputs stop losing | yes |
| `c` | harness self-check at startup | yes |
| `b` | one-shot execution cost benchmark | yes |
| `m` | hit-count high-water channel | no |
| `w` | hang watchdog inside the target, needs a compile-time opt-in | no |

The letters are case-insensitive and must be **attached** to `-J`: `-Jdm`
works, `-J dm` does not, because `-J` takes an optional argument. Plain `-J`
selects `dcb`; everything else has to be asked for by letter. A second `-J` on
the same command line is an error.

`d` is the only part measured to improve the search on its own, `m` adds to it
independently, and `c` and `b` are one-shot diagnostics that cannot steer it.

Time accounting is separate from `-J` entirely and is switched on with
`AFL_TIME_ACCOUNTING=1`, with or without state fuzzing mode.

To find out whether the `afl-fuzz` at hand has this mode at all, capture the
help screen first and search the capture. `-h` exits non-zero, so a pipeline
that greps it directly fails under `set -o pipefail`:

```sh
help=$(afl-fuzz -h 2>&1 || true)
case "$help" in *"state fuzzing mode"*) echo yes ;; *) echo no ;; esac
```

The version string is no help here: a build with `-J` and one without report
the same version.

One part needs more than a letter: `w` needs `AFL_TARGET_WATCHDOG` uncommented
in `include/config.h` and both `afl-fuzz` and the target rebuilt.

The shelf's achievement axis is the operation count a custom mutator reports
through `afl_custom_describe_state`; without one it falls back to the input
length. Supplying it was measured not to change depth on its own, so it is
worth having because the number is then right, not because it buys depth.

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

`-Jd` sorts entries into cells by `(achievement, cost)` — 8 buckets each,
64 cells — and changes two things:

* **Comparison happens inside the cell.** The alias-table weight normalises
  `exec_us`, `len` and information against the entry's own cell mean, not the
  global mean, whenever that cell holds at least two entries. A slow deep input
  is compared against other slow deep inputs.
* **Each cell keeps four witnesses**, not one: the shortest, the fastest, the
  broadest — usually a different route to the same state — and the one that did
  the most work. Witnesses join the favored set alongside the usual set-cover
  winners.

The per-edge winner selection (`fav_factor`) is deliberately left alone. It is
a much larger blast radius than this needs, and the two changes above already
let a deep input survive without beating a tiny fast one.

The achievement axis is the operation count a mutator reports, and the input
length where there is none — which makes the axis a proxy for file size, so a
mutator that speaks the format is worth loading.

Stats: `shelf_cells_used`, `shelf_members`.

### `m` — the hit-count high-water channel

An edge AFL++ has already seen tells it nothing more, however many times the
next input drives it. `-Jm` keeps a per-edge high-water mark of the raw hit
count and treats a large enough increase over it as a reason to keep an input:
a loop that ran 8 times and now runs 40 is doing something the coverage map
cannot express.

A credit needs the count to reach `AFL_HW_MIN_COUNT` (default 8) and to exceed
the recorded mark by `AFL_HW_GROWTH_PCT` (default 25). Both defaults were
measured against alternatives and neither mattered, so leave them alone.

Like every save channel it is bounded: once high-water-only entries own more
than `AFL_STATE_ADMIT_PCT` of the queue and fewer than `AFL_STATE_YIELD_PCT` of
them have gone on to mother a coverage find, the channel stops saving and says
so.

`-Jm` alone is never the best arm and lowers a depth metric on two of the five
targets it was measured on. Under `-Jd` it is additive — the two contribute
independently, with no interaction — and `-Jdm` was best or tied-best on four
of five targets and harmful on none. Ask for it with `d`, not on its own.

Stats: `hw_only_saves`, `hw_only_paid`, `hw_credits`, `hw_slots`,
`hw_admit_off`.

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

**A third number, when the input format has operation boundaries.** A snapshot
pool does not compete with process setup — it removes *prefix replay*. So `-Jb`
also times the same input truncated after its first `n/2` operations, which is
exactly what a process parked halfway through the program will already have done.
`cost_prefix_us` is that timing and `cost_prefix_pct` is its share of a whole
forkserver execution.

The truncation point comes from `afl_custom_describe_state_ops` (see
[custom_mutators.md](custom_mutators.md)). Without a mutator that implements it
there is no honest boundary to cut at, so the decomposition is **skipped with one
warning** and neither key is written — a boundary is never guessed. `b` is in bare
`-J`'s default set (`dcb`), and no mutator outside the `state_records` class
implements the callback, so a bare `-J` user pays nothing for this. Users who do
implement it pay 200 extra forkserver runs once at startup: roughly 0.5–0.8 s on a
target whose forkserver iteration is 2.7–4.0 ms, against `-Jb`'s existing 0.85 s.

Two cautions on reading `cost_prefix_pct`:

* It is a share of a **whole execution**, fixed per-execution cost included, so it
  over-reports the prefix share of *operation work* — in a pool's favour. Writing
  an execution as `F + W` (fixed cost plus the work of `n` operations), a measured
  share `p` implies the prefix's operation work is only
  `(p - 0.5) / (1 - p) x 0.5` of an execution. On `state_records/example_harness`
  a measured 83.9 % at 20 operations is **15.5 %** of an execution by that
  correction, and 64.7 % at 200 operations is **36 %**.
* It rises with program length, because `W` grows while `F` does not. One reading
  at one input length is not a property of the target.

Stats: `cost_fork_us`, `cost_setup_us`, `cost_prefix_us`, `cost_prefix_pct`.

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

**Every execution:** the coverage map, the exit status, the per-edge high-water
scan under `m`, and — only under time accounting — two clock reads. Nothing
else.

**Candidates and intervals only:**

| Work | When | Cost |
|---|---|---|
| harness self-check | startup, once | 2 execs, up to 17 in persistent mode |
| cost benchmark | startup, once | ~220 execs, plus up to one deadline |
| shelf rebuild and cell keying | per queue cull | queue scans, no executions |

`slow_path_execs` and `slow_path_pct` report exactly how much of your budget
this feature set consumed, so the overhead is visible rather than assumed.

Read that table in *executions*, not in percent. `c` and `b` re-run inputs, so
they cost a fraction of your own cost-per-execution: the same letters that
measure `slow_path_pct 0.05%` on a microsecond-scale demo target measure a few
percent on a target that spends milliseconds per execution. They are one-shot,
so the share falls for the rest of the campaign.

Memory, on top of the usual maps: one map-sized array for the high-water marks
with `m`, and about 3 KB of shelf bookkeeping with `d`.

---

## Reading the numbers

Every field this mode adds to `fuzzer_stats` is listed and explained in
[afl-fuzz_approach.md](afl-fuzz_approach.md). A field appears only when the part
that produces it is enabled.

The UI adds one line below the grid whenever `-J` or time accounting is active,
which is why the minimum terminal height rises from 24 to 25 rows. It carries
`tgt/tot`, `shelf` (cells/witnesses) and `slow`, padded to a fixed width so a
value that shrinks leaves no leftover characters behind.

`stability` is unchanged and still means what it always meant — the cumulative
union of every map byte ever seen to vary, over the whole corpus. It is not
comparable between runs with different corpus sizes.

It is **not comparable across an IJON boundary**. `IJON_STATE` mixes the
situation into every later edge index, so the same harness annotated and
unannotated produces different cumulative figures — annotated arms of one
ablation read 83–93% where the plain arms read 99.4–99.8%, for harnesses whose
per-input stability was indistinguishable. On top of that, the fuzzer's map in an
IJON build includes the 64 KB `IJON_SET`/`IJON_INC` area, so `total_edges` and
every percentage derived from it (`bitmap_cvg`, `stability`) are computed over a
larger map than the coverage region alone. When comparing an annotated build
against a plain one, compare `input_stab_avg` and `input_stab_min`.

### Judging IJON annotations: not by coverage

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

Measure it from the harness: an env-gated line per operation carrying
the ladder position, the situation id and the operation counter, replayed over
the final corpus, yields program length and situation variety from one
instrument. Two details that bite: measure any fixed warm-up prefix on an empty
input rather than assuming it, and count what the harness **retires**, not what
the bytes encode.

`cov_edges_found` in `fuzzer_stats` reports the coverage area of an IJON map
alone, where `edges_found` counts the whole map including the 64 KB
`IJON_SET`/`IJON_INC` area. Compare arms on `cov_edges_found`, and only between
builds with the same map geometry.

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

Two rounds of measurement, both on real targets, both with the arms interleaved
and each instance on its own `-o` with no syncing.

**Round 1**, two targets — an OpenSSL 3.5 QUIC server harness with
`IJON_STATE()` annotations and lwext4's `fuzz_ops` — each letter against `-Jd`
alone, one letter at a time, 2 h per instance, n=18 and n=11.

**Round 2**, five targets — nginx QUIC/HTTP-3, libssh, Samba SMB2, Mbed TLS
`fuzz_ssl_state` and lwext4 — flag arms at n=28, 30 min each.

Depth comes from an external probe compiled without AFL that reports what one
execution achieved; coverage is a union over an equal-N sample per arm replayed
through one common build; bugs are crashes reproduced standalone and
deduplicated on assertion text with values stripped.

What survived:

| target | best arm | what it buys | cost (median) |
|---|---|---|---|
| `state_records/example_harness` | `-Jdm` | `depth_ge12` 1.585x ✱✱ | ~none |
| lwext4 | `-Jd` | `ops_ge128` 2.636x ✱ | ~none |
| Mbed TLS | `-Jdm` | `depth_ge12` 1.257x ✱✱ | 29% |
| nginx | `-Jdm` | 46+ operation band 1.814x ✱✱ | 5% |
| libssh | `-Jdm` | situations 1.361x ✱✱, depth/input 1.102x ✱✱ | none |

`-Jdm` does not buy the same thing everywhere, which is a point in its favour:
on four targets it lengthens programs, on libssh it *shortens* them 0.82x at p95
while raising per-input situation richness 1.10x.

The 2x2 on QUIC at n=28, states at depth >= 12: control 1.00, `m` alone 1.37,
`d` alone 1.77, both 2.10 against an additive prediction of 2.14. **The two
contribute independently — there is no interaction**, and the plain scheduling
fix carries two thirds of it.

The shelf's breadth cost depends on whether the target has saturated. QUIC,
which never does: 0.08%, noise. lwext4, which exhausts its reachable edges in
minutes: **-3.4%, with 120 edges reached only by the control**. Budget spent
driving programs longer is budget not spent on breadth, and that only bites once
breadth has run out. **Check whether your coverage curve has flattened before
enabling a depth feature.**

---

## Environment variables

| Variable | Effect |
|---|---|
| `AFL_TIME_ACCOUNTING` | time accounting, independent of `-J` |
| `AFL_HW_MIN_COUNT` | hit count a slot must reach before `-Jm` credits it (default 8) |
| `AFL_HW_GROWTH_PCT` | growth over the recorded mark a credit must show (default 25) |
| `AFL_STATE_ADMIT_PCT` | largest share of the queue a save channel may create (default 25, 0 = no bound) |
| `AFL_STATE_YIELD_PCT` | percent of channel-only entries that must have mothered a find to keep the licence (default 10) |
| `AFL_IJON_ADMIT_PCT` | largest share of the queue `IJON_SET`/`IJON_INC` may create (default 0 = no bound) |
| `AFL_IJON_REPLAY_INTERVAL` | scheduling turns between two `IJON_MAX` replays (default 16, 0 = no replay) |
| `AFL_WATCHDOG_MS` | target-side watchdog, `abort()` after N ms (needs `AFL_TARGET_WATCHDOG`) |

`include/config.h` holds the compile-time defaults behind these, plus the
benchmark run counts, the admission minimums and `AFL_TARGET_WATCHDOG` itself.

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
