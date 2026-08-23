# pool_probe — measurement tools for the snapshot pool (`-Jo`)

Two independent tools plus a mandatory pre-launch check. None of them needs the
snapshot pool to exist; they are the Phase 0 measurements of
`SNAPSHOT-PLAN.md`, and they answer the questions `SNAPSHOT-SPEC.md` §2.3 uses
to decide whether the pool is worth building at all.

Build:

```sh
make
```

## `pool-hit-rate` — spec §7.6, offline pool hit rate

```sh
./pool-hit-rate <out_dir>/<instance>/queue
```

Reads a finished campaign's queue directory, recovers lineage from the `id:`
and `src:` fields of the file names, decodes each entry with the format's own
self-contained decoder (`state_records.h`, `state_rec_decode`), and simulates an
LRU pool of size K for K in 1, 4, 16, 64.

It reports **two** rates per K, because the honest one is not obtainable
offline:

* **append** — the pool holds the mother's *complete* record list and this entry
  extends it. This is the case spec advantage #1 is about, and it is a
  conservative **lower** bound.
* **prefix** — the pool holds *any* proper prefix of this entry of length >= 1.
  A **generous upper** bound: a real pool could only exploit it by re-running
  everything after the point where the two inputs diverge.

Both are **per queue entry, not per execution.** The truth is between them and
below the generous one. The tool prints that caveat on every run, and it should
be repeated wherever the numbers are: a number printed without it will be quoted
without it.

**One bias to state, because it points the wrong way for us.** The pool's
audience is the `state_records`-format class, and a mutator that mostly emits
well-formed records produces more stable prefixes than byte-level havoc does, so
the simulated hit rate is *flattered* relative to a general harness. That is the
same mutator `STATE_LESSONS.md` §7 measured as simultaneously the deepest and
the narrowest arm in its experiment — 302 distinct states against 1,551–1,641,
and the lowest coverage of any arm. Read both bounds as upper-leaning.

`pool_lookup()` uses the same prefix definition this tool does, so the simulated
number and a live `pool_hit_rate` stat are comparable — and the live rate can
never exceed the prefix rate printed here.

### Fixture and expected output

The fixture is three entries: entry 0 is one record, entry 1 is entry 0 plus a
second record, entry 2 is a single *different* record.

```sh
mkdir -p /tmp/pool-hr/queue && cd /tmp/pool-hr/queue
printf '\x5a\xa5\x01\x00\x00\x00\x00\x00'                                 > 'id:000000,time:0,execs:0,op:init,pos:0'
printf '\x5a\xa5\x01\x00\x00\x00\x00\x00\x5a\xa5\x02\x00\x00\x00\x00\x00' > 'id:000001,src:000000,time:1,execs:1,op:havoc,rep:1'
printf '\x5a\xa5\x03\x00\x00\x00\x00\x00'                                 > 'id:000002,src:000000,time:2,execs:2,op:havoc,rep:1'
```

Entry 1 appends to entry 0, so it is an append hit for any K >= 1. Entry 2 shares
no leading record with entry 0, so it is neither. Entry 0 has no `src:` and is
not a candidate. Expected: `entries: 3` and every K row reading
`50.0% 50.0% 2` — one hit over the two entries that have a mother.

## `fork-cost.sh` — spec §7.2 and §7.7, fork cost against dirty footprint

```sh
./fork-cost.sh <harness> <input> [depths...]
```

Sweeps `AFL_POOL_FORK_PROBE=<k>` over the harness, which replays `k` operations
and then times 200 fork-plus-reap cycles and reports its own RSS. The input goes in
on **stdin**, not as `argv[1]`: under `afl-clang-fast` the harness's `main` always
takes the `__AFL_LOOP` path and the `argv` branch is compiled out, so an `argv[1]`
input is silently ignored and every depth reports `park_ops=0` on an empty input.
Use the **plain-`cc`** build here in any case — this measures fork cost against
dirty footprint, and instrumentation is neither. (`make` builds the plain one;
`make CC=../../afl-clang-fast` replaces it with the instrumented one.) The reap is
inside the timed loop deliberately: what a pool hit pays is fork *plus* reap, and
timing the fork alone would flatter it. Do not re-derive a smaller number by
removing the `waitpid`.

`delta_us_vs_0` is the extra fork cost at that depth against a slot parked at
operation 0 — the quantity spec §7.2 kills the design on. Compare it against
`cost_prefix_us` from `-Jb`: **if the delta exceeds the prefix cost it would
save, the pool is arithmetically dead and no engineering fixes it.**

Run the sweep at least three times. Fork cost is noisy, and on a harness with a
small dirty footprint the noise is larger than the trend — which is a result
about the harness, not a pass.

## `prefix-share.sh` — spec §7.3 for a target with no boundary-aware mutator

```sh
./prefix-share.sh <afl-fuzz> <seed-file> <core> -- <target...>
```

`-Jb`'s in-process prefix decomposition needs `afl_custom_describe_state_ops`,
which only a mutator that understands the input format can implement. For any
other target this asks the same question from the outside: run `-Jb` on one seed,
then on the same seed truncated to 50 %, 25 % and 10 % of its bytes, and compare
`cost_fork_us`.

A share that stays near 100 % as the fraction falls means execution cost is fixed
per-execution work rather than input-proportional — prefix replay is ~0 % of
target time and a pool has nothing to remove. That is what samba
`fuzz_smb2_server` measured: **10 % of the bytes, 100.2 % of the cost.** A share
that falls roughly with the fraction means prefix replay is real.

The truncation is a proxy: it assumes the first f % of bytes is roughly the first
f % of operations. That holds for a concatenated record or PDU sequence. It does
**not** hold for a format that a truncated input fails to *parse* — a trailing
checksum, a rewritten length prefix, or any serialised protobuf. **Check for that
before believing a result**: the signature is every truncated fraction costing the
same tiny amount, because the harness rejects the input and returns immediately.
sqlite's `sql_fuzzer` is `DEFINE_BINARY_PROTO_FUZZER`, and its 50 %, 25 % and 10 %
inputs all cost 0.005 s against 1.8 s for the whole — that is a parse failure, not
a 99.7 % prefix saving. Such a target needs truncation at message boundaries (drop
trailing entries from the repeated field and re-serialise), not at byte offsets. Where the
mutator can answer, prefer `-Jb`'s own `cost_prefix_pct`.

## `cpu-split.sh` — did the arms get the same CPU, and where did it go?

```sh
./cpu-split.sh            # run on the host, while the campaign is alive
```

Reports, per live `afl-fuzz` instance whose `-o` is under `/tmp/pool-p0`: total
CPU seconds, utilisation against `run_time`, and the split into **fuzzer-side**
(the `afl-fuzz` process itself) and **target-side** (every descendant, live or
already reaped) CPU, plus CPU microseconds per execution.

**This is the comparison to make, not `execs_done`.** An arm with more executions
may have less fuzzer-side overhead, or it may be running cheaper inputs, and
`execs_done` cannot tell those apart — they have opposite implications. CPU time
can: overhead shows up as fuzzer-side seconds, cheap inputs show up as target
CPU per execution.

Two things to check before reading any ratio:

* **Total CPU must be equal between arms.** If it is not, the arms did not get the
  same machine and nothing else in the comparison means anything. Measured on the
  §7.5 A/B: 808.8-816.5 s across all 24 instances, medians 812.70 (off) and 813.10
  (on) — equal to three digits, so that comparison was CPU-fair by construction.
* **Utilisation reads about 104 %, and that is expected.** `run_time` starts from
  `afl->start_time`, which is reset after the dry run
  (`src/afl-fuzz.c:3723`), so it undercounts real elapsed time by the startup
  duration. Adding that back gives 100.0 %. A reading meaningfully *below* 100 %
  means the instance was not getting its core.

Run it more than once during a campaign: the numbers are cumulative, so two
samples give a windowed rate for the interval between them.

## `free-cores.sh` — what a shared host has spare

```sh
./free-cores.sh [host ...]        # default: bigfuzz fuzzybear
```

Read-only: it starts nothing and kills nothing. Run it **before every launch** of
anything remote, every time.

bigfuzz and fuzzybear are shared machines and other people's campaigns live on
them. While this plan was written bigfuzz was running **40 `afl-fuzz` instances
pinned across CPUs 24-63 at load 30**, leaving only CPUs 0-23 free, while
fuzzybear was idle. Taking a CPU that already carries someone's fuzzer halves
their execs/s *and* invalidates your own arm at the same time. Never skip the
check because the host was free an hour ago.

Then:

* Take cores from the reported **free** list, and prefer to keep every replicate
  of both arms inside **one** NUMA node (node0 = 0-15,32-47; node1 = 16-31,48-63)
  so that memory locality does not become a second variable. These hosts have 16
  *physical* cores per node, so an A/B wanting more than 16 replicates has to
  span both nodes — balance the arms evenly across nodes rather than giving one
  arm a node.
* Watch hyperthread siblings: `0` and `32` are the same physical core. A "free"
  logical CPU whose sibling is busy is not free.
* Leave at least a quarter of the free set spare, and **abort rather than shrink
  n** — a gate run at half its replicate count is a number nobody can use.
* If neither host has room, wait. Do not fall back to a development laptop.
* Re-run the check after the campaign finishes, to confirm nothing of yours was
  left pinned.

`pgrep -xc` is deliberate. `pgrep -f afl-fuzz` matches the command line of the
shell running the check, so it never reports zero.

## Where the numbers go

`SNAPSHOT-MEASUREMENTS.md` at the repository root, in the table format each
measurement task of `SNAPSHOT-PLAN.md` specifies. See `SNAPSHOT-SPEC.md` §7.6,
§7.2 and §7.7 for what each measurement is for.
