# The state fuzzing ablation experiment

This directory ships the experiment, not its results.

## Why it exists

Every published comparison of stateful fuzzers changes the executor and the
state model at the same time. When the combined thing wins, nobody can tell
which half did the work — and the two halves have very different costs and very
different generality. This experiment separates them by changing one thing at a
time:

```
A  normal coverage, normal executor
B  normal coverage, improved executor      -> B minus A = engineering wins
C  improved executor + record mutator
D  improved executor + state signal        -> D minus B = state wins
E  improved executor + records + state
```

If `B - A` is most of the total, the win is engineering: throughput,
determinism, and a queue that stops punishing depth. If `D - B` is most of it,
the state model is earning its keep. Either answer is useful. Not knowing is
not.

## Running it

```bash
./run_ablation.sh -t ./target -i ./seeds -o ./ablation -V 3600 -n 5 -- @@
./analyze_ablation.py ./ablation
```

Arms C and E need a target that speaks the record format; point `-T` at
`custom_mutators/state_records/example_harness` or your own equivalent, and
`-m` at `state_records.so`. Without them, run `-a "A B D"` and you still get
the two contrasts that matter most.

Aimed havoc (`-Jh`) is deliberately left out of every arm. Its annotation path
rides on the state shared memory, so enabling it would arrive together with the
state signal in arms D and E and change two things at once — which is the exact
failure mode this experiment exists to avoid. Measure it separately if you want
a number for it.

Runs are sequential by default. On a machine with performance and efficiency
cores, running arms in parallel lands some of them on the slow cores and halves
their execs/s, which silently changes what you are measuring. `-p` is there if
you know your cores are equal.

Five repetitions per arm is the default for a reason: fuzzing run-to-run
variance routinely exceeds the effect sizes involved here. `analyze_ablation.py`
prints the min-max spread next to every median and refuses to let a contrast
look meaningful when it falls inside that spread.

## Reading the output

Three numbers per arm, never one:

* **per wall-clock second** — what you get for an hour of machine time. This is
  the number that matters to whoever is paying for the machine.
* **per execution** — separates "the executor got faster" from "the search got
  smarter".
* **per operation** — the only axis that survives once one input byte can drive
  a thousand target operations. A record-format arm can look catastrophic on
  executions per second while doing strictly more work.

For the third one the harness must write its total operation count to the file
named by `AFL_OPS_COUNTER_FILE`, which `run_ablation.sh` sets per run. Two
lines in the harness:

```c
static unsigned long long ops_total;
/* ... ops_total += n_ops; per execution ... */
/* at exit: */
const char *p = getenv("AFL_OPS_COUNTER_FILE");
if (p) { FILE *f = fopen(p, "w"); if (f) { fprintf(f, "%llu\n", ops_total); fclose(f); } }
```

`analyze_ablation.py` also dumps a "context, not results" line per arm —
ballast share, target-time share, per-input stability, gate rejections, whether
the state signal was ever trusted. Those explain a result. They are not the
result.

## What is deliberately not reported

**Number of states found.** It is not a success metric and this tooling will
not print one as a headline. A broken observer that hashes the clock finds
millions of states and fuzzes nothing. If you want to know whether a state
definition is any good, use the utility test built into `-Js`: it takes two
inputs the definition calls identical, applies the same next action to both,
and checks whether they behave the same. That number (`state_utility_pct`) is
in the context line.

See [../../docs/fuzzing_stateful_targets.md](../../docs/fuzzing_stateful_targets.md).
