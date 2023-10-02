# American Fuzzy Lop plus plus (AFL++)

## benchmarking

This directory contains benchmarking tools that allow you to compare one machine
with another in terms of raw ability to execute a fuzzing target repeatedly.

To achieve this, we use a sample program ("test-instr.c") where each path is
equally likely, supply it a single seed, and tell AFL to exit after one run of
deterministic mutations against that seed.

Usage:

```
cd aflplusplus/benchmark
python3 benchmark.py
 [*] Using 16 fuzzers for multicore fuzzing (use --fuzzers to override)
 [*] Ready, starting benchmark...
 [*] Compiling the test-instr-persist-shmem fuzzing harness for the benchmark to use.
 [*] multicore test-instr-persist-shmem run 1 of 3, execs/s: 846065.81
 [*] multicore test-instr-persist-shmem run 2 of 3, execs/s: 849694.03
 [*] multicore test-instr-persist-shmem run 3 of 3, execs/s: 850757.52
 [*] Average AFL execs/sec for this test across all runs was: 848839.12
 [*] Average total execs/sec for this test across all runs was: 833138.28
 [*] Results have been written to benchmark-results.jsonl
```

By default, the script will use a number of parallel fuzzers equal to your
available CPUs/threads (change with `--fuzzers`), and will perform each test
three times and average the result (change with `--runs`).

The script will use multicore fuzzing instead of singlecore by default (change
with `--mode singlecore`) and use a persistent-mode shared memory harness for
optimal speed (change with `--target test-instr`).

Each run writes results to [benchmark-results.jsonl](benchmark-results.jsonl)
in [JSON Lines](https://jsonlines.org/) format, ready to be pulled in to other
tools such as [jq -cs](https://jqlang.github.io/jq/) or
[pandas](https://pandas.pydata.org/) for analysis.

## Data analysis

There is sample data in [benchmark-results.jsonl](benchmark-results.jsonl), and
a Jupyter notebook for exploring the results and suggesting their meaning at
[benchmark.ipynb](benchmark.ipynb).

