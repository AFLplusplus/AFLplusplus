# American Fuzzy Lop plus plus (AFL++)

## benchmarking

This directory contains benchmarking tools that allow you to compare one machine
with another in terms of raw ability to execute a fuzzing target repeatedly.

To achieve this, we use a sample program ("test-instr.c") where each path is
equally likely, supply it a single seed, and tell AFL to exit after one run of
deterministic mutations against that seed.

**Note that this is not a real-world scenario!**
Because the target does basically nothing this is rather a stress test on
Kernel I/O / context switching.
For this reason you will not see a difference if you run the multicore test
with 20 or 40 threads - or even see the performance decline the more threads
(`-f` parameter) you use. In a real-world scenario you can expect to gain
exec/s until 40-60 threads (if you have that many available on your CPU).

Usage example:

```
cd aflplusplus/benchmark
python3 benchmark.py
 [*] Ready, starting benchmark...
 [*] Compiling the test-instr-persist-shmem fuzzing harness for the benchmark to use.
 [*] singlecore test-instr-persist-shmem run 1 of 2, execs/s: 124883.62
 [*] singlecore test-instr-persist-shmem run 2 of 2, execs/s: 126704.93
 [*] Average execs/sec for this test across all runs was: 125794.28
 [*] Using 16 fuzzers for multicore fuzzing (use --fuzzers to override).
 [*] multicore test-instr-persist-shmem run 1 of 2, execs/s: 1179822.66
 [*] multicore test-instr-persist-shmem run 2 of 2, execs/s: 1175584.09
 [*] Average execs/sec for this test across all runs was: 1177703.38
 [*] Results have been written to the benchmark-results.jsonl file.
 [*] Results have been written to the COMPARISON.md file.
```

By default, the script will use a number of parallel fuzzers equal to your
available CPUs/threads (change with `--fuzzers`), and will perform each test
three times and average the result (change with `--runs`).

The script will use multicore fuzzing instead of singlecore by default (change
with `--mode singlecore`) and use a persistent-mode shared memory harness for
optimal speed (change with `--target test-instr`).

Feel free to submit the resulting line for your CPU added to the COMPARISON.md
and benchmark-results.jsonl files back to AFL++ in a pull request.

Each run writes results to [benchmark-results.jsonl](benchmark-results.jsonl)
in [JSON Lines](https://jsonlines.org/) format, ready to be pulled in to other
tools such as [jq -cs](https://jqlang.github.io/jq/) or
[pandas](https://pandas.pydata.org/) for analysis.

## Data analysis

There is sample data in [benchmark-results.jsonl](benchmark-results.jsonl), and
a Jupyter notebook for exploring the results and suggesting their meaning at
[benchmark.ipynb](benchmark.ipynb).

