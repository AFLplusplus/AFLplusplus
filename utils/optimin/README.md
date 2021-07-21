# OptiMin

OptiMin is a corpus minimizer that uses a
[MaxSAT](https://en.wikipedia.org/wiki/Maximum_satisfiability_problem) solver
to identify a subset of functionally distinct files that exercise different code
paths in a target program.

Unlike most corpus minimizers, such as `afl-cmin`, OptiMin does not rely on
heuristic and/or greedy algorithms to identify these functionally distinct
files. This means that minimized corpora are generally much smaller than those
produced by other tools.

## Building

To build the `optimin` just execute the `build_optimin.sh` script.

## Running

Running `optimin` is the same as running `afl-cmin`:

```
Required parameters:
  -i dir        - input directory with starting corpus
  -o dir        - output directory for minimized files

Execution control settings:
  -f file       - location read by the fuzzed program (stdin)
  -m megs       - memory limit for child process (none MB)
  -t msec       - run time limit for child process (none)
  -O            - use binary-only instrumentation (FRIDA mode)
  -Q            - use binary-only instrumentation (QEMU mode)
  -U            - use unicorn-based instrumentation (unicorn mode)

Minimization settings:
  -C            - keep crashing inputs, reject everything else
  -e            - solve for edge coverage only, ignore hit counts

For additional tips, please consult README.md

Environment variables used:
AFL_ALLOW_TMP: allow unsafe use of input/output directories under {/var}/tmp
AFL_CRASH_EXITCODE: optional child exit code to be interpreted as crash
AFL_FORKSRV_INIT_TMOUT: time the fuzzer waits for the forkserver to come up
AFL_KEEP_TRACES: leave the temporary <out_dir>/.traces directory
AFL_KILL_SIGNAL: Signal delivered to child processes on timeout (default: SIGKILL)
AFL_NO_FORKSRV: run target via execve instead of using the forkserver
AFL_PATH: path for the afl-showmap binary if not found anywhere in PATH
AFL_PRINT_FILENAMES: If set, the filename currently processed will be printed to stdout
AFL_SKIP_BIN_CHECK: skip afl instrumentation checks for target binary
```

Example: `optimin -i files -o seeds -- ./target @@`

### Weighted Minimizations

OptiMin allows for weighted minimizations. For examples, seeds can be weighted
by file size (or execution time), thus preferencing the selection of smaller (or
faster) seeds.

To perform a weighted minimization, supply a CSV file with the `-w` option. This
CSV file is formatted as follows:

```
SEED_1,WEIGHT_1
SEED_2,WEIGHT_2
...
SEED_N,WEIGHT_N
```

Where `SEED_N` is the file name (**not** path) of a seed in the input directory,
and `WEIGHT_N` is an integer weight.

## Further Details and Citation

For more details, please see the paper [Seed Selection for Successful
Fuzzing](https://dl.acm.org/doi/10.1145/3460319.3464795). If you use OptiMin in
your research, please cite this paper.

Bibtex:

```bibtex
@inproceedings{Herrera:2021:FuzzSeedSelection,
  author = {Adrian Herrera and Hendra Gunadi and Shane Magrath and Michael Norrish and Mathias Payer and Antony L. Hosking},
  title = {Seed Selection for Successful Fuzzing},
  booktitle = {30th ACM SIGSOFT International Symposium on Software Testing and Analysis},
  series = {ISSTA},
  year = {2021},
  pages = {230--243},
  numpages = {14},
  location = {Virtual, Denmark},
  publisher = {Association for Computing Machinery},
}
```
