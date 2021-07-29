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
./optimin -h
OVERVIEW: Optimal corpus minimizer
USAGE: optimin [options] <target program> [target args...]

OPTIONS:

Color Options:

  --color     - Use colors in output (default=autodetect)

General options:

  -C          - Keep crashing inputs, reject everything else
  -O          - Use binary-only instrumentation (FRIDA mode)
  -Q          - Use binary-only instrumentation (QEMU mode)
  -U          - Use unicorn-based instrumentation (unicorn mode)
  -f          - Include edge hit counts
  -i dir      - Input directory
  -m megs     - Memory limit for child process (default=none)
  -o dir      - Output directory
  -p          - Display progress bar
  -t msec     - Run time limit for child process (default=5000)
  -w csv      - Weights file

Generic Options:

  --help      - Display available options (--help-hidden for more)
  --help-list - Display list of available options (--help-list-hidden for more)
  --version   - Display the version of this program
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
