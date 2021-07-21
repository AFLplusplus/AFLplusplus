# OptiMin

OptiMin is a corpus minimizer that uses a
[MaxSAT](https://en.wikipedia.org/wiki/Maximum_satisfiability_problem) solver
to identify a subset of functionally distinct files that exercise different code
paths in a target program.

Unlike most corpus minimizers, such as `afl-cmin`, OptiMin does not rely on
heuristic and/or greedy algorithms to identify these functionally distinct
files. This means that minimized corpora are generally much smaller than those
produced by other tools.

## Usage

To build the `optimin` executable (when cloned from github):

```bash
# Ensure EvalMaxSAT is available
git submodule init
git submodule update

mkdir build
cd build

# You may have to specify -DLLVM_DIR=`llvm-config --cmakedir` if you have a
# non-standard LLVM install (e.g., install via apt)
cmake ..
make -j
make install
```

Otherwise, run the `build_optimin.sh` script. Running `optimin` is the same as
running `afl-cmin`.

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
