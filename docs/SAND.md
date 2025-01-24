# SAND

This repo will contain the implementation and paper for "SAND: Decoupling Sanitization from Fuzzing for Low Overhead".

Preprint is available [here](./paper.pdf) and we will have camera-reday version uploaded shortly.

The original AFL++ README is available [here](./README.AFLpp.md).

## Branch organization

- [sand](https://github.com/wtdcode/sand-aflpp/tree/sand): Forked from 4.05c, this branch contains the reference implementation used in our paper evaluation. Please use this for any evaluation against SAND.
- [upstream](https://github.com/wtdcode/sand-aflpp/tree/upstream): Forked from AFLplusplus mainstream, this branch contains our efforts to port SAND to the latest AFLplusplus.

Track the upstream progress [here](https://github.com/AFLplusplus/AFLplusplus/pull/2288).

## Basic Usage

To use SAND, two binaries need to be built like cmplog:

- The native binary without any sanitizer instrumented. SAND will run it during every loop and collect coverage. 
- The sanitizer instrumented binary but _without AFL instrumentation_. SAND use this binary to check if an interesting input triggers sanitizers. Note, this binary must have fork servers enabled so `afl-clang-fast` is still needed for compilation. We will explain how to build this below.

### Build

Docker is highly recommened to reproduce the build. Simply do:

```
docker build -t sand .
```

If docker is not available, follow [The original AFL++ README](./README.AFLpp.md) to build SAND.

### Simple Example

The following steps assume you have built the docker image and started a container. If not, do it with:

```
docker run --rm -it sand
```

Take `test_instr.c` as an example, firstly build the native binary:

```
afl-clang-fast test-instr.c -o ./native
```

Then build the sanitizer instrumented binary but without AFL instrumentation:

```
AFL_SAN_NO_INST=1 AFL_USE_ASAN=1 afl-clang-fast test-instr.c -o ./san
```

Run SAND:

```
mkdir /tmp/test
echo "a" > /tmp/test/a
# Note the "-a ./san" parameter.  
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i /tmp/test -o /tmp/out -a ./san -- ./native -f @@
```

That's it! We also have detailed usage and caveats [here](./docs/SAND.md).

## Evaluation Reproduction

Building the evaluation images might take ~10-30 hours depending on your CPU and memory configuration.

Some building process might has a dependency on the host kernel version and our evaluation environment is:

```bash
> uname -a
Linux <redacted> 5.4.0-200-generic #220-Ubuntu SMP Fri Sep 27 13:19:16 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
> cat /etc/issue
<redacted> Ubuntu 20.04 (x86_64)
```

Please note, a recent kernel introduces changes that [might break ASAN instrumentation](https://github.com/google/sanitizers/issues/1614). This causes issues because the build process of some programs contains bootstraping, e.g. firstly building a helper program and further building other code by the helper program. ASAN instrumentation could crash these helper programs. A quick workaround is: `sudo sysctl vm.mmap_rnd_bits=28`

### Build UNIFUZZ Image

For easy experiment, we bundle all targets within the SAND image. Build it via:

```bash
docker build -t sand-unifuzz -f Dockerfile.UNIFUZZ .
```

### ASAN-- baseline

Firstly, build ASAN-- with:

```bash
git clone https://github.com/wtdcode/ASAN-- debloat12
cd debloat12 && docker build -t debloat12 -f Dockerfile_ASAN-- .
```

Likewise, build another all-in-one image for the base line:

```bash
docker build -t sand-debloat12 -f Dockerfile.ASAN-- .
```

### Merge Image

For ease of experiment, it is possible to merge the two images to a single image. We provide a script [merge.sh](./merge.sh) to do so:

```bash
./merge.sh sand-debloat12 sand-unifuzz
```

This will produce an image `sand-debloat12-sand-unifuzz-merged`.

### Start Experiments

Assume you have built the two images above, you could refer to [experiments](./experiments/) to reproduce our fuzzing experiments.

## Other AFLplusplus Schedule

We use the default schedule of AFLplusplus but other schedule should be agnostic to our approach. We also evaluated SAND on the `mmopt` schedule of AFLplusplus and confirmed the similar performance.

## Port SAND to other fuzzers

The approach of SAND is rather simple and easy to port to other fuzzers. We once applied SAND on [Fuzzilli](https://github.com/wtdcode/sand_fuzzilli). Due to time and pages limitation, we didn't spend too much time exploring this direction.

## Cite

```bib
@inproceedings{sand,
    author = {Ziqiao Kong, Shaohua Li, Heqing Huang, Zhendong Su},
    title = {SAND: Decoupling Sanitization from Fuzzing for LowOverhead},
    booktitle = {IEEE/ACM International Conference on Software Engineering (ICSE)},
    year = {2025},
}
```