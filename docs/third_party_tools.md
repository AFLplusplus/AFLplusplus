# Tools that help fuzzing with AFL++

## Speeding up fuzzing

* [libfiowrapper](https://github.com/marekzmyslowski/libfiowrapper) - if the
  function you want to fuzz requires loading a file, this allows using the
  shared memory test case feature :-) - recommended.

## Minimization of test cases

* [afl-pytmin](https://github.com/ilsani/afl-pytmin) - a wrapper for afl-tmin
  that tries to speed up the process of minimization of a single test case by
  using many CPU cores.
* [afl-ddmin-mod](https://github.com/MarkusTeufelberger/afl-ddmin-mod) - a
  variation of afl-tmin based on the ddmin algorithm.
* [halfempty](https://github.com/googleprojectzero/halfempty) -  is a fast
  utility for minimizing test cases by Tavis Ormandy based on parallelization.

## Distributed execution

* [disfuzz-afl](https://github.com/MartijnB/disfuzz-afl) - distributed fuzzing
  for AFL.
* [AFLDFF](https://github.com/quantumvm/AFLDFF) - AFL distributed fuzzing
  framework.
* [afl-launch](https://github.com/bnagy/afl-launch) - a tool for the execution
  of many AFL instances.
* [afl-mothership](https://github.com/afl-mothership/afl-mothership) -
  management and execution of many synchronized AFL fuzzers on AWS cloud.
* [afl-in-the-cloud](https://github.com/abhisek/afl-in-the-cloud) - another
  script for running AFL in AWS.

## Deployment, management, monitoring, reporting

* [afl-utils](https://gitlab.com/rc0r/afl-utils) - a set of utilities for
  automatic processing/analysis of crashes and reducing the number of test
  cases.
* [afl-other-arch](https://github.com/shellphish/afl-other-arch) - is a set of
  patches and scripts for easily adding support for various non-x86
  architectures for AFL.
* [afl-trivia](https://github.com/bnagy/afl-trivia) - a few small scripts to
  simplify the management of AFL.
* [afl-monitor](https://github.com/reflare/afl-monitor) - a script for
  monitoring AFL.
* [afl-manager](https://github.com/zx1340/afl-manager) - a web server on Python
  for managing multi-afl.
* [afl-remote](https://github.com/block8437/afl-remote) - a web server for the
  remote management of AFL instances.
* [afl-extras](https://github.com/fekir/afl-extras) - shell scripts to
  parallelize afl-tmin, startup, and data collection.

## Crash processing

* [AFLTriage](https://github.com/quic/AFLTriage) -
  triage crashing input files using gdb.
* [afl-crash-analyzer](https://github.com/floyd-fuh/afl-crash-analyzer) -
  another crash analyzer for AFL.
* [fuzzer-utils](https://github.com/ThePatrickStar/fuzzer-utils) - a set of
  scripts for the analysis of results.
* [atriage](https://github.com/Ayrx/atriage) - a simple triage tool.
* [afl-kit](https://github.com/kcwu/afl-kit) - afl-cmin on Python.
* [AFLize](https://github.com/d33tah/aflize) - a tool that automatically
  generates builds of debian packages suitable for AFL.
* [afl-fid](https://github.com/FoRTE-Research/afl-fid) - a set of tools for
  working with input data.
