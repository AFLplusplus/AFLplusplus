# Frequently asked questions (FAQ)

If you find an interesting or important question missing, submit it via
[https://github.com/AFLplusplus/AFLplusplus/discussions](https://github.com/AFLplusplus/AFLplusplus/discussions).

## General

<details>
  <summary id="what-is-the-difference-between-afl-and-aflplusplus">What is the difference between AFL and AFL++?</summary><p>

  AFL++ is a superior fork to Google's AFL - more speed, more and better
  mutations, more and better instrumentation, custom module support, etc.

  American Fuzzy Lop (AFL) was developed by Michał "lcamtuf" Zalewski starting
  in 2013/2014, and when he left Google end of 2017 he stopped developing it.

  At the end of 2019, the Google fuzzing team took over maintenance of AFL,
  however, it is only accepting PRs from the community and is not developing
  enhancements anymore.

  In the second quarter of 2019, 1 1/2 years later, when no further development
  of AFL had happened and it became clear there would none be coming, AFL++ was
  born, where initially community patches were collected and applied for bug
  fixes and enhancements. Then from various AFL spin-offs - mostly academic
  research - features were integrated. This already resulted in a much advanced
  AFL.

  Until the end of 2019, the AFL++ team had grown to four active developers
  which then implemented their own research and features, making it now by far
  the most flexible and feature rich guided fuzzer available as open source. And
  in independent fuzzing benchmarks it is one of the best fuzzers available,
  e.g., [Fuzzbench
  Report](https://www.fuzzbench.com/reports/2020-08-03/index.html).
</p></details>

<details>
  <summary id="is-afl-a-whitebox-graybox-or-blackbox-fuzzer">Is AFL++ a whitebox, graybox, or blackbox fuzzer?</summary><p>

  The definition of the terms whitebox, graybox, and blackbox fuzzing varies
  from one source to another. For example, "graybox fuzzing" could mean
  binary-only or source code fuzzing, or something completely different.
  Therefore, we try to avoid them.

  [The Fuzzing Book](https://www.fuzzingbook.org/html/GreyboxFuzzer.html#AFL:-An-Effective-Greybox-Fuzzer)
  describes the original AFL to be a graybox fuzzer. In that sense, AFL++ is
  also a graybox fuzzer.
</p></details>

<details>
  <summary id="where-can-i-find-tutorials">Where can I find tutorials?</summary><p>

  We compiled a list of tutorials and exercises, see
  [tutorials.md](tutorials.md).
</p></details>

<details>
  <summary id="what-is-an-edge">What is an "edge"?</summary><p>

  A program contains `functions`, `functions` contain the compiled machine code.
  The compiled machine code in a `function` can be in a single or many `basic
  blocks`. A `basic block` is the **largest possible number of subsequent machine
  code instructions** that has **exactly one entry point** (which can be be entered by
  multiple other basic blocks) and runs linearly **without branching or jumping to
  other addresses** (except at the end).

  ```
  function() {
    A:
      some
      code
    B:
      if (x) goto C; else goto D;
    C:
      some code
      goto E
    D:
      some code
      goto B
    E:
      return
  }
  ```

  Every code block between two jump locations is a `basic block`.

  An `edge` is then the unique relationship between two directly connected
  `basic blocks` (from the code example above):

  ```
                Block A
                  |
                  v
                Block B  <------+
              /        \       |
              v          v      |
          Block C    Block D --+
              \
                v
                Block E
  ```

  Every line between two blocks is an `edge`. Note that a few basic block loop
  to itself, this too would be an edge.
</p></details>

## Targets

<details>
  <summary id="how-can-i-fuzz-a-binary-only-target">How can I fuzz a binary-only target?</summary><p>

  AFL++ is a great fuzzer if you have the source code available.

  However, if there is only the binary program and no source code available,
  then the standard non-instrumented mode is not effective.

  To learn how these binaries can be fuzzed, read
  [fuzzing_binary-only_targets.md](fuzzing_binary-only_targets.md).
</p></details>

<details>
  <summary id="how-can-i-fuzz-a-network-service">How can I fuzz a network service?</summary><p>

  The short answer is - you cannot, at least not "out of the box".

  For more information on fuzzing network services, see
  [best_practices.md#fuzzing-a-network-service](best_practices.md#fuzzing-a-network-service).
</p></details>

<details>
  <summary id="how-can-i-fuzz-a-gui-program">How can I fuzz a GUI program?</summary><p>

  Not all GUI programs are suitable for fuzzing. If the GUI program can read the
  fuzz data from a file without needing any user interaction, then it would be
  suitable for fuzzing.

  For more information on fuzzing GUI programs, see
  [best_practices.md#fuzzing-a-gui-program](best_practices.md#fuzzing-a-gui-program).
</p></details>

## Performance

<details>
  <summary id="what-makes-a-good-performance">What makes a good performance?</summary><p>

  Good performance generally means "making the fuzzing results better". This can
  be influenced by various factors, for example, speed (finding lots of paths
  quickly) or thoroughness (working with decreased speed, but finding better
  mutations).
</p></details>

<details>
  <summary id="how-can-i-improve-the-fuzzing-speed">How can I improve the fuzzing speed?</summary><p>

  There are a few things you can do to improve the fuzzing speed, see
  [best_practices.md#improving-speed](best_practices.md#improving-speed).
</p></details>

<details>
  <summary id="why-is-my-stability-below-100percent">Why is my stability below 100%?</summary><p>

  Stability is measured by how many percent of the edges in the target are
  "stable". Sending the same input again and again should take the exact same
  path through the target every time. If that is the case, the stability is
  100%.

  If, however, randomness happens, e.g., a thread reading other external data,
  reaction to timing, etc., then in some of the re-executions with the same data
  the edge coverage result will be different across runs. Those edges that
  change are then flagged "unstable".

  The more "unstable" edges there are, the harder it is for AFL++ to identify
  valid new paths.

  A value above 90% is usually fine and a value above 80% is also still ok, and
  even a value above 20% can still result in successful finds of bugs. However,
  it is recommended that for values below 90% or 80% you should take
  countermeasures to improve stability.

  For more information on stability and how to improve the stability value, see
  [best_practices.md#improving-stability](best_practices.md#improving-stability).
</p></details>

<details>
  <summary id="what-are-power-schedules">What are power schedules?</summary><p>

  Not every item in our queue/corpus is the same, some are more interesting,
  others provide little value.
  A power schedule measures how "interesting" a value is, and depending on
  the calculated value spends more or less time mutating it.

  AFL++ comes with several power schedules, initially ported from
  [AFLFast](https://github.com/mboehme/aflfast), however, modified to be more
  effective and several more modes added.

  The most effective modes are `-p fast` (default) and `-p explore`.

  If you fuzz with several parallel afl-fuzz instances, then it is beneficial
  to assign a different schedule to each instance, however the majority should
  be `fast` and `explore`.

  It does not make sense to explain the details of the calculation and
  reasoning behind all of the schedules. If you are interested, read the source
  code and the AFLFast paper.
</p></details>

## Troubleshooting

<details>
  <summary id="fatal-forkserver-is-already-up-but-an-instrumented-dlopen-library-loaded-afterwards">FATAL: forkserver is already up but an instrumented dlopen library loaded afterwards</summary><p>

  It can happen that you see this error on startup when fuzzing a target:

  ```
  [-] FATAL: forkserver is already up, but an instrumented dlopen() library
             loaded afterwards. You must AFL_PRELOAD such libraries to be able
             to fuzz them or LD_PRELOAD to run outside of afl-fuzz.
             To ignore this set AFL_IGNORE_PROBLEMS=1.
  ```

  As the error describes, a dlopen() call is happening in the target that is
  loading an instrumented library after the forkserver is already in place. This
  is a problem for afl-fuzz because when the forkserver is started, we must know
  the map size already and it can't be changed later.

  The best solution is to simply set `AFL_PRELOAD=foo.so` to the libraries that
  are dlopen'ed (e.g., use `strace` to see which), or to set a manual forkserver
  after the final dlopen().

  If this is not a viable option, you can set `AFL_IGNORE_PROBLEMS=1` but then
  the existing map will be used also for the newly loaded libraries, which
  allows it to work, however, the efficiency of the fuzzing will be partially
  degraded.
</p></details>

<details>
  <summary id="i-got-a-weird-compile-error-from-clang">I got a weird compile error from clang.</summary><p>

  If you see this kind of error when trying to instrument a target with
  afl-cc/afl-clang-fast/afl-clang-lto:

  ```
  /prg/tmp/llvm-project/build/bin/clang-13: symbol lookup error: /usr/local/bin/../lib/afl//cmplog-instructions-pass.so: undefined symbol: _ZNK4llvm8TypeSizecvmEv
  clang-13: error: unable to execute command: No such file or directory
  clang-13: error: clang frontend command failed due to signal (use -v to see invocation)
  clang version 13.0.0 (https://github.com/llvm/llvm-project 1d7cf550721c51030144f3cd295c5789d51c4aad)
  Target: x86_64-unknown-linux-gnu
  Thread model: posix
  InstalledDir: /prg/tmp/llvm-project/build/bin
  clang-13: note: diagnostic msg:
  ********************
  ```

  Then this means that your OS updated the clang installation from an upgrade
  package and because of that the AFL++ llvm plugins do not match anymore.

  Solution: `git pull ; make clean install` of AFL++.
</p></details>
