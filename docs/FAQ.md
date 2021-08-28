# Frequently asked questions (FAQ)

If you find an interesting or important question missing, submit it via
[https://github.com/AFLplusplus/AFLplusplus/discussions](https://github.com/AFLplusplus/AFLplusplus/discussions).

### General

  * [What is the difference between AFL and AFL++?](#what-is-the-difference-between-afl-and-afl)
  * [Where can I find tutorials?](#where-can-i-find-tutorials)
  * [What is an "edge"?](#what-is-an-edge)

### Targets

  * [How can I fuzz a binary-only target?](#how-can-i-fuzz-a-binary-only-target)
  * [How can I fuzz a network service?](#how-can-i-fuzz-a-network-service)
  * [How can I fuzz a GUI program?](#how-can-i-fuzz-a-gui-program)

### Performance

  * [How can I improve the fuzzing speed?](#how-can-i-improve-the-fuzzing-speed)
  * [Why is my stability below 100%?](#why-is-my-stability-below-100)
  * [How can I improve the stability value?](#how-can-i-improve-the-stability-value)

### Troubleshooting

  * [I got a weird compile error from clang](#i-got-a-weird-compile-error-from-clang)

## Questions & answers

### What is the difference between AFL and AFL++?

AFL++ is a superior fork to Google's AFL - more speed, more and better mutations, more and better instrumentation, custom module support, etc.

American Fuzzy Lop (AFL) was developed by Michał "lcamtuf" Zalewski starting in 2013/2014, and when he left Google end of 2017 he stopped developing it.

At the end of 2019, the Google fuzzing team took over maintenance of AFL, however it is only accepting PRs from the community and is not developing enhancements anymore.

In the second quarter of 2019, 1 1/2 years later, when no further development of AFL had happened and it became clear there would none be coming, AFL++ was born, where initially community patches were collected and applied for bug fixes and enhancements.
Then from various AFL spin-offs - mostly academic research - features were integrated.
This already resulted in a much advanced AFL.

Until the end of 2019, the AFL++ team had grown to four active developers which then implemented their own research and features, making it now by far the most flexible and feature rich guided fuzzer available as open source.
And in independent fuzzing benchmarks it is one of the best fuzzers available, e.g. [Fuzzbench Report](https://www.fuzzbench.com/reports/2020-08-03/index.html).

### Where can I find tutorials?

We compiled a list of tutorials and exercises, see [tutorials.md](tutorials.md).

### What is an "edge"?

A program contains `functions`, `functions` contain the compiled machine code.
The compiled machine code in a `function` can be in a single or many `basic blocks`.
A `basic block` is the largest possible number of subsequent machine code instructions that has exactly one entrypoint (which can be be entered by multiple other basic blocks) and runs linearly without branching or jumping to other addresses (except at the end).

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

An `edge` is then the unique relationship between two directly connected `basic blocks` (from the code example above):

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

Every line between two blocks is an `edge`.
Note that a few basic block loop to itself, this too would be an edge.

### How can I fuzz a binary-only target?

AFL++ is a great fuzzer if you have the source code available.

However, if there is only the binary program and no source code available, then the standard non-instrumented mode is not effective.

To learn how these binaries can be fuzzed, read [binaryonly_fuzzing.md](binaryonly_fuzzing.md).

### How can I fuzz a network service?

The short answer is - you cannot, at least not "out of the box".

For more information on fuzzing network services, see [best_practices.md#fuzzing-a-network-service](best_practices.md#fuzzing-a-network-service).

### How can I fuzz a GUI program?

Not all GUI programs are suitable for fuzzing. If the GUI program can read the fuzz data from a file without needing any user interaction, then it would be suitable for fuzzing.

For more information on fuzzing GUI programs, see [best_practices.md#fuzzing-a-gui-program](best_practices.md#fuzzing-a-gui-program).

### How can I improve the fuzzing speed?

There are a few things you can do to improve the fuzzing speed, see [best_practices.md#improving-speed](best_practices.md#improving-speed).

### Why is my stability below 100%?

Stability is measured by how many percent of the edges in the target are "stable".
Sending the same input again and again should take the exact same path through the target every time.
If that is the case, the stability is 100%.

If however randomness happens, e.g. a thread reading other external data, reaction to timing, etc., then in some of the re-executions with the same data the edge coverage result will be different accross runs.
Those edges that change are then flagged "unstable".

The more "unstable" edges, the more difficult for AFL++ to identify valid new paths.

A value above 90% is usually fine and a value above 80% is also still ok, and even a value above 20% can still result in successful finds of bugs.
However, it is recommended that for values below 90% or 80% you should take countermeasures to improve stability.

### How can I improve the stability value?

This depends on the target and the instrumentation.

For more information on stability and how to improve the stability value, see [best_practices.md#improving-stability](best_practices.md#improving-stability).

### I got a weird compile error from clang

If you see this kind of error when trying to instrument a target with afl-cc/afl-clang-fast/afl-clang-lto:

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

Then this means that your OS updated the clang installation from an upgrade package and because of that the AFL++ llvm plugins do not match anymore.

Solution: `git pull ; make clean install` of AFL++.