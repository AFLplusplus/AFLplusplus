# Frequently asked questions and troubleshooting

If you find an interesting or important question missing, submit it via
[https://github.com/AFLplusplus/AFLplusplus/issues](https://github.com/AFLplusplus/AFLplusplus/issues).

## Contents

  * [What is the difference between AFL and AFL++?](#what-is-the-difference-between-afl-and-afl)
  * [I got a weird compile error from clang](#i-got-a-weird-compile-error-from-clang)
  * [How can I improve the fuzzing speed?](#how-can-i-improve-the-fuzzing-speed)
  * [How can I fuzz a network service?](#how-can-i-fuzz-a-network-service)
  * [How can I fuzz a GUI program?](#how-can-i-fuzz-a-gui-program)
  * [What is an edge?](#what-is-an-edge)
  * [Why is my stability below 100%?](#why-is-my-stability-below-100)
  * [How can I improve the stability value?](#how-can-i-improve-the-stability-value)

## What is the difference between AFL and AFL++?

AFL++ is a superior fork to Google's AFL - more speed, more and better mutations, more and better instrumentation, custom module support, etc.

For more information about the history of AFL++, see [docs/history_afl++.md](docs/history_afl++.md).

## I got a weird compile error from clang

If you see this kind of error when trying to instrument a target with afl-cc/
afl-clang-fast/afl-clang-lto:
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

Solution: `git pull ; make clean install` of AFL++

## How can I improve the fuzzing speed?

See [docs/best_practices.md#improving-speed](docs/best_practices.md#improving-speed).

## How can I improve the stability value?

See [docs/best_practices.md#improving-stability](docs/best_practices.md#improving-stability).

## How can I fuzz a network service?

The short answer is - you cannot, at least not "out of the box".

For more information, see [docs/best_practices.md#fuzzing-network-service](docs/best_practices.md#fuzzing-network-service).

## How can I fuzz a GUI program?

See [docs/best_practices.md#fuzzing-gui-program](docs/best_practices.md#fuzzing-gui-program).

## What is an "edge"?

A program contains `functions`, `functions` contain the compiled machine code.
The compiled machine code in a `function` can be in a single or many `basic blocks`.
A `basic block` is the largest possible number of subsequent machine code
instructions that has exactly one entrypoint (which can be be entered by multiple other basic blocks)
and runs linearly without branching or jumping to other addresses (except at the end).
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

An `edge` is then the unique relationship between two directly connected `basic blocks` (from the
code example above):
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

## Why is my stability below 100%?

Stability is measured by how many percent of the edges in the target are
"stable". Sending the same input again and again should take the exact same
path through the target every time. If that is the case, the stability is 100%.

If however randomness happens, e.g. a thread reading other external data,
reaction to timing, etc., then in some of the re-executions with the same data
the edge coverage result will be different accross runs.
Those edges that change are then flagged "unstable".

The more "unstable" edges, the more difficult for AFL++ to identify valid new
paths.

A value above 90% is usually fine and a value above 80% is also still ok, and
even a value above 20% can still result in successful finds of bugs.
However, it is recommended that for values below 90% or 80% you should take
countermeasures to improve stability.
