# Frequently asked questions about AFL++

## Contents

  * [What is the difference between AFL and AFL++?](#what-is-the-difference-between-afl-and-afl)
  * [I got a weird compile error from clang](#i-got-a-weird-compile-error-from-clang)
  * [How to improve the fuzzing speed?](#how-to-improve-the-fuzzing-speed)
  * [How do I fuzz a network service?](#how-do-i-fuzz-a-network-service)
  * [How do I fuzz a GUI program?](#how-do-i-fuzz-a-gui-program)
  * [What is an edge?](#what-is-an-edge)
  * [Why is my stability below 100%?](#why-is-my-stability-below-100)
  * [How can I improve the stability value?](#how-can-i-improve-the-stability-value)

If you find an interesting or important question missing, submit it via
[https://github.com/AFLplusplus/AFLplusplus/issues](https://github.com/AFLplusplus/AFLplusplus/issues)

## What is the difference between AFL and AFL++?

American Fuzzy Lop (AFL) was developed by Michał "lcamtuf" Zalewski starting in
2013/2014, and when he left Google end of 2017 he stopped developing it.

At the end of 2019 the Google fuzzing team took over maintenance of AFL, however
it is only accepting PRs from the community and is not developing enhancements
anymore.

In the second quarter of 2019, 1 1/2 year later when no further development of
AFL had happened and it became clear there would none be coming, AFL++
was born, where initially community patches were collected and applied
for bug fixes and enhancements. Then from various AFL spin-offs - mostly academic
research - features were integrated. This already resulted in a much advanced
AFL.

Until the end of 2019 the AFL++ team had grown to four active developers which
then implemented their own research and features, making it now by far the most
flexible and feature rich guided fuzzer available as open source.
And in independent fuzzing benchmarks it is one of the best fuzzers available,
e.g. [Fuzzbench Report](https://www.fuzzbench.com/reports/2020-08-03/index.html)

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

## How to improve the fuzzing speed?

  1. Use [llvm_mode](../instrumentation/README.llvm.md): afl-clang-lto (llvm >= 11) or afl-clang-fast (llvm >= 9 recommended)
  2. Use [persistent mode](../instrumentation/README.persistent_mode.md) (x2-x20 speed increase)
  3. Use the [AFL++ snapshot module](https://github.com/AFLplusplus/AFL-Snapshot-LKM) (x2 speed increase)
  4. If you do not use shmem persistent mode, use `AFL_TMPDIR` to put the input file directory on a tempfs location, see [docs/env_variables.md](docs/env_variables.md)
  5. Improve Linux kernel performance: modify `/etc/default/grub`, set `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then `update-grub` and `reboot` (warning: makes the system less secure)
  6. Running on an `ext2` filesystem with `noatime` mount option will be a bit faster than on any other journaling filesystem
  7. Use your cores! [README.md:3.b) Using multiple cores/threads](../README.md#b-using-multiple-coresthreads)

## How do I fuzz a network service?

The short answer is - you cannot, at least not "out of the box".

Using a network channel is inadequate for several reasons:
- it has a slow-down of x10-20 on the fuzzing speed
- it does not scale to fuzzing multiple instances easily,
- instead of one initial data packet often a back-and-forth interplay of packets is needed for stateful protocols (which is totally unsupported by most coverage aware fuzzers).

The established method to fuzz network services is to modify the source code
to read from a file or stdin (fd 0) (or even faster via shared memory, combine
this with persistent mode [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)
and you have a performance gain of x10 instead of a performance loss of over
x10 - that is a x100 difference!).

If modifying the source is not an option (e.g. because you only have a binary
and perform binary fuzzing) you can also use a shared library with AFL_PRELOAD
to emulate the network. This is also much faster than the real network would be.
See [utils/socket_fuzzing/](../utils/socket_fuzzing/).

There is an outdated AFL++ branch that implements networking if you are
desperate though: [https://github.com/AFLplusplus/AFLplusplus/tree/networking](https://github.com/AFLplusplus/AFLplusplus/tree/networking) - 
however a better option is AFLnet ([https://github.com/aflnet/aflnet](https://github.com/aflnet/aflnet))
which allows you to define network state with different type of data packets.

## How do I fuzz a GUI program?

If the GUI program can read the fuzz data from a file (via the command line,
a fixed location or via an environment variable) without needing any user
interaction then it would be suitable for fuzzing.

Otherwise it is not possible without modifying the source code - which is a
very good idea anyway as the GUI functionality is a huge CPU/time overhead
for the fuzzing.

So create a new `main()` that just reads the test case and calls the
functionality for processing the input that the GUI program is using.

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
reaction to timing, etc. then in some of the re-executions with the same data
the edge coverage result will be different accross runs.
Those edges that change are then flagged "unstable".

The more "unstable" edges, the more difficult for AFL++ to identify valid new
paths.

A value above 90% is usually fine and a value above 80% is also still ok, and
even a value above 20% can still result in successful finds of bugs.
However, it is recommended that for values below 90% or 80% you should take
countermeasures to improve stability.

## How can I improve the stability value?

For fuzzing a 100% stable target that covers all edges is the best case.
A 90% stable target that covers all edges is however better than a 100% stable
target that ignores 10% of the edges.

With instability you basically have a partial coverage loss on an edge, with
ignored functions you have a full loss on that edges.

There are functions that are unstable, but also provide value to coverage, eg
init functions that use fuzz data as input for example.
If however a function that has nothing to do with the input data is the
source of instability, e.g. checking jitter, or is a hash map function etc.
then it should not be instrumented.

To be able to exclude these functions (based on AFL++'s measured stability)
the following process will allow to identify functions with variable edges.

Four steps are required to do this and it also requires quite some knowledge
of coding and/or disassembly and is effectively possible only with
afl-clang-fast PCGUARD and afl-clang-lto LTO instrumentation.

  1. First step: Instrument to be able to find the responsible function(s).

     a) For LTO instrumented binaries this can be documented during compile
        time, just set `export AFL_LLVM_DOCUMENT_IDS=/path/to/a/file`.
        This file will have one assigned edge ID and the corresponding
        function per line.

     b) For PCGUARD instrumented binaries it is much more difficult. Here you
        can either modify the __sanitizer_cov_trace_pc_guard function in
        instrumentation/afl-llvm-rt.o.c to write a backtrace to a file if the ID in
        __afl_area_ptr[*guard] is one of the unstable edge IDs.
        (Example code is already there).
        Then recompile and reinstall llvm_mode and rebuild your target.
        Run the recompiled target with afl-fuzz for a while and then check the
        file that you wrote with the backtrace information.
        Alternatively you can use `gdb` to hook __sanitizer_cov_trace_pc_guard_init
        on start, check to which memory address the edge ID value is written
        and set a write breakpoint to that address (`watch 0x.....`).

     c) in all other instrumentation types this is not possible. So just
        recompile with the two mentioned above. This is just for
        identifying the functions that have unstable edges.

  2. Second step: Identify which edge ID numbers are unstable

     run the target with `export AFL_DEBUG=1` for a few minutes then terminate.
     The out/fuzzer_stats file will then show the edge IDs that were identified
     as unstable in the `var_bytes` entry. You can match these numbers
     directly to the data you created in the first step.
     Now you know which functions are responsible for the instability

  3. Third step: create a text file with the filenames/functions

     Identify which source code files contain the functions that you need to
     remove from instrumentation, or just specify the functions you want to
     skip for instrumentation. Note that optimization might inline functions!

     Simply follow this document on how to do this: [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)
     If PCGUARD is used, then you need to follow this guide (needs llvm 12+!):
     [http://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation](http://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation)

     Only exclude those functions from instrumentation that provide no value
     for coverage - that is if it does not process any fuzz data directly
     or indirectly (e.g. hash maps, thread management etc.).
     If however a function directly or indirectly handles fuzz data then you
     should not put the function in a deny instrumentation list and rather
     live with the instability it comes with.

  4. Fourth step: recompile the target

     Recompile, fuzz it, be happy :)

     This link explains this process for [Fuzzbench](https://github.com/google/fuzzbench/issues/677)
