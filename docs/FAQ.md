# Frequently asked questions about afl++

## Contents

  1. [How to improve the fuzzing speed?](#how-to-improve-the-fuzzing-speed)
  2. [What is an edge?](#what-is-an-edge)
  3. [Why is my stability below 100%?](#why-is-my-stability-below-100)
  4. [How can I improve the stability value](#how-can-i-improve-the-stability-value)

If you find an interesting or important question missing, submit it via
[https://github.com/AFLplusplus/AFLplusplus/issues](https://github.com/AFLplusplus/AFLplusplus/issues)

## How to improve the fuzzing speed

  1. use [llvm_mode](docs/llvm_mode/README.md): afl-clang-lto (llvm >= 11) or afl-clang-fast (llvm >= 9 recommended)
  2. Use [persistent mode](llvm_mode/README.persistent_mode.md) (x2-x20 speed increase)
  3. Use the [afl++ snapshot module](https://github.com/AFLplusplus/AFL-Snapshot-LKM) (x2 speed increase)
  4. If you do not use shmem persistent mode, use `AFL_TMPDIR` to point the input file on a tempfs location, see [docs/env_variables.md](docs/env_variables.md)
  5. Improve kernel performance: modify `/etc/default/grub`, set `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then `update-grub` and `reboot` (warning: makes the system more insecure)
  6. Running on an `ext2` filesystem with `noatime` mount option will be a bit faster than on any other journaling filesystem
  7. Use your cores! [README.md:3.b) Using multiple cores/threads](../README.md#b-using-multiple-coresthreads)

## What is an "edge"

A program contains `functions`, `functions` contain the compiled machine code.
The compiled machine code in a `function` can be in a single or many `basic blocks`.
A `basic block` is the largest possible number of subsequent machine code
instructions that runs independent, meaning it does not split up to different
locations nor is it jumped into it from a different location:
```
function() {
  A:
    some
    code
  B:
    if (x) goto C; else goto D;
  C:
    some code
    goto D
  D:
    some code
    goto B
  E:
    return
}
```
Every code block between two jump locations is a `basic block`.

An `edge` is then the unique relationship between two `basic blocks` (from the
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

## Why is my stability below 100

Stability is measured by how many percent of the edges in the target are
"stable". Sending the same input again and again should take the exact same
path through the target every time. If that is the case, the stability is 100%.

If however randomness happens, e.g. a thread reading from shared memory,
reaction to timing, etc. then in some of the re-executions with the same data
will result in the edge information being different accross runs.
Those edges that change are then flagged "unstable".

The more "unstable" edges, the more difficult for afl++ to identify valid new
paths.

A value above 90% is usually fine and a value above 80% is also still ok, and
even above 20% can still result in successful finds of bugs.
However, it is recommended that below 90% or 80% you should take measures to
improve the stability.

## How can I improve the stability value

Four steps are required to do this and requires quite some knowledge of
coding and/or disassembly and it is only effectively possible with
afl-clang-fast PCGUARD and afl-clang-lto LTO instrumentation!

  1. First step: Identify which edge ID numbers are unstable

     run the target with `export AFL_DEBUG=1` for a few minutes then terminate.
     The out/fuzzer_stats file will then show the edge IDs that were identified
     as unstable.

  2. Second step: Find the responsible function.

     a) For LTO instrumented binaries just disassemble or decompile the target
        and look which edge is writing to that edge ID. Ghidra is a good tool
        for this: [https://ghidra-sre.org/](https://ghidra-sre.org/)

     b) For PCGUARD instrumented binaries it is more difficult. Here you can
        either modify the __sanitizer_cov_trace_pc_guard function in
        llvm_mode/afl-llvm-rt.o.c to write a backtrace to a file if the ID in
        __afl_area_ptr[*guard] is one of the unstable edge IDs. Then recompile
        and reinstall llvm_mode and rebuild your target. Run the recompiled
	target with afl-fuzz for a while and then check the file that you
        wrote with the backtrace information.
        Alternatively you can use `gdb` to hook __sanitizer_cov_trace_pc_guard_init
        on start, check to which memory address the edge ID value is written
        and set a write breakpoint to that address (`watch 0x.....`).

  3. Third step: create a text file with the filenames

     Identify which source code files contain the functions that you need to
     remove from instrumentation.

     Simply follow this document on how to do this: [llvm_mode/README.instrument_file.md](llvm_mode/README.instrument_file.md)
     If PCGUARD is used, then you need to follow this guide: [http://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation](http://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation)

  4. Fourth step: recompile the target

     Recompile, fuzz it, be happy :)

