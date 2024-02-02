# Best practices

## Contents

### Targets

* [Fuzzing a target with source code available](#fuzzing-a-target-with-source-code-available)
* [Fuzzing a target with dlopen() instrumented libraries](#fuzzing-a-target-with-dlopen-instrumented-libraries)
* [Fuzzing a binary-only target](#fuzzing-a-binary-only-target)
* [Fuzzing a GUI program](#fuzzing-a-gui-program)
* [Fuzzing a network service](#fuzzing-a-network-service)

### Improvements

* [Improving speed](#improving-speed)
* [Improving stability](#improving-stability)

## Targets

### Fuzzing a target with source code available

To learn how to fuzz a target if source code is available, see
[fuzzing_in_depth.md](fuzzing_in_depth.md).

### Fuzzing a target with dlopen instrumented libraries

If a source code based fuzzing target loads instrumented libraries with
dlopen() after the forkserver has been activated and non-colliding coverage
instrumentation is used (PCGUARD (which is the default), or LTO), then this
an issue, because this would enlarge the coverage map, but afl-fuzz doesn't
know about it.

The solution is to use `AFL_PRELOAD` for all dlopen()'ed libraries to
ensure that all coverage targets are present on startup in the target,
even if accessed only later with dlopen().

For PCGUARD instrumentation `abort()` is called if this is detected, for LTO
there will either be no coverage for the instrumented dlopen()'ed libraries or
you will see lots of crashes in the UI.

Note that this is not an issue if you use the inferiour `afl-gcc-fast`,
`afl-gcc` or`AFL_LLVM_INSTRUMENT=CLASSIC/NGRAM/CTX afl-clang-fast`
instrumentation.

### Fuzzing a binary-only target

For a comprehensive guide, see
[fuzzing_binary-only_targets.md](fuzzing_binary-only_targets.md).

### Fuzzing a GUI program

If the GUI program can read the fuzz data from a file (via the command line, a
fixed location or via an environment variable) without needing any user
interaction, then it would be suitable for fuzzing.

Otherwise, it is not possible without modifying the source code - which is a
very good idea anyway as the GUI functionality is a huge CPU/time overhead for
the fuzzing.

So create a new `main()` that just reads the test case and calls the
functionality for processing the input that the GUI program is using.

### Fuzzing a network service
对网络服务进行模糊测试

Fuzzing a network service does not work "out of the box".
对网络服务进行模糊测试并不能“开箱即用”。

Using a network channel is inadequate for several reasons:
使用网络通道有几个不足之处：
- it has a slow-down of x10-20 on the fuzzing speed
- 它会使模糊测试速度减慢10-20倍
- it does not scale to fuzzing multiple instances easily,
- 它不容易扩展到多实例模糊测试，
- instead of one initial data packet often a back-and-forth interplay of packets
  is needed for stateful protocols (which is totally unsupported by most
  coverage aware fuzzers).
- 对于有状态的协议，通常需要多个数据包的来回交互，而不是一个初始数据包（这是大多数覆盖率感知的模糊测试器完全不支持的）。

The established method to fuzz network services is to modify the source code to
read from a file or stdin (fd 0) (or even faster via shared memory, combine this
with persistent mode
[instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)
and you have a performance gain of x10 instead of a performance loss of over x10
对网络服务进行模糊测试的既定方法是修改源代码，以从文件或标准输入（文件描述符0）读取（或者通过共享内存更快，将其与持久模式结合使用，你将获得10倍的性能提升，而不是超过10倍的性能损失 
- that is a x100 difference!).
- 这是100倍的差异！）。

If modifying the source is not an option (e.g., because you only have a binary
and perform binary fuzzing) you can also use a shared library with AFL_PRELOAD
to emulate the network. This is also much faster than the real network would be.
See [utils/socket_fuzzing/](../utils/socket_fuzzing/).
如果修改源代码不是一个选项（例如，因为你只有一个二进制文件并进行二进制模糊测试），你也可以使用 AFL_PRELOAD 的共享库来模拟网络。这也比真实的网络要快得多。参见 [utils/socket_fuzzing/](../utils/socket_fuzzing/)。

There is an outdated AFL++ branch that implements networking if you are
desperate though:
[https://github.com/AFLplusplus/AFLplusplus/tree/networking](https://github.com/AFLplusplus/AFLplusplus/tree/networking)
如果你非常需要的话，有一个过时的 AFL++ 分支实现了网络功能：[https://github.com/AFLplusplus/AFLplusplus/tree/networking](https://github.com/AFLplusplus/AFLplusplus/tree/networking) 
- however, a better option is AFLnet
([https://github.com/aflnet/aflnet](https://github.com/aflnet/aflnet)) which
allows you to define network state with different type of data packets.
- 然而，一个更好的选择是 AFLnet ([https://github.com/aflnet/aflnet](https://github.com/aflnet/aflnet))，它允许你用不同类型的数据包定义网络状态。

## Improvements

### Improving speed
提高速度

1. Use [llvm_mode](../instrumentation/README.llvm.md): afl-clang-lto (llvm >=
   11) or afl-clang-fast (llvm >= 9 recommended).
   使用 [llvm_mode](../instrumentation/README.llvm.md): afl-clang-lto (llvm >= 11) 或 afl-clang-fast (推荐 llvm >= 9)。
2. Use [persistent mode](../instrumentation/README.persistent_mode.md) (x2-x20
   speed increase).
   使用 [persistent mode](../instrumentation/README.persistent_mode.md) (可以提高2-20倍的速度)。
3. Instrument just what you are interested in, see
   [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).
   只对你感兴趣的部分进行插桩，参见 [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)。
4. If you do not use shmem persistent mode, use `AFL_TMPDIR` to put the input
   file directory on a tempfs location, see
   [env_variables.md](env_variables.md).
   如果你没有使用 shmem 持久模式，使用 `AFL_TMPDIR` 将输入文件目录放在 tempfs 位置，参见 [env_variables.md](env_variables.md)。
5. Improve Linux kernel performance: modify `/etc/default/grub`, set
   `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off
   mitigations=off no_stf_barrier noibpb noibrs nopcid nopti
   nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off
   spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then
   `update-grub` and `reboot` (warning: makes the system less secure).
   提高 Linux 内核性能：修改 `/etc/default/grub`，设置 `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`；然后 `update-grub` 并 `reboot` (警告：这会降低系统的安全性)。
6. Running on an `ext2` filesystem with `noatime` mount option will be a bit
   faster than on any other journaling filesystem.
   在带有 `noatime` 挂载选项的 `ext2` 文件系统上运行会比在任何其他日志文件系统上快一点。
7. Use your cores
   ([fuzzing_in_depth.md:3c) Using multiple cores](fuzzing_in_depth.md#c-using-multiple-cores))!
   使用多核心 ([fuzzing_in_depth.md:3c) Using multiple cores](fuzzing_in_depth.md#c-using-multiple-cores))!


### Improving stability
提升稳定性

For fuzzing, a 100% stable target that covers all edges is the best case. A 90%
stable target that covers all edges is, however, better than a 100% stable
target that ignores 10% of the edges.
对于模糊测试，覆盖所有边缘的 100% 稳定目标是最好的情况。但是，覆盖所有边缘的 90% 稳定目标比忽略 10% 边缘的 100% 稳定目标要好。

With instability, you basically have a partial coverage loss on an edge, with
ignored functions you have a full loss on that edges.

There are functions that are unstable, but also provide value to coverage, e.g.,
init functions that use fuzz data as input. If, however, a function that has
nothing to do with the input data is the source of instability, e.g., checking
jitter, or is a hash map function etc., then it should not be instrumented.

To be able to exclude these functions (based on AFL++'s measured stability), the
following process will allow to identify functions with variable edges.

Note that this is only useful for non-persistent targets!
If a persistent target is unstable whereas when run non-persistent is fine,
then this means that the target is keeping internal state, which is bad for
fuzzing. Fuzz such targets **without** persistent mode.

Four steps are required to do this and it also requires quite some knowledge of
coding and/or disassembly and is effectively possible only with `afl-clang-fast`
`PCGUARD` and `afl-clang-lto` `LTO` instrumentation.

  1. Instrument to be able to find the responsible function(s):

     a) For LTO instrumented binaries, this can be documented during compile
        time, just set `export AFL_LLVM_DOCUMENT_IDS=/path/to/a/file`. This file
        will have one assigned edge ID and the corresponding function per line.

     b) For PCGUARD instrumented binaries, it is much more difficult. Here you
        can either modify the `__sanitizer_cov_trace_pc_guard` function in
        `instrumentation/afl-llvm-rt.o.c` to write a backtrace to a file if the
        ID in `__afl_area_ptr[*guard]` is one of the unstable edge IDs. (Example
        code is already there). Then recompile and reinstall `llvm_mode` and
        rebuild your target. Run the recompiled target with `afl-fuzz` for a
        while and then check the file that you wrote with the backtrace
        information. Alternatively, you can use `gdb` to hook
        `__sanitizer_cov_trace_pc_guard_init` on start, check to which memory
        address the edge ID value is written, and set a write breakpoint to that
        address (`watch 0x.....`).

     c) In other instrumentation types, this is not possible. So just recompile
        with the two mentioned above. This is just for identifying the functions
        that have unstable edges.

  2. Identify which edge ID numbers are unstable.

     Run the target with `export AFL_DEBUG=1` for a few minutes then terminate.
     The out/fuzzer_stats file will then show the edge IDs that were identified
     as unstable in the `var_bytes` entry. You can match these numbers directly
     to the data you created in the first step. Now you know which functions are
     responsible for the instability

  3. Create a text file with the filenames/functions

     Identify which source code files contain the functions that you need to
     remove from instrumentation, or just specify the functions you want to skip
     for instrumentation. Note that optimization might inline functions!

     Follow this document on how to do this:
     [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).

     If `PCGUARD` is used, then you need to follow this guide (needs llvm 12+!):
     [https://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation](https://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation)

     Only exclude those functions from instrumentation that provide no value for
     coverage - that is if it does not process any fuzz data directly or
     indirectly (e.g., hash maps, thread management etc.). If, however, a
     function directly or indirectly handles fuzz data, then you should not put
     the function in a deny instrumentation list and rather live with the
     instability it comes with.

  4. Recompile the target

     Recompile, fuzz it, be happy :)

     This link explains this process for
     [Fuzzbench](https://github.com/google/fuzzbench/issues/677).
