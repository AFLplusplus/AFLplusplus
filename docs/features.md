# Important features of AFL++

AFL++ supports llvm from 3.8 up to version 12, very fast binary fuzzing with
QEMU 5.1 with laf-intel and Redqueen, FRIDA mode, unicorn mode, gcc plugin, full
*BSD, Mac OS, Solaris and Android support and much, much, much more.

## Features and instrumentation

| Feature/Instrumentation       | afl-gcc  | llvm      | gcc_plugin | FRIDA mode(9)  | QEMU mode(10)    | unicorn_mode(10) | nyx_mode(12) | coresight_mode(11) |
| ------------------------------|:--------:|:---------:|:----------:|:--------------:|:----------------:|:----------------:|:------------:|:------------------:|
| Threadsafe counters [A]       |          |    x(3)   |            |                |                  |                  |       x      |                    |
| NeverZero           [B]       | x86[_64] |    x(1)   |      x     |        x       |         x        |         x        |              |                    |
| Persistent Mode     [C]       |          |     x     |      x     | x86[_64]/arm64 | x86[_64]/arm[64] |         x        |              |                    |
| LAF-Intel / CompCov [D]       |          |     x     |            |                | x86[_64]/arm[64] | x86[_64]/arm[64] |   x86[_64]   |                    |
| CmpLog              [E]       |          |     x     |      x     | x86[_64]/arm64 | x86[_64]/arm[64] |                  |              |                    |
| Selective Instrumentation [F] |          |     x     |      x     |        x       |         x        |                  |              |                    |
| Non-Colliding Coverage    [G] |          |    x(4)   |            |                |       (x)(5)     |                  |              |                    |
| Ngram prev_loc Coverage   [H] |          |    x(6)   |            |                |                  |                  |              |                    |
| Context Coverage    [I]       |          |    x(6)   |            |                |                  |                  |              |                    |
| Auto Dictionary     [J]       |          |    x(7)   |            |                |                  |                  |              |                    |
| Snapshot Support    [K]       |          |   (x)(8)  |   (x)(8)   |                |       (x)(5)     |                  |       x      |                    |
| Shared Memory Test cases  [L] |          |     x     |      x     | x86[_64]/arm64 |         x        |         x        |       x      |                    |

## More information about features

A. Default is not thread-safe coverage counter updates for better performance,
   see [instrumentation/README.llvm.md](../instrumentation/README.llvm.md)

B. On wrapping coverage counters (255 + 1), skip the 0 value and jump to 1
   instead. This has shown to give better coverage data and is the default; see
   [instrumentation/README.llvm.md](../instrumentation/README.llvm.md).

C. Instead of forking, reiterate the fuzz target function in a loop (like
   `LLVMFuzzerTestOneInput`. Great speed increase but only works with target
   functions that do not keep state, leak memory, or exit; see
   [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)

D. Split any non-8-bit comparison to 8-bit comparison; see
   [instrumentation/README.laf-intel.md](../instrumentation/README.laf-intel.md)

E. CmpLog is our enhanced
   [Redqueen](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/)
   implementation, see
   [instrumentation/README.cmplog.md](../instrumentation/README.cmplog.md)

F. Similar and compatible to clang 13+ sancov sanitize-coverage-allow/deny but
   for all llvm versions and all our compile modes, only instrument what should
   be instrumented, for more speed, directed fuzzing and less instability; see
   [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)

G. Vanilla AFL uses coverage where edges could collide to the same coverage
   bytes the larger the target is. Our default instrumentation in LTO and
   afl-clang-fast (PCGUARD) uses non-colliding coverage that also makes it
   faster. Vanilla AFL style is available with `AFL_LLVM_INSTRUMENT=AFL`; see
   [instrumentation/README.llvm.md](../instrumentation/README.llvm.md).

H.+I. Alternative coverage based on previous edges (NGRAM) or depending on the
   caller (CTX), based on
   [https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf](https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf);
   see [instrumentation/README.llvm.md](../instrumentation/README.llvm.md).

J. An LTO feature that creates a fuzzing dictionary based on comparisons found
   during compilation/instrumentation. Automatic feature :) See
   [instrumentation/README.lto.md](../instrumentation/README.lto.md)

K. The snapshot feature requires a kernel module that was a lot of work to get
   right and maintained so it is no longer supported. We have
   [nyx_mode](../nyx_mode/README.md) instead.

L. Faster fuzzing and less kernel syscall overhead by in-memory fuzz testcase
   delivery, see
   [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)

## More information about instrumentation

1. Default for LLVM >= 9.0, environment variable for older version due an
   efficiency bug in previous llvm versions
2. GCC creates non-performant code, hence it is disabled in gcc_plugin
3. With `AFL_LLVM_THREADSAFE_INST`, disables NeverZero
4. With pcguard mode and LTO mode for LLVM 11 and newer
5. Upcoming, development in the branch
6. Not compatible with LTO instrumentation and needs at least LLVM v4.1
7. Automatic in LTO mode with LLVM 11 and newer, an extra pass for all LLVM
   versions that write to a file to use with afl-fuzz' `-x`
8. The snapshot LKM is currently unmaintained due to too many kernel changes
   coming too fast :-(
9. FRIDA mode is supported on Linux and MacOS for Intel and ARM
10. QEMU/Unicorn is only supported on Linux
11. Coresight mode is only available on AARCH64 Linux with a CPU with Coresight
    extension
12. Nyx mode is only supported on Linux and currently restricted to x86_x64

## Integrated features and patches

Among others, the following features and patches have been integrated:

* NeverZero patch for afl-gcc, instrumentation, QEMU mode and unicorn_mode which
  prevents a wrapping map value to zero, increases coverage
* Persistent mode, deferred forkserver and in-memory fuzzing for QEMU mode
* Unicorn mode which allows fuzzing of binaries from completely different
  platforms (integration provided by domenukk)
* The new CmpLog instrumentation for LLVM and QEMU inspired by
  [Redqueen](https://github.com/RUB-SysSec/redqueen)
* Win32 PE binary-only fuzzing with QEMU and Wine
* AFLfast's power schedules by Marcel Böhme:
  [https://github.com/mboehme/aflfast](https://github.com/mboehme/aflfast)
* The MOpt mutator:
  [https://github.com/puppet-meteor/MOpt-AFL](https://github.com/puppet-meteor/MOpt-AFL)
* LLVM mode Ngram coverage by Adrian Herrera
  [https://github.com/adrianherrera/afl-ngram-pass](https://github.com/adrianherrera/afl-ngram-pass)
* LAF-Intel/CompCov support for instrumentation, QEMU mode and unicorn_mode
  (with enhanced capabilities)
* Radamsa and honggfuzz mutators (as custom mutators).
* QBDI mode to fuzz android native libraries via Quarkslab's
  [QBDI](https://github.com/QBDI/QBDI) framework
* Frida and ptrace mode to fuzz binary-only libraries, etc.

So all in all this is the best-of AFL that is out there :-)