# Important features of AFL++

AFL++ supports llvm from 3.8 up to version 12, very fast binary fuzzing with
QEMU 5.1 with laf-intel and redqueen, FRIDA mode, unicorn mode, gcc plugin, full
*BSD, Mac OS, Solaris and Android support and much, much, much more.

| Feature/Instrumentation  | afl-gcc | llvm      | gcc_plugin | FRIDA mode(9)    | QEMU mode(10)    |unicorn_mode(10)  |nyx_mode(12)|coresight_mode(11)|
| -------------------------|:-------:|:---------:|:----------:|:----------------:|:----------------:|:----------------:|:----------:|:----------------:|
| Threadsafe counters      |         |     x(3)  |            |                  |                  |                  |     x      |                  |
| NeverZero                | x86[_64]|     x(1)  |     x      |         x        |         x        |         x        |            |                  |
| Persistent Mode          |         |     x     |     x      | x86[_64]/arm64   | x86[_64]/arm[64] |         x        |            |                  |
| LAF-Intel / CompCov      |         |     x     |            |                  | x86[_64]/arm[64] | x86[_64]/arm[64] | x86[_64]   |                  |
| CmpLog                   |         |     x     |            | x86[_64]/arm64   | x86[_64]/arm[64] |                  |            |                  |
| Selective Instrumentation|         |     x     |     x      |         x        |         x        |                  |            |                  |
| Non-Colliding Coverage   |         |     x(4)  |            |                  |        (x)(5)    |                  |            |                  |
| Ngram prev_loc Coverage  |         |     x(6)  |            |                  |                  |                  |            |                  |
| Context Coverage         |         |     x(6)  |            |                  |                  |                  |            |                  |
| Auto Dictionary          |         |     x(7)  |            |                  |                  |                  |            |                  |
| Snapshot Support         |         |    (x)(8) |    (x)(8)  |                  |        (x)(5)    |                  |     x      |                  |
| Shared Memory Test cases |         |     x     |     x      | x86[_64]/arm64   |         x        |         x        |     x      |                  |

1. default for LLVM >= 9.0, environment variable for older version due an
   efficiency bug in previous llvm versions
2. GCC creates non-performant code, hence it is disabled in gcc_plugin
3. with `AFL_LLVM_THREADSAFE_INST`, disables NeverZero
4. with pcguard mode and LTO mode for LLVM 11 and newer
5. upcoming, development in the branch
6. not compatible with LTO instrumentation and needs at least LLVM v4.1
7. automatic in LTO mode with LLVM 11 and newer, an extra pass for all LLVM
   versions that write to a file to use with afl-fuzz' `-x`
8. the snapshot LKM is currently unmaintained due to too many kernel changes
   coming too fast :-(
9. FRIDA mode is supported on Linux and MacOS for Intel and ARM
10. QEMU/Unicorn is only supported on Linux
11. Coresight mode is only available on AARCH64 Linux with a CPU with Coresight
    extension
12. Nyx mode is only supported on Linux and currently restricted to x86_x64

Among others, the following features and patches have been integrated:

* NeverZero patch for afl-gcc, instrumentation, QEMU mode and unicorn_mode which
  prevents a wrapping map value to zero, increases coverage
* Persistent mode, deferred forkserver and in-memory fuzzing for QEMU mode
* Unicorn mode which allows fuzzing of binaries from completely different
  platforms (integration provided by domenukk)
* The new CmpLog instrumentation for LLVM and QEMU inspired by
  [Redqueen](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2018/12/17/NDSS19-Redqueen.pdf)
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