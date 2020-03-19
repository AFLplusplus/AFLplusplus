# Fuzzing binary-only programs with afl++

  afl++, libfuzzer and others are great if you have the source code, and
  it allows for very fast and coverage guided fuzzing.

  However, if there is only the binary program and no source code available,
  then standard `afl-fuzz -n` (dumb mode) is not effective.

  The following is a description of how these binaries can be fuzzed with afl++

## TL;DR:

  qemu_mode in persistent mode is the fastest - if the stability is
  high enough. Otherwise try retrowrite, afl-dyninst and if these
  fail too then standard qemu_mode with AFL_ENTRYPOINT to where you need it.


## QEMU

  Qemu is the "native" solution to the program.
  It is available in the ./qemu_mode/ directory and once compiled it can
  be accessed by the afl-fuzz -Q command line option.
  It is the easiest to use alternative and even works for cross-platform binaries.

  The speed decrease is at about 50%.
  However various options exist to increase the speed:
   - using AFL_ENTRYPOINT to move the forkserver to a later basic block in
     the binary (+5-10% speed)
   - using persistent mode [qemu_mode/README.persistent.md](../qemu_mode/README.persistent.md)
     this will result in 150-300% overall speed - so 3-8x the original
     qemu_mode speed!
   - using AFL_CODE_START/AFL_CODE_END to only instrument specific parts

  Note that there is also honggfuzz: [https://github.com/google/honggfuzz](https://github.com/google/honggfuzz)
  which now has a qemu_mode, but its performance is just 1.5% ...

  As it is included in afl++ this needs no URL.


## WINE+QEMU

  Wine mode can run Win32 PE binaries with the QEMU instrumentation.
  It needs Wine, python3 and the pefile python package installed.

  As it is included in afl++ this needs no URL.


## UNICORN

  Unicorn is a fork of QEMU. The instrumentation is, therefore, very similar.
  In contrast to QEMU, Unicorn does not offer a full system or even userland
  emulation. Runtime environment and/or loaders have to be written from scratch,
  if needed. On top, block chaining has been removed. This means the speed boost
  introduced in  the patched QEMU Mode of afl++ cannot simply be ported over to
  Unicorn. For further information, check out [unicorn_mode/README.md](../unicorn_mode/README.md).

  As it is included in afl++ this needs no URL.


## DYNINST

  Dyninst is a binary instrumentation framework similar to Pintool and
  Dynamorio (see far below). However whereas Pintool and Dynamorio work at
  runtime, dyninst instruments the target at load time, and then let it run -
  or save the  binary with the changes.
  This is great for some things, e.g. fuzzing, and not so effective for others,
  e.g. malware analysis.

  So what we can do with dyninst is taking every basic block, and put afl's
  instrumention code in there - and then save the binary.
  Afterwards we can just fuzz the newly saved target binary with afl-fuzz.
  Sounds great? It is. The issue though - it is a non-trivial problem to
  insert instructions, which change addresses in the process space, so that
  everything is still working afterwards. Hence more often than not binaries
  crash when they are run.

  The speed decrease is about 15-35%, depending on the optimization options
  used with afl-dyninst.

  So if Dyninst works, it is the best option available. Otherwise it just
  doesn't work well.

  [https://github.com/vanhauser-thc/afl-dyninst](https://github.com/vanhauser-thc/afl-dyninst)


## RETROWRITE

  If you have an x86/x86_64 binary that still has it's symbols, is compiled
  with position independant code (PIC/PIE) and does not use most of the C++
  features then the retrowrite solution might be for you.
  It decompiles to ASM files which can then be instrumented with afl-gcc.

  It is at about 80-85% performance.

  [https://github.com/HexHive/retrowrite](https://github.com/HexHive/retrowrite)


## MCSEMA

  Theoretically you can also decompile to llvm IR with mcsema, and then
  use llvm_mode to instrument the binary.
  Good luck with that.

  [https://github.com/lifting-bits/mcsema](https://github.com/lifting-bits/mcsema)


## INTEL-PT

  If you have a newer Intel CPU, you can make use of Intels processor trace.
  The big issue with Intel's PT is the small buffer size and the complex
  encoding of the debug information collected through PT.
  This makes the decoding very CPU intensive and hence slow.
  As a result, the overall speed decrease is about 70-90% (depending on
  the implementation and other factors).

  There are two afl intel-pt implementations:

  1. [https://github.com/junxzm1990/afl-pt](https://github.com/junxzm1990/afl-pt)
     => this needs Ubuntu 14.04.05 without any updates and the 4.4 kernel.

  2. [https://github.com/hunter-ht-2018/ptfuzzer](https://github.com/hunter-ht-2018/ptfuzzer)
     => this needs a 4.14 or 4.15 kernel. the "nopti" kernel boot option must
        be used. This one is faster than the other.

  Note that there is also honggfuzz: https://github.com/google/honggfuzz
  But its IPT performance is just 6%!


## CORESIGHT

  Coresight is ARM's answer to Intel's PT.
  There is no implementation so far which handle coresight and getting
  it working on an ARM Linux is very difficult due to custom kernel building
  on embedded systems is difficult. And finding one that has coresight in
  the ARM chip is difficult too.
  My guess is that it is slower than Qemu, but faster than Intel PT.

  If anyone finds any coresight implementation for afl please ping me: vh@thc.org


## FRIDA

  Frida is a dynamic instrumentation engine like Pintool, Dyninst and Dynamorio.
  What is special is that it is written Python, and scripted with Javascript.
  It is mostly used to reverse binaries on mobile phones however can be used
  everywhere.

  There is a WIP fuzzer available at [https://github.com/andreafioraldi/frida-fuzzer](https://github.com/andreafioraldi/frida-fuzzer)

  There is also an early implementation in an AFL++ test branch:
  [https://github.com/AFLplusplus/AFLplusplus/tree/frida](https://github.com/AFLplusplus/AFLplusplus/tree/frida)


## PIN & DYNAMORIO

  Pintool and Dynamorio are dynamic instrumentation engines, and they can be
  used for getting basic block information at runtime.
  Pintool is only available for Intel x32/x64 on Linux, Mac OS and Windows
  whereas Dynamorio is additionally available for ARM and AARCH64.
  Dynamorio is also 10x faster than Pintool.

  The big issue with Dynamorio (and therefore Pintool too) is speed.
  Dynamorio has a speed decrease of 98-99%
  Pintool has a speed decrease of 99.5%

  Hence Dynamorio is the option to go for if everything fails, and Pintool
  only if Dynamorio fails too.

  Dynamorio solutions:
  * [https://github.com/vanhauser-thc/afl-dynamorio](https://github.com/vanhauser-thc/afl-dynamorio)
  * [https://github.com/mxmssh/drAFL](https://github.com/mxmssh/drAFL)
  * [https://github.com/googleprojectzero/winafl/](https://github.com/googleprojectzero/winafl/) <= very good but windows only

  Pintool solutions:
  * [https://github.com/vanhauser-thc/afl-pin](https://github.com/vanhauser-thc/afl-pin)
  * [https://github.com/mothran/aflpin](https://github.com/mothran/aflpin)
  * [https://github.com/spinpx/afl_pin_mode](https://github.com/spinpx/afl_pin_mode) <= only old Pintool version supported


## Non-AFL solutions

  There are many binary-only fuzzing frameworks.
  Some are great for CTFs but don't work with large binaries, others are very
  slow but have good path discovery, some are very hard to set-up ...

  * QSYM: [https://github.com/sslab-gatech/qsym](https://github.com/sslab-gatech/qsym)
  * Manticore: [https://github.com/trailofbits/manticore](https://github.com/trailofbits/manticore)
  * S2E: [https://github.com/S2E](https://github.com/S2E)
  *  ... please send me any missing that are good


## Closing words

  That's it! News, corrections, updates? Send an email to vh@thc.org
