# Fuzzing binary-only targets

AFL++, libfuzzer, and other fuzzers are great if you have the source code of the
target. This allows for very fast and coverage guided fuzzing.

However, if there is only the binary program and no source code available, then
standard `afl-fuzz -n` (non-instrumented mode) is not effective.

For fast, on-the-fly instrumentation of black-box binaries, AFL++ still offers
various support. The following is a description of how these binaries can be
fuzzed with AFL++.

## TL;DR:

FRIDA mode and QEMU mode in persistent mode are the fastest - if persistent mode
is possible and the stability is high enough.

Otherwise, try Zafl, RetroWrite, Dyninst, and if these fail, too, then try
standard FRIDA/QEMU mode with `AFL_ENTRYPOINT` to where you need it.

If your target is non-linux, then use unicorn_mode.

## Fuzzing binary-only targets with AFL++

### QEMU mode

QEMU mode is the "native" solution to the program. It is available in the
./qemu_mode/ directory and, once compiled, it can be accessed by the afl-fuzz -Q
command line option. It is the easiest to use alternative and even works for
cross-platform binaries.

For linux programs and its libraries, this is accomplished with a version of
QEMU running in the lesser-known "user space emulation" mode. QEMU is a project
separate from AFL++, but you can conveniently build the feature by doing:

```shell
cd qemu_mode
./build_qemu_support.sh
```

The following setup to use QEMU mode is recommended:

* run 1 afl-fuzz -Q instance with CMPLOG (`-c 0` + `AFL_COMPCOV_LEVEL=2`)
* run 1 afl-fuzz -Q instance with QASAN (`AFL_USE_QASAN=1`)
* run 1 afl-fuzz -Q instance with LAF (`AFL_PRELOAD=libcmpcov.so` +
  `AFL_COMPCOV_LEVEL=2`), alternatively you can use FRIDA mode, just switch `-Q`
  with `-O` and remove the LAF instance

Then run as many instances as you have cores left with either -Q mode or - even
better - use a binary rewriter like Dyninst, RetroWrite, ZAFL, etc.
The binary rewriters all have their own advantages and caveats.
ZAFL is the best but cannot be used in a business/commercial context.

If a binary rewriter works for your target then you can use afl-fuzz normally
and it will have twice the speed compared to QEMU mode (but slower than QEMU
persistent mode).

The speed decrease of QEMU mode is at about 50%. However, various options exist
to increase the speed:
- using AFL_ENTRYPOINT to move the forkserver entry to a later basic block in
  the binary (+5-10% speed)
- using persistent mode
  [qemu_mode/README.persistent.md](../qemu_mode/README.persistent.md) this will
  result in a 150-300% overall speed increase - so 3-8x the original QEMU mode
  speed!
- using AFL_CODE_START/AFL_CODE_END to only instrument specific parts

For additional instructions and caveats, see
[qemu_mode/README.md](../qemu_mode/README.md). If possible, you should use the
persistent mode, see
[qemu_mode/README.persistent.md](../qemu_mode/README.persistent.md). The mode is
approximately 2-5x slower than compile-time instrumentation, and is less
conducive to parallelization.

Note that there is also honggfuzz:
[https://github.com/google/honggfuzz](https://github.com/google/honggfuzz) which
now has a QEMU mode, but its performance is just 1.5% ...

If you like to code a customized fuzzer without much work, we highly recommend
to check out our sister project libafl which supports QEMU, too:
[https://github.com/AFLplusplus/LibAFL](https://github.com/AFLplusplus/LibAFL)

### WINE+QEMU

Wine mode can run Win32 PE binaries with the QEMU instrumentation. It needs
Wine, python3, and the pefile python package installed.

It is included in AFL++.

For more information, see
[qemu_mode/README.wine.md](../qemu_mode/README.wine.md).

### FRIDA mode

In FRIDA mode, you can fuzz binary-only targets as easily as with QEMU mode.
FRIDA mode is most of the times slightly faster than QEMU mode. It is also
newer, lacks COMPCOV, and has the advantage that it works on MacOS (both intel
and M1).

To build FRIDA mode:

```shell
cd frida_mode
gmake
```

For additional instructions and caveats, see
[frida_mode/README.md](../frida_mode/README.md).

If possible, you should use the persistent mode, see
[instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md).
The mode is approximately 2-5x slower than compile-time instrumentation, and is
less conducive to parallelization. But for binary-only fuzzing, it gives a huge
speed improvement if it is possible to use.

If you want to fuzz a binary-only library, then you can fuzz it with frida-gum
via frida_mode/. You will have to write a harness to call the target function in
the library, use afl-frida.c as a template.

You can also perform remote fuzzing with frida, e.g., if you want to fuzz on
iPhone or Android devices, for this you can use
[https://github.com/ttdennis/fpicker/](https://github.com/ttdennis/fpicker/) as
an intermediate that uses AFL++ for fuzzing.

If you like to code a customized fuzzer without much work, we highly recommend
to check out our sister project libafl which supports Frida, too:
[https://github.com/AFLplusplus/LibAFL](https://github.com/AFLplusplus/LibAFL).
Working examples already exist :-)

### Nyx mode

Nyx is a full system emulation fuzzing environment with snapshot support that is
built upon KVM and QEMU. It is only available on Linux and currently restricted
to x86_x64.

For binary-only fuzzing a special 5.10 kernel is required.

See [nyx_mode/README.md](../nyx_mode/README.md).

### Unicorn

Unicorn is a fork of QEMU. The instrumentation is, therefore, very similar. In
contrast to QEMU, Unicorn does not offer a full system or even userland
emulation. Runtime environment and/or loaders have to be written from scratch,
if needed. On top, block chaining has been removed. This means the speed boost
introduced in the patched QEMU Mode of AFL++ cannot be ported over to Unicorn.

For non-Linux binaries, you can use AFL++'s unicorn_mode which can emulate
anything you want - for the price of speed and user written scripts.

To build unicorn_mode:

```shell
cd unicorn_mode
./build_unicorn_support.sh
```

For further information, check out
[unicorn_mode/README.md](../unicorn_mode/README.md).

### Shared libraries

If the goal is to fuzz a dynamic library, then there are two options available.
For both, you need to write a small harness that loads and calls the library.
Then you fuzz this with either FRIDA mode or QEMU mode and either use
`AFL_INST_LIBS=1` or `AFL_QEMU/FRIDA_INST_RANGES`.

Another, less precise and slower option is to fuzz it with utils/afl_untracer/
and use afl-untracer.c as a template. It is slower than FRIDA mode.

For more information, see
[utils/afl_untracer/README.md](../utils/afl_untracer/README.md).

### Coresight

Coresight is ARM's answer to Intel's PT. With AFL++ v3.15, there is a coresight
tracer implementation available in `coresight_mode/` which is faster than QEMU,
however, cannot run in parallel. Currently, only one process can be traced, it
is WIP.

Fore more information, see
[coresight_mode/README.md](../coresight_mode/README.md).

## Binary rewriters

An alternative solution are binary rewriters. They are faster than the solutions
native to AFL++ but don't always work.

### ZAFL

ZAFL is a static rewriting platform supporting x86-64 C/C++,
stripped/unstripped, and PIE/non-PIE binaries. Beyond conventional
instrumentation, ZAFL's API enables transformation passes (e.g., laf-Intel,
context sensitivity, InsTrim, etc.).

Its baseline instrumentation speed typically averages 90-95% of
afl-clang-fast's.

[https://git.zephyr-software.com/opensrc/zafl](https://git.zephyr-software.com/opensrc/zafl)

### RetroWrite

RetroWrite is a static binary rewriter that can be combined with AFL++. If you
have an x86_64 binary that still has its symbols (i.e., not stripped binary), is
compiled with position independent code (PIC/PIE), and does not contain C++
exceptions, then the RetroWrite solution might be for you. It decompiles to ASM
files which can then be instrumented with afl-gcc.

Binaries that are statically instrumented for fuzzing using RetroWrite are close
in performance to compiler-instrumented binaries and outperform the QEMU-based
instrumentation.

[https://github.com/HexHive/retrowrite](https://github.com/HexHive/retrowrite)

### Dyninst

Dyninst is a binary instrumentation framework similar to Pintool and DynamoRIO.
However, whereas Pintool and DynamoRIO work at runtime, Dyninst instruments the
target at load time and then let it run - or save the binary with the changes.
This is great for some things, e.g., fuzzing, and not so effective for others,
e.g., malware analysis.

So, what you can do with Dyninst is taking every basic block and putting AFL++'s
instrumentation code in there - and then save the binary. Afterwards, just fuzz
the newly saved target binary with afl-fuzz. Sounds great? It is. The issue
though - it is a non-trivial problem to insert instructions, which change
addresses in the process space, so that everything is still working afterwards.
Hence, more often than not binaries crash when they are run.

The speed decrease is about 15-35%, depending on the optimization options used
with afl-dyninst.

[https://github.com/vanhauser-thc/afl-dyninst](https://github.com/vanhauser-thc/afl-dyninst)

### Mcsema

Theoretically, you can also decompile to llvm IR with mcsema, and then use
llvm_mode to instrument the binary. Good luck with that.

[https://github.com/lifting-bits/mcsema](https://github.com/lifting-bits/mcsema)

## Binary tracers

### Pintool & DynamoRIO

Pintool and DynamoRIO are dynamic instrumentation engines. They can be used for
getting basic block information at runtime. Pintool is only available for Intel
x32/x64 on Linux, Mac OS, and Windows, whereas DynamoRIO is additionally
available for ARM and AARCH64. DynamoRIO is also 10x faster than Pintool.

The big issue with DynamoRIO (and therefore Pintool, too) is speed. DynamoRIO
has a speed decrease of 98-99%, Pintool has a speed decrease of 99.5%.

Hence, DynamoRIO is the option to go for if everything else fails and Pintool
only if DynamoRIO fails, too.

DynamoRIO solutions:
* [https://github.com/vanhauser-thc/afl-dynamorio](https://github.com/vanhauser-thc/afl-dynamorio)
* [https://github.com/mxmssh/drAFL](https://github.com/mxmssh/drAFL)
* [https://github.com/googleprojectzero/winafl/](https://github.com/googleprojectzero/winafl/)
  <= very good but windows only

Pintool solutions:
* [https://github.com/vanhauser-thc/afl-pin](https://github.com/vanhauser-thc/afl-pin)
* [https://github.com/mothran/aflpin](https://github.com/mothran/aflpin)
* [https://github.com/spinpx/afl_pin_mode](https://github.com/spinpx/afl_pin_mode)
  <= only old Pintool version supported

### Intel PT

If you have a newer Intel CPU, you can make use of Intel's processor trace. The
big issue with Intel's PT is the small buffer size and the complex encoding of
the debug information collected through PT. This makes the decoding very CPU
intensive and hence slow. As a result, the overall speed decrease is about
70-90% (depending on the implementation and other factors).

There are two AFL intel-pt implementations:

1. [https://github.com/junxzm1990/afl-pt](https://github.com/junxzm1990/afl-pt)
    => This needs Ubuntu 14.04.05 without any updates and the 4.4 kernel.

2. [https://github.com/hunter-ht-2018/ptfuzzer](https://github.com/hunter-ht-2018/ptfuzzer)
    => This needs a 4.14 or 4.15 kernel. The "nopti" kernel boot option must be
    used. This one is faster than the other.

Note that there is also honggfuzz:
[https://github.com/google/honggfuzz](https://github.com/google/honggfuzz). But
its IPT performance is just 6%!

## Non-AFL++ solutions

There are many binary-only fuzzing frameworks. Some are great for CTFs but don't
work with large binaries, others are very slow but have good path discovery,
some are very hard to set-up...

* Jackalope:
  [https://github.com/googleprojectzero/Jackalope](https://github.com/googleprojectzero/Jackalope)
* Manticore:
  [https://github.com/trailofbits/manticore](https://github.com/trailofbits/manticore)
* QSYM:
  [https://github.com/sslab-gatech/qsym](https://github.com/sslab-gatech/qsym)
* S2E: [https://github.com/S2E](https://github.com/S2E)
* TinyInst:
  [https://github.com/googleprojectzero/TinyInst](https://github.com/googleprojectzero/TinyInst)
  (Mac/Windows only)
*  ... please send me any missing that are good

## Closing words

That's it! News, corrections, updates? Send an email to vh@thc.org.
