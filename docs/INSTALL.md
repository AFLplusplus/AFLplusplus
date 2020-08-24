# Installation instructions

  This document provides basic installation instructions and discusses known
  issues for a variety of platforms. See README.md for the general instruction
  manual.

## 1) Linux on x86
---------------

This platform is expected to work well. Compile the program with:

```bash
make
```

You can start using the fuzzer without installation, but it is also possible to
install it with:

```bash
sudo make install
```

There are no special dependencies to speak of; you will need GNU make and a
working compiler (gcc or clang). Some of the optional scripts bundled with the
program may depend on bash, gdb, and similar basic tools.

If you are using clang, please review README.llvm.md; the LLVM
integration mode can offer substantial performance gains compared to the
traditional approach.

You may have to change several settings to get optimal results (most notably,
disable crash reporting utilities and switch to a different CPU governor), but
afl-fuzz will guide you through that if necessary.

## OpenBSD, FreeBSD, NetBSD on x86

Similarly to Linux, these platforms are expected to work well and are
regularly tested. Compile everything with GNU make:

```bash
gmake
```

Note that BSD make will *not* work; if you do not have gmake on your system,
please install it first. As on Linux, you can use the fuzzer itself without
installation, or install it with:

```
sudo gmake install
```

Keep in mind that if you are using csh as your shell, the syntax of some of the
shell commands given in the README.md and other docs will be different.

The `llvm` requires a dynamically linked, fully-operational installation of
clang. At least on FreeBSD, the clang binaries are static and do not include
some of the essential tools, so if you want to make it work, you may need to
follow the instructions in README.llvm.md.

Beyond that, everything should work as advertised.

The QEMU mode is currently supported only on Linux. I think it's just a QEMU
problem, I couldn't get a vanilla copy of user-mode emulation support working
correctly on BSD at all.

## 3. MacOS X on x86

MacOS X should work, but there are some gotchas due to the idiosyncrasies of
the platform. On top of this, I have limited release testing capabilities
and depend mostly on user feedback.

To build AFL, install Xcode and follow the general instructions for Linux.

The Xcode 'gcc' tool is just a wrapper for clang, so be sure to use afl-clang
to compile any instrumented binaries; afl-gcc will fail unless you have GCC
installed from another source (in which case, please specify `AFL_CC` and
`AFL_CXX` to point to the "real" GCC binaries).

Only 64-bit compilation will work on the platform; porting the 32-bit
instrumentation would require a fair amount of work due to the way OS X
handles relocations, and today, virtually all MacOS X boxes are 64-bit.

The crash reporting daemon that comes by default with MacOS X will cause
problems with fuzzing. You need to turn it off by following the instructions
provided here: http://goo.gl/CCcd5u

The `fork()` semantics on OS X are a bit unusual compared to other unix systems
and definitely don't look POSIX-compliant. This means two things:

  - Fuzzing will be probably slower than on Linux. In fact, some folks report
    considerable performance gains by running the jobs inside a Linux VM on
    MacOS X.
  - Some non-portable, platform-specific code may be incompatible with the
    AFL forkserver. If you run into any problems, set `AFL_NO_FORKSRV=1` in the
    environment before starting afl-fuzz.

User emulation mode of QEMU does not appear to be supported on MacOS X, so
black-box instrumentation mode (`-Q`) will not work.

The llvm instrumentation requires a fully-operational installation of clang. The one that
comes with Xcode is missing some of the essential headers and helper tools.
See README.llvm.md for advice on how to build the compiler from scratch.

## 4. Linux or *BSD on non-x86 systems

Standard build will fail on non-x86 systems, but you should be able to
leverage two other options:

  - The LLVM mode (see README.llvm.md), which does not rely on
    x86-specific assembly shims. It's fast and robust, but requires a
    complete installation of clang.
  - The QEMU mode (see qemu_mode/README.md), which can be also used for
    fuzzing cross-platform binaries. It's slower and more fragile, but
    can be used even when you don't have the source for the tested app.

If you're not sure what you need, you need the LLVM mode, which is built by
default.

...and compile your target program with afl-clang-fast or afl-clang-fast++
instead of the traditional afl-gcc or afl-clang wrappers.

## 5. Solaris on x86

The fuzzer reportedly works on Solaris, but I have not tested this first-hand,
and the user base is fairly small, so I don't have a lot of feedback.

To get the ball rolling, you will need to use GNU make and GCC or clang. I'm
being told that the stock version of GCC that comes with the platform does not
work properly due to its reliance on a hardcoded location for 'as' (completely
ignoring the `-B` parameter or `$PATH`).

To fix this, you may want to build stock GCC from the source, like so:

```sh
./configure --prefix=$HOME/gcc --with-gnu-as --with-gnu-ld \
  --with-gmp-include=/usr/include/gmp --with-mpfr-include=/usr/include/mpfr
make
sudo make install
```

Do *not* specify `--with-as=/usr/gnu/bin/as` - this will produce a GCC binary that
ignores the `-B` flag and you will be back to square one.

Note that Solaris reportedly comes with crash reporting enabled, which causes
problems with crashes being misinterpreted as hangs, similarly to the gotchas
for Linux and MacOS X. AFL does not auto-detect crash reporting on this
particular platform, but you may need to run the following command:

```sh
coreadm -d global -d global-setid -d process -d proc-setid \
  -d kzone -d log
```

User emulation mode of QEMU is not available on Solaris, so black-box
instrumentation mode (`-Q`) will not work.

## 6. Everything else

You're on your own. On POSIX-compliant systems, you may be able to compile and
run the fuzzer; and the LLVM mode may offer a way to instrument non-x86 code.

The fuzzer will run on Windows in WSL only. It will not work under Cygwin on in the normal Windows world. It
could be ported to the latter platform fairly easily, but it's a pretty bad
idea, because Cygwin is extremely slow. It makes much more sense to use
VirtualBox or so to run a hardware-accelerated Linux VM; it will run around
20x faster or so. If you have a *really* compelling use case for Cygwin, let
me know.

Although Android on x86 should theoretically work, the stock kernel may have
SHM support compiled out, and if so, you may have to address that issue first.
It's possible that all you need is this workaround:

  https://github.com/pelya/android-shmem

Joshua J. Drake notes that the Android linker adds a shim that automatically
intercepts `SIGSEGV` and related signals. To fix this issue and be able to see
crashes, you need to put this at the beginning of the fuzzed program:

```sh
  signal(SIGILL, SIG_DFL);
  signal(SIGABRT, SIG_DFL);
  signal(SIGBUS, SIG_DFL);
  signal(SIGFPE, SIG_DFL);
  signal(SIGSEGV, SIG_DFL);
```

You may need to `#include <signal.h>` first.
