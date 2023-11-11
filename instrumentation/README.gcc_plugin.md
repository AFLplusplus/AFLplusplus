# GCC-based instrumentation for afl-fuzz

For the general instruction manual, see [docs/README.md](../docs/README.md).
有关一般说明手册，请参阅[docs/readme.md](./docs/readme.md)。

For the LLVM-based instrumentation, see [README.llvm.md](README.llvm.md).

This document describes how to build and use `afl-gcc-fast` and `afl-g++-fast`,
which instrument the target with the help of gcc plugins.
本文档描述了如何构建和使用`afl-gcc-fast`和`afl-g++-fast`，它们在gcc-plugin的帮助下对目标程序进行插桩。

TL;DR:
* Check the version of your gcc compiler: `gcc --version`
  检查gcc版本
* `apt-get install gcc-VERSION-plugin-dev` or similar to install headers for gcc
  plugins.
  安装gcc-plugin的头文件
* `gcc` and `g++` must match the gcc-VERSION you installed headers for. You can
  set `AFL_CC`/`AFL_CXX` to point to these!
  gcc和gcc-plugin的版本应保持一致。
* `make`
* Just use `afl-gcc-fast`/`afl-g++-fast` normally like you would do with
  `afl-clang-fast`.
  使用`afl-gcc-fast`/`afl-g++-fast`编译程序。

## 1) Introduction 简介

The code in this directory allows to instrument programs for AFL++ using true
compiler-level instrumentation, instead of the more crude assembly-level
rewriting approach taken by afl-gcc and afl-clang. This has several interesting
properties:
这个目录下的代码允许afl++使用编译器级别的插桩，比起afl-cc和afl-clang粗糙的汇编重写，有几个有趣的特性：

- The compiler can make many optimizations that are hard to pull off when
  manually inserting assembly. As a result, some slow, CPU-bound programs will
  run up to around faster.
  编译器可以实现在手动插桩很难实现的一些优化，可以使一些速度较慢、CPU受限的程序运行更快。

  The gains are less pronounced for fast binaries, where the speed is limited
  chiefly by the cost of creating new processes. In such cases, the gain will
  probably stay within 10%.
  快速二进制的收益不会很明显，因为主要受限于创建新进程的效率。在这种情况下，提升将少于10%。

- The instrumentation is CPU-independent. At least in principle, you should be
  able to rely on it to fuzz programs on non-x86 architectures (after building
  `afl-fuzz` with `AFL_NOX86=1`).
  插桩是独立于CPU的，因此原则上你可以用它来fuzz非x86架构（使用AFL_NOX86=1编译afl-fuzz）。
  

- Because the feature relies on the internals of GCC, it is gcc-specific and
  will *not* work with LLVM (see [README.llvm.md](README.llvm.md) for an
  alternative).
  由于该特性依赖于gcc，所以不能和llvm一起使用。（参阅 [README.llvm.md](README.llvm.md) 获取替代方案）。

Once this implementation is shown to be sufficiently robust and portable, it
will probably replace afl-gcc. For now, it can be built separately and co-exists
with the original code.
一旦该实现被证实是健壮和可移植的，它将替代afl-gcc。目前他们可以分别构建并且在源码中是共存的。

The idea and much of the implementation comes from Laszlo Szekeres.
创意和实现来自Laszlo Szekeres.。

## 2) How to use 如何使用

In order to leverage this mechanism, you need to have modern enough GCC (>=
version 4.5.0) and the plugin development headers installed on your system. That
should be all you need. On Debian machines, these headers can be acquired by
installing the `gcc-VERSION-plugin-dev` packages.
为了使用该机制，需要安装4.5以上版本的gcc和gcc-plugin。在debian系统可使用apt install gcc-VERSION-plugin-dev安装。

To build the instrumentation itself, type `make`. This will generate binaries
called `afl-gcc-fast` and `afl-g++-fast` in the parent directory.
使用make编译插桩工具，在他的上级目录会生成`afl-gcc-fast` 和 `afl-g++-fast`

The gcc and g++ compiler links have to point to gcc-VERSION - or set these by
pointing the environment variables `AFL_CC`/`AFL_CXX` to them. If the `CC`/`CXX`
environment variables have been set, those compilers will be preferred over
those from the `AFL_CC`/`AFL_CXX` settings.


Once this is done, you can instrument third-party code in a way similar to the
standard operating mode of AFL++, e.g.:

```
  CC=/path/to/afl/afl-gcc-fast
  CXX=/path/to/afl/afl-g++-fast
  export CC CXX
  ./configure [...options...]
  make
```

Note: We also used `CXX` to set the C++ compiler to `afl-g++-fast` for C++ code.

The tool honors roughly the same environmental variables as `afl-gcc` (see
[docs/env_variables.md](../docs/env_variables.md). This includes
`AFL_INST_RATIO`, `AFL_USE_ASAN`, `AFL_HARDEN`, and `AFL_DONT_OPTIMIZE`.

Note: if you want the GCC plugin to be installed on your system for all users,
you need to build it before issuing 'make install' in the parent directory.

## 3) Gotchas, feedback, bugs

This is an early-stage mechanism, so field reports are welcome. You can send bug
reports to afl@aflplus.plus.

## 4) Bonus feature #1: deferred initialization

See
[README.persistent_mode.md#3) Deferred initialization](README.persistent_mode.md#3-deferred-initialization).

## 5) Bonus feature #2: persistent mode

See
[README.persistent_mode.md#4) Persistent mode](README.persistent_mode.md#4-persistent-mode).

## 6) Bonus feature #3: selective instrumentation

It can be more effective to fuzzing to only instrument parts of the code. For
details, see [README.instrument_list.md](README.instrument_list.md).

## 7) Bonus feature #4: CMPLOG

The gcc_plugin also support CMPLOG/Redqueen, just set `AFL_GCC_CMPLOG` before
instrumenting the target.
Read more about this in the llvm document.

