# QEMU AddressSanitizer Runtime

This library is the injected runtime used by QEMU AddressSanitizer (QASan).

The original repository is [here](https://github.com/andreafioraldi/qasan).

The version embedded in qemuafl is an updated version of just the usermode part
and this runtime is injected via LD_PRELOAD (so works just for dynamically
linked binaries).

The usage is super simple, just set the env var `AFL_USE_QASAN=1` when fuzzing
in QEMU mode (-Q). afl-fuzz will automatically set AFL_PRELOAD to load this
library and enable the QASan instrumentation in afl-qemu-trace.

For debugging purposes, we still suggest to run the original QASan as the
stacktrace support for ARM (just a debug feature, it does not affect the bug
finding capabilities during fuzzing) is WIP.

### Building for musl

If your target is linked against musl instead of glibc, build the runtime with a
musl compiler so that it matches the libc of the target:

```
make -C qemu_mode/libqasan CC=musl-gcc
```

On Debian/Ubuntu `musl-gcc` comes from the `musl-tools` package, on Alpine the
system `gcc` is already a musl compiler.

Two things differ on musl:

* As on any other libc, the runtime is injected via LD_PRELOAD, so only
  dynamically linked targets can be instrumented. Statically linked musl
  binaries (the Alpine default for Rust and Go, for instance) are out of reach.
* musl keeps `FILE` opaque, so the `fgets` hook cannot use `sizeof(FILE)` and
  checks a conservative prefix of the stream instead. It checks less of the
  object than on glibc, but it never reports a bug that did not happen. The
  build works this out per libc, see `QASAN_FILE_CHECK_SIZE` in `hooks.c`.

### When should I use QASan?

If your target binary is PIC x86_64, you should also give a try to
[RetroWrite](https://github.com/HexHive/retrowrite) for static rewriting.

If it fails, or if your binary is for another architecture, or you want to use
persistent and snapshot mode, AFL++ QASan mode is what you want/have to use.

Note that the overhead of libdislocator when combined with QEMU mode is much
lower but it can catch less bugs. This is a short blanket, take your choice.
