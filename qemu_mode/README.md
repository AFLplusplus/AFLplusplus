# High-performance binary-only instrumentation for afl-fuzz

  (See ../README.md for the general instruction manual.)

## 1) Introduction

The code in this directory allows you to build a standalone feature that
leverages the QEMU "user emulation" mode and allows callers to obtain
instrumentation output for black-box, closed-source binaries. This mechanism
can be then used by afl-fuzz to stress-test targets that couldn't be built
with afl-gcc.

The usual performance cost is 2-5x, which is considerably better than
seen so far in experiments with tools such as DynamoRIO and PIN.

The idea and much of the initial implementation comes from Andrew Griffiths.
The actual implementation on current QEMU (shipped as qemuafl) is from
Andrea Fioraldi. Special thanks to abiondo that re-enabled TCG chaining.

## 2) How to use qemu_mode

The feature is implemented with a patched QEMU. The simplest way
to build it is to run ./build_qemu_support.sh. The script will download,
configure, and compile the QEMU binary for you.

QEMU is a big project, so this will take a while, and you may have to
resolve a couple of dependencies (most notably, you will definitely need
libtool and glib2-devel).

Once the binaries are compiled, you can leverage the QEMU tool by calling
afl-fuzz and all the related utilities with -Q in the command line.

Note that QEMU requires a generous memory limit to run; somewhere around
200 MB is a good starting point, but considerably more may be needed for
more complex programs. The default -m limit will be automatically bumped up
to 200 MB when specifying -Q to afl-fuzz; be careful when overriding this.

In principle, if you set CPU_TARGET before calling ./build_qemu_support.sh,
you should get a build capable of running non-native binaries (say, you
can try CPU_TARGET=arm). This is also necessary for running 32-bit binaries
on a 64-bit system (CPU_TARGET=i386). If you're trying to run QEMU on a
different architecture you can also set HOST to the cross-compiler prefix
to use (for example HOST=arm-linux-gnueabi to use arm-linux-gnueabi-gcc).

You can also compile statically-linked binaries by setting STATIC=1. This
can be useful when compiling QEMU on a different system than the one you're
planning to run the fuzzer on and is most often used with the HOST variable.

Note: when targetting the i386 architecture, on some binaries the forkserver
handshake may fail due to the lack of reserved memory. Fix it with

export QEMU_RESERVED_VA=0x1000000

Note: if you want the QEMU helper to be installed on your system for all
users, you need to build it before issuing 'make install' in the parent
directory.

If you want to specify a different path for libraries (e.g. to run an arm64
binary on x86_64) use QEMU_LD_PREFIX.

## 3) Deferred initialization

As for LLVM mode (refer to its README.md for mode details) QEMU mode supports
the deferred initialization.

This can be enabled setting the environment variable AFL_ENTRYPOINT which allows
to move the forkserver to a different part, e.g. just before the file is
opened (e.g. way after command line parsing and config file loading, etc.)
which can be a huge speed improvement.

## 4) Persistent mode

AFL++'s QEMU mode now supports also persistent mode for x86, x86_64, arm
and aarch64 targets.
This increases the speed by several factors, however it is a bit of work to set
up - but worth the effort.

Please see the extra documentation for it: [README.persistent.md](README.persistent.md)

## 5) Snapshot mode

As an extension to persistent mode, qemuafl can snapshot and restore the memory
state and brk(). Details are in the persistent mode readme.

The env var that enables the ready to use snapshot mode is AFL_QEMU_SNAPSHOT and
takes a hex address as a value that is the snapshot entrypoint.

Snapshot mode can work restoring all the writeable pages, that is typically slower than
fork() mode but, on the other hand, it can scale better with multicore.
If the AFL++ Snapshot kernel module is loaded, qemuafl will use it and, in this
case, the speed is better than fork() and also the scaling capabilities.

## 6) Partial instrumentation

You can tell QEMU to instrument only a part of the address space.

Just set AFL_QEMU_INST_RANGES=A,B,C...

The format of the items in the list is either a range of addresses like 0x123-0x321
or a module name like module.so (that is matched in the mapped object filename).

Alternatively you can tell QEMU to ignore part of an address space for instrumentation.

Just set AFL_QEMU_EXCLUDE_RANGES=A,B,C...

The format of the items on the list is the same as for AFL_QEMU_INST_RANGES, and excluding ranges
takes priority over any included ranges or AFL_INST_LIBS.

## 7) CompareCoverage

CompareCoverage is a sub-instrumentation with effects similar to laf-intel.

You have to set `AFL_PRELOAD=/path/to/libcompcov.so` together with
setting the AFL_COMPCOV_LEVEL you want to enable it.

AFL_COMPCOV_LEVEL=1 is to instrument comparisons with only immediate
values / read-only memory.

AFL_COMPCOV_LEVEL=2 instruments all comparison instructions and memory
comparison functions when libcompcov is preloaded.

AFL_COMPCOV_LEVEL=3 has the same effects of AFL_COMPCOV_LEVEL=2 but enables
also the instrumentation of the floating-point comparisons on x86 and x86_64
(experimental).

Integer comparison instructions are currently instrumented only
on the x86, x86_64, arm and aarch64 targets.

Recommended, but not as good as CMPLOG mode (see below).

## 8) CMPLOG mode

Another new feature is CMPLOG, which is based on the redqueen project.
Here all immediates in CMP instructions are learned and put into a dynamic
dictionary and applied to all locations in the input that reached that
CMP, trying to solve and pass it.
This is a very effective feature and it is available for x86, x86_64, arm
and aarch64.

To enable it you must pass on the command line of afl-fuzz:
  -c /path/to/your/target

## 9) Wine mode

AFL++ QEMU can use Wine to fuzz Win32 PE binaries. Use the -W flag of afl-fuzz.

Note that some binaries require user interaction with the GUI and must be patched.

For examples look [here](https://github.com/andreafioraldi/WineAFLplusplusDEMO).

## 10) Notes on linking

The feature is supported only on Linux. Supporting BSD may amount to porting
the changes made to linux-user/elfload.c and applying them to
bsd-user/elfload.c, but I have not looked into this yet.

The instrumentation follows only the .text section of the first ELF binary
encountered in the linking process. It does not trace shared libraries. In
practice, this means two things:

  - Any libraries you want to analyze *must* be linked statically into the
    executed ELF file (this will usually be the case for closed-source
    apps).

  - Standard C libraries and other stuff that is wasteful to instrument
    should be linked dynamically - otherwise, AFL will have no way to avoid
    peeking into them.

Setting AFL_INST_LIBS=1 can be used to circumvent the .text detection logic
and instrument every basic block encountered.

## 11) Benchmarking

If you want to compare the performance of the QEMU instrumentation with that of
afl-gcc compiled code against the same target, you need to build the
non-instrumented binary with the same optimization flags that are normally
injected by afl-gcc, and make sure that the bits to be tested are statically
linked into the binary. A common way to do this would be:

CFLAGS="-O3 -funroll-loops" ./configure --disable-shared
make clean all

Comparative measurements of execution speed or instrumentation coverage will be
fairly meaningless if the optimization levels or instrumentation scopes don't
match.

## 12) Other features

With `AFL_QEMU_FORCE_DFL` you force QEMU to ignore the registered signal
handlers of the target.

## 13) Gotchas, feedback, bugs

If you need to fix up checksums or do other cleanups on mutated test cases, see
`afl_custom_post_process` in custom_mutators/examples/example.c for a viable solution.

Do not mix QEMU mode with ASAN, MSAN, or the likes; QEMU doesn't appreciate
the "shadow VM" trick employed by the sanitizers and will probably just
run out of memory.

Compared to fully-fledged virtualization, the user emulation mode is *NOT* a
security boundary. The binaries can freely interact with the host OS. If you
somehow need to fuzz an untrusted binary, put everything in a sandbox first.

QEMU does not necessarily support all CPU or hardware features that your
target program may be utilizing. In particular, it does not appear to have
full support for AVX2 / FMA3. Using binaries for older CPUs, or recompiling them
with -march=core2, can help.

Beyond that, this is an early-stage mechanism, so fields reports are welcome.
You can send them to <afl-users@googlegroups.com>.

## 14) Alternatives: static rewriting

Statically rewriting binaries just once, instead of attempting to translate
them at run time, can be a faster alternative. That said, static rewriting is
fraught with peril, because it depends on being able to properly and fully model
program control flow without actually executing each and every code path.

Checkout the "Fuzzing binary-only targets" section in our main README.md and
the docs/binaryonly_fuzzing.md document for more information and hints.
