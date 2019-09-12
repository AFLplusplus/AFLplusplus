# High-performance binary-only instrumentation for afl-fuzz

  (See ../docs/README for the general instruction manual.)

## 1) Introduction

The code in this directory allows you to build a standalone feature that
leverages the QEMU "user emulation" mode and allows callers to obtain
instrumentation output for black-box, closed-source binaries. This mechanism
can be then used by afl-fuzz to stress-test targets that couldn't be built
with afl-gcc.

The usual performance cost is 2-5x, which is considerably better than
seen so far in experiments with tools such as DynamoRIO and PIN.

The idea and much of the initial implementation comes from Andrew Griffiths.
The actual implementation on QEMU 3 (shipped with afl++) is from
Andrea Fioraldi. Special thanks to abiondo that re-enabled TCG chaining.

## 2) How to use

The feature is implemented with a patch to QEMU 3.1.0. The simplest way
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
on a 64-bit system (CPU_TARGET=i386).

Note: if you want the QEMU helper to be installed on your system for all
users, you need to build it before issuing 'make install' in the parent
directory.

## 3) Options

There is ./libcompcov/ which implements laf-intel (splitting memcmp,
strncmp, etc. to make these conditions easier solvable by afl-fuzz).
Highly recommended.

The option that enables QEMU CompareCoverage is AFL_COMPCOV_LEVEL.
AFL_COMPCOV_LEVEL=1 is to instrument comparisons with only immediate
values / read-only memory. AFL_COMPCOV_LEVEL=2 instruments all
comparison instructions and memory comparison functions when libcompcov
is preloaded. Comparison instructions are currently instrumented only
on the x86 and x86_64 targets.

Another option is the environment variable AFL_ENTRYPOINT which allows
move the forkserver to a different part, e.g. just before the file is
opened (e.g. way after command line parsing and config file loading, etc)
which can be a huge speed improvement. Note that the specified address
must be an address of a basic block.

QEMU mode support also persistent mode for x86 and x86_64 targets.
The environment variable to enable it is AFL_QEMU_PERSISTENT_ADDR=`start addr`.
In this variable you must specify the address of the function that
have to be the body of the persistent loop.
The code in this function must be stateless like in the LLVM persistent mode.
The return address on stack is patched like in WinAFL in order to repeat the
execution of such function.
Another modality to execute the persistent loop is to specify also the
AFL_QEMU_PERSISTENT_RET=`end addr` env variable.
With this variable assigned, instead of patching the return address, the
specified instruction is transformed to a jump towards `start addr`.
Note that the format of the addresses in such variables is hex.

Note that the base address of PIE binaries in QEMU user is 0x4000000000.

Warning: in x86_64 parameters are passed via registers and so the target
function of persistent mode cannot make use of arguments. An option to restore
the state of each GPR each iteration of the loop is planned.

## 4) Notes on linking

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

## 5) Benchmarking

If you want to compare the performance of the QEMU instrumentation with that of
afl-gcc compiled code against the same target, you need to build the
non-instrumented binary with the same optimization flags that are normally
injected by afl-gcc, and make sure that the bits to be tested are statically
linked into the binary. A common way to do this would be:

$ CFLAGS="-O3 -funroll-loops" ./configure --disable-shared
$ make clean all

Comparative measurements of execution speed or instrumentation coverage will be
fairly meaningless if the optimization levels or instrumentation scopes don't
match.

## 6) Gotchas, feedback, bugs

If you need to fix up checksums or do other cleanup on mutated test cases, see
experimental/post_library/ for a viable solution.

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

## 7) Alternatives: static rewriting

Statically rewriting binaries just once, instead of attempting to translate
them at run time, can be a faster alternative. That said, static rewriting is
fraught with peril, because it depends on being able to properly and fully model
program control flow without actually executing each and every code path.

The best implementation is this one:

  https://github.com/vanhauser-thc/afl-dyninst

The issue however is Dyninst which is not rewriting the binaries so that
they run stable. a lot of crashes happen, especially in C++ programs that
use throw/catch. Try it first, and if it works for you be happy as it is
2-3x as fast as qemu_mode.
