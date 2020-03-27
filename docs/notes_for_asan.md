# Notes for using ASAN with afl-fuzz

  This file discusses some of the caveats for fuzzing under ASAN, and suggests
  a handful of alternatives. See README.md for the general instruction manual.

## 1) Short version

ASAN on 64-bit systems requests a lot of memory in a way that can't be easily
distinguished from a misbehaving program bent on crashing your system.

Because of this, fuzzing with ASAN is recommended only in four scenarios:

  - On 32-bit systems, where we can always enforce a reasonable memory limit
    (-m 800 or so is a good starting point),

  - On 64-bit systems only if you can do one of the following:

    - Compile the binary in 32-bit mode (gcc -m32),

    - Precisely gauge memory needs using http://jwilk.net/software/recidivm .

    - Limit the memory available to process using cgroups on Linux (see
      examples/asan_cgroups).

To compile with ASAN, set AFL_USE_ASAN=1 before calling 'make clean all'. The
afl-gcc / afl-clang wrappers will pick that up and add the appropriate flags.
Note that ASAN is incompatible with -static, so be mindful of that.

(You can also use AFL_USE_MSAN=1 to enable MSAN instead.)

NOTE: if you run several slaves only one should run the target compiled with
ASAN (and UBSAN, CFISAN), the others should run the target with no sanitizers
compiled in.

There is also the option of generating a corpus using a non-ASAN binary, and
then feeding it to an ASAN-instrumented one to check for bugs. This is faster,
and can give you somewhat comparable results. You can also try using
libdislocator (see libdislocator/README.dislocator.md in the parent directory) as a
lightweight and hassle-free (but less thorough) alternative.

## 2) Long version

ASAN allocates a huge region of virtual address space for bookkeeping purposes.
Most of this is never actually accessed, so the OS never has to allocate any
real pages of memory for the process, and the VM grabbed by ASAN is essentially
"free" - but the mapping counts against the standard OS-enforced limit
(RLIMIT_AS, aka ulimit -v).

On our end, afl-fuzz tries to protect you from processes that go off-rails
and start consuming all the available memory in a vain attempt to parse a
malformed input file. This happens surprisingly often, so enforcing such a limit
is important for almost any fuzzer: the alternative is for the kernel OOM
handler to step in and start killing random processes to free up resources.
Needless to say, that's not a very nice prospect to live with.

Unfortunately, un*x systems offer no portable way to limit the amount of
pages actually given to a process in a way that distinguishes between that
and the harmless "land grab" done by ASAN. In principle, there are three standard
ways to limit the size of the heap:

  - The RLIMIT_AS mechanism (ulimit -v) caps the size of the virtual space -
    but as noted, this pays no attention to the number of pages actually
    in use by the process, and doesn't help us here.

  - The RLIMIT_DATA mechanism (ulimit -d) seems like a good fit, but it applies
    only to the traditional sbrk() / brk() methods of requesting heap space;
    modern allocators, including the one in glibc, routinely rely on mmap()
    instead, and circumvent this limit completely.

  - Finally, the RLIMIT_RSS limit (ulimit -m) sounds like what we need, but
    doesn't work on Linux - mostly because nobody felt like implementing it.

There are also cgroups, but they are Linux-specific, not universally available
even on Linux systems, and they require root permissions to set up; I'm a bit
hesitant to make afl-fuzz require root permissions just for that. That said,
if you are on Linux and want to use cgroups, check out the contributed script
that ships in examples/asan_cgroups/.

In settings where cgroups aren't available, we have no nice, portable way to
avoid counting the ASAN allocation toward the limit. On 32-bit systems, or for
binaries compiled in 32-bit mode (-m32), this is not a big deal: ASAN needs
around 600-800 MB or so, depending on the compiler - so all you need to do is
to specify -m that is a bit higher than that.

On 64-bit systems, the situation is more murky, because the ASAN allocation
is completely outlandish - around 17.5 TB in older versions, and closer to
20 TB with newest ones. The actual amount of memory on your system is
(probably!) just a tiny fraction of that - so unless you dial the limit
with surgical precision, you will get no protection from OOM bugs.

On my system, the amount of memory grabbed by ASAN with a slightly older
version of gcc is around 17,825,850 MB; for newest clang, it's 20,971,600.
But there is no guarantee that these numbers are stable, and if you get them
wrong by "just" a couple gigs or so, you will be at risk.

To get the precise number, you can use the recidivm tool developed by Jakub
Wilk (http://jwilk.net/software/recidivm). In absence of this, ASAN is *not*
recommended when fuzzing 64-bit binaries, unless you are confident that they
are robust and enforce reasonable memory limits (in which case, you can
specify '-m none' when calling afl-fuzz).

Using recidivm or running with no limits aside, there are two other decent
alternatives: build a corpus of test cases using a non-ASAN binary, and then
examine them with ASAN, Valgrind, or other heavy-duty tools in a more
controlled setting; or compile the target program with -m32 (32-bit mode)
if your system supports that.

## 3) Interactions with the QEMU mode

ASAN, MSAN, and other sanitizers appear to be incompatible with QEMU user
emulation, so please do not try to use them with the -Q option; QEMU doesn't
seem to appreciate the shadow VM trick used by these tools, and will likely
just allocate all your physical memory, then crash.

You can, however, use QASan to run binaries that are not instrumented with ASan
under QEMU with the AFL++ instrumentation.

https://github.com/andreafioraldi/qasan

## 4) ASAN and OOM crashes

By default, ASAN treats memory allocation failures as fatal errors, immediately
causing the program to crash. Since this is a departure from normal POSIX
semantics (and creates the appearance of security issues in otherwise
properly-behaving programs), we try to disable this by specifying 
allocator_may_return_null=1 in ASAN_OPTIONS.

Unfortunately, it's been reported that this setting still causes ASAN to
trigger phantom crashes in situations where the standard allocator would
simply return NULL. If this is interfering with your fuzzing jobs, you may
want to cc: yourself on this bug:

  https://bugs.llvm.org/show_bug.cgi?id=22026

## 5) What about UBSAN?

New versions of UndefinedBehaviorSanitizer offers the
-fsanitize=undefined-trap-on-error compiler flag that tells UBSan to insert an
istruction that will cause SIGILL (ud2 on x86) when an undefined behaviour
is detected. This is the option that you want to use when combining AFL++
and UBSan.

AFL_USE_UBSAN=1 env var will add this compiler flag to afl-clang-fast,
afl-gcc-fast and afl-gcc for you.

Old versions of UBSAN don't offer a consistent way
to abort() on fault conditions or to terminate with a distinctive exit code
but there are some versions of the library can be binary-patched to address this
issue. You can also preload a shared library that substitute all the UBSan
routines used to report errors with abort().
