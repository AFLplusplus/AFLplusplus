# libdislocator, an abusive allocator

  (See ../docs/README.md for the general instruction manual.)

This is a companion library that can be used as a drop-in replacement for the
libc allocator in the fuzzed binaries. It improves the odds of bumping into
heap-related security bugs in several ways:

  - It allocates all buffers so that they are immediately adjacent to a
    subsequent PROT_NONE page, causing most off-by-one reads and writes to
    immediately segfault,

  - It adds a canary immediately below the allocated buffer, to catch writes
    to negative offsets (won't catch reads, though),

  - It sets the memory returned by malloc() to garbage values, improving the
    odds of crashing when the target accesses uninitialized data,

  - It sets freed memory to PROT_NONE and does not actually reuse it, causing
    most use-after-free bugs to segfault right away,

  - It forces all realloc() calls to return a new address - and sets
    PROT_NONE on the original block. This catches use-after-realloc bugs,

  - It checks for calloc() overflows and can cause soft or hard failures
    of alloc requests past a configurable memory limit (AFL_LD_LIMIT_MB,
    AFL_LD_HARD_FAIL).

  - Optionally, in platforms supporting it, huge pages can be used by passing
    USEHUGEPAGE=1 to make.
  
  - Size alignment to `max_align_t` can be enforced with AFL_ALIGNED_ALLOC=1.
    In this case, a tail canary is inserted in the padding bytes at the end
    of the allocated zone. This reduce the ability of libdislocator to detect
    off-by-one bugs but also it make slibdislocator compliant to the C standard.

Basically, it is inspired by some of the non-default options available for the
OpenBSD allocator - see malloc.conf(5) on that platform for reference. It is
also somewhat similar to several other debugging libraries, such as gmalloc
and DUMA - but is simple, plug-and-play, and designed specifically for fuzzing
jobs.

Note that it does nothing for stack-based memory handling errors. The
-fstack-protector-all setting for GCC / clang, enabled when using AFL_HARDEN,
can catch some subset of that.

The allocator is slow and memory-intensive (even the tiniest allocation uses up
4 kB of physical memory and 8 kB of virtual mem), making it completely unsuitable
for "production" uses; but it can be faster and more hassle-free than ASAN / MSAN
when fuzzing small, self-contained binaries.

To use this library, run AFL like so:

```
AFL_PRELOAD=/path/to/libdislocator.so ./afl-fuzz [...other params...]
```

You *have* to specify path, even if it's just ./libdislocator.so or
$PWD/libdislocator.so.

Similarly to afl-tmin, the library is not "proprietary" and can be used with
other fuzzers or testing tools without the need for any code tweaks. It does not
require AFL-instrumented binaries to work.

Note that the AFL_PRELOAD approach (which AFL internally maps to LD_PRELOAD or
DYLD_INSERT_LIBRARIES, depending on the OS) works only if the target binary is
dynamically linked. Otherwise, attempting to use the library will have no
effect.
