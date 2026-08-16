# Optional oracle helpers

Four detectors a harness can opt into. None of them is on by default and none
of them needs AFL++ to be present: they find bugs that produce no crash on
their own, by turning silent wrongness into a signal the fuzzer already knows
how to save.

| File | Oracle |
|---|---|
| `afl-oracles.h` | round-trip check, exact-size buffer allocator |
| `afl_allocfail.c` | `LD_PRELOAD` allocation-failure injection |
| `afl-perturb-check.sh` | uninitialised-memory probe |
| `tests/` | one broken and one correct example per detector |

```sh
make            # builds afl_allocfail.so
make tests      # builds the self-test examples
make selftest   # builds everything and asserts every detector fires
```

## Round-trip check

`save -> load -> save` must produce identical bytes, **and** the loader must
refuse anything the saver would never write. Both halves matter; the second is
the one that finds parser/serialiser disagreements.

The two callables have to satisfy:

```c
long save(const OBJ *obj, unsigned char *out, size_t cap);
     /* bytes written, or negative if this object cannot be saved */

int  load(const unsigned char *in, size_t len, OBJ *out);
     /* 0 on success, non-zero to refuse the input */
```

`mangle(buf, len)` turns a valid encoding into something the saver would never
emit and returns the new length, or 0 to skip the refusal half.
`AFL_ORACLE_MANGLE_FLIP` inverts the first byte and is a reasonable default;
a format with its own idea of "impossible" should supply its own.

```c
#include "afl-oracles.h"

record_t obj = parse_from_fuzzer_input(data, size), tmp;

AFL_ORACLE_ROUNDTRIP(save, load, &obj, &tmp, AFL_ORACLE_MANGLE_FLIP);
```

A failing check calls `abort()`, so the fuzzer saves it as a crash with a
readable stack rather than a message nobody looks at.

## Exact-size buffers

`afl_exact_alloc(n)` places an `mmap`'d `PROT_NONE` page immediately after the
`n` requested bytes, so a one-byte overrun faults instead of landing in
allocator slack. A generous buffer hides real overflows.

```c
unsigned char *buf = afl_exact_alloc(len);
...
afl_exact_free(buf, len);
```

The returned pointer is `n` bytes below a page boundary, so its alignment is
the alignment of `n`. This is meant for the byte buffers overflows actually
land in, not for arbitrary types.

## Allocation-failure injection

`afl_allocfail.so` interposes `malloc`, `calloc`, `realloc` and `strdup`, and
fails allocation number `AFL_ALLOCFAIL_N`. It then **disarms itself**, so one
execution exercises exactly one error path and the resulting crash is
attributable: the input plus the value of `N` reproduce it, and no second
failure muddies the stack.

```sh
AFL_ALLOCFAIL_N=7 LD_PRELOAD=./afl_allocfail.so ./target input
```

`AFL_ALLOCFAIL_VERBOSE=1` writes one line to stderr when the failure is
injected. With `AFL_ALLOCFAIL_N` unset or 0 the interposer passes everything
through.

The first few allocations of any process belong to libc startup rather than to
the program, so sweep `N` rather than assuming `N=1` reaches your code.

## Uninitialised-memory probe

`afl-perturb-check.sh <target> <input> [args ...]` runs the target four times
at different `MALLOC_PERTURB_` values and diffs the outputs. Any difference
means the output depends on uninitialised heap. `@@` in the argument list is
replaced by the input path; without it the input is fed on stdin.

```sh
./afl-perturb-check.sh ./target input          # exit 0 clean, 1 dependent
./afl-perturb-check.sh ./target input -f @@
```

## Self-tests

`tests/` ships one deliberately broken example per detector and one correct
counterpart, and `tests/run-selftests.sh` asserts that each detector fires on
the broken one and stays quiet on the correct one. A detector never seen to
fire is not known to work.

The examples are built at `-O0` with `-fno-builtin` and route the defect
through `volatile` on purpose: a leak self-test once reported "clean" at `-O1`
because the compiler had deleted the leak.

Expected outcomes:

| Example | Expected |
|---|---|
| `tests/roundtrip_bad` | exit 134 (`SIGABRT` from the oracle) |
| `tests/roundtrip_good` | exit 0 |
| `tests/exactbuf_bad` | exit 139 (`SIGSEGV` on the guard page) |
| `tests/exactbuf_good` | exit 0 |
| `tests/allocfail_bad` under the preload | killed by a signal for some `N` in 1..20 |
| `tests/allocfail_good` under the preload | exit 0 for every `N` in 1..20 |
| `afl-perturb-check.sh ./tests/perturb_bad` | exit 1 |
| `afl-perturb-check.sh ./tests/perturb_good` | exit 0 |
