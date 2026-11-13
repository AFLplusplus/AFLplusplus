/*
   Shared driver for the afl-compiler-fuzzer custom mutators.

   afl-compiler-fuzzer (https://github.com/agroce/afl-compiler-fuzzer) changed
   the AFL havoc stage so that each stacked havoc step was, with some
   probability, a source-level mutation instead of a byte-level one; if the
   source-level mutation could not be applied, the step fell back to a normal
   havoc operation.  This header reproduces that loop for AFL++: the
   source-level step is supplied by the including mutator, and the fallback is
   AFL++'s own havoc operator set (afl_mutate() from afl-mutations.h).

   Include this from exactly one translation unit per mutator.
*/

#ifndef AFL_COMPILER_COMMON_H
#define AFL_COMPILER_COMMON_H

#include "afl-fuzz.h"
#include "afl-mutations.h"

#include <stdlib.h>
#include <string.h>

/* A source-level mutation step: mutate buf[0..*len) in place (the buffer has
   room for max_len bytes).  Returns 1 if a mutation was applied, 0 if not. */
typedef int (*acf_step_fn)(void *ctx, u8 *buf, size_t *len, size_t max_len);

typedef struct acf_driver {

  afl_state_t *afl;
  u8          *buf;
  size_t       buf_size;
  u32          prob;            /* % of stacked steps that try acf_step_fn  */
  u32          stack_pow2;      /* stacked steps = 1 << (1 + rand(pow2))    */

} acf_driver_t;

static u32 acf_env_u32(const char *name, u32 def, u32 lo, u32 hi) {

  const char *v = getenv(name);
  if (!v || !*v) return def;

  char         *end = NULL;
  unsigned long n = strtoul(v, &end, 10);
  if (*end || n < lo || n > hi) {

    FATAL("%s must be an integer in [%u, %u], got '%s'", name, lo, hi, v);

  }

  return (u32)n;

}

static int acf_driver_init(acf_driver_t *d, afl_state_t *afl,
                           const char *prob_env, u32 prob_default) {

  d->afl = afl;
  d->buf_size = MAX_FILE;
  d->buf = malloc(d->buf_size);
  if (!d->buf) return 0;
  d->prob = acf_env_u32(prob_env, prob_default, 0, 100);
  d->stack_pow2 = acf_env_u32("ACF_STACK_POW2", afl->havoc_stack_pow2, 1, 16);
  return 1;

}

static void acf_driver_deinit(acf_driver_t *d) {

  free(d->buf);
  d->buf = NULL;

}

/* The afl-compiler-fuzzer havoc loop.  Returns the new length, with the
   mutated data in d->buf, or 0 on failure. */
static size_t acf_stacked_fuzz(acf_driver_t *d, const u8 *in, size_t in_len,
                               u8 *add_buf, size_t add_len, size_t max_size,
                               acf_step_fn step, void *ctx) {

  afl_state_t *afl = d->afl;

  if (!in_len) return 0;

  if (max_size > d->buf_size) {

    u8 *p = realloc(d->buf, max_size);
    if (!p) return 0;
    d->buf = p;
    d->buf_size = max_size;

  }

  if (in_len > max_size) in_len = max_size;
  memcpy(d->buf, in, in_len);

  size_t len = in_len;
  u32    stacking = 1U << (1 + rand_below(afl, d->stack_pow2));
  bool   explore = afl->fuzz_mode == 0;

  for (u32 i = 0; i < stacking && !afl->stop_soon; ++i) {

    if (rand_below(afl, 100) < d->prob && step(ctx, d->buf, &len, max_size)) {

      continue;

    }

    /* Fall back to a single AFL++ havoc operation. */
    u32 n = afl_mutate(afl, d->buf, (u32)len, 1, true, explore, add_buf,
                       (u32)add_len, (u32)max_size);
    if (n) len = n;

  }

  return len;

}

#endif

