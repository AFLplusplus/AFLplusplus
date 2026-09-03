/*
   american fuzzy lop++ - describe_state template
   ----------------------------------------------

   A starting point for telling afl-fuzz how much work an input performs.

   Fill in one function, next_record(), and afl-fuzz gains an operation count
   for every queue entry. That count replaces mutation depth - which counts
   generations from a seed, not work done - in the -Jd deep-input shelf, in
   -Jo's deep-witness favouring, and in the fuzzer_stats plugin_ops_* figures.
   Without it a target that performs 200 protocol operations and one that
   performs 3 are judged only by how large and how slow they are.

   This mutator deliberately does NOT export afl_custom_fuzz. afl-fuzz warns
   about the missing symbol and keeps its own mutations, so adding this file to
   a campaign changes what afl-fuzz *knows* without changing what it *does* -
   which is what makes it usable as an A/B arm and safe to drop into a running
   configuration.

   Build:  make
   Use:    AFL_CUSTOM_MUTATOR_LIBRARY=./describe_state_template.so afl-fuzz -Jdm
   ... Check:  fuzzer_stats should grow plugin_ops_avg and plugin_ops_max.

   VALIDATE IT. A record parser that disagrees with the harness is worse than
   no parser at all, because every scheduling decision downstream then rests on
   a number nobody checked. Have the harness print its own operation count
   under an environment variable, replay a hundred queue entries through both,
   and require exact agreement before you trust an experiment that uses this.
   See README.md.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MARKER0 0x5a
#define DEFAULT_MARKER1 0xa5
#define DEFAULT_HDR 8
#define DEFAULT_LENOFF 6
#define DEFAULT_MAX_OPS 4096

typedef struct {

  uint8_t marker[2];
  int     use_marker;
  size_t  hdr_len;
  int     len_off;                       /* < 0: no length field, scan only */
  size_t  max_ops;

} describe_state_t;

static size_t env_size(const char *name, size_t dflt) {

  const char *v = getenv(name);
  return v && *v ? (size_t)strtoul(v, NULL, 0) : dflt;

}

/* ------------------------------------------------------------------------ */
/* EDIT HERE. Everything above and below this block is boilerplate.          */
/*                                                                          */
/* Return the first byte after the operation starting at *cur, or NULL when  */
/* no further operation starts there. Advance by at least one byte on every  */
/* call or the caller will not terminate.                                   */
/*                                                                          */
/* The default understands the common framing: a two-byte record marker, a   */
/* fixed header, and a little-endian 16-bit length in the header, with the   */
/* length accepted only when it lands on the next marker or the end of the   */
/* buffer. Configure it from the environment (see README.md) or replace the  */
/* body outright with a call to your own decoder.                           */
/* ------------------------------------------------------------------------ */

static const uint8_t *next_record(describe_state_t *st, const uint8_t *cur,
                                  const uint8_t *end) {

  const uint8_t *marker = cur, *body;
  size_t         avail, hint;

  if (st->use_marker) {

    for (marker = cur; marker + 2 <= end; marker++) {

      if (marker[0] == st->marker[0] && marker[1] == st->marker[1]) { break; }

    }

    if (marker + 2 > end) { return NULL; }

  }

  if ((size_t)(end - marker) < st->hdr_len) { return NULL; }

  body = marker + st->hdr_len;
  avail = (size_t)(end - body);

  if (st->len_off >= 0 && (size_t)st->len_off + 1 < st->hdr_len) {

    hint = (size_t)marker[st->len_off] | ((size_t)marker[st->len_off + 1] << 8);

    if (hint <= avail) {

      const uint8_t *at = body + hint;

      if (!st->use_marker || at == end ||
          (at + 2 <= end && at[0] == st->marker[0] && at[1] == st->marker[1])) {

        return at;

      }

    }

  }

  if (!st->use_marker) { return end; }

  for (const uint8_t *p = body; p + 2 <= end; p++) {

    if (p[0] == st->marker[0] && p[1] == st->marker[1]) { return p; }

  }

  return end;

}

/* ------------------------------------------------------------------------ */
/* Boilerplate below.                                                        */
/* ------------------------------------------------------------------------ */

void *afl_custom_init(void *afl, unsigned int seed) {

  describe_state_t *st = calloc(1, sizeof(*st));
  const char       *m = getenv("DESCRIBE_MARKER");

  (void)afl;
  (void)seed;
  if (!st) { return NULL; }

  st->marker[0] = DEFAULT_MARKER0;
  st->marker[1] = DEFAULT_MARKER1;
  st->use_marker = 1;

  if (m) {

    if (!*m || !strcmp(m, "none")) {

      st->use_marker = 0;

    } else {

      unsigned b0 = 0, b1 = 0;

      if (sscanf(m, "%2x%2x", &b0, &b1) == 2) {

        st->marker[0] = (uint8_t)b0;
        st->marker[1] = (uint8_t)b1;

      }

    }

  }

  st->hdr_len = env_size("DESCRIBE_HDR", DEFAULT_HDR);
  st->max_ops = env_size("DESCRIBE_MAXOPS", DEFAULT_MAX_OPS);

  {

    const char *lo = getenv("DESCRIBE_LENOFF");
    st->len_off = lo && *lo ? (int)strtol(lo, NULL, 0) : DEFAULT_LENOFF;

  }

  if (!st->hdr_len) { st->hdr_len = 1; }

  return st;

}

void afl_custom_deinit(void *data) {

  free(data);

}

unsigned char afl_custom_describe_state(void *data, const unsigned char *buf,
                                        size_t buf_size, unsigned int *ops,
                                        unsigned int *state_id) {

  describe_state_t *st = (describe_state_t *)data;
  const uint8_t    *cur = buf, *end = buf + buf_size;
  unsigned int      n = 0;

  if (!st || !buf || !ops) { return 0; }

  while (n < st->max_ops) {

    const uint8_t *next = next_record(st, cur, end);

    if (!next || next <= cur) { break; }
    cur = next;
    n++;

  }

  *ops = n;

  /* afl-fuzz ignores the state id; the parameter survives so that mutators
     built against the older API still link. See docs/custom_mutators.md. */

  if (state_id) { *state_id = 0; }

  return n > 0;

}

/*
   Optional. Report where each operation starts, so afl-fuzz can say "this new
   input shares your first k operations". Implement it only for a format whose
   operations are contiguous byte ranges - a trailing checksum over the whole
   input, or a length prefix that has to be rewritten, has no honest answer
   here, and leaving the symbol out is better than approximate offsets.

   Delete this function if that describes your format.
*/

unsigned int afl_custom_describe_state_ops(void *data, const unsigned char *buf,
                                           size_t        buf_size,
                                           unsigned int *offsets,
                                           unsigned int  max_ops) {

  describe_state_t *st = (describe_state_t *)data;
  const uint8_t    *cur = buf, *end = buf + buf_size;
  unsigned int      n = 0;

  if (!st || !buf || !offsets || !max_ops) { return 0; }

  while (n < st->max_ops) {

    const uint8_t *next = next_record(st, cur, end);

    if (!next || next <= cur) { break; }
    if (n < max_ops) { offsets[n] = (unsigned int)(cur - buf); }
    cur = next;
    n++;

  }

  /* One past the last operation, so the caller learns the program's length
     and not only where the last operation begins. */

  if (n && n + 1 <= max_ops) { offsets[n] = (unsigned int)(cur - buf); }

  return n;

}

