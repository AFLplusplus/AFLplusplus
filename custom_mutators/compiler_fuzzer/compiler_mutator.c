/*
   afl-compiler-fuzzer source-level mutator for AFL++

   Port of the built-in string mutations of afl-compiler-fuzzer
   (https://github.com/agroce/afl-compiler-fuzzer, Alex Groce), see
   "Making No-Fuss Compiler Fuzzing Effective", CC 2022.

   The mutations are mutation-testing style operators (operator replacement,
   statement deletion, argument swapping, ...) over C-like source text.  They
   are applied as stacked havoc steps, interleaved with AFL++ havoc, exactly
   as afl-fuzz-compiler did on top of AFL 2.56b.

   Environment:
     ACF_MUTATION_PROB  % of stacked havoc steps that try a source-level
                        mutation (default 75; was -1 / AFL_P_C_STRING_MUTATION)
     ACF_STACK_POW2     stacked steps per input = 2^(1..N) (default: AFL++'s
                        havoc stacking, 4; AFL 2.56b used 7)
*/

#include "compiler_common.h"

#define MAX_MUTANT_CHANGE 1024
#define MAX_MUTANT_TRIES 16

typedef enum {

  RULE_SIMPLE,      /* replace first `from` at/after pos with `to`          */
  RULE_DELIM_REP,   /* replace l ... r (inclusive) with `to`                */
  RULE_DELIM_DUP,   /* duplicate l ... r (inclusive)                        */
  RULE_DELIM_SWAP   /* l A m B r  ->  l B m A r                             */

} rule_kind_t;

typedef struct {

  rule_kind_t kind;
  const char *from, *to;
  char        l, m, r;

} rule_t;

#define S(f, t) \
  { RULE_SIMPLE, f, t, 0, 0, 0 }
#define REP(l, r, t) \
  { RULE_DELIM_REP, NULL, t, l, 0, r }
#define DUP(l, r) \
  { RULE_DELIM_DUP, NULL, NULL, l, 0, r }
#define SWAP(l, m, r) \
  { RULE_DELIM_SWAP, NULL, NULL, l, m, r }

/* Same 64 operators, in the same order, as use_mutation_tool() in
   afl-compiler-fuzzer's afl-fuzz.c. */
static const rule_t rules[] = {

    S("\n", "\nif (0==1)\n"),                /* semantic statement deletion */
    S("(", "(!"),
    S("==", "!="),
    S("!=", "=="),
    S("==", "<"),
    S("<", "=="),
    S("==", ">"),
    S(">", "=="),
    S("=", "<"),
    S("=", ">"),
    S("<", ">"),
    S(">", "<"),
    S("++", "--"),
    S("--", "++"),
    S("+", "-"),
    S("+", "*"),
    S("+", "/"),
    S("+", "%"),
    S("*", "-"),
    S("*", "+"),
    S("*", "/"),
    S("*", "%"),
    S("-", "+"),
    S("-", "*"),
    S("-", "/"),
    S("-", "%"),
    S("/", "-"),
    S("/", "*"),
    S("/", "+"),
    S("/", "%"),
    S("%", "-"),
    S("%", "*"),
    S("%", "/"),
    S("%", "+"),
    S("\n", "\nbreak;\n"),
    S("\n", "\ncontinue;\n"),
    S("0", "1"),
    S("1", "0"),
    S("if", "while"),
    S("while", "if"),
    S("\n", "\nwhile(1==1)\n"),
    S("&&", "||"),
    S("||", "&&"),
    S("!", ""),
    REP(';', ';', ";"),        /* remove a statement after a semicolon      */
    REP('}', ';', "}"),        /* remove a statement after a right brace    */
    REP('{', '}', ""),         /* remove a (non-nested) brace construct     */
    REP('{', '}', "{}"),       /* empty a (non-nested) brace construct      */
    SWAP(';', ';', ';'),       /* swap adjacent statements                  */
    SWAP('}', ';', ';'),
    SWAP('(', ',', ')'),       /* swap comma-delimited things, cases 1-4    */
    SWAP('(', ',', ','),
    SWAP(',', ',', ','),
    SWAP(',', ',', ')'),
    REP('\n', '\n', ""),       /* delete a line                             */
    REP(' ', ' ', ""),         /* delete something like "const", cases 1-3  */
    REP('\n', ' ', ""),
    REP('(', ' ', ""),
    SWAP(' ', ' ', ' '),       /* swap space-delimited things, cases 1-4    */
    SWAP(' ', ' ', ')'),
    SWAP('(', ' ', ' '),
    SWAP('(', ' ', ')'),
    DUP('\n', '\n'),           /* duplicate a line                          */
    DUP('\n', '}'),            /* duplicate a construct, e.g. a for loop    */

};

#define NUM_RULES (sizeof(rules) / sizeof(rules[0]))

typedef struct {

  acf_driver_t drv;
  u8           rep[2 * MAX_MUTANT_CHANGE + 2];
  char         desc[64];

} compiler_mutator_t;

static const u8 *find_bytes(const u8 *hay, size_t hlen, const char *needle) {

  size_t nlen = strlen(needle);
  if (!nlen || nlen > hlen) return NULL;
  const u8 *end = hay + hlen - nlen;
  for (const u8 *p = hay; p <= end; ++p) {

    p = memchr(p, needle[0], end - p + 1);
    if (!p) return NULL;
    if (!memcmp(p, needle, nlen)) return p;

  }

  return NULL;

}

static ssize_t find_char(const u8 *buf, size_t from, size_t to, char c) {

  if (from >= to) return -1;
  const u8 *p = memchr(buf + from, c, to - from);
  return p ? p - buf : -1;

}

/* Replace buf[at, at+olen) with rep[0, rlen), in place. */
static int replace_span(u8 *buf, size_t *len, size_t max_len, size_t at,
                        size_t olen, const u8 *rep, size_t rlen) {

  size_t new_len = *len - olen + rlen;
  if (!new_len || new_len > max_len) return 0;
  memmove(buf + at + rlen, buf + at + olen, *len - at - olen);
  memcpy(buf + at, rep, rlen);
  *len = new_len;
  return 1;

}

static int apply_rule(compiler_mutator_t *m, const rule_t *r, u8 *buf,
                      size_t *len, size_t max_len, size_t pos) {

  size_t n = *len;

  if (r->kind == RULE_SIMPLE) {

    const u8 *hit = find_bytes(buf + pos, n - pos, r->from);
    if (!hit) return 0;
    return replace_span(buf, len, max_len, hit - buf, strlen(r->from),
                        (const u8 *)r->to, strlen(r->to));

  }

  /* Delimiter-based rules: anchor on the first left delimiter at/after pos,
     then look for the closing delimiter(s) within MAX_MUTANT_CHANGE bytes. */
  ssize_t a = find_char(buf, pos, n, r->l);
  if (a < 0 || (size_t)a >= n - 2) return 0;

  size_t limit = MIN(n, (size_t)a + MAX_MUTANT_CHANGE);

  if (r->kind == RULE_DELIM_SWAP) {

    ssize_t b = find_char(buf, a + 1, limit, r->m);
    if (b < 0) return 0;
    ssize_t c = find_char(buf, b + 1, limit, r->r);
    if (c < 0) return 0;

    /* buf[a+1 .. c] = A m B r  ->  B m A r */
    size_t alen = b - (a + 1), blen = c - (b + 1), k = 0;
    memcpy(m->rep + k, buf + b + 1, blen);
    k += blen;
    m->rep[k++] = r->m;
    memcpy(m->rep + k, buf + a + 1, alen);
    k += alen;
    m->rep[k++] = r->r;
    return replace_span(buf, len, max_len, a + 1, k, m->rep, k);

  }

  ssize_t b = find_char(buf, a + 1, limit, r->r);
  if (b < 0) return 0;
  size_t olen = b - a + 1;

  if (r->kind == RULE_DELIM_DUP) {

    memcpy(m->rep, buf + a, olen);
    memcpy(m->rep + olen, buf + a, olen);
    return replace_span(buf, len, max_len, a, olen, m->rep, 2 * olen);

  }

  return replace_span(buf, len, max_len, a, olen, (const u8 *)r->to,
                      strlen(r->to));

}

static int source_step(void *ctx, u8 *buf, size_t *len, size_t max_len) {

  compiler_mutator_t *m = ctx;
  afl_state_t        *afl = m->drv.afl;

  if (*len < 2) return 0;

  for (u32 t = 0; t < MAX_MUTANT_TRIES; ++t) {

    size_t pos = rand_below(afl, *len - 1);
    if (apply_rule(m, &rules[rand_below(afl, NUM_RULES)], buf, len, max_len,
                   pos)) {

      return 1;

    }

  }

  return 0;

}

/* ---------------------------- AFL++ API -------------------------------- */

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;
  compiler_mutator_t *m = calloc(1, sizeof(*m));
  if (!m) return NULL;
  if (!acf_driver_init(&m->drv, afl, "ACF_MUTATION_PROB", 75)) {

    free(m);
    return NULL;

  }

  OKF("compiler mutator: %u%% source-level steps, stacking 2^(1..%u)",
      m->drv.prob, m->drv.stack_pow2);
  return m;

}

size_t afl_custom_fuzz(void *data, u8 *buf, size_t buf_size, u8 **out_buf,
                       u8 *add_buf, size_t add_buf_size, size_t max_size) {

  compiler_mutator_t *m = data;
  size_t len = acf_stacked_fuzz(&m->drv, buf, buf_size, add_buf, add_buf_size,
                                max_size, source_step, m);
  *out_buf = m->drv.buf;
  return len;

}

const char *afl_custom_describe(void *data, size_t max_description_len) {

  compiler_mutator_t *m = data;
  snprintf(m->desc, MIN(sizeof(m->desc), max_description_len), "compiler");
  return m->desc;

}

void afl_custom_deinit(void *data) {

  compiler_mutator_t *m = data;
  acf_driver_deinit(&m->drv);
  free(m);

}

