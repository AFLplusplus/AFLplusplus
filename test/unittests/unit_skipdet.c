/* Regression test for SkipDet quick-effective-map resume (P2-19): a
   >32 KiB input must have its bytes past the per-invocation budget tested
   across resumed invocations instead of being permanently skipped. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"

static u64 fake_time = 0;
static u32 early_pos;
static u32 late_pos;
static u32 quick_runs;

u64 get_cur_time(void) {

  return fake_time;

}

u64 hash64(u8 *key, u32 len, u64 seed) {

  u64 hash = seed;
  for (u32 i = 0; i < len; ++i) {

    hash ^= key[i];
    hash *= 1099511628211ULL;

  }

  return hash;

}

u8 common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  memset(afl->fsrv.trace_bits, 0, afl->fsrv.map_size);
  ++afl->fsrv.total_execs;

  if (!strcmp(afl->stage_short, "inf")) {

    for (u32 i = 0; i < len; ++i) {

      if (out_buf[i] != 0xaa) {

        afl->fsrv.trace_bits[1] = 1;
        break;

      }

    }

  } else if (!strcmp(afl->stage_short, "quick")) {

    ++quick_runs;
    afl->fsrv.trace_bits[3] = quick_runs & 1;
    if (out_buf[early_pos] != 0xaa || out_buf[late_pos] != 0xaa) {

      afl->fsrv.trace_bits[2] = 1;

    }

  }

  return 0;

}

AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  (void)afl;
  return 0;

}

static afl_state_t *make_afl(void) {

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  afl->fixed_seed = 1;
  afl->fsrv.map_size = 8;
  afl->fsrv.trace_bits = calloc(1, afl->fsrv.map_size);
  afl->map_tmp_buf = calloc(1, afl->fsrv.map_size);
  afl->var_bytes = calloc(1, afl->fsrv.map_size);
  afl->var_bytes[3] = 1;
  afl->skipdet_g = calloc(1, sizeof(struct skipdet_global));
  afl->skipdet_g->inf_prof = calloc(1, sizeof(struct inf_profile));
  return afl;

}

static struct queue_entry *make_entry(u32 len) {

  struct queue_entry *q = calloc(1, sizeof(struct queue_entry));
  q->len = len;
  q->skipdet_e = calloc(1, sizeof(struct skipdet_entry));
  q->skipdet_e->continue_inf = 1;
  return q;

}

static void test_skipdet_resumes_past_32k(void **state) {

  (void)state;
  const u32           len = 32 * 1024 * 2 + 100;
  afl_state_t        *afl = make_afl();
  struct queue_entry *q = make_entry(len);
  afl->queue_cur = q;

  u8 *orig_buf = malloc(len), *out_buf = malloc(len);
  memset(orig_buf, 0xAA, len);
  memset(out_buf, 0xAA, len);

  early_pos = 7;
  late_pos = len - 3;
  quick_runs = 0;

  u8 r = skip_deterministic_stage(afl, orig_buf, out_buf, len, fake_time);
  assert_int_equal(r, 1);
  assert_int_equal(q->skipdet_e->done_eff, 0);
  assert_true(bitmap_read(q->skipdet_e->skip_eff_map, early_pos));
  assert_false(bitmap_read(q->skipdet_e->skip_eff_map, late_pos));
  assert_true(q->skipdet_e->eff_cursor > early_pos);

  u32 prev_cursor = q->skipdet_e->eff_cursor;
  u32 max_cursor = prev_cursor;
  int guard = 0;

  while (!q->skipdet_e->done_eff && guard++ < 100) {

    memset(out_buf, 0xAA, len);
    r = skip_deterministic_stage(afl, orig_buf, out_buf, len, fake_time);
    assert_int_equal(r, 1);

    if (!q->skipdet_e->done_eff) {

      assert_true(q->skipdet_e->eff_cursor > prev_cursor);
      prev_cursor = q->skipdet_e->eff_cursor;
      if (prev_cursor > max_cursor) max_cursor = prev_cursor;

    }

  }

  assert_int_equal(q->skipdet_e->done_eff, 1);
  assert_int_equal(q->skipdet_e->eff_cursor, 0);
  assert_true(max_cursor > 32u * 1024u);
  assert_true(bitmap_read(q->skipdet_e->skip_eff_map, early_pos));
  assert_true(bitmap_read(q->skipdet_e->skip_eff_map, late_pos));
  assert_int_equal(q->skipdet_e->quick_eff_bytes, 2);

  free(orig_buf);
  free(out_buf);
  free(q->skipdet_e->skip_eff_map);
  free(q->skipdet_e->done_inf_map);
  free(q->skipdet_e);
  free(q);
  free(afl->fsrv.trace_bits);
  free(afl->map_tmp_buf);
  free(afl->var_bytes);
  free(afl->skipdet_g->inf_prof);
  free(afl->skipdet_g);
  free(afl);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_skipdet_resumes_past_32k),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

