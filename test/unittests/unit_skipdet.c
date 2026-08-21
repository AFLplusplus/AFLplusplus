/* Regression tests for SkipDet threshold admission, block inference, and
   quick-effective-map resume. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"

u8 should_det_fuzz(afl_state_t *, struct queue_entry *);

static u64 fake_time = 0;
static u32 early_pos;
static u32 late_pos;
static u32 quick_runs;
static u8  correlated_mode;

u64 get_cur_time(void) {

  return fake_time;

}

u8 common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  memset(afl->fsrv.trace_bits, 0, afl->fsrv.map_size);
  ++afl->fsrv.total_execs;

  if (!strcmp(afl->stage_short, "inf")) {

    if (correlated_mode) {

      afl->fsrv.trace_bits[1] = out_buf[0] ^ out_buf[1];

    } else {

      for (u32 i = 0; i < len; ++i) {

        if (out_buf[i] != 0xaa) {

          afl->fsrv.trace_bits[1] = 1;
          break;

        }

      }

    }

  } else if (!strcmp(afl->stage_short, "quick")) {

    ++quick_runs;
    afl->fsrv.trace_bits[3] = quick_runs & 1;
    if (correlated_mode) {

      afl->fsrv.trace_bits[2] = out_buf[0] ^ out_buf[1];

    } else if (out_buf[early_pos] != 0xaa || out_buf[late_pos] != 0xaa) {

      afl->fsrv.trace_bits[2] = 1;

    }

    if (afl->fsrv.trace_bits[2]) { ++afl->queued_items; }

  }

  return 0;

}

AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  (void)afl;
  return 0;

}

void afl_trig_log(afl_state_t *afl, const char *event, u8 mode) {

  (void)afl;
  (void)event;
  (void)mode;

}

static afl_state_t *make_afl(u32 map_size) {

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  afl->fixed_seed = 1;
  afl->fsrv.map_size = map_size;
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

static struct queue_entry *make_threshold_entry(u32 map_size, u32 bit_count) {

  struct queue_entry *q = make_entry(1);
  q->favored = 1;
  q->trace_mini = calloc(1, (map_size + 7) / 8);
  for (u32 i = 0; i < bit_count; ++i)
    bitmap_set(q->trace_mini, i);
  return q;

}

static void free_entry(struct queue_entry *q) {

  free(q->trace_mini);
  free(q->skipdet_e->skip_eff_map);
  free(q->skipdet_e->done_inf_map);
  free(q->skipdet_e);
  free(q);

}

static void free_afl(afl_state_t *afl) {

  free(afl->fsrv.trace_bits);
  free(afl->map_tmp_buf);
  free(afl->var_bytes);
  free(afl->skipdet_g->inf_prof);
  free(afl->skipdet_g->virgin_det_bits);
  free(afl->skipdet_g);
  free(afl);

}

static void check_initial_threshold(u32 bit_count, u32 expected_threshold,
                                    u8 expected_result) {

  afl_state_t        *afl = make_afl(64);
  struct queue_entry *q = make_threshold_entry(afl->fsrv.map_size, bit_count);

  assert_int_equal(should_det_fuzz(afl, q), expected_result);
  assert_int_equal(afl->skipdet_g->undet_bits_threshold, expected_threshold);
  assert_int_equal(q->skipdet_e->undet_bits, expected_result ? bit_count : 0);

  free_entry(q);
  free_afl(afl);

}

static void test_skipdet_initial_thresholds(void **state) {

  (void)state;
  fake_time = 1;
  check_initial_threshold(0, 0, 0);
  check_initial_threshold(1, 1, 1);
  check_initial_threshold(19, 1, 1);
  check_initial_threshold(20, 1, 1);
  check_initial_threshold(21, 2, 1);

}

static void test_skipdet_threshold_decay(void **state) {

  (void)state;
  afl_state_t        *afl = make_afl(64);
  struct queue_entry *q = make_threshold_entry(afl->fsrv.map_size, 1);

  afl->skipdet_g->undet_bits_threshold = 2;
  afl->skipdet_g->last_cov_undet_execs = 1;
  afl->fsrv.total_execs = 1 + SKIPDET_DECAY_EXECS;
  assert_true(should_det_fuzz(afl, q));
  assert_int_equal(afl->skipdet_g->undet_bits_threshold, 1);

  free_entry(q);
  free_afl(afl);

  afl = make_afl(64);
  q = make_threshold_entry(afl->fsrv.map_size, 1);
  afl->skipdet_g->undet_bits_threshold = 3;
  afl->skipdet_g->last_cov_undet_execs = 1;
  afl->fsrv.total_execs = 1 + SKIPDET_DECAY_EXECS;
  assert_false(should_det_fuzz(afl, q));
  assert_int_equal(afl->skipdet_g->undet_bits_threshold, 2);

  free_entry(q);
  free_afl(afl);

}

static void test_skipdet_correlated_block(void **state) {

  (void)state;
  const u32           len = 1024;
  afl_state_t        *afl = make_afl(8);
  struct queue_entry *q = make_entry(len);
  afl->queue_cur = q;

  u8 *orig_buf = malloc(len), *out_buf = malloc(len);
  memset(orig_buf, 0xaa, len);
  memset(out_buf, 0xaa, len);

  correlated_mode = 1;
  quick_runs = 0;
  fake_time = 0;

  afl->det_start_time = fake_time;
  afl->det_start_execs = afl->fsrv.total_execs;
  assert_true(skip_deterministic_stage(afl, orig_buf, out_buf, len));
  assert_true(q->skipdet_e->done_eff);
  assert_true(bitmap_read(q->skipdet_e->skip_eff_map, 0));
  assert_true(bitmap_read(q->skipdet_e->skip_eff_map, 1));
  assert_int_equal(q->skipdet_e->quick_eff_bytes, 2);

  correlated_mode = 0;
  free(orig_buf);
  free(out_buf);
  free_entry(q);
  free_afl(afl);

}

static void test_skipdet_resumes_past_32k(void **state) {

  (void)state;
  const u32           len = 32 * 1024 * 2 + 100;
  afl_state_t        *afl = make_afl(8);
  struct queue_entry *q = make_entry(len);
  afl->queue_cur = q;

  u8 *orig_buf = malloc(len), *out_buf = malloc(len);
  memset(orig_buf, 0xAA, len);
  memset(out_buf, 0xAA, len);

  early_pos = 7;
  late_pos = len - 3;
  quick_runs = 0;
  correlated_mode = 0;

  afl->det_start_time = fake_time;
  afl->det_start_execs = afl->fsrv.total_execs;
  u8 r = skip_deterministic_stage(afl, orig_buf, out_buf, len);
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
    afl->det_start_time = fake_time;
    afl->det_start_execs = afl->fsrv.total_execs;
    r = skip_deterministic_stage(afl, orig_buf, out_buf, len);
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
  free_entry(q);
  free_afl(afl);

}

static void test_is_det_timeout_exec_cap(void **state) {

  (void)state;
  afl_state_t *afl = make_afl(64);
  fake_time = 1000;
  afl->det_start_time = fake_time;
  afl->det_start_execs = 0;

  afl->fsrv.total_execs = 0;
  assert_int_equal(is_det_timeout(afl, 0), 0);
  assert_int_equal(is_det_timeout(afl, 1), 0);

  afl->fsrv.total_execs = MAX_EFF_EXECS + 1;
  assert_int_equal(is_det_timeout(afl, 1), 1);
  assert_int_equal(is_det_timeout(afl, 0), 0);

  afl->fsrv.total_execs = MAX_DET_EXECS + 1;
  assert_int_equal(is_det_timeout(afl, 0), 1);

  free_afl(afl);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_skipdet_initial_thresholds),
      cmocka_unit_test(test_skipdet_threshold_decay),
      cmocka_unit_test(test_skipdet_correlated_block),
      cmocka_unit_test(test_skipdet_resumes_past_32k),
      cmocka_unit_test(test_is_det_timeout_exec_cap),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

