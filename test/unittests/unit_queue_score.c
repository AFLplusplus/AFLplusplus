/* Regression tests for queue scoring and culling. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"

AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  (void)afl;
  return 0;

}

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i;

  memset(dst, 0, (afl->fsrv.map_size + 7) >> 3);
  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (src[i]) { dst[i >> 3] |= 1 << (i & 7); }

  }

}

void vp_coverage_owner_released(afl_state_t *afl, struct queue_entry *q) {

  (void)afl;
  (void)q;

}

void vp_apply_delayed_evictions(afl_state_t *afl) {

  (void)afl;

}

void vp_mark_favored_queue_entry(afl_state_t *afl, struct queue_entry *q) {

  (void)afl;
  (void)q;

}

u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

  (void)afl;
  (void)virgin_map;
  return 0;

}

u32 write_to_testcase(afl_state_t *afl, void **mem, u32 len, u32 fix) {

  (void)afl;
  (void)mem;
  (void)fix;
  return len;

}

fsrv_run_result_t fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv,
                                  u32 timeout) {

  (void)afl;
  (void)timeout;
  memset(fsrv->trace_bits, 0, fsrv->map_size);
  fsrv->trace_bits[0] = 1;
  return FSRV_RUN_OK;

}

void classify_counts(afl_forkserver_t *fsrv) {

  (void)fsrv;

}

static void base_state(afl_state_t *afl) {

  memset(afl, 0, sizeof(*afl));
  afl->havoc_max_mult = HAVOC_MAX_MULT;
  afl->total_cal_cycles = 1;
  afl->total_cal_us = 500;
  afl->total_bitmap_entries = 1;
  afl->total_bitmap_size = 100;

}

static void base_entry(struct queue_entry *q) {

  memset(q, 0, sizeof(*q));
  q->exec_us = 500;
  q->bitmap_size = 100;
  q->depth = 0;
  q->len = 100;

}

static void test_calculate_score_is_pure(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  base_state(afl);
  afl->schedule = EXPLORE;

  struct queue_entry q;
  base_entry(&q);
  q.handicap = 9;
  q.depth = 5;

  u64 h0 = q.handicap;
  u32 s1 = calculate_score(afl, &q);
  assert_int_equal(q.handicap, h0);

  u32 s2 = calculate_score(afl, &q);
  assert_int_equal(s1, s2);
  assert_int_equal(q.handicap, h0);

  for (int i = 0; i < 100; ++i) {

    assert_int_equal(calculate_score(afl, &q), s1);
    assert_int_equal(q.handicap, h0);

  }

  free(afl);

}

static void test_lin_fraction_not_truncated(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  base_state(afl);
  afl->schedule = LIN;
  u32 nf[1] = {3};
  afl->n_fuzz = nf;

  struct queue_entry q;
  base_entry(&q);
  q.fuzz_level = 1;
  q.n_fuzz_entry = 0;

  assert_int_equal(calculate_score(afl, &q), 25);

  free(afl);

}

static void test_quad_fraction_not_truncated(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  base_state(afl);
  afl->schedule = QUAD;
  u32 nf[1] = {15};
  afl->n_fuzz = nf;

  struct queue_entry q;
  base_entry(&q);
  q.fuzz_level = 3;
  q.n_fuzz_entry = 0;

  assert_int_equal(calculate_score(afl, &q), 56);

  free(afl);

}

static void test_starve_rescores_before_redundant_disable(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);

  struct queue_entry  entries[2];
  struct queue_entry *queue[2] = {&entries[0], &entries[1]};
  u8                  trace_bits[8] = {0};
  u8                  map_tmp[1] = {0};
  u8                  inputs[2] = {0, 1};

  base_entry(&entries[0]);
  base_entry(&entries[1]);
  entries[0].len = 1;
  entries[0].exec_us = 1;
  entries[0].was_fuzzed = 1;
  entries[0].testcase_buf = &inputs[0];
  entries[1].len = 2;
  entries[1].exec_us = 2;
  entries[1].was_fuzzed = 1;
  entries[1].testcase_buf = &inputs[1];

  afl->fsrv.map_size = sizeof(trace_bits);
  afl->fsrv.trace_bits = trace_bits;
  afl->map_tmp_buf = map_tmp;
  afl->top_rated = calloc(afl->fsrv.map_size, sizeof(*afl->top_rated));
  assert_non_null(afl->top_rated);
  afl->queue_buf = queue;
  afl->queued_items = 2;
  afl->active_items = 2;
  afl->starve_minimize = 1;
  afl->score_changed = 1;
  afl->afl_env.afl_disable_redundant = 1;

  cull_queue(afl);

  assert_int_equal(afl->starve_minimize, 3);
  assert_false(entries[0].disabled);
  assert_true(entries[0].favored);
  assert_true(entries[1].disabled);
  assert_ptr_equal(afl->top_rated[0], &entries[0]);

  free(entries[0].trace_mini);
  free(afl->top_rated);
  free(afl);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_calculate_score_is_pure),
      cmocka_unit_test(test_lin_fraction_not_truncated),
      cmocka_unit_test(test_quad_fraction_not_truncated),
      cmocka_unit_test(test_starve_rescores_before_redundant_disable),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

