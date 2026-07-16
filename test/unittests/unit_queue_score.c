/* Regression tests for calculate_score() purity (P2-16) and the LIN/QUAD
   floating-point factor computation. */

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

static void test_consume_handicap_invalidates_score_table(void **state) {

  (void)state;
  afl_state_t        afl;
  struct queue_entry q;
  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  q.handicap = 9;
  consume_handicap(&afl, &q);
  assert_int_equal(q.handicap, 5);
  assert_int_equal(afl.reinit_table, 1);

  afl.reinit_table = 0;
  consume_handicap(&afl, &q);
  assert_int_equal(q.handicap, 1);
  assert_int_equal(afl.reinit_table, 1);

  afl.reinit_table = 0;
  consume_handicap(&afl, &q);
  assert_int_equal(q.handicap, 0);
  assert_int_equal(afl.reinit_table, 1);

  afl.reinit_table = 0;
  consume_handicap(&afl, &q);
  assert_int_equal(q.handicap, 0);
  assert_int_equal(afl.reinit_table, 0);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_calculate_score_is_pure),
      cmocka_unit_test(test_lin_fraction_not_truncated),
      cmocka_unit_test(test_quad_fraction_not_truncated),
      cmocka_unit_test(test_consume_handicap_invalidates_score_table),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

