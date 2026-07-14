#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"

#define OP_A 5
#define OP_B 10
#define OP_C 20

static void test_ctx_index(void **state) {

  (void)state;
  assert_int_equal(mopt_ctx_index(0, 0), 0);
  assert_int_equal(mopt_ctx_index(0, 1), 1);
  assert_int_equal(mopt_ctx_index(1, 0), 2);
  assert_int_equal(mopt_ctx_index(1, 1), 3);
  assert_int_equal(mopt_ctx_index(2, 0), 4);
  assert_int_equal(mopt_ctx_index(2, 1), 5);
  assert_int_equal(mopt_ctx_index(9, 0), 0);

}

static void test_rebuild_fills_full_lut(void **state) {

  (void)state;
  struct mopt_ctx c;
  memset(&c, 0, sizeof(c));
  u32 prior[8] = {OP_A, OP_A, OP_B, OP_C, 0, 1, 2, 3};
  mopt_rebuild_ctx(&c, prior, 8);

  for (u32 i = 0; i < MOPT_LUT_SIZE; ++i)
    assert_in_range(c.learned_array[i], 0, MOPT_OP_MAX - 1);

}

static void test_no_signal_tracks_prior(void **state) {

  (void)state;
  struct mopt_ctx c;
  memset(&c, 0, sizeof(c));
  u32 prior[4] = {OP_A, OP_A, OP_A, OP_B};
  mopt_rebuild_ctx(&c, prior, 4);

  u32 counts[MOPT_OP_MAX];
  memset(counts, 0, sizeof(counts));
  for (u32 i = 0; i < MOPT_LUT_SIZE; ++i)
    counts[c.learned_array[i]]++;

  assert_true(counts[OP_A] > MOPT_LUT_SIZE / 2);
  for (u32 op = 0; op < MOPT_OP_MAX; ++op)
    if (op != OP_A && op != OP_B) assert_true(counts[op] <= 1);

}

static void test_learned_signal_shifts_weight(void **state) {

  (void)state;
  struct mopt_ctx c;
  memset(&c, 0, sizeof(c));
  c.op_uses[OP_B] = 100;
  c.op_finds[OP_B] = 50;
  c.op_uses[OP_A] = 100;
  c.op_finds[OP_A] = 0;
  u32 prior[2] = {OP_A, OP_B};
  mopt_rebuild_ctx(&c, prior, 2);

  u32 a = 0, b = 0;
  for (u32 i = 0; i < MOPT_LUT_SIZE; ++i) {

    if (c.learned_array[i] == OP_A)
      a++;
    else if (c.learned_array[i] == OP_B)
      b++;

  }

  assert_true(b > a);
  assert_true(a > 0);

}

static void test_decay_reduces_tallies(void **state) {

  (void)state;
  struct mopt_ctx c;
  memset(&c, 0, sizeof(c));
  c.op_uses[OP_B] = 1000;
  c.op_finds[OP_B] = 1000;
  u32 prior[1] = {OP_B};
  mopt_rebuild_ctx(&c, prior, 1);
  assert_int_equal(c.op_uses[OP_B], 900);
  assert_int_equal(c.op_finds[OP_B], 900);

}

static void test_policy_prefers_higher_finds_per_sec(void **state) {

  (void)state;
  struct mopt_ctx c;
  memset(&c, 0, sizeof(c));
  c.arm_execs[0] = 1000;
  c.arm_finds[0] = 5;
  c.arm_time_us[0] = 1000000;
  c.arm_execs[1] = 1000;
  c.arm_finds[1] = 20;
  c.arm_time_us[1] = 1000000;
  mopt_policy_update(&c);
  assert_int_equal(c.active_arm, 1);

  memset(&c, 0, sizeof(c));
  c.arm_execs[0] = 1000;
  c.arm_finds[0] = 20;
  c.arm_time_us[0] = 1000000;
  c.arm_execs[1] = 1000;
  c.arm_finds[1] = 5;
  c.arm_time_us[1] = 1000000;
  mopt_policy_update(&c);
  assert_int_equal(c.active_arm, 0);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_ctx_index),
      cmocka_unit_test(test_rebuild_fills_full_lut),
      cmocka_unit_test(test_no_signal_tracks_prior),
      cmocka_unit_test(test_learned_signal_shifts_weight),
      cmocka_unit_test(test_decay_reduces_tallies),
      cmocka_unit_test(test_policy_prefers_higher_finds_per_sec),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

