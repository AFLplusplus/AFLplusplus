/* Regression tests for state fuzzing mode (-J).

   Covers the arithmetic that decides how an input is judged: the shelf cell
   that keeps deep inputs from being compared against tiny fast ones, and the
   allocations the letters ask for. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <math.h>
#include <cmocka.h>
#include "afl-fuzz.h"

/* --- stubs for everything the tested functions do not exercise --- */

AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  (void)afl;
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
  (void)fsrv;
  (void)timeout;
  return FSRV_RUN_OK;

}

void classify_counts(afl_forkserver_t *fsrv) {

  (void)fsrv;

}

u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

  (void)afl;
  (void)virgin_map;
  return 0;

}

u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  (void)afl;
  (void)q;
  return NULL;

}

u32 run_afl_custom_describe_state_ops(afl_state_t *afl, u8 *mem, u32 len,
                                      u32 *offsets, u32 max_ops) {

  (void)afl;
  (void)mem;
  (void)len;
  (void)offsets;
  (void)max_ops;
  return 0;

}

u64 hash64(u8 *key, u32 len, u64 seed) {

  (void)key;
  (void)len;
  return seed;

}

u64 get_cur_time(void) {

  return 0;

}

u64 get_cur_time_us(void) {

  return 0;

}

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 i, ret = 0;

  for (i = 0; i < afl->fsrv.map_size; i++) {

    if (mem[i]) { ++ret; }

  }

  return ret;

}

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 i, ret = 0;

  for (i = 0; i < afl->fsrv.map_size; i++) {

    if (mem[i] != 0xff) { ++ret; }

  }

  return ret;

}

/* --- fixture --- */

#define TEST_MAP 512

static afl_state_t         *afl;
static struct queue_entry **entries;
static u32                  entry_cnt;

static void setup(u32 state_mode) {

  afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);

  afl->fsrv.map_size = TEST_MAP;
  afl->fsrv.real_map_size = TEST_MAP;
  afl->state_mode = state_mode;

  afl->fsrv.trace_bits = calloc(1, TEST_MAP);
  afl->virgin_bits = malloc(TEST_MAP);
  memset(afl->virgin_bits, 255, TEST_MAP);

  state_alloc(afl);

  entries = NULL;
  entry_cnt = 0;

}

static void teardown(void) {

  u32 i;

  state_free(afl);
  free(afl->fsrv.trace_bits);
  free(afl->virgin_bits);

  for (i = 0; i < entry_cnt; i++) {

    free(entries[i]);

  }

  free(entries);
  free(afl->queue_buf);
  free(afl);

}

static struct queue_entry *add_entry(void) {

  struct queue_entry *q = calloc(1, sizeof(struct queue_entry));

  assert_non_null(q);

  entries = realloc(entries, (entry_cnt + 1) * sizeof(void *));
  entries[entry_cnt] = q;

  afl->queue_buf = realloc(afl->queue_buf, (entry_cnt + 1) * sizeof(void *));
  afl->queue_buf[entry_cnt] = q;

  ++entry_cnt;
  afl->queued_items = entry_cnt;

  return q;

}

/* --- the deep-input shelf --- */

static void test_shelf_cell_separates_depth(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP);

  struct queue_entry *shallow = add_entry();
  struct queue_entry *deep = add_entry();

  shallow->len = 8;
  shallow->exec_us = 100;
  deep->len = 4000;
  deep->exec_us = 100;

  state_shelf_cell(afl, shallow);
  state_shelf_cell(afl, deep);

  u32 a = state_shelf_cell(afl, shallow);
  u32 b = state_shelf_cell(afl, deep);

  assert_int_not_equal(a, b);
  assert_true(a < STATE_SHELF_CELLS);
  assert_true(b < STATE_SHELF_CELLS);

  teardown();

}

static void test_shelf_cell_separates_cost(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP);

  struct queue_entry *fast = add_entry();
  struct queue_entry *slow = add_entry();

  fast->len = 4;
  fast->exec_us = 10;
  slow->len = 4;
  slow->exec_us = 900000;

  state_shelf_cell(afl, fast);
  state_shelf_cell(afl, slow);

  assert_int_not_equal(state_shelf_cell(afl, fast),
                       state_shelf_cell(afl, slow));

  teardown();

}

/* An operation count is what the achievement axis is for; where a mutator
   reports one it must beat the file size it falls back to. */

static void test_shelf_cell_prefers_op_count(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP);

  struct queue_entry *few = add_entry();
  struct queue_entry *many = add_entry();

  few->len = 4000;
  few->exec_us = 100;
  few->op_count = 2;
  many->len = 8;
  many->exec_us = 100;
  many->op_count = 200;

  state_shelf_cell(afl, few);
  state_shelf_cell(afl, many);

  assert_true(state_shelf_cell(afl, many) > state_shelf_cell(afl, few));

  teardown();

}

static void test_shelf_cell_always_in_range(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP);

  struct queue_entry *q = add_entry();

  for (u32 i = 0; i < 64; i++) {

    q->len = (u64)1 << i % 40;
    q->exec_us = (u64)1 << i % 40;
    q->op_count = i * 2654435761u;
    assert_true(state_shelf_cell(afl, q) < STATE_SHELF_CELLS);

  }

  teardown();

}

/* --- allocation is driven by the letters --- */

static void test_alloc_follows_the_letters(void **unused) {

  (void)unused;
  setup(STATE_MODE_CONTRACT);

  assert_null(afl->hw_bits);
  assert_null(afl->shelf);

  teardown();

  setup(STATE_MODE_DEEP | STATE_MODE_HIWATER);

  assert_non_null(afl->hw_bits);
  assert_non_null(afl->shelf);
  assert_non_null(afl->shelf_count);

  teardown();

}

static void test_alloc_is_idempotent(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP | STATE_MODE_HIWATER);

  struct queue_entry **shelf = afl->shelf;
  u8                  *hw = afl->hw_bits;

  state_alloc(afl);
  state_alloc(afl);

  assert_ptr_equal(afl->shelf, shelf);
  assert_ptr_equal(afl->hw_bits, hw);

  teardown();

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_shelf_cell_separates_depth),
      cmocka_unit_test(test_shelf_cell_separates_cost),
      cmocka_unit_test(test_shelf_cell_prefers_op_count),
      cmocka_unit_test(test_shelf_cell_always_in_range),
      cmocka_unit_test(test_alloc_follows_the_letters),
      cmocka_unit_test(test_alloc_is_idempotent),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

