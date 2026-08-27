/* Regression tests for Frameshift relation bookkeeping (P2-15): insertion
   boundary (idx == pos) semantics and lightweight_run reporting a skipped
   execution instead of leaving a stale trace. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"

int  rel_on_insert(fs_relation_t *rel, u64 idx, u64 size);
int  rel_on_remove(fs_relation_t *rel, u64 idx, u64 size);
void rel_apply(u8 *buf, fs_relation_t *rel);
int fs_track_insert(fs_meta_t *meta, u64 idx, u64 data_size, u8 ignore_invalid);
void fs_sanitize(fs_meta_t *meta, u8 *buf, u32 len);
u8   lightweight_run(afl_state_t *afl, u8 *out_buf, u32 len);
u64  frameshift_slice_budget(u64 spent_ms, u64 allowed_ms);
u64  frameshift_shift_amount(u8 size, u64 curr_size);

static u8                g_write_ok = 1;
static u64               g_time;
static u64               g_run_advance;
static u32               g_run_calls;
static u32               g_timeout;
static fsrv_run_result_t g_fault;

u64 get_cur_time(void) {

  return g_time;

}

u32 write_to_testcase(afl_state_t *afl, void **mem, u32 len, u32 fix) {

  (void)afl;
  (void)mem;
  (void)fix;
  return g_write_ok ? len : 0;

}

fsrv_run_result_t fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv,
                                  u32 timeout) {

  (void)afl;
  (void)fsrv;
  ++g_run_calls;
  g_timeout = timeout;
  g_time += g_run_advance;
  return g_fault;

}

u8 save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {

  (void)afl;
  (void)mem;
  (void)len;
  (void)fault;
  return 0;

}

static void test_rel_insert_at_pos_shifts_field(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 10,
                       .val = 5,
                       .anchor = 20,
                       .insert = 30,
                       .size = 4,
                       .le = 1,
                       .enabled = 1};

  int r = rel_on_insert(&rel, 10, 3);
  assert_int_equal(r, 0);
  assert_int_equal(rel.pos, 13);
  assert_int_equal(rel.anchor, 23);
  assert_int_equal(rel.insert, 33);

}

static void test_rel_insert_inside_field_errors(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 10,
                       .val = 5,
                       .anchor = 20,
                       .insert = 30,
                       .size = 4,
                       .le = 1,
                       .enabled = 1};

  assert_int_equal(rel_on_insert(&rel, 11, 3), 1);

}

static void test_rel_insert_after_field_no_shift(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 10,
                       .val = 5,
                       .anchor = 20,
                       .insert = 30,
                       .size = 4,
                       .le = 1,
                       .enabled = 1};

  assert_int_equal(rel_on_insert(&rel, 15, 3), 0);
  assert_int_equal(rel.pos, 10);

}

static void test_rel_insert_between_anchor_insert_updates_val(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 50,
                       .val = 5,
                       .anchor = 20,
                       .insert = 30,
                       .size = 4,
                       .le = 1,
                       .enabled = 1};

  assert_int_equal(rel_on_insert(&rel, 25, 3), 0);
  assert_int_equal(rel.val, 8);
  assert_int_equal(rel.pos, 53);

}

static void test_rel_insert_rejects_full_width_wrap(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 50,
                       .val = 5,
                       .anchor = 20,
                       .insert = 30,
                       .size = 1,
                       .le = 1,
                       .enabled = 1};

  assert_int_equal(rel_on_insert(&rel, 25, 256), 1);

}

static void test_tracking_disables_wrapped_relation(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 0,
                       .val = 5,
                       .anchor = 1,
                       .insert = 10,
                       .size = 1,
                       .le = 1,
                       .enabled = 1};
  fs_meta_t     meta = {.relations = &rel, .rel_count = 1, .rel_capacity = 1};
  u8            buf[300] = {99};

  assert_int_equal(fs_track_insert(&meta, 5, 256, 1), 0);
  assert_int_equal(rel.enabled, 0);

  fs_sanitize(&meta, buf, sizeof(buf));
  assert_int_equal(buf[0], 99);

}

static void test_shift_amount_never_overflows_field(void **state) {

  (void)state;
  assert_int_equal(frameshift_shift_amount(1, 0x10), 0x20);
  assert_int_equal(frameshift_shift_amount(1, 0xf0), 0x0f);
  assert_int_equal(frameshift_shift_amount(1, 0xff), 0);
  assert_int_equal(frameshift_shift_amount(2, 0x100), 0xff);
  assert_int_equal(frameshift_shift_amount(2, 0xff80), 0x7f);
  assert_int_equal(frameshift_shift_amount(2, 0xffff), 0);
  assert_int_equal(frameshift_shift_amount(4, 0xffffff80), 0x7f);
  assert_int_equal(frameshift_shift_amount(4, 0xffffffff), 0);
  assert_int_equal(frameshift_shift_amount(8, 0x1000), 0xff);

}

static void test_rel_remove_overlapping_field_errors(void **state) {

  (void)state;
  fs_relation_t rel = {.pos = 10,
                       .val = 5,
                       .anchor = 20,
                       .insert = 30,
                       .size = 4,
                       .le = 1,
                       .enabled = 1};

  assert_int_equal(rel_on_remove(&rel, 12, 1), 1);

}

static void test_rel_apply_endianness(void **state) {

  (void)state;
  u8            buf[8];
  fs_relation_t rel = {.pos = 2, .val = 0x0102, .size = 2, .le = 1};

  memset(buf, 0, sizeof(buf));
  rel_apply(buf, &rel);
  assert_int_equal(buf[2], 0x02);
  assert_int_equal(buf[3], 0x01);

  rel.le = 0;
  memset(buf, 0, sizeof(buf));
  rel_apply(buf, &rel);
  assert_int_equal(buf[2], 0x01);
  assert_int_equal(buf[3], 0x02);

}

static void test_lightweight_run_reports_skip(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  u8 buf[8] = {0};

  g_time = 0;
  g_run_advance = 0;
  g_run_calls = 0;
  g_fault = FSRV_RUN_OK;
  afl->frameshift_deadline = 1000;
  afl->fsrv.exec_tmout = 500;
  afl->crash_mode = FSRV_RUN_OK;

  g_write_ok = 0;
  assert_int_equal(lightweight_run(afl, buf, sizeof(buf)), 0);
  assert_int_equal(g_run_calls, 0);

  g_write_ok = 1;
  assert_int_equal(lightweight_run(afl, buf, sizeof(buf)), 1);
  assert_int_equal(g_run_calls, 1);
  assert_int_equal(g_timeout, 500);

  free(afl);

}

static void test_lightweight_run_deadline_and_fault(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(*afl));
  assert_non_null(afl);
  u8 buf[8] = {0};

  g_write_ok = 1;
  g_time = 100;
  g_run_advance = 0;
  g_run_calls = 0;
  g_fault = FSRV_RUN_OK;
  afl->frameshift_deadline = 100;
  afl->fsrv.exec_tmout = 500;
  afl->crash_mode = FSRV_RUN_OK;

  assert_int_equal(lightweight_run(afl, buf, sizeof(buf)), 2);
  assert_int_equal(g_run_calls, 0);

  g_time = 900;
  afl->frameshift_deadline = 1000;
  assert_int_equal(lightweight_run(afl, buf, sizeof(buf)), 1);
  assert_int_equal(g_timeout, 100);

  g_time = 0;
  afl->frameshift_deadline = 1000;
  g_fault = FSRV_RUN_TMOUT;
  assert_int_equal(lightweight_run(afl, buf, sizeof(buf)), 0);

  g_fault = FSRV_RUN_OK;
  g_run_advance = 1000;
  assert_int_equal(lightweight_run(afl, buf, sizeof(buf)), 2);

  free(afl);

}

static void test_slice_budget_no_credit(void **state) {

  (void)state;
  assert_int_equal(frameshift_slice_budget(0, 0), 0);
  assert_int_equal(frameshift_slice_budget(500, 500), 0);
  assert_int_equal(frameshift_slice_budget(600, 500), 0);

}

static void test_slice_budget_below_min_slice(void **state) {

  (void)state;
  assert_int_equal(frameshift_slice_budget(0, 199), 0);
  assert_int_equal(frameshift_slice_budget(1900, 2000), 0);
  assert_int_equal(frameshift_slice_budget(0, 200), 200);
  assert_int_equal(frameshift_slice_budget(1800, 2000), 200);

}

static void test_slice_budget_partial_remaining(void **state) {

  (void)state;
  assert_int_equal(frameshift_slice_budget(100, 1000), 900);

}

static void test_slice_budget_caps_at_full(void **state) {

  (void)state;
  assert_int_equal(frameshift_slice_budget(0, 2000), 2000);
  assert_int_equal(frameshift_slice_budget(0, 10000), 2000);
  assert_int_equal(frameshift_slice_budget(5000, 10000), 2000);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_rel_insert_at_pos_shifts_field),
      cmocka_unit_test(test_rel_insert_inside_field_errors),
      cmocka_unit_test(test_rel_insert_after_field_no_shift),
      cmocka_unit_test(test_rel_insert_between_anchor_insert_updates_val),
      cmocka_unit_test(test_rel_insert_rejects_full_width_wrap),
      cmocka_unit_test(test_tracking_disables_wrapped_relation),
      cmocka_unit_test(test_shift_amount_never_overflows_field),
      cmocka_unit_test(test_rel_remove_overlapping_field_errors),
      cmocka_unit_test(test_rel_apply_endianness),
      cmocka_unit_test(test_lightweight_run_reports_skip),
      cmocka_unit_test(test_lightweight_run_deadline_and_fault),
      cmocka_unit_test(test_slice_budget_no_credit),
      cmocka_unit_test(test_slice_budget_below_min_slice),
      cmocka_unit_test(test_slice_budget_partial_remaining),
      cmocka_unit_test(test_slice_budget_caps_at_full),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

