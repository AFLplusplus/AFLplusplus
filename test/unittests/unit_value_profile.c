#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
/* cmocka < 1.0 didn't support these features we need */
#ifndef assert_ptr_equal
  #define assert_ptr_equal(a, b)                                      \
    _assert_int_equal(cast_ptr_to_largest_integral_type(a),           \
                      cast_ptr_to_largest_integral_type(b), __FILE__, \
                      __LINE__)
  #define CMUnitTest UnitTest
  #define cmocka_unit_test unit_test
  #define cmocka_run_group_tests(t, setup, teardown) run_tests(t)
#endif

extern void mock_assert(const int result, const char *const expression,
                        const char *const file, const int line);
#undef assert
#define assert(expression) \
  mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#include "afl-fuzz.h"
#include "value-profile.h"

/* Stubs for functions referenced by afl-fuzz-valprof.o. */
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

/* remap exit -> assert, then use cmocka's mock_assert
   (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
void        __wrap_exit(int status) {

  (void)status;
  assert(0);

}

/* ignore all printfs */
#undef printf
extern int printf(const char *format, ...);
int        __wrap_printf(const char *format, ...) {

  (void)format;
  return 1;

}

/* Deterministic clock for vp_update_activation(). */
static u64 fake_time_ms;
u64        get_cur_time(void) {

  return fake_time_ms;

}

static void test_mode2_activation_and_deactivation(void **state) {

  (void)state;

  afl_state_t afl;
  memset(&afl, 0, sizeof(afl));

  afl.value_profile_mode = 2;
  afl.value_profile_stagnation_secs = 60;
  fake_time_ms = 61000;
  afl.start_time = 0;
  afl.queue_cycle = 7;

  vp_update_activation(&afl);
  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_enabled_cycle, 7);
  assert_int_equal(afl.score_changed, 1);

  /* A fresh edge find in the same cycle should not disable VP yet. */
  afl.score_changed = 0;
  afl.last_cov_find_time = fake_time_ms;
  vp_update_activation(&afl);
  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_enabled_cycle, 7);
  assert_int_equal(afl.score_changed, 0);

  /* Disable after one full cycle once edge coverage recovers. */
  afl.score_changed = 0;
  afl.queue_cycle = 8;
  afl.last_cov_find_time = fake_time_ms;
  vp_update_activation(&afl);
  assert_int_equal(afl.value_profile_active, 0);
  assert_int_equal(afl.value_profile_enabled_cycle, 0);
  assert_int_equal(afl.score_changed, 1);

}

static void test_non_stagnation_mode_is_noop(void **state) {

  (void)state;

  afl_state_t afl;
  memset(&afl, 0, sizeof(afl));

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.value_profile_enabled_cycle = 5;
  afl.score_changed = 0;

  vp_update_activation(&afl);
  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_enabled_cycle, 5);
  assert_int_equal(afl.score_changed, 0);

}

static void setup_vp_frontier(afl_state_t *afl, u32 slots);
static void free_vp_frontier(afl_state_t *afl);

static void test_wide_ins_compare_keeps_vp_site_active(void **state) {

  (void)state;

  afl_state_t         afl;
  struct cmp_map     *cmp;
  struct queue_entry  old_q, new_q;
  struct queue_entry *vp_saved;

  memset(&afl, 0, sizeof(afl));
  memset(&old_q, 0, sizeof(old_q));
  memset(&new_q, 0, sizeof(new_q));

  cmp = calloc(1, sizeof(struct cmp_map));
  assert_non_null(cmp);
  afl.shm.cmp_map = cmp;
  afl.value_profile_level = 2;
  afl.value_profile_source = VP_SOURCE_CMPLOG_INLINE;

  setup_vp_frontier(&afl, 1);

  old_q.exec_us = 100;
  old_q.len = 100;
  old_q.vp_ref_cnt = 1;
  new_q.exec_us = 1;
  new_q.len = 1;

  /* 16-byte compare with identical low half and differing high half. */
  cmp->headers[0].hits = 1;
  cmp->headers[0].type = CMP_TYPE_INS;
  cmp->headers[0].shape = 15;                                   /* 16 bytes */
  cmp->log[0][0].v0 = 0x1122334455667788ULL;
  cmp->log[0][0].v1 = 0x1122334455667788ULL;
  cmp->log[0][0].v0_128 = 0x1ULL;
  cmp->log[0][0].v1_128 = 0x2ULL;
  afl.vp_trigger_bitmap[0] = 1;

  afl.vp_frontier[0].owner = &old_q;
  afl.vp_frontier[0].dist = 10;
  afl.vp_frontier[0].tag = 0;
  afl.vp_frontier[0].cost = 10000;
  afl.top_rated_vp[0] = &old_q;
  afl.top_rated_vp_dist[0] = 10;

  vp_frontier_apply(&afl, &new_q);

  vp_saved = afl.top_rated_vp[0];
  assert_ptr_equal(vp_saved, &new_q);
  assert_int_equal(old_q.vp_ref_cnt, 0);
  assert_true(new_q.vp_ref_cnt > 0);
  assert_true(afl.top_rated_vp_dist[0] < 65);
  assert_true(afl.top_rated_vp_dist[0] != 0xffffffff);

  free_vp_frontier(&afl);
  free(cmp);

}

static void test_solved_wide_ins_compare_does_not_consume_vp_bits(
    void **state) {

  (void)state;

  afl_state_t     afl;
  struct cmp_map *cmp;
  u8             *virgin;
  u32             bits;

  memset(&afl, 0, sizeof(afl));

  cmp = calloc(1, sizeof(struct cmp_map));
  assert_non_null(cmp);
  virgin = calloc(1, VALUE_PROFILE_MAP_SIZE);
  assert_non_null(virgin);
  memset(virgin, 0xff, VALUE_PROFILE_MAP_SIZE);

  afl.shm.cmp_map = cmp;
  afl.virgin_val_prof = virgin;

  cmp->headers[0].hits = 1;
  cmp->headers[0].type = CMP_TYPE_INS;
  cmp->headers[0].shape = 15;                                   /* 16 bytes */
  cmp->log[0][0].v0 = 0x1122334455667788ULL;
  cmp->log[0][0].v1 = 0x1122334455667788ULL;
  cmp->log[0][0].v0_128 = 0x99aabbccddeeff00ULL;
  cmp->log[0][0].v1_128 = 0x99aabbccddeeff00ULL;

  bits = vp_check_cmpmap(&afl);
  assert_int_equal(bits, 0);

  free(virgin);
  free(cmp);

}

static void test_solved_rtn_compare_does_not_consume_vp_bits(void **state) {

  (void)state;

  afl_state_t            afl;
  struct cmp_map        *cmp;
  struct cmpfn_operands *rtn;
  u8                    *virgin;
  u32                    bits;

  memset(&afl, 0, sizeof(afl));

  cmp = calloc(1, sizeof(struct cmp_map));
  assert_non_null(cmp);
  virgin = calloc(1, VALUE_PROFILE_MAP_SIZE);
  assert_non_null(virgin);
  memset(virgin, 0xff, VALUE_PROFILE_MAP_SIZE);

  afl.shm.cmp_map = cmp;
  afl.virgin_val_prof = virgin;

  cmp->headers[0].hits = 1;
  cmp->headers[0].type = CMP_TYPE_RTN;
  rtn = (struct cmpfn_operands *)cmp->log[0];

  /* String-like compare with equal content must not consume VP bits. */
  rtn[0].v0_len = 0x80 + 5;
  rtn[0].v1_len = 0x80 + 5;
  memcpy(rtn[0].v0, "AAAA", 5);
  memcpy(rtn[0].v1, "AAAA", 5);

  bits = vp_check_cmpmap(&afl);
  assert_int_equal(bits, 0);

  free(virgin);
  free(cmp);

}

static void setup_vp_frontier(afl_state_t *afl, u32 slots) {

  size_t n = (size_t)CMP_MAP_W * slots;
  afl->value_profile_level = 1;
  afl->value_profile_slots = slots;
  afl->top_rated_vp = calloc(CMP_MAP_W, sizeof(struct queue_entry *));
  assert_non_null(afl->top_rated_vp);
  afl->top_rated_vp_dist = calloc(CMP_MAP_W, sizeof(u32));
  assert_non_null(afl->top_rated_vp_dist);
  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    afl->top_rated_vp_dist[i] = VP_DIST_UNSOLVED;

  }

  afl->vp_frontier = calloc(n, sizeof(vp_frontier_entry_t));
  assert_non_null(afl->vp_frontier);
  for (size_t i = 0; i < n; ++i) {

    afl->vp_frontier[i].dist = VP_DIST_UNSOLVED;

  }

}

static void free_vp_frontier(afl_state_t *afl) {

  free(afl->vp_frontier);
  free(afl->top_rated_vp_dist);
  free(afl->top_rated_vp);

}

static void test_runtime_frontier_update_with_overflow_scan(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));
  q.exec_us = 3;
  q.len = 7;

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_source = VP_SOURCE_RUNTIME_SHM;
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl, 4);

  vp->exec_id = 1;
  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = 7;
  vp->site[7].valid_mask = 1;
  vp->site[7].touched_mask = 1;
  vp->site[7].slots[0].slot_key = 3;
  vp->site[7].slots[0].best_dist = 9;

  assert_true(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &q);

  assert_ptr_equal(afl.top_rated_vp[7], &q);
  assert_int_equal(afl.top_rated_vp_dist[7], 9);
  assert_true(q.vp_ref_cnt > 0);

  free_vp_frontier(&afl);
  free(vp);

}

int main(int argc, char **argv) {

  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_mode2_activation_and_deactivation),
      cmocka_unit_test(test_non_stagnation_mode_is_noop),
      cmocka_unit_test(test_wide_ins_compare_keeps_vp_site_active),
      cmocka_unit_test(test_solved_wide_ins_compare_does_not_consume_vp_bits),
      cmocka_unit_test(test_solved_rtn_compare_does_not_consume_vp_bits),
      cmocka_unit_test(test_runtime_frontier_update_with_overflow_scan)};

  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}
