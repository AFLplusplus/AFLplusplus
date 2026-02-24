#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
/* cmocka < 1.0 didn't support these features we need */
#ifndef assert_ptr_equal
#define assert_ptr_equal(a, b)                                                  \
  _assert_int_equal(cast_ptr_to_largest_integral_type(a),                      \
                    cast_ptr_to_largest_integral_type(b), __FILE__, __LINE__)
#define CMUnitTest UnitTest
#define cmocka_unit_test unit_test
#define cmocka_run_group_tests(t, setup, teardown) run_tests(t)
#endif

extern void mock_assert(const int result, const char *const expression,
                        const char *const file, const int line);
#undef assert
#define assert(expression)                                                       \
  mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#include "afl-fuzz.h"

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

  afl.top_rated_vp = calloc(CMP_MAP_W, sizeof(struct queue_entry *));
  assert_non_null(afl.top_rated_vp);
  afl.top_rated_vp_dist = calloc(CMP_MAP_W, sizeof(u32));
  assert_non_null(afl.top_rated_vp_dist);
  memset(afl.top_rated_vp_dist, 0xff, CMP_MAP_W * sizeof(u32));

  old_q.exec_us = 100;
  old_q.len = 100;
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

  afl.vp_trigger_bitmap[0] = 1ULL;
  afl.top_rated_vp[0] = &old_q;
  afl.top_rated_vp_dist[0] = 10;

  vp_update_bitmap_score(&afl, &new_q);

  vp_saved = afl.top_rated_vp[0];
  assert_ptr_equal(vp_saved, &new_q);
  assert_true(afl.top_rated_vp_dist[0] < 65);
  assert_true(afl.top_rated_vp_dist[0] != 0xffffffff);

  free(afl.top_rated_vp_dist);
  free(afl.top_rated_vp);
  free(cmp);

}

static void test_solved_wide_ins_compare_does_not_consume_vp_bits(void **state) {

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

int main(int argc, char **argv) {

  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_mode2_activation_and_deactivation),
      cmocka_unit_test(test_non_stagnation_mode_is_noop),
      cmocka_unit_test(test_wide_ins_compare_keeps_vp_site_active),
      cmocka_unit_test(test_solved_wide_ins_compare_does_not_consume_vp_bits),
      cmocka_unit_test(test_solved_rtn_compare_does_not_consume_vp_bits)};

  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));

  // fake return for dumb compilers
  return 0;

}
