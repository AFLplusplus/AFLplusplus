/* Regression tests for state fuzzing mode (-J).

   Covers the arithmetic that decides how an input is judged: the per-input
   stability number, the information score that replaces raw edge count, and
   the shelf cell that keeps deep inputs from being compared against tiny fast
   ones. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <math.h>
#include <cmocka.h>
#include "afl-fuzz.h"

/* --- stubs for everything state_calibration_stats does not exercise --- */

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

void virgin_undo_rollback(afl_state_t *afl, struct queue_entry *q) {

  (void)afl;
  (void)q;

}

void afl_shm_state_env_set(sharedmem_t *shm) {

  (void)shm;

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
  afl->corpus_stability_min = 100.0;

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

/* --- the state map (item 16) --- */

static state_map_t *state_map_setup_fixture(void) {

  static state_map_t map;

  memset(&map, 0, sizeof(map));
  afl->shm.state_mode = 1;
  afl->shm.state_map = &map;
  state_map_setup(afl);

  return &map;

}

static void test_state_map_observing_keeps_admission_unspent(void **unused) {

  (void)unused;
  setup(STATE_MODE_SMAP);

  state_map_t *map = state_map_setup_fixture();

  map->map[17] = 1;

  /* The observational phase runs for every execution and must not consume
     the transitions the admission map is asked about later. */
  state_map_observe(afl);
  state_map_observe(afl);

  assert_int_equal(afl->state_transitions_found, 1);
  assert_int_equal(state_map_has_new(afl), 1);

  teardown();

}

static void test_state_map_admission_consumes_once(void **unused) {

  (void)unused;
  setup(STATE_MODE_SMAP);

  state_map_t *map = state_map_setup_fixture();

  map->map[17] = 1;

  assert_int_equal(state_map_has_new(afl), 1);
  assert_int_equal(state_map_has_new(afl), 0);

  map->map[18] = 1;
  assert_int_equal(state_map_has_new(afl), 1);

  teardown();

}

static void test_situations_counted_with_first_reach_depth(void **unused) {

  (void)unused;
  setup(STATE_MODE_SMAP);

  state_map_t *map = state_map_setup_fixture();
  u8           hist[256];

  map->sit_ok = 1;
  map->sit_n = 3;
  map->transitions = 3;
  map->sit[0] = 5;
  map->sit[1] = 9;
  map->sit[2] = 5;

  state_map_observe(afl);

  assert_int_equal(afl->situations_found, 2);
  assert_int_equal(afl->situation_depth_max, 3);
  assert_int_equal(afl->situation_depth_runs, 1);
  assert_int_equal(afl->situation_depth_sum, 3);

  state_situation_hist(afl, hist, sizeof(hist));
  assert_string_equal((char *)hist, "1:1 2:1");

  /* The same chain again reaches nothing new, but still counts as a run. */
  state_map_observe(afl);

  assert_int_equal(afl->situations_found, 2);
  assert_int_equal(afl->situation_depth_runs, 2);

  teardown();

}

static void test_situations_absent_without_target_support(void **unused) {

  (void)unused;
  setup(STATE_MODE_SMAP);

  state_map_t *map = state_map_setup_fixture();

  map->sit_n = 2;
  map->transitions = 2;
  map->sit[0] = 5;
  map->sit[1] = 9;

  state_map_observe(afl);

  assert_int_equal(afl->situations_found, 0);
  assert_int_equal(afl->situation_depth_runs, 0);

  teardown();

}

static void test_state_map_density_counts_observations(void **unused) {

  (void)unused;
  setup(STATE_MODE_SMAP);

  state_map_t *map = state_map_setup_fixture();

  assert_int_equal(state_map_density(afl), 0);

  u32 i;

  for (i = 0; i < STATE_MAP_SIZE / 4; ++i) {

    map->map[i] = 1;

  }

  state_map_observe(afl);

  /* A quarter of the map, reported in hundredths of a percent. */
  assert_int_equal(state_map_density(afl), 2500);
  assert_int_equal(afl->state_transitions_found, STATE_MAP_SIZE / 4);

  teardown();

}

/* --- the shelf cell (item 9) --- */

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

static void test_shelf_cell_ignores_state_until_trusted(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP);

  struct queue_entry *a = add_entry();
  struct queue_entry *b = add_entry();

  a->len = b->len = 4;
  a->exec_us = b->exec_us = 100;
  a->state_id = 1;
  b->state_id = 2;

  /* An untrusted state signal must not influence bucketing: that is the
     item 16 rule, applied here. */
  assert_int_equal(state_shelf_cell(afl, a), state_shelf_cell(afl, b));

  afl->state_signal_trusted = 1;
  assert_int_not_equal(state_shelf_cell(afl, a), state_shelf_cell(afl, b));

  teardown();

}

static void test_shelf_cell_always_in_range(void **unused) {

  (void)unused;
  setup(STATE_MODE_DEEP);

  struct queue_entry *q = add_entry();

  afl->state_signal_trusted = 1;

  for (u32 i = 0; i < 64; i++) {

    q->depth = (u64)1 << i % 40;
    q->exec_us = (u64)1 << i % 40;
    q->state_id = i * 2654435761u;
    assert_true(state_shelf_cell(afl, q) < STATE_SHELF_CELLS);

  }

  teardown();

}

/* --- per-input stability (item 6) --- */

static void test_stability_clean_entry_is_100(void **unused) {

  (void)unused;
  setup(STATE_MODE_PROBE);

  struct queue_entry *q = add_entry();

  q->bitmap_size = 40;
  memset(afl->cal_var_map, 0, TEST_MAP);

  state_calibration_stats(afl, q);

  assert_int_equal(q->var_edge_cnt, 0);
  assert_int_equal(q->var_hit_cnt, 0);
  assert_true(q->stability > 99.99);

  teardown();

}

static void test_stability_splits_edges_from_hit_counts(void **unused) {

  (void)unused;
  setup(STATE_MODE_PROBE);

  struct queue_entry *q = add_entry();

  q->bitmap_size = 100;
  memset(afl->cal_var_map, 0, TEST_MAP);

  /* 3 edges that came and went, 7 that only wobbled in hit count. The two
     are counted separately because they mean different things: a missing
     edge means a saved input no longer describes what it does, a hit-count
     wobble usually does not. */
  afl->cal_var_map[10] = 2;
  afl->cal_var_map[11] = 2;
  afl->cal_var_map[12] = 2;
  for (u32 i = 20; i < 27; i++) {

    afl->cal_var_map[i] = 1;

  }

  state_calibration_stats(afl, q);

  assert_int_equal(q->var_edge_cnt, 3);
  assert_int_equal(q->var_hit_cnt, 7);
  assert_true(fabs(q->stability - 90.0) < 0.001);

  teardown();

}

static void test_stability_clamped_to_zero(void **unused) {

  (void)unused;
  setup(STATE_MODE_PROBE);

  struct queue_entry *q = add_entry();

  q->bitmap_size = 2;
  memset(afl->cal_var_map, 0, TEST_MAP);

  for (u32 i = 0; i < 50; i++) {

    afl->cal_var_map[i] = 2;

  }

  state_calibration_stats(afl, q);

  assert_true(q->stability >= 0.0);
  assert_true(q->stability <= 100.0);

  teardown();

}

static void test_corpus_stability_tracks_the_worst(void **unused) {

  (void)unused;
  setup(STATE_MODE_PROBE);

  struct queue_entry *good = add_entry();
  struct queue_entry *bad = add_entry();

  good->bitmap_size = 100;
  good->stability = 100.0;
  bad->bitmap_size = 100;

  memset(afl->cal_var_map, 0, TEST_MAP);
  for (u32 i = 0; i < 25; i++) {

    afl->cal_var_map[i] = 2;

  }

  state_calibration_stats(afl, bad);

  assert_true(fabs(bad->stability - 75.0) < 0.001);
  assert_true(fabs(afl->corpus_stability_avg - 87.5) < 0.001);
  assert_true(fabs(afl->corpus_stability_min - 75.0) < 0.001);

  teardown();

}

/* --- information score (item 8) --- */

static void test_info_score_ignores_ballast(void **unused) {

  (void)unused;
  setup(STATE_MODE_RARE);

  struct queue_entry *q;
  u32                 i;

  /* Edge 5 fires on every input, edge 6 fires only on the last one. After
     the corpus has grown, the ballast edge must contribute nothing and the
     rare edge must carry the whole score. */
  for (i = 0; i < 16; i++) {

    q = add_entry();
    q->bitmap_size = 1;
    memset(afl->fsrv.trace_bits, 0, TEST_MAP);
    afl->fsrv.trace_bits[5] = 1;
    if (i == 15) {

      afl->fsrv.trace_bits[6] = 1;
      q->bitmap_size = 2;

    }

    state_calibration_stats(afl, q);

  }

  assert_int_equal(afl->corpus_trace_cnt, 16);
  assert_int_equal(afl->edge_corpus_cnt[5], 16);
  assert_int_equal(afl->edge_corpus_cnt[6], 1);

  /* log2(16/16) = 0 for the ballast edge, log2(16/1) = 4 for the rare one. */
  assert_true(fabs(entries[0]->info_score - 0.0) < 0.001);
  assert_true(fabs(entries[15]->info_score - 4.0) < 0.001);

  teardown();

}

static void test_info_score_absent_without_the_letter(void **unused) {

  (void)unused;
  setup(STATE_MODE_PROBE);

  struct queue_entry *q = add_entry();

  q->bitmap_size = 1;
  afl->fsrv.trace_bits[5] = 1;

  assert_null(afl->edge_corpus_cnt);

  state_calibration_stats(afl, q);

  assert_true(fabs(q->info_score - 0.0) < 0.001);

  teardown();

}

/* --- ballast (item 2) --- */

static void test_ballast_is_the_intersection(void **unused) {

  (void)unused;
  setup(STATE_MODE_GATE);

  /* Edge 1 in both traces, edge 2 in only one. Ballast is what every input
     hits, so only edge 1 survives. */
  memset(afl->fsrv.trace_bits, 0, TEST_MAP);
  afl->fsrv.trace_bits[1] = 1;
  afl->fsrv.trace_bits[2] = 1;
  afl->virgin_bits[1] = 0xfe;
  afl->virgin_bits[2] = 0xfe;
  state_ballast_fold(afl);

  assert_int_equal(afl->ballast_bits[1], 1);
  assert_int_equal(afl->ballast_bits[2], 1);

  memset(afl->fsrv.trace_bits, 0, TEST_MAP);
  afl->fsrv.trace_bits[1] = 1;
  state_ballast_fold(afl);

  assert_int_equal(afl->ballast_bits[1], 1);
  assert_int_equal(afl->ballast_bits[2], 0);
  assert_true(fabs(afl->ballast_pct - 50.0) < 0.001);

  teardown();

}

/* --- allocation is driven by the letters --- */

static void test_alloc_follows_the_letters(void **unused) {

  (void)unused;
  setup(STATE_MODE_GATE);

  assert_non_null(afl->ballast_bits);
  assert_non_null(afl->cal_var_map);
  assert_null(afl->probe_union);
  assert_null(afl->edge_corpus_cnt);
  assert_null(afl->shelf);

  teardown();

  setup(STATE_MODE_PROBE | STATE_MODE_RARE | STATE_MODE_DEEP);

  assert_non_null(afl->probe_union);
  assert_non_null(afl->probe_isect);
  assert_non_null(afl->edge_corpus_cnt);
  assert_non_null(afl->shelf);
  assert_non_null(afl->shelf_count);

  teardown();

}

static void test_alloc_is_idempotent(void **unused) {

  (void)unused;
  setup(STATE_MODE_RARE);

  u8  *first = afl->ballast_bits;
  u32 *counts = afl->edge_corpus_cnt;

  state_alloc(afl);
  state_alloc(afl);

  assert_ptr_equal(afl->ballast_bits, first);
  assert_ptr_equal(afl->edge_corpus_cnt, counts);

  teardown();

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_state_map_observing_keeps_admission_unspent),
      cmocka_unit_test(test_state_map_admission_consumes_once),
      cmocka_unit_test(test_state_map_density_counts_observations),
      cmocka_unit_test(test_situations_counted_with_first_reach_depth),
      cmocka_unit_test(test_situations_absent_without_target_support),
      cmocka_unit_test(test_shelf_cell_separates_depth),
      cmocka_unit_test(test_shelf_cell_separates_cost),
      cmocka_unit_test(test_shelf_cell_ignores_state_until_trusted),
      cmocka_unit_test(test_shelf_cell_always_in_range),
      cmocka_unit_test(test_stability_clean_entry_is_100),
      cmocka_unit_test(test_stability_splits_edges_from_hit_counts),
      cmocka_unit_test(test_stability_clamped_to_zero),
      cmocka_unit_test(test_corpus_stability_tracks_the_worst),
      cmocka_unit_test(test_info_score_ignores_ballast),
      cmocka_unit_test(test_info_score_absent_without_the_letter),
      cmocka_unit_test(test_ballast_is_the_intersection),
      cmocka_unit_test(test_alloc_follows_the_letters),
      cmocka_unit_test(test_alloc_is_idempotent),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

