/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <math.h>
#include <time.h>
#include <cmocka.h>
#include "afl-fuzz.h"

static u64 fake_now_us;

u64 get_cur_time_us(void) {

  return fake_now_us;

}

static struct queue_entry *mk_entry(const char *s) {

  struct queue_entry *q = calloc(1, sizeof(struct queue_entry));
  assert_non_null(q);
  q->len = strlen(s);
  q->testcase_buf = (u8 *)strdup(s);
  q->bas_mult = 1.0;
  return q;

}

static afl_state_t *mk_afl(void) {

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  afl->queue_buf = calloc(16, sizeof(struct queue_entry *));
  assert_non_null(afl->queue_buf);
  afl->afl_env.afl_basfuzz = 1;
  afl->afl_env.afl_basfuzz_interval = (u8 *)"1";
  return afl;

}

static void free_afl(afl_state_t *afl) {

  bas_destroy(afl);
  for (u32 i = 0; i < afl->queued_items; ++i) {

    free(afl->queue_buf[i]->testcase_buf);
    free(afl->queue_buf[i]);

  }

  free(afl->queue_buf);
  free(afl);

}

static void push(afl_state_t *afl, const char *s) {

  afl->queue_buf[afl->queued_items++] = mk_entry(s);

}

static void test_setup_gating(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);

  bas_setup(afl);
  assert_null(afl->bas);

  afl->afl_env.afl_basfuzz = 1;
  afl->old_seed_selection = 1;
  bas_setup(afl);
  assert_null(afl->bas);

  afl->old_seed_selection = 0;
  bas_setup(afl);
  assert_non_null(afl->bas);
  assert_true(afl->bas->boost == BAS_DEFAULT_BOOST);
  assert_int_equal(afl->bas->hist.max_pos, BAS_DEFAULT_MAX_POS);
  assert_true(afl->bas->interval_us == BAS_DEFAULT_INTERVAL * 1000000ULL);

  bas_destroy(afl);
  assert_null(afl->bas);
  bas_destroy(afl);
  free(afl);

}

static void test_rescore_weights_and_interval(void **state) {

  (void)state;
  afl_state_t *afl = mk_afl();
  push(afl, "AAAA");
  push(afl, "AAAA");
  push(afl, "ZZZZ");
  bas_setup(afl);
  assert_non_null(afl->bas);

  fake_now_us = 1000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->rescores, 1);
  assert_int_equal(afl->reinit_table, 1);
  assert_true(fabs(afl->queue_buf[2]->bas_mult - 2.0) < 1e-12);
  assert_true(fabs(afl->queue_buf[0]->bas_mult - pow(2.0, -0.5)) < 1e-12);
  assert_true(afl->queue_buf[0]->bas_mult == afl->queue_buf[1]->bas_mult);

  afl->reinit_table = 0;
  fake_now_us += 500000;
  push(afl, "ZZZA");
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->rescores, 1);
  assert_int_equal(afl->reinit_table, 0);
  assert_true(afl->queue_buf[3]->bas_mult == 1.0);

  fake_now_us += 1000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->rescores, 2);
  assert_int_equal(afl->bas->indexed, 4);
  assert_int_equal(afl->reinit_table, 1);

  afl->reinit_table = 0;
  fake_now_us += 2000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->rescores, 2);
  assert_int_equal(afl->reinit_table, 0);

  assert_true(bas_mem_bytes(afl->bas) > 0);
  free_afl(afl);

}

static void test_disable_and_trim_are_reconciled(void **state) {

  (void)state;
  afl_state_t *afl = mk_afl();
  push(afl, "AAAA");
  push(afl, "AAAA");
  push(afl, "ZZZZ");
  push(afl, "ZZZA");
  bas_setup(afl);

  fake_now_us = 1000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->hist.npos[0], 4);

  afl->queue_buf[0]->disabled = 1;
  fake_now_us += 2000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->hist.npos[0], 3);
  assert_true(afl->queue_buf[0]->bas_mult == 1.0);

  afl->queue_buf[3]->len = 2;
  memcpy(afl->queue_buf[3]->testcase_buf, "ZZ", 3);
  fake_now_us += 2000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->hist.npos[0], 3);
  assert_int_equal(afl->bas->hist.npos[1], 3);
  assert_int_equal(afl->bas->hist.npos[2], 2);
  assert_int_equal(afl->bas->hist.npos[3], 2);

  afl->queue_buf[0]->disabled = 0;
  fake_now_us += 2000000;
  bas_maybe_rescore(afl);
  assert_int_equal(afl->bas->hist.npos[0], 4);
  assert_int_equal(afl->bas->hist.npos[3], 3);

  free_afl(afl);

}

static double sim_of(bas_hist_t *h, const u8 *buf, u32 len) {

  double *inv = calloc(h->max_pos, sizeof(double));
  assert_non_null(inv);
  u32    lim = bas_hist_prepare(h, inv);
  double s = bas_similarity(h, inv, lim, buf, len);
  free(inv);
  return s;

}

static void test_hist_add_sub_roundtrip(void **state) {

  (void)state;
  bas_hist_t h;
  bas_hist_init(&h, 64);
  const u8 a[] = "hello world";

  bas_hist_add(&h, a, 11);
  bas_hist_add(&h, a, 5);
  assert_int_equal(h.npos[0], 2);
  assert_int_equal(h.npos[10], 1);
  assert_int_equal(h.cnt[0 * 256 + 'h'], 2);

  bas_hist_sub(&h, a, 5);
  bas_hist_sub(&h, a, 11);
  for (u32 p = 0; p < h.rows; ++p) {

    assert_int_equal(h.npos[p], 0);
    for (u32 b = 0; b < 256; ++b) {

      assert_int_equal(h.cnt[p * 256 + b], 0);

    }

  }

  bas_hist_free(&h);

}

static void test_similarity_identical_and_distinct(void **state) {

  (void)state;
  bas_hist_t h;
  bas_hist_init(&h, 64);
  const u8 a[] = "AAAA", b[] = "AAAA", c[] = "ZZZZ";

  bas_hist_add(&h, a, 4);
  bas_hist_add(&h, b, 4);
  assert_true(fabs(sim_of(&h, a, 4) - 1.0) < 1e-12);

  bas_hist_add(&h, c, 4);
  assert_true(fabs(sim_of(&h, a, 4) - 0.5) < 1e-12);
  assert_true(fabs(sim_of(&h, c, 4) - 0.0) < 1e-12);

  bas_hist_free(&h);

}

static void test_no_length_bias(void **state) {

  (void)state;
  bas_hist_t h;
  bas_hist_init(&h, 64);
  const u8 s1[] = "ab", s2[] = "ab", l[] = "abcdefgh";

  bas_hist_add(&h, s1, 2);
  bas_hist_add(&h, s2, 2);
  bas_hist_add(&h, l, 8);

  double *inv = calloc(h.max_pos, sizeof(double));
  assert_non_null(inv);
  assert_int_equal(bas_hist_prepare(&h, inv), 2);
  free(inv);

  assert_true(fabs(sim_of(&h, s1, 2) - 1.0) < 1e-12);
  assert_true(fabs(sim_of(&h, l, 8) - 1.0) < 1e-12);

  bas_hist_free(&h);

}

static void test_max_pos_clipping(void **state) {

  (void)state;
  bas_hist_t h;
  bas_hist_init(&h, 16);
  u8 x[40], y[40];
  memset(x, 'x', sizeof(x));
  memset(y, 'x', sizeof(y));
  y[20] = 'Q';

  bas_hist_add(&h, x, 40);
  bas_hist_add(&h, y, 40);
  assert_int_equal(h.rows, 16);
  assert_true(fabs(sim_of(&h, x, 40) - 1.0) < 1e-12);
  assert_true(fabs(sim_of(&h, y, 40) - 1.0) < 1e-12);

  bas_hist_free(&h);

}

static double brute_sim(u8 **bufs, u32 *lens, u32 n, u32 i, u32 cap) {

  u32    mi = lens[i] < cap ? lens[i] : cap;
  double acc = 0.0;
  u32    valid = 0;

  for (u32 p = 0; p < mi; ++p) {

    u32 cover = 0, same = 0;
    for (u32 j = 0; j < n; ++j) {

      u32 mj = lens[j] < cap ? lens[j] : cap;
      if (j == i || p >= mj) { continue; }
      ++cover;
      if (bufs[j][p] == bufs[i][p]) { ++same; }

    }

    if (cover) {

      acc += (double)same / cover;
      ++valid;

    }

  }

  return valid ? acc / valid : 0.0;

}

static void test_matches_bruteforce(void **state) {

  (void)state;
  const u32 n = 50, cap = 128;
  u8       *bufs[50];
  u32       lens[50];
  bas_hist_t h;

  srand(1234);
  bas_hist_init(&h, cap);
  for (u32 i = 0; i < n; ++i) {

    lens[i] = 1 + rand() % 300;
    bufs[i] = malloc(lens[i]);
    assert_non_null(bufs[i]);
    for (u32 p = 0; p < lens[i]; ++p) {

      bufs[i][p] = (u8)(rand() % 4);

    }

    bas_hist_add(&h, bufs[i], lens[i]);

  }

  double *inv = calloc(cap, sizeof(double));
  assert_non_null(inv);
  u32 lim = bas_hist_prepare(&h, inv);

  for (u32 i = 0; i < n; ++i) {

    double fast = bas_similarity(&h, inv, lim, bufs[i], lens[i]);
    double slow = brute_sim(bufs, lens, n, i, cap);
    assert_true(fabs(fast - slow) < 1e-9);

  }

  free(inv);
  for (u32 i = 0; i < n; ++i) {

    free(bufs[i]);

  }

  bas_hist_free(&h);

}

static void test_rank_mult(void **state) {

  (void)state;
  double s[3] = {0.9, 0.1, 0.5}, m[3];
  bas_rank_mult(s, 3, 4.0, m);
  assert_true(fabs(m[1] - 4.0) < 1e-12);
  assert_true(fabs(m[2] - 1.0) < 1e-12);
  assert_true(fabs(m[0] - 0.25) < 1e-12);

  double t[4] = {0.3, 0.3, 0.3, 0.3}, tm[4];
  bas_rank_mult(t, 4, 4.0, tm);
  for (u32 i = 0; i < 4; ++i) {

    assert_true(fabs(tm[i] - 1.0) < 1e-12);

  }

  double one = 0.7, om = 0.0;
  bas_rank_mult(&one, 1, 4.0, &om);
  assert_true(fabs(om - 1.0) < 1e-12);

  bas_rank_mult(s, 3, 1.0, m);
  for (u32 i = 0; i < 3; ++i) {

    assert_true(fabs(m[i] - 1.0) < 1e-12);

  }

}

static void test_rescore_throughput(void **state) {

  (void)state;
  const u32 n = 20000, len = 1024, cap = BAS_DEFAULT_MAX_POS;
  u8       *data = malloc((size_t)n * len);
  double   *sim = malloc(n * sizeof(double));
  double   *mult = malloc(n * sizeof(double));
  double   *inv = calloc(cap, sizeof(double));
  assert_non_null(data);
  assert_non_null(sim);
  assert_non_null(mult);
  assert_non_null(inv);

  srand(42);
  for (size_t k = 0; k < (size_t)n * len; ++k) {

    data[k] = (u8)(rand() % 16);

  }

  bas_hist_t h;
  bas_hist_init(&h, cap);

  clock_t t0 = clock();
  for (u32 i = 0; i < n; ++i) {

    bas_hist_add(&h, data + (size_t)i * len, len);

  }

  clock_t t1 = clock();
  u32     lim = bas_hist_prepare(&h, inv);
  for (u32 i = 0; i < n; ++i) {

    sim[i] = bas_similarity(&h, inv, lim, data + (size_t)i * len, len);
    assert_true(sim[i] >= 0.0 && sim[i] <= 1.0);

  }

  bas_rank_mult(sim, n, BAS_DEFAULT_BOOST, mult);
  clock_t t2 = clock();

  print_message("basfuzz: index %u x %u B: %.1f ms, score+rank: %.1f ms\n", n,
                len, 1000.0 * (t1 - t0) / CLOCKS_PER_SEC,
                1000.0 * (t2 - t1) / CLOCKS_PER_SEC);

  bas_hist_free(&h);
  free(inv);
  free(mult);
  free(sim);
  free(data);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_hist_add_sub_roundtrip),
      cmocka_unit_test(test_similarity_identical_and_distinct),
      cmocka_unit_test(test_no_length_bias),
      cmocka_unit_test(test_max_pos_clipping),
      cmocka_unit_test(test_matches_bruteforce),
      cmocka_unit_test(test_rank_mult),
      cmocka_unit_test(test_setup_gating),
      cmocka_unit_test(test_rescore_weights_and_interval),
      cmocka_unit_test(test_disable_and_trim_are_reconciled),
      cmocka_unit_test(test_rescore_throughput),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

