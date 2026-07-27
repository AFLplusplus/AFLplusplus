#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmocka.h>
#include "afl-fuzz.h"

AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  (void)afl;
  return 0;

}

static afl_state_t *cache_state(u64 budget) {

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_non_null(afl);
  afl->havoc_max_mult = HAVOC_MAX_MULT;
  afl->total_cal_cycles = 1;
  afl->total_cal_us = 500;
  afl->total_bitmap_entries = 1;
  afl->total_bitmap_size = 100;
  afl->schedule = EXPLORE;
  afl->q_testcase_max_cache_size = budget;
  return afl;

}

static void cache_entry(struct queue_entry *q, u32 len) {

  memset(q, 0, sizeof(*q));
  q->len = len;
  q->bitmap_size = 100;
  q->exec_us = 500;
  q->was_fuzzed = 1;

}

static void test_retake_mem_keeps_size_exact(void **state) {

  (void)state;
  afl_state_t       *afl = cache_state(1024 * 1024);
  struct queue_entry q;

  cache_entry(&q, 5000);
  q.testcase_buf = malloc(5000);
  assert_non_null(q.testcase_buf);
  memset(q.testcase_buf, 'A', 5000);
  afl->q_testcase_cache_size = 5000;
  afl->q_testcase_cache_count = 1;

  u8 *in = malloc(4000);
  assert_non_null(in);
  memset(in, 'B', 4000);

  q.len = 4000;
  queue_testcase_retake_mem(afl, &q, in, 4000, 5000);

  assert_int_equal(afl->q_testcase_cache_size, 4000);
  assert_memory_equal(q.testcase_buf, in, 4000);

  free(in);
  free(q.testcase_buf);
  free(afl);

}

static void build_queue(afl_state_t *afl, struct queue_entry *q,
                        struct queue_entry **buf, u32 *nf, const u32 *lens,
                        u32 count) {

  u32 i;

  for (i = 0; i < count; i++) {

    cache_entry(&q[i], lens[i]);
    q[i].id = i;
    q[i].n_fuzz_entry = i;
    nf[i] = 1;
    buf[i] = &q[i];

  }

  afl->queue_buf = buf;
  afl->queued_items = count;
  afl->n_fuzz = nf;

}

static void test_marking_prefers_dense_entries(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};

  build_queue(afl, q, buf, nf, lens, 4);
  create_alias_table(afl);

  assert_int_equal(afl->cache_bucket_min, 1011);
  assert_int_equal(q[0].cache_wanted, 1);
  assert_int_equal(q[1].cache_wanted, 1);
  assert_int_equal(q[2].cache_wanted, 1);
  assert_int_equal(q[3].cache_wanted, 0);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_skips_disabled(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};

  build_queue(afl, q, buf, nf, lens, 4);
  q[0].disabled = 1;
  create_alias_table(afl);

  assert_int_equal(q[0].cache_wanted, 0);
  assert_int_equal(q[1].cache_wanted, 1);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_wants_all_when_budget_ample(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(1024 * 1024);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};
  u32                 i;

  build_queue(afl, q, buf, nf, lens, 4);
  create_alias_table(afl);

  assert_int_equal(afl->cache_bucket_min, 0);
  for (i = 0; i < 4; i++) {

    assert_int_equal(q[i].cache_wanted, 1);

  }

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_noop_when_cache_disabled(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(0);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};
  u32                 i;

  build_queue(afl, q, buf, nf, lens, 4);
  create_alias_table(afl);

  for (i = 0; i < 4; i++) {

    assert_int_equal(q[i].cache_wanted, 0);

  }

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static u8 *make_file(const char *dir, const char *name, u32 len, u8 fill) {

  u8 *path = malloc(strlen(dir) + strlen(name) + 2);
  u8 *data = malloc(len);
  int fd;

  assert_non_null(path);
  assert_non_null(data);
  sprintf((char *)path, "%s/%s", dir, name);
  memset(data, fill, len);

  fd = open((char *)path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert_true(fd >= 0);
  assert_int_equal(write(fd, data, len), len);
  close(fd);
  free(data);

  return path;

}

static void test_get_admits_wanted_only(void **state) {

  (void)state;
  char dir[] = "/tmp/afl-unit-testcache-XXXXXX";
  assert_non_null(mkdtemp(dir));

  afl_state_t       *afl = cache_state(1024 * 1024);
  struct queue_entry wanted, unwanted;

  cache_entry(&wanted, 1000);
  cache_entry(&unwanted, 1000);
  wanted.fname = make_file(dir, "wanted", 1000, 'W');
  unwanted.fname = make_file(dir, "unwanted", 1000, 'U');
  wanted.cache_wanted = 1;
  unwanted.cache_wanted = 0;

  u8 *a = queue_testcase_get(afl, &wanted);
  assert_ptr_equal(a, wanted.testcase_buf);
  assert_int_equal(a[0], 'W');
  assert_int_equal(afl->q_testcase_cache_size, 1000);
  assert_int_equal(afl->q_testcase_cache_count, 1);
  assert_int_equal(afl->q_testcase_misses, 1);
  assert_int_equal(afl->q_testcase_hits, 0);

  u8 *b = queue_testcase_get(afl, &unwanted);
  assert_null(unwanted.testcase_buf);
  assert_int_equal(b[0], 'U');
  assert_int_equal(afl->q_testcase_cache_size, 1000);
  assert_int_equal(afl->q_testcase_cache_count, 1);
  assert_int_equal(afl->q_testcase_misses, 2);

  u8 *again = queue_testcase_get(afl, &wanted);
  assert_ptr_equal(again, a);
  assert_int_equal(afl->q_testcase_hits, 1);
  assert_int_equal(afl->q_testcase_misses, 2);

  free(wanted.testcase_buf);
  afl_free(afl->splicecase_buf);
  unlink((char *)wanted.fname);
  unlink((char *)unwanted.fname);
  rmdir(dir);
  free(wanted.fname);
  free(unwanted.fname);
  free(afl);

}

static void test_get_never_exceeds_budget(void **state) {

  (void)state;
  char dir[] = "/tmp/afl-unit-testcache-XXXXXX";
  assert_non_null(mkdtemp(dir));

  afl_state_t       *afl = cache_state(2500);
  struct queue_entry q[3];
  const char        *names[3] = {"a", "b", "c"};
  u32                i;

  for (i = 0; i < 3; i++) {

    cache_entry(&q[i], 1000);
    q[i].fname = make_file(dir, names[i], 1000, 'A' + i);
    q[i].cache_wanted = 1;
    (void)queue_testcase_get(afl, &q[i]);

  }

  assert_int_equal(afl->q_testcase_cache_count, 2);
  assert_int_equal(afl->q_testcase_cache_size, 2000);
  assert_non_null(q[0].testcase_buf);
  assert_non_null(q[1].testcase_buf);
  assert_null(q[2].testcase_buf);
  assert_true(afl->q_testcase_cache_size <= afl->q_testcase_max_cache_size);

  for (i = 0; i < 3; i++) {

    free(q[i].testcase_buf);
    unlink((char *)q[i].fname);
    free(q[i].fname);

  }

  afl_free(afl->splicecase_buf);
  rmdir(dir);
  free(afl);

}

static void test_store_mem_admits_wanted_only(void **state) {

  (void)state;
  afl_state_t       *afl = cache_state(1024 * 1024);
  struct queue_entry wanted, unwanted;
  u8                 mem[64];

  memset(mem, 'Z', sizeof(mem));

  cache_entry(&wanted, sizeof(mem));
  cache_entry(&unwanted, sizeof(mem));
  wanted.cache_wanted = 1;
  unwanted.cache_wanted = 0;

  queue_testcase_store_mem(afl, &wanted, mem);
  queue_testcase_store_mem(afl, &unwanted, mem);

  assert_non_null(wanted.testcase_buf);
  assert_null(unwanted.testcase_buf);
  assert_memory_equal(wanted.testcase_buf, mem, sizeof(mem));
  assert_int_equal(afl->q_testcase_cache_size, sizeof(mem));
  assert_int_equal(afl->q_testcase_cache_count, 1);

  free(wanted.testcase_buf);
  free(afl);

}

static void test_rebuild_evicts_unwanted(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};

  build_queue(afl, q, buf, nf, lens, 4);

  q[3].testcase_buf = malloc(8000);
  assert_non_null(q[3].testcase_buf);
  q[3].cache_wanted = 1;
  afl->q_testcase_cache_size = 8000;
  afl->q_testcase_cache_count = 1;

  create_alias_table(afl);

  assert_null(q[3].testcase_buf);
  assert_int_equal(q[3].cache_wanted, 0);
  assert_int_equal(afl->q_testcase_cache_size, 0);
  assert_int_equal(afl->q_testcase_cache_count, 0);
  assert_int_equal(afl->q_testcase_evictions, 1);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_rebuild_evicts_disabled(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(1024 * 1024);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};

  build_queue(afl, q, buf, nf, lens, 4);

  q[0].disabled = 1;
  q[0].testcase_buf = malloc(1000);
  assert_non_null(q[0].testcase_buf);
  q[0].cache_wanted = 1;
  afl->q_testcase_cache_size = 1000;
  afl->q_testcase_cache_count = 1;

  create_alias_table(afl);

  assert_null(q[0].testcase_buf);
  assert_int_equal(afl->q_testcase_cache_size, 0);
  assert_int_equal(afl->q_testcase_evictions, 1);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_rebuild_keeps_queue_cur(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};

  build_queue(afl, q, buf, nf, lens, 4);

  q[3].testcase_buf = malloc(8000);
  assert_non_null(q[3].testcase_buf);
  afl->q_testcase_cache_size = 8000;
  afl->q_testcase_cache_count = 1;
  afl->queue_cur = &q[3];

  create_alias_table(afl);

  assert_non_null(q[3].testcase_buf);
  assert_int_equal(q[3].cache_wanted, 0);
  assert_int_equal(afl->q_testcase_evictions, 0);

  free(q[3].testcase_buf);
  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_works_for_rare_schedule(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};
  u32                 i;

  build_queue(afl, q, buf, nf, lens, 4);
  afl->schedule = RARE;
  afl->fsrv.total_execs = 100000;

  for (i = 0; i < 4; i++) {

    q[i].tc_ref = 1;
    q[i].fuzz_level = 1;
    nf[i] = 10;

  }

  create_alias_table(afl);

  assert_int_equal(afl->cache_bucket_min, 1011);
  assert_int_equal(q[0].cache_wanted, 1);
  assert_int_equal(q[1].cache_wanted, 1);
  assert_int_equal(q[2].cache_wanted, 1);
  assert_int_equal(q[3].cache_wanted, 0);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_top_bucket_alone_exceeds_target(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[2];
  struct queue_entry *buf[2];
  u32                 nf[2];
  const u32           lens[2] = {4096, 4096};

  build_queue(afl, q, buf, nf, lens, 2);
  create_alias_table(afl);

  assert_int_equal(afl->cache_bucket_min, 1011);
  assert_int_equal(q[0].cache_wanted, 1);
  assert_int_equal(q[1].cache_wanted, 1);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_over_marks_then_budget_refuses(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[2];
  struct queue_entry *buf[2];
  u32                 nf[2];
  const u32           lens[2] = {8, 1000000};

  build_queue(afl, q, buf, nf, lens, 2);
  create_alias_table(afl);

  assert_int_equal(afl->cache_bucket_min, 1003);
  assert_int_equal(q[0].cache_wanted, 1);
  assert_int_equal(q[1].cache_wanted, 1);
  assert_true(q[1].len > afl->q_testcase_max_cache_size);

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_marking_all_disabled_queue(void **state) {

  (void)state;
  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};
  u32                 i;

  build_queue(afl, q, buf, nf, lens, 4);
  afl->schedule = RARE;
  afl->fsrv.total_execs = 100000;

  for (i = 0; i < 4; i++) {

    q[i].disabled = 1;
    nf[i] = 10;

  }

  create_alias_table(afl);

  for (i = 0; i < 4; i++) {

    assert_int_equal(q[i].cache_wanted, 0);

  }

  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_accounting_invariant_holds_after_churn(void **state) {

  (void)state;
  char dir[] = "/tmp/afl-unit-testcache-XXXXXX";
  assert_non_null(mkdtemp(dir));

  afl_state_t        *afl = cache_state(4096);
  struct queue_entry  q[4];
  struct queue_entry *buf[4];
  u32                 nf[4];
  const u32           lens[4] = {1000, 2000, 4000, 8000};
  const char         *names[4] = {"a", "b", "c", "d"};
  u64                 sum = 0;
  u32                 count = 0, i;

  build_queue(afl, q, buf, nf, lens, 4);

  for (i = 0; i < 4; i++) {

    q[i].fname = make_file(dir, names[i], lens[i], 'A' + i);

  }

  create_alias_table(afl);

  for (i = 0; i < 4; i++) {

    (void)queue_testcase_get(afl, &q[i]);

  }

  create_alias_table(afl);

  for (i = 0; i < 4; i++) {

    if (q[i].testcase_buf) {

      sum += q[i].len;
      ++count;

    }

  }

  assert_int_equal(afl->q_testcase_cache_size, sum);
  assert_int_equal(afl->q_testcase_cache_count, count);
  assert_true(afl->q_testcase_cache_size <= afl->q_testcase_max_cache_size);

  for (i = 0; i < 4; i++) {

    free(q[i].testcase_buf);
    unlink((char *)q[i].fname);
    free(q[i].fname);

  }

  afl_free(afl->testcase_buf);
  afl_free(afl->splicecase_buf);
  rmdir(dir);
  free(afl->alias_table);
  free(afl->alias_probability);
  free(afl);

}

static void test_retake_mem_aliased_keeps_size_exact(void **state) {

  (void)state;
  afl_state_t       *afl = cache_state(1024 * 1024);
  struct queue_entry q;
  u8                *in;

  cache_entry(&q, 5000);
  q.testcase_buf = malloc(5000);
  assert_non_null(q.testcase_buf);
  memset(q.testcase_buf, 'A', 5000);
  afl->q_testcase_cache_size = 5000;
  afl->q_testcase_cache_count = 1;

  in = q.testcase_buf;
  q.len = 4000;
  queue_testcase_retake_mem(afl, &q, in, 4000, 5000);

  assert_int_equal(afl->q_testcase_cache_size, 4000);
  assert_int_equal(afl->q_testcase_cache_count, 1);
  assert_non_null(q.testcase_buf);
  assert_int_equal(q.testcase_buf[0], 'A');
  assert_int_equal(q.testcase_buf[3999], 'A');

  free(q.testcase_buf);
  free(afl);

}

static void test_retake_mem_aliased_growth_accounts(void **state) {

  (void)state;
  afl_state_t       *afl = cache_state(1024 * 1024);
  struct queue_entry q;
  u8                *in;

  cache_entry(&q, 4000);
  q.testcase_buf = malloc(4000);
  assert_non_null(q.testcase_buf);
  memset(q.testcase_buf, 'B', 4000);
  afl->q_testcase_cache_size = 4000;
  afl->q_testcase_cache_count = 1;

  in = q.testcase_buf;
  q.len = 5000;
  queue_testcase_retake_mem(afl, &q, in, 5000, 4000);

  assert_int_equal(afl->q_testcase_cache_size, 5000);
  assert_int_equal(afl->q_testcase_cache_count, 1);
  assert_int_equal(q.testcase_buf[0], 'B');

  free(q.testcase_buf);
  free(afl);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_retake_mem_keeps_size_exact),
      cmocka_unit_test(test_retake_mem_aliased_keeps_size_exact),
      cmocka_unit_test(test_retake_mem_aliased_growth_accounts),
      cmocka_unit_test(test_marking_works_for_rare_schedule),
      cmocka_unit_test(test_marking_top_bucket_alone_exceeds_target),
      cmocka_unit_test(test_marking_over_marks_then_budget_refuses),
      cmocka_unit_test(test_marking_all_disabled_queue),
      cmocka_unit_test(test_marking_prefers_dense_entries),
      cmocka_unit_test(test_marking_skips_disabled),
      cmocka_unit_test(test_marking_wants_all_when_budget_ample),
      cmocka_unit_test(test_marking_noop_when_cache_disabled),
      cmocka_unit_test(test_get_admits_wanted_only),
      cmocka_unit_test(test_get_never_exceeds_budget),
      cmocka_unit_test(test_store_mem_admits_wanted_only),
      cmocka_unit_test(test_rebuild_evicts_unwanted),
      cmocka_unit_test(test_rebuild_evicts_disabled),
      cmocka_unit_test(test_rebuild_keeps_queue_cur),
      cmocka_unit_test(test_accounting_invariant_holds_after_churn),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

