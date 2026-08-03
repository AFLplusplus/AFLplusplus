#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
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

static u32                 queue_testcase_get_calls;
static struct queue_entry *queue_testcase_get_last;

u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  static u8 dummy[4];
  (void)afl;
  ++queue_testcase_get_calls;
  queue_testcase_get_last = q;
  return dummy;

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

static inline size_t vp_test_frontier_idx(u32 site, u32 rel) {

  return (size_t)site * VP_SLOTS + rel;

}

static inline u64 vp_test_site_token(u32 primary, u32 primary_way,
                                     u32 secondary, u32 secondary_way,
                                     u32 tag) {

  return ((u64)tag << 32) | ((u64)secondary_way << 30) |
         ((u64)secondary << 16) | ((u64)primary_way << 14) | primary;

}

static void test_site_selector_primary_secondary_and_filter(void **state) {

  (void)state;

  vp_map_t *vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  u64 token = vp_test_site_token(17, 2, 29, 1, 0x12345678U);
  u32 key = vp_map_select(vp, token, 1);
  assert_int_equal(key, 17U * VP_MAP_A + 2U);
  assert_int_equal(vp->site_ids[key], 0x12345678U);
  assert_int_equal(vp_map_select(vp, token, 1), key);
  assert_int_equal(vp_map_select(vp, token, 0), key);

  vp->site_ids[23U * VP_MAP_A + 1U] = 0x11111111U;
  token = vp_test_site_token(23, 1, 37, 0, 0x22222222U);
  key = vp_map_select(vp, token, 1);
  assert_int_equal(key, 23U * VP_MAP_A + 2U);
  assert_int_equal(vp->site_ids[key], 0x22222222U);

  for (u32 i = 0; i < VP_MAP_A; ++i) {

    vp->site_ids[31U * VP_MAP_A + i] = 0x100U + i;

  }

  token = vp_test_site_token(31, 0, 47, 3, 0x87654321U);
  key = vp_map_select(vp, token, 1);
  assert_int_equal(key, 47U * VP_MAP_A + 3U);
  assert_int_equal(vp->site_ids[key], 0x87654321U);

  vp->filter_mode = VP_FILTER_STRICT;
  token = vp_test_site_token(53, 1, 59, 2, 0xabcdef01U);
  assert_int_equal(vp_map_select(vp, token, 0), VP_MAP_INVALID);
  assert_int_equal(vp->site_ids[53U * VP_MAP_A + 1U], 0);
  assert_int_equal(vp->site_ids[59U * VP_MAP_A + 2U], 0);

  free(vp);

}

static void test_site_selector_full_sets_and_zero_tag(void **state) {

  (void)state;

  vp_map_t *vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  u64 token = vp_test_site_token(61, 0, 67, 0, 0);
  u32 key = vp_map_select(vp, token, 1);
  assert_int_equal(key, 61U * VP_MAP_A);
  assert_int_equal(vp->site_ids[key], 1);

  token = vp_test_site_token(69, 0, 69, 0, 0x10101010U);
  assert_int_equal(vp_token_secondary_set(token), 70);

  for (u32 i = 0; i < VP_MAP_A; ++i) {

    vp->site_ids[71U * VP_MAP_A + i] = 0x200U + i;
    vp->site_ids[73U * VP_MAP_A + i] = 0x300U + i;

  }

  token = vp_test_site_token(71, 2, 73, 1, 0xfeedbeefU);
  assert_int_equal(vp_map_select(vp, token, 1), VP_MAP_INVALID);

  free(vp);

}

static void setup_vp_frontier(afl_state_t *afl) {

  size_t n = (size_t)VP_MAP_W * VP_SLOTS;
  afl->vp_frontier = calloc(n, sizeof(vp_frontier_entry_t));
  assert_non_null(afl->vp_frontier);

  for (size_t i = 0; i < n; ++i) {

    afl->vp_frontier[i].dist = VP_DIST_UNSOLVED;

  }

}

static void free_vp_frontier(afl_state_t *afl) {

  free(afl->vp_frontier);

}

static void setup_vp_focus(afl_state_t *afl) {

  afl->vp_focus_bitmap = calloc(VP_MAP_W / 64U, sizeof(u64));
  assert_non_null(afl->vp_focus_bitmap);
  afl->vp_focus_prev = calloc(VP_MAP_W / 64U, sizeof(u64));
  assert_non_null(afl->vp_focus_prev);
  afl->vp_focus_relevant = calloc(VP_MAP_W / 64U, sizeof(u64));
  assert_non_null(afl->vp_focus_relevant);
  afl->vp_site_idle = calloc(VP_MAP_W, sizeof(u16));
  assert_non_null(afl->vp_site_idle);
  afl->vp_site_owned = calloc(VP_MAP_W, sizeof(u8));
  assert_non_null(afl->vp_site_owned);

}

static void free_vp_focus(afl_state_t *afl) {

  free(afl->vp_focus_bitmap);
  free(afl->vp_focus_prev);
  free(afl->vp_focus_relevant);
  free(afl->vp_site_idle);
  free(afl->vp_site_owned);
  afl->vp_site_owned = NULL;
  afl->vp_focus_bitmap = NULL;
  afl->vp_focus_prev = NULL;
  afl->vp_focus_relevant = NULL;
  afl->vp_site_idle = NULL;

}

static u32 vp_test_focus_popcount(const afl_state_t *afl) {

  u32 total = 0;

  for (u32 i = 0; i < VP_MAP_W / 64U; ++i) {

    u64 word = afl->vp_focus_bitmap[i];
    while (word) {

      word &= word - 1U;
      ++total;

    }

  }

  return total;

}

static void vp_test_init_direct_site(vp_site_t *site, u64 exec_id) {

  memset(site->slots, 0xFF, sizeof(site->slots));
  site->exec_seen = exec_id;
  site->hit_count = 0;
  site->touched_mask = 0;

}

static void vp_test_mkdir(const char *path) {

  assert_true(mkdir(path, 0700) == 0 || errno == EEXIST);

}

static void vp_test_touch(const char *path) {

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert_true(fd >= 0);
  assert_int_equal(close(fd), 0);

}

static void vp_test_cleanup_state_tree(const char *root, int queue_layout,
                                       const char *case_name) {

  char path[PATH_MAX];

  if (case_name) {

    snprintf(path, sizeof(path), "%s%s.state/vp_only/%s", root,
             queue_layout ? "/queue/." : "/.", case_name);
    unlink(path);
    snprintf(path, sizeof(path), "%s%s.state/vp_disabled/%s", root,
             queue_layout ? "/queue/." : "/.", case_name);
    unlink(path);

  }

  snprintf(path, sizeof(path), "%s%s.state/vp_only", root,
           queue_layout ? "/queue/." : "/.");
  rmdir(path);
  snprintf(path, sizeof(path), "%s%s.state/vp_disabled", root,
           queue_layout ? "/queue/." : "/.");
  rmdir(path);
  snprintf(path, sizeof(path), "%s%s.state", root,
           queue_layout ? "/queue/." : "/.");
  rmdir(path);
  if (queue_layout) {

    snprintf(path, sizeof(path), "%s/queue", root);
    rmdir(path);

  }

  rmdir(root);

}

static void test_mode2_activation_is_one_way(void **state) {

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
  assert_int_equal(afl.value_profile_replay_idx, 0);
  assert_int_equal(afl.score_changed, 1);

  afl.score_changed = 0;
  afl.last_edge_time = fake_time_ms;
  fake_time_ms += 1000;
  vp_update_activation(&afl);
  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_replay_idx, 0);
  assert_int_equal(afl.score_changed, 0);

}

static void test_non_stagnation_mode_is_noop(void **state) {

  (void)state;

  afl_state_t afl;
  memset(&afl, 0, sizeof(afl));

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.value_profile_replay_idx = 5;
  afl.score_changed = 0;

  vp_update_activation(&afl);
  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_replay_idx, 5);
  assert_int_equal(afl.score_changed, 0);

}

static void test_prepare_exec_suppression_preserves_runtime_sample(
    void **state) {

  (void)state;

  afl_state_t afl;
  vp_map_t    vp;

  memset(&afl, 0, sizeof(afl));
  memset(&vp, 0, sizeof(vp));

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.fsrv.use_value_profile = 1;
  afl.shm.vp_map = &vp;
  vp.exec_id = 41;
  vp.control_len = 3;

  vp_prepare_exec(&afl, &afl.fsrv);
  assert_int_equal(vp.enabled, 1);
  assert_int_equal(vp.exec_id, 42);
  assert_int_equal(vp.control_len, 0);

  vp.control_len = 5;
  afl.value_profile_suppressed = 1;
  vp_prepare_exec(&afl, &afl.fsrv);
  assert_int_equal(vp.enabled, 0);
  assert_int_equal(vp.exec_id, 42);
  assert_int_equal(vp.control_len, 5);

  afl.value_profile_suppressed = 0;
  vp_prepare_exec(&afl, &afl.fsrv);
  assert_int_equal(vp.enabled, 1);
  assert_int_equal(vp.exec_id, 43);
  assert_int_equal(vp.control_len, 0);

}

static void test_mode2_resume_restores_active_state(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];
  vp_map_t           *vp;
  u32                 site = 9;
  size_t              idx;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_mode = 2;
  afl.vp_start_time = 1234;
  afl.queued_items = 1;
  afl.queue_buf = queue_buf;
  afl.queue_buf[0] = &q;
  afl.shm.vp_map = vp;
  q.len = 4;
  q.exec_us = 11;

  setup_vp_frontier(&afl);
  idx = vp_test_frontier_idx(site, 0);

  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = site;
  vp_test_init_direct_site(&vp->site[site], 1);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 5;

  vp_restore_resume_state(&afl);

  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_replay_idx, 1);
  assert_int_equal(afl.score_changed, 1);
  assert_ptr_equal(afl.vp_frontier[idx].owner, &q);
  assert_int_equal(afl.vp_frontier[idx].dist, 5);
  assert_int_equal(q.vp_ref_cnt, 1);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_mode1_resume_rebuilds_frontier(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];
  vp_map_t           *vp;
  u32                 site = 11;
  size_t              idx;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queued_items = 1;
  afl.queue_buf = queue_buf;
  afl.queue_buf[0] = &q;
  afl.shm.vp_map = vp;
  q.len = 4;
  q.exec_us = 13;

  setup_vp_frontier(&afl);
  idx = vp_test_frontier_idx(site, 0);

  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = site;
  vp_test_init_direct_site(&vp->site[site], 1);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 7;

  vp_restore_resume_state(&afl);

  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_replay_idx, 1);
  assert_int_equal(afl.score_changed, 1);
  assert_ptr_equal(afl.vp_frontier[idx].owner, &q);
  assert_int_equal(afl.vp_frontier[idx].dist, 7);
  assert_int_equal(q.vp_ref_cnt, 1);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_activation_replay_skips_disabled_queue_entries(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  disabled_q, enabled_q;
  struct queue_entry *queue_buf[2];
  vp_map_t           *vp;
  u32                 site = 13;
  size_t              idx;

  memset(&afl, 0, sizeof(afl));
  memset(&disabled_q, 0, sizeof(disabled_q));
  memset(&enabled_q, 0, sizeof(enabled_q));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_mode = 2;
  afl.value_profile_stagnation_secs = 1;
  afl.queued_items = 2;
  afl.queue_buf = queue_buf;
  afl.queue_buf[0] = &disabled_q;
  afl.queue_buf[1] = &enabled_q;
  afl.shm.vp_map = vp;

  disabled_q.disabled = 1;
  disabled_q.len = 4;
  disabled_q.exec_us = 7;
  enabled_q.len = 4;
  enabled_q.exec_us = 11;

  setup_vp_frontier(&afl);
  idx = vp_test_frontier_idx(site, 0);

  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = site;
  vp_test_init_direct_site(&vp->site[site], 1);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 5;

  queue_testcase_get_calls = 0;
  queue_testcase_get_last = NULL;
  fake_time_ms = 1001;

  vp_update_activation(&afl);

  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_replay_idx, 2);
  assert_int_equal(queue_testcase_get_calls, 1);
  assert_ptr_equal(queue_testcase_get_last, &enabled_q);
  assert_ptr_equal(afl.vp_frontier[idx].owner, &enabled_q);
  assert_int_equal(afl.vp_frontier[idx].dist, 5);
  assert_int_equal(disabled_q.vp_ref_cnt, 0);
  assert_int_equal(enabled_q.vp_ref_cnt, 1);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_resume_replay_discards_fastresume_vp_ownership(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];
  vp_map_t           *vp;
  u32                 old_site = 3, site = 11;
  size_t              old_idx, idx;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queued_items = 1;
  afl.queue_buf = queue_buf;
  afl.queue_buf[0] = &q;
  afl.queue_cycle = 7;
  afl.shm.vp_map = vp;
  q.len = 4;
  q.exec_us = 13;
  q.vp_only = 1;
  q.vp_ref_cnt = 5;
  q.vp_unresolved_ref_cnt = 4;
  q.vp_last_ref_cycle = 99;
  q.trim_done = 1;
  q.vp_trim_deferred = 1;

  setup_vp_frontier(&afl);
  old_idx = vp_test_frontier_idx(old_site, 0);
  idx = vp_test_frontier_idx(site, 0);
  afl.vp_frontier[old_idx].owner = &q;
  afl.vp_frontier[old_idx].dist = 3;
  afl.vp_delayed_evictions_pending = 1;

  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = site;
  vp_test_init_direct_site(&vp->site[site], 1);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 7;

  vp_restore_resume_state(&afl);

  assert_int_equal(afl.value_profile_replay_idx, 1);
  assert_ptr_equal(afl.vp_frontier[old_idx].owner, NULL);
  assert_int_equal(afl.vp_frontier[old_idx].dist, VP_DIST_UNSOLVED);
  assert_ptr_equal(afl.vp_frontier[idx].owner, &q);
  assert_int_equal(afl.vp_frontier[idx].dist, 7);
  assert_int_equal(q.vp_ref_cnt, 1);
  assert_int_equal(q.vp_unresolved_ref_cnt, 1);
  assert_int_equal(q.vp_last_ref_cycle, afl.queue_cycle);
  assert_int_equal(q.vp_trim_deferred, 0);
  assert_int_equal(q.trim_done, 0);
  assert_int_equal(afl.vp_delayed_evictions_pending, 0);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_resume_without_vp_clears_fastresume_vp_ownership(
    void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];
  u32                 old_site = 11;
  size_t              old_idx;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  afl.queued_items = 1;
  afl.queue_buf = queue_buf;
  afl.queue_buf[0] = &q;
  afl.queue_cycle = 7;

  q.vp_only = 1;
  q.vp_ref_cnt = 5;
  q.vp_unresolved_ref_cnt = 4;
  q.vp_last_ref_cycle = 99;
  q.trim_done = 1;
  q.vp_trim_deferred = 1;

  setup_vp_frontier(&afl);
  old_idx = vp_test_frontier_idx(old_site, 0);
  afl.vp_frontier[old_idx].owner = &q;
  afl.vp_frontier[old_idx].dist = 3;
  afl.vp_delayed_evictions_pending = 1;

  vp_restore_resume_state(&afl);

  assert_int_equal(afl.value_profile_active, 0);
  assert_int_equal(afl.value_profile_replay_idx, 0);
  assert_int_equal(afl.score_changed, 0);
  assert_int_equal(q.vp_only, 1);
  assert_int_equal(q.vp_ref_cnt, 0);
  assert_int_equal(q.vp_unresolved_ref_cnt, 0);
  assert_int_equal(q.vp_last_ref_cycle, 0);
  assert_int_equal(q.vp_trim_deferred, 0);
  assert_int_equal(q.trim_done, 0);
  assert_ptr_equal(afl.vp_frontier[old_idx].owner, NULL);
  assert_int_equal(afl.vp_frontier[old_idx].dist, VP_DIST_UNSOLVED);
  assert_int_equal(afl.vp_delayed_evictions_pending, 0);

  free_vp_frontier(&afl);

}

static void test_mode2_keeps_runtime_frontier_after_recovery(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q;
  u32                site = 17;
  size_t             idx;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_mode = 2;
  afl.value_profile_active = 1;
  afl.value_profile_stagnation_secs = 60;
  afl.queue_cycle = 7;
  afl.shm.vp_map = vp;
  afl.queued_items = 3;
  afl.value_profile_replay_idx = 2;
  setup_vp_frontier(&afl);

  idx = vp_test_frontier_idx(site, 0);
  afl.vp_frontier[idx].owner = &q;
  afl.vp_frontier[idx].dist = 5;

  q.vp_only = 1;
  q.vp_ref_cnt = 1;
  q.vp_unresolved_ref_cnt = 1;

  fake_time_ms = 61000;
  afl.last_edge_time = fake_time_ms;
  fake_time_ms += 1000;

  vp_update_activation(&afl);

  assert_int_equal(afl.value_profile_active, 1);
  assert_int_equal(afl.value_profile_replay_idx, 2);
  assert_ptr_equal(afl.vp_frontier[idx].owner, &q);
  assert_int_equal(afl.vp_frontier[idx].dist, 5);
  assert_int_equal(q.vp_ref_cnt, 1);
  assert_int_equal(q.vp_unresolved_ref_cnt, 1);
  assert_int_equal(q.vp_last_ref_cycle, 0);
  assert_int_equal(afl.score_changed, 0);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_vp_queue_state_markers_round_trip(void **state) {

  (void)state;

  char temp_root[] = "/tmp/afl-vp-state-XXXXXX";
  char queue_dir[PATH_MAX], state_dir[PATH_MAX], vp_only_dir[PATH_MAX],
      vp_disabled_dir[PATH_MAX], case_path[PATH_MAX], vp_only_marker[PATH_MAX],
      vp_disabled_marker[PATH_MAX];
  char *root = mkdtemp(temp_root);
  assert_non_null(root);

  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", root);
  snprintf(state_dir, sizeof(state_dir), "%s/queue/.state", root);
  snprintf(vp_only_dir, sizeof(vp_only_dir), "%s/queue/.state/vp_only", root);
  snprintf(vp_disabled_dir, sizeof(vp_disabled_dir),
           "%s/queue/.state/vp_disabled", root);
  snprintf(case_path, sizeof(case_path), "%s/queue/id:000001", root);
  snprintf(vp_only_marker, sizeof(vp_only_marker),
           "%s/queue/.state/vp_only/id:000001", root);
  snprintf(vp_disabled_marker, sizeof(vp_disabled_marker),
           "%s/queue/.state/vp_disabled/id:000001", root);

  vp_test_mkdir(queue_dir);
  vp_test_mkdir(state_dir);
  vp_test_mkdir(vp_only_dir);
  vp_test_mkdir(vp_disabled_dir);
  vp_test_touch(case_path);

  afl_state_t        afl_write, afl_read;
  struct queue_entry q_write, q_read;
  memset(&afl_write, 0, sizeof(afl_write));
  memset(&afl_read, 0, sizeof(afl_read));
  memset(&q_write, 0, sizeof(q_write));
  memset(&q_read, 0, sizeof(q_read));

  afl_write.out_dir = (u8 *)root;
  afl_write.perm = 0600;
  q_write.fname = (u8 *)case_path;

  vp_mark_entry_vp_only(&afl_write, &q_write);
  vp_persist_disabled_marker(&afl_write, &q_write);

  assert_int_equal(access(vp_only_marker, F_OK), 0);
  assert_int_equal(access(vp_disabled_marker, F_OK), 0);
  assert_int_equal(q_write.vp_only, 1);

  afl_read.in_dir = (u8 *)queue_dir;
  afl_read.active_items = 3;
  afl_read.pending_not_fuzzed = 2;
  q_read.perf_score = 100;

  vp_restore_queue_entry_state(&afl_read, &q_read, "id:000001");

  assert_int_equal(q_read.vp_only, 1);
  assert_int_equal(q_read.disabled, 1);
  assert_int_equal(q_read.was_fuzzed, 1);
  assert_int_equal(q_read.perf_score, 0);
  assert_int_equal(afl_read.active_items, 2);
  assert_int_equal(afl_read.pending_not_fuzzed, 1);

  vp_restore_queue_entry_state(&afl_read, &q_read, "id:000001");
  assert_int_equal(afl_read.active_items, 2);
  assert_int_equal(afl_read.pending_not_fuzzed, 1);

  unlink(case_path);
  vp_test_cleanup_state_tree(root, 1, "id:000001");

}

static void test_fastresume_defers_vp_disabled_counter_restore(void **state) {

  (void)state;

  char temp_root[] = "/tmp/afl-vp-fastresume-state-XXXXXX";
  char queue_dir[PATH_MAX], state_dir[PATH_MAX], vp_only_dir[PATH_MAX],
      vp_disabled_dir[PATH_MAX], case_path[PATH_MAX], vp_only_marker[PATH_MAX],
      vp_disabled_marker[PATH_MAX];
  char *root = mkdtemp(temp_root);
  assert_non_null(root);

  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", root);
  snprintf(state_dir, sizeof(state_dir), "%s/queue/.state", root);
  snprintf(vp_only_dir, sizeof(vp_only_dir), "%s/queue/.state/vp_only", root);
  snprintf(vp_disabled_dir, sizeof(vp_disabled_dir),
           "%s/queue/.state/vp_disabled", root);
  snprintf(case_path, sizeof(case_path), "%s/queue/id:000002", root);
  snprintf(vp_only_marker, sizeof(vp_only_marker),
           "%s/queue/.state/vp_only/id:000002", root);
  snprintf(vp_disabled_marker, sizeof(vp_disabled_marker),
           "%s/queue/.state/vp_disabled/id:000002", root);

  vp_test_mkdir(queue_dir);
  vp_test_mkdir(state_dir);
  vp_test_mkdir(vp_only_dir);
  vp_test_mkdir(vp_disabled_dir);
  vp_test_touch(case_path);
  vp_test_touch(vp_disabled_marker);

  afl_state_t        afl;
  struct queue_entry q;
  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  afl.in_dir = (u8 *)queue_dir;
  afl.out_dir = (u8 *)root;
  afl.perm = 0600;
  afl.fast_resume = 1;
  afl.active_items = 1;
  afl.pending_not_fuzzed = 1;
  q.fname = (u8 *)case_path;
  q.perf_score = 100;

  vp_restore_queue_entry_state(&afl, &q, "id:000002");

  assert_int_equal(q.vp_only, 1);
  assert_int_equal(q.disabled, 0);
  assert_int_equal(q.was_fuzzed, 0);
  assert_int_equal(q.perf_score, 100);
  assert_int_equal(afl.active_items, 1);
  assert_int_equal(afl.pending_not_fuzzed, 1);
  assert_int_equal(access(vp_only_marker, F_OK), 0);

  unlink(case_path);
  vp_test_cleanup_state_tree(root, 1, "id:000002");

}

static void test_vp_restore_recreates_queue_state_markers(void **state) {

  (void)state;

  char old_root[] = "/tmp/afl-vp-resume-old-XXXXXX";
  char new_root[] = "/tmp/afl-vp-resume-new-XXXXXX";
  char old_state_dir[PATH_MAX], old_vp_only_dir[PATH_MAX],
      old_vp_disabled_dir[PATH_MAX], new_queue_dir[PATH_MAX],
      new_state_dir[PATH_MAX], new_vp_only_dir[PATH_MAX],
      new_vp_disabled_dir[PATH_MAX], old_vp_only_marker[PATH_MAX],
      old_vp_disabled_marker[PATH_MAX], new_vp_only_marker[PATH_MAX],
      new_vp_disabled_marker[PATH_MAX];
  char *old_dir = mkdtemp(old_root);
  char *new_dir = mkdtemp(new_root);
  assert_non_null(old_dir);
  assert_non_null(new_dir);

  snprintf(old_state_dir, sizeof(old_state_dir), "%s/.state", old_dir);
  snprintf(old_vp_only_dir, sizeof(old_vp_only_dir), "%s/.state/vp_only",
           old_dir);
  snprintf(old_vp_disabled_dir, sizeof(old_vp_disabled_dir),
           "%s/.state/vp_disabled", old_dir);
  snprintf(new_queue_dir, sizeof(new_queue_dir), "%s/queue", new_dir);
  snprintf(new_state_dir, sizeof(new_state_dir), "%s/queue/.state", new_dir);
  snprintf(new_vp_only_dir, sizeof(new_vp_only_dir), "%s/queue/.state/vp_only",
           new_dir);
  snprintf(new_vp_disabled_dir, sizeof(new_vp_disabled_dir),
           "%s/queue/.state/vp_disabled", new_dir);
  snprintf(old_vp_only_marker, sizeof(old_vp_only_marker),
           "%s/.state/vp_only/id:000007", old_dir);
  snprintf(old_vp_disabled_marker, sizeof(old_vp_disabled_marker),
           "%s/.state/vp_disabled/id:000007", old_dir);
  snprintf(new_vp_only_marker, sizeof(new_vp_only_marker),
           "%s/queue/.state/vp_only/id:000007", new_dir);
  snprintf(new_vp_disabled_marker, sizeof(new_vp_disabled_marker),
           "%s/queue/.state/vp_disabled/id:000007", new_dir);

  vp_test_mkdir(old_state_dir);
  vp_test_mkdir(old_vp_only_dir);
  vp_test_mkdir(old_vp_disabled_dir);
  vp_test_mkdir(new_queue_dir);
  vp_test_mkdir(new_state_dir);
  vp_test_mkdir(new_vp_only_dir);
  vp_test_mkdir(new_vp_disabled_dir);
  vp_test_touch(old_vp_only_marker);
  vp_test_touch(old_vp_disabled_marker);

  afl_state_t        afl;
  struct queue_entry q;
  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));
  afl.in_dir = (u8 *)old_dir;
  afl.out_dir = (u8 *)new_dir;
  afl.perm = 0600;
  afl.active_items = 1;
  afl.pending_not_fuzzed = 1;
  q.perf_score = 100;

  vp_restore_queue_entry_state(&afl, &q, "id:000007");

  assert_int_equal(q.vp_only, 1);
  assert_int_equal(q.disabled, 1);
  assert_int_equal(access(new_vp_only_marker, F_OK), 0);
  assert_int_equal(access(new_vp_disabled_marker, F_OK), 0);

  vp_test_cleanup_state_tree(old_dir, 0, "id:000007");
  vp_test_cleanup_state_tree(new_dir, 1, "id:000007");

}

static void test_runtime_frontier_applies_direct_slots(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q;
  u32                site = 7;
  size_t             idx0, idx1, idx2;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));
  q.exec_us = 3;
  q.len = 7;

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);

  vp->exec_id = 1;
  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = (u16)((1U << 0) | (1U << 1) | (1U << 2));
  vp->site[site].slots[0].best_dist = 9;
  vp->site[site].slots[2].best_dist = 3;

  assert_true(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &q);

  idx0 = vp_test_frontier_idx(site, 0);
  idx1 = vp_test_frontier_idx(site, 1);
  idx2 = vp_test_frontier_idx(site, 2);
  assert_ptr_equal(afl.vp_frontier[idx0].owner, &q);
  assert_int_equal(afl.vp_frontier[idx0].dist, 9);
  assert_null(afl.vp_frontier[idx1].owner);
  assert_int_equal(afl.vp_frontier[idx1].dist, VP_DIST_UNSOLVED);
  assert_ptr_equal(afl.vp_frontier[idx2].owner, &q);
  assert_int_equal(afl.vp_frontier[idx2].dist, 3);
  assert_int_equal(q.vp_ref_cnt, 2);
  assert_int_equal(q.vp_unresolved_ref_cnt, 2);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_solved_only_signal_does_not_admit(void **state) {

  (void)state;

  afl_state_t afl;
  vp_map_t   *vp;
  u32         site = 7;

  memset(&afl, 0, sizeof(afl));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);

  vp->exec_id = 1;
  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = (u16)((1U << 0) | (1U << 1));
  vp->site[site].slots[0].best_dist = 0;
  vp->site[site].slots[1].best_dist = 0;

  assert_false(vp_frontier_would_improve(&afl));

  vp->exec_id = 2;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = (u16)((1U << 0) | (1U << 1));
  vp->site[site].slots[0].best_dist = 4;
  vp->site[site].slots[1].best_dist = 0;

  assert_true(vp_frontier_would_improve(&afl));

  free_vp_frontier(&afl);
  free(vp);

}

static void test_runtime_frontier_replaces_owner_and_clears_trim_deferred(
    void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry old_q, new_q;
  u32                site = 29;
  size_t             idx;

  memset(&afl, 0, sizeof(afl));
  memset(&old_q, 0, sizeof(old_q));
  memset(&new_q, 0, sizeof(new_q));
  old_q.exec_us = 9;
  old_q.len = 11;
  old_q.vp_only = 1;
  old_q.vp_ref_cnt = 1;
  old_q.vp_unresolved_ref_cnt = 1;
  old_q.trim_done = 1;
  old_q.vp_trim_deferred = 1;
  new_q.exec_us = 5;
  new_q.len = 8;

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 5;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);

  idx = vp_test_frontier_idx(site, 0);
  afl.vp_frontier[idx].owner = &old_q;
  afl.vp_frontier[idx].dist = 9;

  vp->exec_id = 2;
  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 4;

  assert_true(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &new_q);

  assert_ptr_equal(afl.vp_frontier[idx].owner, &new_q);
  assert_int_equal(afl.vp_frontier[idx].dist, 4);
  assert_int_equal(old_q.vp_ref_cnt, 0);
  assert_int_equal(old_q.vp_unresolved_ref_cnt, 0);
  assert_int_equal(old_q.trim_done, 0);
  assert_int_equal(old_q.vp_trim_deferred, 0);
  assert_int_equal(old_q.vp_last_ref_cycle, afl.queue_cycle);
  assert_int_equal(afl.vp_delayed_evictions_pending, 1);
  assert_int_equal(new_q.vp_ref_cnt, 1);
  assert_int_equal(new_q.vp_unresolved_ref_cnt, 1);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_runtime_frontier_anchors_solved_slots(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry old_q, solver_q, regress_q, costly_solver_q,
      cheaper_solver_q;
  u32    site = 31;
  size_t idx;

  memset(&afl, 0, sizeof(afl));
  memset(&old_q, 0, sizeof(old_q));
  memset(&solver_q, 0, sizeof(solver_q));
  memset(&regress_q, 0, sizeof(regress_q));
  memset(&costly_solver_q, 0, sizeof(costly_solver_q));
  memset(&cheaper_solver_q, 0, sizeof(cheaper_solver_q));

  old_q.exec_us = 9;
  old_q.len = 11;
  old_q.vp_ref_cnt = 1;
  old_q.vp_unresolved_ref_cnt = 1;
  old_q.trim_done = 1;
  old_q.vp_trim_deferred = 1;
  solver_q.exec_us = 5;
  solver_q.len = 8;
  regress_q.exec_us = 3;
  regress_q.len = 7;
  costly_solver_q.exec_us = 4;
  costly_solver_q.len = 5;
  cheaper_solver_q.exec_us = 1;
  cheaper_solver_q.len = 1;

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 9;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);

  idx = vp_test_frontier_idx(site, 0);
  afl.vp_frontier[idx].owner = &old_q;
  afl.vp_frontier[idx].dist = 9;

  vp->exec_id = 3;
  vp->enabled = 1;
  vp->control_len = 1;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 0;

  assert_true(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &solver_q);

  assert_ptr_equal(afl.vp_frontier[idx].owner, &solver_q);
  assert_int_equal(afl.vp_frontier[idx].dist, 0);
  assert_int_equal(old_q.vp_ref_cnt, 0);
  assert_int_equal(old_q.trim_done, 0);
  assert_int_equal(old_q.vp_trim_deferred, 0);
  assert_int_equal(old_q.vp_last_ref_cycle, afl.queue_cycle);
  assert_int_equal(solver_q.vp_ref_cnt, 1);
  assert_int_equal(solver_q.vp_unresolved_ref_cnt, 0);

  vp->exec_id = 4;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 3;

  assert_false(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &regress_q);

  assert_ptr_equal(afl.vp_frontier[idx].owner, &solver_q);
  assert_int_equal(afl.vp_frontier[idx].dist, 0);
  assert_int_equal(regress_q.vp_ref_cnt, 0);
  assert_int_equal(regress_q.vp_unresolved_ref_cnt, 0);
  assert_int_equal(solver_q.vp_ref_cnt, 1);
  assert_int_equal(solver_q.vp_unresolved_ref_cnt, 0);

  solver_q.exec_us = 2;
  solver_q.len = 5;

  vp->exec_id = 5;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 0;

  assert_false(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &costly_solver_q);

  assert_ptr_equal(afl.vp_frontier[idx].owner, &solver_q);
  assert_int_equal(afl.vp_frontier[idx].dist, 0);
  assert_int_equal(costly_solver_q.vp_ref_cnt, 0);
  assert_int_equal(costly_solver_q.vp_unresolved_ref_cnt, 0);
  assert_int_equal(solver_q.vp_ref_cnt, 1);
  assert_int_equal(solver_q.vp_unresolved_ref_cnt, 0);

  vp->exec_id = 6;
  vp->control[0] = (u16)site;
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 0;

  /* By design, VP-only admission ignores equal-distance cost improvements,
     but frontier application still refreshes the solved anchor to the cheaper
     owner once that seed is being applied. */
  assert_false(vp_frontier_would_improve(&afl));
  vp_frontier_apply(&afl, &cheaper_solver_q);

  assert_ptr_equal(afl.vp_frontier[idx].owner, &cheaper_solver_q);
  assert_int_equal(afl.vp_frontier[idx].dist, 0);
  assert_int_equal(solver_q.vp_ref_cnt, 0);
  assert_int_equal(solver_q.vp_unresolved_ref_cnt, 0);
  assert_int_equal(cheaper_solver_q.vp_ref_cnt, 1);
  assert_int_equal(cheaper_solver_q.vp_unresolved_ref_cnt, 0);

  free_vp_frontier(&afl);
  free(vp);

}

static void test_delayed_eviction_waits_without_score_retry(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  q.vp_only = 1;
  q.vp_last_ref_cycle = 3;
  queue_buf[0] = &q;
  afl.value_profile_mode = 1;
  afl.queue_cycle = 3;
  afl.queue_buf = queue_buf;
  afl.queued_items = 1;
  afl.active_items = 1;
  afl.pending_not_fuzzed = 1;
  afl.vp_delayed_evictions_pending = 1;

  vp_apply_delayed_evictions(&afl);

  assert_false(q.disabled);
  assert_int_equal(afl.score_changed, 0);
  assert_int_equal(afl.vp_delayed_evictions_pending, 1);

  ++afl.queue_cycle;
  vp_apply_delayed_evictions(&afl);

  assert_true(q.disabled);
  assert_true(q.was_fuzzed);
  assert_int_equal(afl.active_items, 0);
  assert_int_equal(afl.pending_not_fuzzed, 0);
  assert_int_equal(afl.score_changed, 1);
  assert_int_equal(afl.reinit_table, 1);
  assert_int_equal(afl.vp_delayed_evictions_pending, 0);

}

static void test_delayed_eviction_keeps_coverage_owner_active(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  q.vp_only = 1;
  q.vp_last_ref_cycle = 3;
  q.tc_ref = 1;
  queue_buf[0] = &q;
  afl.value_profile_mode = 1;
  afl.queue_cycle = 4;
  afl.queue_buf = queue_buf;
  afl.queued_items = 1;
  afl.active_items = 1;
  afl.pending_not_fuzzed = 1;
  afl.vp_delayed_evictions_pending = 1;

  vp_apply_delayed_evictions(&afl);

  assert_false(q.disabled);
  assert_false(q.was_fuzzed);
  assert_int_equal(afl.active_items, 1);
  assert_int_equal(afl.pending_not_fuzzed, 1);
  assert_int_equal(afl.score_changed, 0);

}

static void test_initial_duplicate_keeps_vp_frontier_owner(void **state) {

  (void)state;

  afl_state_t        afl;
  struct queue_entry q;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.active_items = 2;
  afl.pending_not_fuzzed = 2;
  q.vp_ref_cnt = 1;
  q.vp_unresolved_ref_cnt = 1;
  q.perf_score = 100;

  assert_false(vp_try_disable_coverage_duplicate(&afl, &q));
  assert_false(q.disabled);
  assert_false(q.was_fuzzed);
  assert_int_equal(q.perf_score, 100);
  assert_int_equal(afl.active_items, 2);
  assert_int_equal(afl.pending_not_fuzzed, 2);

}

static void test_initial_duplicate_disables_non_vp_owner(void **state) {

  (void)state;

  afl_state_t        afl;
  struct queue_entry q;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.active_items = 2;
  afl.pending_not_fuzzed = 2;
  q.perf_score = 100;

  assert_true(vp_try_disable_coverage_duplicate(&afl, &q));
  assert_true(q.disabled);
  assert_true(q.was_fuzzed);
  assert_int_equal(q.perf_score, 0);
  assert_int_equal(afl.active_items, 1);
  assert_int_equal(afl.pending_not_fuzzed, 1);

}

static void test_coverage_release_rearms_vp_eviction(void **state) {

  (void)state;

  afl_state_t         afl;
  struct queue_entry  q;
  struct queue_entry *queue_buf[1];

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  q.vp_only = 1;
  q.vp_last_ref_cycle = 3;
  queue_buf[0] = &q;
  afl.value_profile_mode = 1;
  afl.queue_cycle = 4;
  afl.queue_buf = queue_buf;
  afl.queued_items = 1;
  afl.active_items = 1;
  afl.pending_not_fuzzed = 1;

  vp_coverage_owner_released(&afl, &q);

  assert_false(q.disabled);
  assert_int_equal(afl.vp_delayed_evictions_pending, 1);

  vp_apply_delayed_evictions(&afl);

  assert_true(q.disabled);
  assert_true(q.was_fuzzed);
  assert_int_equal(afl.active_items, 0);
  assert_int_equal(afl.pending_not_fuzzed, 0);
  assert_int_equal(afl.vp_delayed_evictions_pending, 0);

}

static void test_failed_vp_admission_disables_unowned_entry(void **state) {

  (void)state;

  char temp_root[] = "/tmp/afl-vp-failed-admission-XXXXXX";
  char queue_dir[PATH_MAX], state_dir[PATH_MAX], vp_only_dir[PATH_MAX],
      vp_disabled_dir[PATH_MAX], case_path[PATH_MAX],
      vp_disabled_marker[PATH_MAX];
  char *root = mkdtemp(temp_root);
  assert_non_null(root);

  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", root);
  snprintf(state_dir, sizeof(state_dir), "%s/queue/.state", root);
  snprintf(vp_only_dir, sizeof(vp_only_dir), "%s/queue/.state/vp_only", root);
  snprintf(vp_disabled_dir, sizeof(vp_disabled_dir),
           "%s/queue/.state/vp_disabled", root);
  snprintf(case_path, sizeof(case_path), "%s/queue/id:000009", root);
  snprintf(vp_disabled_marker, sizeof(vp_disabled_marker),
           "%s/queue/.state/vp_disabled/id:000009", root);

  vp_test_mkdir(queue_dir);
  vp_test_mkdir(state_dir);
  vp_test_mkdir(vp_only_dir);
  vp_test_mkdir(vp_disabled_dir);
  vp_test_touch(case_path);

  afl_state_t        afl;
  struct queue_entry q;
  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  afl.out_dir = (u8 *)root;
  afl.perm = 0600;
  afl.active_items = 1;
  afl.pending_not_fuzzed = 1;
  q.fname = (u8 *)case_path;
  q.vp_only = 1;
  q.perf_score = 100;

  vp_disable_unowned_entry(&afl, &q);

  assert_true(q.disabled);
  assert_true(q.was_fuzzed);
  assert_int_equal(q.perf_score, 0);
  assert_int_equal(afl.active_items, 0);
  assert_int_equal(afl.pending_not_fuzzed, 0);
  assert_int_equal(afl.score_changed, 1);
  assert_int_equal(afl.reinit_table, 1);
  assert_int_equal(access(vp_disabled_marker, F_OK), 0);

  unlink(case_path);
  vp_test_cleanup_state_tree(root, 1, "id:000009");

}

static void test_l1_favoring_uses_unresolved_refs_and_skips_disabled(
    void **state) {

  (void)state;

  afl_state_t        afl;
  struct queue_entry q_enabled, q_disabled, q_already;

  memset(&afl, 0, sizeof(afl));
  memset(&q_enabled, 0, sizeof(q_enabled));
  memset(&q_disabled, 0, sizeof(q_disabled));
  memset(&q_already, 0, sizeof(q_already));
  afl.value_profile_active = 1;
  afl.queued_favored = 1;
  afl.pending_favored = 1;
  afl.smallest_favored = 5;
  setup_vp_frontier(&afl);

  q_enabled.id = 10;
  q_enabled.vp_unresolved_ref_cnt = 2;
  q_disabled.id = 20;
  q_disabled.disabled = 1;
  q_disabled.vp_unresolved_ref_cnt = 1;
  q_already.id = 5;
  q_already.favored = 1;
  q_already.vp_unresolved_ref_cnt = 1;

  vp_mark_favored_queue_entry(&afl, &q_enabled);
  vp_mark_favored_queue_entry(&afl, &q_disabled);
  vp_mark_favored_queue_entry(&afl, &q_already);

  assert_true(q_enabled.favored);
  assert_false(q_disabled.favored);
  assert_true(q_already.favored);
  assert_int_equal(afl.queued_favored, 2);
  assert_int_equal(afl.pending_favored, 2);
  assert_int_equal(afl.smallest_favored, 5);

  free_vp_frontier(&afl);

}

static void test_runtime_observe_helper_resets_and_restores_sites(
    void **state) {

  (void)state;

  afl_state_t afl;
  vp_map_t   *vp;
  u16         site_ids[2] = {3, 9};
  vp_site_t   saved[2];
  vp_site_t   orig0, orig1, untouched;

  memset(&afl, 0, sizeof(afl));
  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.shm.vp_map = vp;
  vp->enabled = 1;
  vp->exec_id = 7;
  vp->site_ids[3] = 0x12345678U;
  vp->site_ids[9] = 0x87654321U;

  vp_test_init_direct_site(&vp->site[3], 11);
  vp->site[3].hit_count = 2;
  vp->site[3].touched_mask = 0x3;
  vp->site[3].slots[0].best_dist = 9;

  vp_test_init_direct_site(&vp->site[9], 13);
  vp->site[9].hit_count = 4;
  vp->site[9].touched_mask = 0x5;
  vp->site[9].slots[1].best_dist = 5;

  vp_test_init_direct_site(&vp->site[4], 21);
  vp->site[4].touched_mask = 0x9;
  vp->site[4].slots[0].best_dist = 12;

  orig0 = vp->site[3];
  orig1 = vp->site[9];
  untouched = vp->site[4];

  assert_true(vp_runtime_observe_begin(&afl, site_ids, 2, saved));
  assert_int_equal(vp->filter_mode, VP_FILTER_STRICT);
  assert_int_equal(vp->site[3].exec_seen, 0);
  assert_int_equal(vp->site[3].hit_count, 0);
  assert_int_equal(vp->site[3].touched_mask, 0);
  assert_int_equal(vp->site[3].slots[0].best_dist, 9);
  assert_memory_equal(&vp->site[4], &untouched, sizeof(vp_site_t));

  vp->site[3].touched_mask = 1;
  vp->site[9].touched_mask = 1;
  vp_runtime_observe_end(&afl, site_ids, 2, saved);
  assert_int_equal(vp->filter_mode, VP_FILTER_OFF);
  assert_memory_equal(&vp->site[3], &orig0, sizeof(vp_site_t));
  assert_memory_equal(&vp->site[9], &orig1, sizeof(vp_site_t));
  assert_memory_equal(&vp->site[4], &untouched, sizeof(vp_site_t));
  assert_int_equal(vp->site_ids[3], 0x12345678U);
  assert_int_equal(vp->site_ids[9], 0x87654321U);

  free(vp);

}

static void test_runtime_trim_guard_preserve_and_regress(void **state) {

  (void)state;

  afl_state_t        afl;
  struct queue_entry q;
  vp_map_t          *vp;
  vp_trim_guard_t   *guard;
  u32                site = 41;
  size_t             idx0, idx1;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));
  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);

  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);

  q.vp_ref_cnt = 2;
  q.vp_unresolved_ref_cnt = 2;
  q.exec_us = 3;
  q.len = 9;
  idx0 = vp_test_frontier_idx(site, 0);
  idx1 = vp_test_frontier_idx(site, 1);
  afl.vp_frontier[idx0].owner = &q;
  afl.vp_frontier[idx0].dist = 5;
  afl.vp_frontier[idx1].owner = &q;
  afl.vp_frontier[idx1].dist = 7;

  vp->enabled = 1;
  vp->exec_id = 4;
  guard = vp_trim_guard_init(&afl, &q);
  assert_non_null(guard);

  vp_trim_guard_before_exec(guard);
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x3;
  vp->site[site].slots[0].best_dist = 4;
  vp->site[site].slots[1].best_dist = 7;
  assert_true(vp_trim_guard_preserved(guard));
  vp_trim_guard_after_exec(guard);

  vp_trim_guard_before_exec(guard);
  vp_test_init_direct_site(&vp->site[site], vp->exec_id);
  vp->site[site].touched_mask = 0x1;
  vp->site[site].slots[0].best_dist = 4;
  assert_false(vp_trim_guard_preserved(guard));
  vp_trim_guard_after_exec(guard);

  vp_trim_guard_destroy(guard);
  free_vp_frontier(&afl);
  free(vp);

}

static void test_focus_retires_solved_and_never_owning_sites(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q_solved, q_open;

  memset(&afl, 0, sizeof(afl));
  memset(&q_solved, 0, sizeof(q_solved));
  memset(&q_open, 0, sizeof(q_open));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);
  setup_vp_focus(&afl);

  vp->site_ids[5] = 0x1111U;
  for (u16 rel = 0; rel < VP_SLOTS; ++rel) {

    afl.vp_frontier[vp_test_frontier_idx(5, rel)].owner = &q_solved;
    afl.vp_frontier[vp_test_frontier_idx(5, rel)].dist = 0;

  }

  vp->site_ids[9] = 0x2222U;
  afl.vp_frontier[vp_test_frontier_idx(9, 0)].owner = &q_open;
  afl.vp_frontier[vp_test_frontier_idx(9, 0)].dist = 4;

  vp->site_ids[11] = 0x3333U;

  vp_focus_rotate(&afl);

  assert_int_equal(afl.vp_sites_assigned, 3);
  assert_int_equal(afl.vp_sites_retired, 1);
  assert_true(vp->site[5].flags & VP_SITE_RETIRED);
  assert_false(vp->site[9].flags & VP_SITE_RETIRED);
  assert_false(vp->site[11].flags & VP_SITE_RETIRED);

  assert_false(afl.vp_focus_active);
  assert_int_equal(vp->filter_mode, VP_FILTER_OFF);

  for (u32 i = 0; i < VP_IDLE_RETIRE_CYCLES; ++i) {

    vp_focus_rotate(&afl);

  }

  assert_true(vp->site[11].flags & VP_SITE_RETIRED);
  assert_false(vp->site[9].flags & VP_SITE_RETIRED);

  vp_restore_resume_state(&afl);
  assert_false(vp->site[5].flags & VP_SITE_RETIRED);
  assert_false(vp->site[11].flags & VP_SITE_RETIRED);
  assert_int_equal(afl.vp_site_idle[11], 1);

  free_vp_focus(&afl);
  free_vp_frontier(&afl);
  free(vp);

}

static void test_partial_ordinal_site_is_not_solved(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q;

  memset(&afl, 0, sizeof(afl));
  memset(&q, 0, sizeof(q));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);
  setup_vp_focus(&afl);

  vp->site_ids[7] = 0x4444U;
  afl.vp_frontier[vp_test_frontier_idx(7, 0)].owner = &q;
  afl.vp_frontier[vp_test_frontier_idx(7, 0)].dist = 0;
  afl.vp_frontier[vp_test_frontier_idx(7, 1)].owner = &q;
  afl.vp_frontier[vp_test_frontier_idx(7, 1)].dist = 0;

  vp_focus_rotate(&afl);
  assert_false(vp->site[7].flags & VP_SITE_RETIRED);

  afl.vp_frontier[vp_test_frontier_idx(7, 2)].owner = &q;
  afl.vp_frontier[vp_test_frontier_idx(7, 2)].dist = 3;
  vp_focus_rotate(&afl);
  assert_false(vp->site[7].flags & VP_SITE_RETIRED);
  assert_int_equal(afl.vp_site_idle[7], 0);

  for (u32 i = 0; i < VP_IDLE_RETIRE_CYCLES + 2U; ++i) {

    vp_focus_rotate(&afl);

  }

  assert_false(vp->site[7].flags & VP_SITE_RETIRED);

  free_vp_focus(&afl);
  free_vp_frontier(&afl);
  free(vp);

}

static void test_retired_heavy_map_keeps_filtering(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q_solved, q_open;
  u32                assigned = 6000U;
  u32                solved = 5000U;

  memset(&afl, 0, sizeof(afl));
  memset(&q_solved, 0, sizeof(q_solved));
  memset(&q_open, 0, sizeof(q_open));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);
  setup_vp_focus(&afl);

  for (u32 s = 0; s < assigned; ++s) {

    vp->site_ids[s] = s + 1U;

  }

  for (u32 s = 0; s < solved; ++s) {

    for (u16 rel = 0; rel < VP_SLOTS; ++rel) {

      afl.vp_frontier[vp_test_frontier_idx(s, rel)].owner = &q_solved;
      afl.vp_frontier[vp_test_frontier_idx(s, rel)].dist = 0;

    }

  }

  for (u32 s = solved; s < assigned; ++s) {

    afl.vp_frontier[vp_test_frontier_idx(s, 0)].owner = &q_open;
    afl.vp_frontier[vp_test_frontier_idx(s, 0)].dist = 5;

  }

  vp_focus_rotate(&afl);

  assert_int_equal(afl.vp_sites_assigned, assigned);
  assert_int_equal(afl.vp_sites_retired, solved);
  assert_true(afl.vp_focus_live < VP_FOCUS_TARGET_SITES);
  assert_true(afl.vp_focus_active);
  assert_int_equal(vp->filter_mode, VP_FILTER_FOCUS);

  for (u32 s = 0; s < solved; ++s) {

    assert_false(afl.vp_focus_bitmap[s >> 6] & (1ULL << (s & 63)));

  }

  free_vp_focus(&afl);
  free_vp_frontier(&afl);
  free(vp);

}

static void test_focus_caps_live_sites_and_rotates(void **state) {

  (void)state;

  afl_state_t        afl;
  vp_map_t          *vp;
  struct queue_entry q_open;
  u32                assigned = 6000U;
  u32                owners = 5000U;
  u64               *first_round;
  u32                sampled = 0;

  memset(&afl, 0, sizeof(afl));
  memset(&q_open, 0, sizeof(q_open));

  vp = calloc(1, sizeof(vp_map_t));
  assert_non_null(vp);
  afl.value_profile_mode = 1;
  afl.value_profile_active = 1;
  afl.queue_cycle = 1;
  afl.shm.vp_map = vp;
  setup_vp_frontier(&afl);
  setup_vp_focus(&afl);

  for (u32 s = 0; s < assigned; ++s) {

    vp->site_ids[s] = s + 1U;

  }

  for (u32 s = 0; s < owners; ++s) {

    afl.vp_frontier[vp_test_frontier_idx(s, 0)].owner = &q_open;
    afl.vp_frontier[vp_test_frontier_idx(s, 0)].dist = 6;

  }

  vp_focus_rotate(&afl);

  assert_true(afl.vp_focus_active);
  assert_int_equal(vp->filter_mode, VP_FILTER_FOCUS);
  assert_int_equal(afl.vp_sites_assigned, assigned);
  assert_int_equal(afl.vp_sites_retired, 0);
  assert_int_equal(afl.vp_focus_live, VP_FOCUS_TARGET_SITES);
  assert_int_equal(vp_test_focus_popcount(&afl), VP_FOCUS_TARGET_SITES);
  assert_memory_equal(vp->filter_bitmap, afl.vp_focus_bitmap,
                      sizeof(vp->filter_bitmap));

  for (u32 s = owners; s < assigned; ++s) {

    if (afl.vp_focus_bitmap[s >> 6] & (1ULL << (s & 63))) { ++sampled; }

  }

  assert_true(sampled > 0);

  first_round = calloc(VP_MAP_W / 64U, sizeof(u64));
  assert_non_null(first_round);
  memcpy(first_round, afl.vp_focus_bitmap, (VP_MAP_W / 64U) * sizeof(u64));

  vp_focus_rotate(&afl);

  assert_true(afl.vp_focus_active);
  assert_int_equal(afl.vp_focus_live, VP_FOCUS_TARGET_SITES);
  assert_int_equal(vp_test_focus_popcount(&afl), VP_FOCUS_TARGET_SITES);
  assert_memory_not_equal(first_round, afl.vp_focus_bitmap,
                          (VP_MAP_W / 64U) * sizeof(u64));

  free(first_round);
  free_vp_focus(&afl);
  free_vp_frontier(&afl);
  free(vp);

}

int main(int argc, char **argv) {

  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_site_selector_primary_secondary_and_filter),
      cmocka_unit_test(test_site_selector_full_sets_and_zero_tag),
      cmocka_unit_test(test_mode2_activation_is_one_way),
      cmocka_unit_test(test_non_stagnation_mode_is_noop),
      cmocka_unit_test(test_prepare_exec_suppression_preserves_runtime_sample),
      cmocka_unit_test(test_mode2_resume_restores_active_state),
      cmocka_unit_test(test_mode1_resume_rebuilds_frontier),
      cmocka_unit_test(test_activation_replay_skips_disabled_queue_entries),
      cmocka_unit_test(test_resume_replay_discards_fastresume_vp_ownership),
      cmocka_unit_test(test_resume_without_vp_clears_fastresume_vp_ownership),
      cmocka_unit_test(test_mode2_keeps_runtime_frontier_after_recovery),
      cmocka_unit_test(test_vp_queue_state_markers_round_trip),
      cmocka_unit_test(test_fastresume_defers_vp_disabled_counter_restore),
      cmocka_unit_test(test_vp_restore_recreates_queue_state_markers),
      cmocka_unit_test(test_runtime_frontier_applies_direct_slots),
      cmocka_unit_test(test_solved_only_signal_does_not_admit),
      cmocka_unit_test(
          test_runtime_frontier_replaces_owner_and_clears_trim_deferred),
      cmocka_unit_test(test_runtime_frontier_anchors_solved_slots),
      cmocka_unit_test(test_delayed_eviction_waits_without_score_retry),
      cmocka_unit_test(test_delayed_eviction_keeps_coverage_owner_active),
      cmocka_unit_test(test_initial_duplicate_keeps_vp_frontier_owner),
      cmocka_unit_test(test_initial_duplicate_disables_non_vp_owner),
      cmocka_unit_test(test_coverage_release_rearms_vp_eviction),
      cmocka_unit_test(test_failed_vp_admission_disables_unowned_entry),
      cmocka_unit_test(
          test_l1_favoring_uses_unresolved_refs_and_skips_disabled),
      cmocka_unit_test(test_runtime_observe_helper_resets_and_restores_sites),
      cmocka_unit_test(test_runtime_trim_guard_preserve_and_regress),
      cmocka_unit_test(test_focus_retires_solved_and_never_owning_sites),
      cmocka_unit_test(test_partial_ordinal_site_is_not_solved),
      cmocka_unit_test(test_retired_heavy_map_keeps_filtering),
      cmocka_unit_test(test_focus_caps_live_sites_and_rotates)};

  __real_exit(cmocka_run_group_tests(tests, NULL, NULL));
  return 0;

}

