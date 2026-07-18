/* Regression tests for IJON max-input persistence (P2-14): in-memory state
   and the update counter are committed only when the file is persisted, and
   one improvement counts as exactly one update. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cmocka.h>
#include "types.h"
#include "alloc-inl.h"
#include "afl-ijon-min.h"

static u8          fail_close;
static u8          fail_fsync;
static u8          fail_rename;
static u8          fail_unlink;
static u8          write_eintr;
static size_t      write_chunk;
static const char *unlink_path;

ssize_t __real_write(int fd, const void *buf, size_t len);
int     __real_fsync(int fd);
int     __real_close(int fd);
int     __real_rename(const char *old_path, const char *new_path);
int     __real_unlink(const char *path);

ssize_t __wrap_write(int fd, const void *buf, size_t len) {

  if (write_eintr) {

    write_eintr = 0;
    errno = EINTR;
    return -1;

  }

  if (write_chunk && len > write_chunk) { len = write_chunk; }
  return __real_write(fd, buf, len);

}

int __wrap_fsync(int fd) {

  if (fail_fsync) {

    fail_fsync = 0;
    errno = EIO;
    return -1;

  }

  return __real_fsync(fd);

}

int __wrap_close(int fd) {

  if (fail_close) {

    fail_close = 0;
    __real_close(fd);
    errno = EIO;
    return -1;

  }

  return __real_close(fd);

}

int __wrap_rename(const char *old_path, const char *new_path) {

  if (fail_rename) {

    fail_rename = 0;
    errno = EIO;
    return -1;

  }

  return __real_rename(old_path, new_path);

}

int __wrap_unlink(const char *path) {

  if (fail_unlink && unlink_path && !strcmp(path, unlink_path)) {

    errno = EACCES;
    return -1;

  }

  return __real_unlink(path);

}

static void reset_failures(void) {

  fail_close = 0;
  fail_fsync = 0;
  fail_rename = 0;
  fail_unlink = 0;
  write_eintr = 0;
  write_chunk = 0;
  unlink_path = NULL;

}

static int suppress_stderr(void) {

  fflush(stderr);
  int saved = dup(STDERR_FILENO);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {

    dup2(devnull, STDERR_FILENO);
    __real_close(devnull);

  }

  return saved;

}

static void restore_stderr(int saved) {

  fflush(stderr);
  if (saved >= 0) {

    dup2(saved, STDERR_FILENO);
    __real_close(saved);

  }

}

static void cleanup_state(ijon_min_state *st, const char *dir,
                          const char *root) {

  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++) {

    unlink(st->infos[i]->filename);
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", st->infos[i]->filename);
    unlink(tmp);

  }

  destroy_ijon_min_state(st);
  rmdir(dir);
  rmdir(root);

}

static void test_store_success_commits(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[64];
  memset(data, 0x5a, sizeof(data));

  assert_int_equal(ijon_store_max_input(st, 3, data, sizeof(data)), 1);
  assert_int_equal(st->infos[3]->len, sizeof(data));

  struct stat stt;
  assert_int_equal(stat(st->infos[3]->filename, &stt), 0);
  assert_int_equal(stt.st_size, sizeof(data));

  cleanup_state(st, dir, root);

}

static void test_store_retries_short_and_interrupted_writes(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[64];
  memset(data, 0x5a, sizeof(data));

  reset_failures();
  write_eintr = 1;
  write_chunk = 3;
  assert_int_equal(ijon_store_max_input(st, 3, data, sizeof(data)), 1);
  assert_int_equal(st->infos[3]->len, sizeof(data));

  reset_failures();
  cleanup_state(st, dir, root);

}

static void test_store_sync_close_and_rename_failures(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[64];
  memset(data, 0x5a, sizeof(data));

  reset_failures();
  fail_close = 1;
  int saved = suppress_stderr();
  u8  ret = ijon_store_max_input(st, 3, data, sizeof(data));
  restore_stderr(saved);
  assert_int_equal(ret, 0);
  assert_int_equal(st->infos[3]->len, 0);

  fail_rename = 1;
  saved = suppress_stderr();
  ret = ijon_store_max_input(st, 3, data, sizeof(data));
  restore_stderr(saved);
  assert_int_equal(ret, 0);
  assert_int_equal(st->infos[3]->len, 0);

  struct stat stt;
  assert_int_equal(stat(st->infos[3]->filename, &stt), -1);

  reset_failures();
  cleanup_state(st, dir, root);

}

static void test_store_failure_no_commit(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[64];
  memset(data, 0x5a, sizeof(data));

  /* Remove the directory so the temp-file open fails. */
  rmdir(dir);

  int saved = suppress_stderr();
  u8  ret = ijon_store_max_input(st, 5, data, sizeof(data));
  restore_stderr(saved);
  assert_int_equal(ret, 0);
  assert_int_equal(st->infos[5]->len, 0);
  assert_int_equal(st->num_updates, 0);

  cleanup_state(st, dir, root);

}

static void test_update_counts_once(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[16];
  memset(data, 0x11, sizeof(data));

  u64                     max_area[MAP_SIZE_IJON_ENTRIES] = {0};
  dynamic_shared_access_t shared = {.ijon_max_area = max_area};
  max_area[7] = 100;

  ijon_update_max_dynamic(st, &shared, data, sizeof(data));

  assert_int_equal(st->num_updates, 1);
  assert_int_equal(st->num_entries, 1);
  assert_int_equal(st->max_map[7], 100);
  assert_int_equal(st->persisted[7], 0);

  cleanup_state(st, dir, root);

}

static void test_update_failure_no_commit(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[16];
  memset(data, 0x11, sizeof(data));

  rmdir(dir);

  u64                     max_area[MAP_SIZE_IJON_ENTRIES] = {0};
  dynamic_shared_access_t shared = {.ijon_max_area = max_area};
  max_area[7] = 100;

  int saved = suppress_stderr();
  ijon_update_max_dynamic(st, &shared, data, sizeof(data));
  restore_stderr(saved);

  assert_int_equal(st->num_updates, 0);
  assert_int_equal(st->num_entries, 0);
  assert_int_equal(st->max_map[7], 0);

  cleanup_state(st, dir, root);

}

static void test_retire_unlink_failure_no_commit(void **state) {

  (void)state;
  char root[] = "/tmp/afl-ijon-unit.XXXXXX";
  assert_non_null(mkdtemp(root));
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/max", root);

  ijon_min_state *st = new_ijon_min_state_with_limit(dir, 100000);
  u8              data[16];
  memset(data, 0x11, sizeof(data));
  assert_int_equal(ijon_store_max_input(st, 7, data, sizeof(data)), 1);
  st->max_map[7] = 100;
  st->num_entries = 1;

  u64                     max_area[MAP_SIZE_IJON_ENTRIES] = {0};
  dynamic_shared_access_t shared = {.ijon_max_area = max_area};
  max_area[7] = UINT64_MAX;

  reset_failures();
  fail_unlink = 1;
  unlink_path = st->infos[7]->filename;
  afl_ijon_retire_max = 1;
  int saved = suppress_stderr();
  ijon_update_max_dynamic(st, &shared, data, sizeof(data));
  restore_stderr(saved);
  afl_ijon_retire_max = 0;

  assert_int_equal(st->max_map[7], 100);
  assert_int_equal(st->infos[7]->len, sizeof(data));
  assert_int_equal(st->num_entries, 1);
  assert_int_equal(st->num_updates, 0);

  reset_failures();
  cleanup_state(st, dir, root);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_store_success_commits),
      cmocka_unit_test(test_store_retries_short_and_interrupted_writes),
      cmocka_unit_test(test_store_sync_close_and_rename_failures),
      cmocka_unit_test(test_store_failure_no_commit),
      cmocka_unit_test(test_update_counts_once),
      cmocka_unit_test(test_update_failure_no_commit),
      cmocka_unit_test(test_retire_unlink_failure_no_commit),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

