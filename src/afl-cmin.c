/*
   american fuzzy lop++ - corpus minimization tool
   -----------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   A tool to minimize the corpus.

 */

#define AFL_MAIN
#define AFL_CMIN

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "common.h"
#include "config.h"
#include "debug.h"
#include "forkserver.h"
#include "hash.h"
#include "hash.h"
#include "sharedmem.h"
#include "types.h"

#define MAX_WORKERS 256
#define SHA1_SIZE 20
#define QUEUE_CAPACITY (64 * 1024 * 1024)
#define DETECTION_MAP_SIZE (16 * 1024 * 1024)

#if defined(__AVX2__)
  #include <immintrin.h>
#endif

typedef struct {

  u8 *dir;
  u8 *name;
  u32 size;
  u8  sha1[SHA1_SIZE];
  u8  is_crash;

} cmin_file_t;

static u8 **in_dir;                    /* one or more input dirs            */
static u32  in_dir_cap;                /* capacity of in_dir                */
static u8  *out_dir,                   /* output directory                  */
    *crash_dir,                        /* crash directory                   */
    *target_bin,                       /* target binary                     */
    *stdin_file;                       /* stdin file                        */

static u8  *progname;
static u8 **target_args;               /* target arguments                  */

static u32 in_dir_cnt,                 /* number of input directories       */
    cpu_count,                         /* number of CPU cores               */
    exec_workers = 1,                  /* number of execution workers       */
    update_workers = 1,                /* number of update workers          */
    mem_limit_given,                   /* memory limit given?               */
    timeout_given,                     /* timeout given?                    */
    mem_limit,                         /* memory limit                      */
    time_limit = 5000,                 /* timeout                           */
    crashes_only,                      /* retain only crashes?              */
    allow_any,                         /* allow any termination status?     */
    edges_only,                        /* coverage only?                    */
    no_dedup,                          /* skip deduplication?               */
    as_queue;                          /* save as queue?                    */

static u8 debug_mode,                  /* debug mode                        */
    frida_mode,                        /* Frida mode                        */
    qemu_mode,                         /* QEMU mode                         */
    unicorn_mode,                      /* Unicorn mode                      */
    nyx_mode;                          /* Nyx mode                          */

static cmin_file_t **files;
static u32           items;
static u32           files_capacity;

/* Parallel collection structures */
static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  queue_cond = PTHREAD_COND_INITIALIZER;

typedef struct dir_queue_item {

  u8                    *dir;
  struct dir_queue_item *next;

} dir_queue_item_t;

static dir_queue_item_t *queue_head;
static dir_queue_item_t *queue_tail;
static u32               busy_collectors;
static volatile u8       collection_done;

static void queue_add(u8 *dir) {

  dir_queue_item_t *item = ck_alloc(sizeof(dir_queue_item_t));
  item->dir = strdup(dir);

  pthread_mutex_lock(&queue_mutex);
  if (!queue_head) {

    queue_head = item;
    queue_tail = item;

  } else {

    queue_tail->next = item;
    queue_tail = item;

  }

  pthread_cond_signal(&queue_cond);
  pthread_mutex_unlock(&queue_mutex);

}

#ifdef __linux__
static u32 get_nyx_map_size(u8 *target_path) {

  u8                   *libnyx_binary = find_afl_binary(progname, "libnyx.so");
  nyx_plugin_handler_t *nyx_handlers = afl_load_libnyx_plugin(libnyx_binary);
  ck_free(libnyx_binary);

  if (!nyx_handlers) { FATAL("failed to initialize libnyx.so..."); }

  void *nyx_config = nyx_handlers->nyx_config_load(target_path);

  char *workdir_path = create_nyx_tmp_workdir();
  nyx_handlers->nyx_config_set_workdir_path(nyx_config, workdir_path);
  nyx_handlers->nyx_config_set_process_role(nyx_config, StandAlone);

  void *nyx_runner = nyx_handlers->nyx_new(nyx_config, 0);

  if (!nyx_runner) { FATAL("nyx_new failed"); }

  u32 size = (u32)nyx_handlers->nyx_get_bitmap_buffer_size(nyx_runner);

  nyx_handlers->nyx_shutdown(nyx_runner);
  nyx_handlers->nyx_config_free(nyx_config);

  afl_forkserver_t fsrv = {0};
  fsrv.nyx_handlers = nyx_handlers;
  remove_nyx_tmp_workdir(&fsrv, workdir_path);

  return size;

}

#endif

/* Shared Memory Queue Implementation */
typedef struct {

  pthread_mutex_t mutex;
  pthread_cond_t  cond_read;
  pthread_cond_t  cond_write;
  u32             head;
  u32             tail;
  u32             size;
  u32             capacity;
  u8              buf[];

} cmin_queue_t;

/* Message format: [type (u32)] [len (u32)] [payload...] */
#define QUEUE_MSG_DATA 1
#define QUEUE_MSG_STOP 2

static cmin_queue_t *queue;

static void queue_init(u32 capacity) {

  // Align to page size? sharedmem_t usually handles this but we need a custom
  // structure We use mmap anon shared
  u32 total_size = sizeof(cmin_queue_t) + capacity;
  queue = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (queue == MAP_FAILED) PFATAL("mmap queue");

  pthread_mutexattr_t mattr;
  pthread_mutexattr_init(&mattr);
  pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
  pthread_mutex_init(&queue->mutex, &mattr);
  pthread_mutexattr_destroy(&mattr);

  pthread_condattr_t cattr;
  pthread_condattr_init(&cattr);
  pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
  pthread_cond_init(&queue->cond_read, &cattr);
  pthread_cond_init(&queue->cond_write, &cattr);
  pthread_condattr_destroy(&cattr);

  queue->head = 0;
  queue->tail = 0;
  queue->size = 0;
  queue->capacity = capacity;

}

static void queue_write(const void *src, u32 len, u32 *tail) {

  u32 part1 = queue->capacity - *tail;
  if (part1 >= len) {

    memcpy(queue->buf + *tail, src, len);
    *tail = (*tail + len) % queue->capacity;

  } else {

    memcpy(queue->buf + *tail, src, part1);
    memcpy(queue->buf, (u8 *)src + part1, len - part1);
    *tail = len - part1;

  }

}

static void queue_read(void *dst, u32 len, u32 *head) {

  u32 part1 = queue->capacity - *head;
  if (part1 >= len) {

    memcpy(dst, queue->buf + *head, len);
    *head = (*head + len) % queue->capacity;

  } else {

    memcpy(dst, queue->buf + *head, part1);
    memcpy((u8 *)dst + part1, queue->buf, len - part1);
    *head = len - part1;

  }

}

static void queue_push(u32 type, const void *data, u32 len) {

  u32 packet_len = sizeof(u32) * 2 + len;
  if (packet_len > queue->capacity) FATAL("Message too large for queue");

  pthread_mutex_lock(&queue->mutex);

  while (queue->capacity - queue->size < packet_len) {

    pthread_cond_wait(&queue->cond_write, &queue->mutex);

  }

  u32 tail = queue->tail;

  // Write Type
  queue_write(&type, sizeof(u32), &tail);

  // Write Len
  queue_write(&len, sizeof(u32), &tail);

  // Write Data
  if (len > 0) { queue_write(data, len, &tail); }

  queue->tail = tail;
  queue->size += packet_len;

  pthread_cond_signal(&queue->cond_read);
  pthread_mutex_unlock(&queue->mutex);

}

static u32 queue_pop(u32 *type, void *buf, u32 max_len) {

  pthread_mutex_lock(&queue->mutex);

  while (queue->size == 0) {

    pthread_cond_wait(&queue->cond_read, &queue->mutex);

  }

  u32 head = queue->head;
  u32 packet_len = 0;

  // Read Type
  queue_read(type, sizeof(u32), &head);

  // Read Len
  u32 len;
  queue_read(&len, sizeof(u32), &head);

  if (len > max_len) FATAL("Buffer too small for message");

  // Read Data
  if (len > 0) { queue_read(buf, len, &head); }

  queue->head = head;
  packet_len = sizeof(u32) * 2 + len;
  queue->size -= packet_len;

  pthread_cond_signal(&queue->cond_write);  // Notify writer space available
  pthread_mutex_unlock(&queue->mutex);

  return len;

}

// specific prototype if not in common headers

void sha1(const u8 *data, size_t len, u8 *out);

/* Classify tuple counts to human-friendly 1-8 buckets */
static const u8 count_class_human[256] = {

    [0] = 0,         [1] = 1,          [2] = 2,
    [3] = 3,         [4 ... 7] = 4,    [8 ... 15] = 5,
    [16 ... 31] = 6, [32 ... 127] = 7, [128 ... 255] = 8};

static volatile u32 deduped_cnt;
static volatile u32 next_dedup_idx;
static u32          cmin_sentinel_idx;

// detect file size only if the first read exceeded the buffer
void get_binary_hash_local(cmin_file_t *f, int dirfd) {

  if (!f || !f->name) { return; }

  // Use openat if dirfd is valid
  int fd;
  if (dirfd >= 0) {

    fd = openat(dirfd, f->name, O_RDONLY);

  } else {

    // Fallback (should typically not happen if logic is correct, but safer)
    u8 *fn = alloc_printf("%s/%s", f->dir, f->name);
    fd = open(fn, O_RDONLY);
    ck_free(fn);

  }

  if (fd < 0) {

    WARNF("Unable to open '%s/'%s'", f->dir, f->name);
    return;

  }

  u8      stack_buf[65536];
  ssize_t res = read(fd, stack_buf, sizeof(stack_buf));

  if (res <= 0) {

    // Empty or error
    close(fd);
    f->size = 0;
    memset(f->sha1, 0, SHA1_SIZE);
    return;  // Invalid

  }

  if (res < (ssize_t)sizeof(stack_buf)) {

    // Small file, we know the size now
    f->size = res;
    close(fd);
    sha1(stack_buf, res, f->sha1);
    return;

  }

  // File is at least 64k. We need real size.
  struct stat st;
  if (fstat(fd, &st) < 0) {

    WARNF("Unable to fstat '%s/%s'", f->dir, f->name);
    close(fd);
    memset(f->sha1, 0, SHA1_SIZE);
    return;

  }

  if (st.st_size >= UINT32_MAX) {

    WARNF("File '%s/%s' is too large (%ld bytes), skipping.", f->dir, f->name,
          st.st_size);
    close(fd);
    f->size = 0;
    memset(f->sha1, 0, SHA1_SIZE);
    return;

  }

  f->size = st.st_size;
  u64 map_len = f->size;

  u8 *f_data = mmap(0, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (f_data == MAP_FAILED) {

    // Fallback to alloc
    f_data = ck_alloc(map_len);
    lseek(fd, 0, SEEK_SET);
    // We don't have full path for logging easily here, but openat works.
    u8 *fn_log = alloc_printf("%s/%s", f->dir, f->name);
    ck_read(fd, f_data, map_len, fn_log);
    ck_free(fn_log);

    sha1(f_data, map_len, f->sha1);
    ck_free(f_data);
    close(fd);
    return;

  }

  close(fd);
  sha1(f_data, map_len, f->sha1);
  munmap(f_data, map_len);

}

static void *dedup_worker(void *arg) {

  (void)arg;

  // Cache for openat
  u8 *last_dir = NULL;
  int last_dirfd = -1;

  u32 i;
  while ((i = __sync_fetch_and_add(&next_dedup_idx, 1)) < items) {

    // Check if dir changed
    if (!last_dir || strcmp(last_dir, files[i]->dir)) {

      if (last_dirfd >= 0) close(last_dirfd);
      last_dir = files[i]->dir;
      last_dirfd = open(last_dir, O_RDONLY | O_DIRECTORY);
      // If fail, get_binary_hash_local will fallback

    }

    get_binary_hash_local(files[i], last_dirfd);
    __sync_fetch_and_add(&deduped_cnt, 1);

  }

  if (last_dirfd >= 0) close(last_dirfd);

  return NULL;

}

static int compare_hashes(const void *a, const void *b) {

  cmin_file_t *fa = *(cmin_file_t **)a;
  cmin_file_t *fb = *(cmin_file_t **)b;

  return memcmp(fa->sha1, fb->sha1, SHA1_SIZE);

}

static void dedup_files(void) {

  OKF("Deduplicating inputs...");

  deduped_cnt = 0;
  next_dedup_idx = 0;
  pthread_t *t = ck_alloc(sizeof(pthread_t) * update_workers);

  for (u32 i = 0; i < update_workers; i++) {

    pthread_create(&t[i], NULL, dedup_worker, (void *)(size_t)i);

  }

  u64 start_ms = get_cur_time();

  while (deduped_cnt < items) {

    usleep(250000);  // Check every 0.25s for responsiveness

    u32    cnt = deduped_cnt;
    u64    cur_ms = get_cur_time();
    double speed =
        (cur_ms > start_ms) ? (cnt * 1000.0 / (cur_ms - start_ms)) : 0.0;
    u64 et = (cur_ms - start_ms) / 1000;

    SAYF(cGRA
         "\r    Processed %u/%u files (%.2f/sec) [elapsed "
         "%llus]..." cRST,
         cnt, items, speed, et);
    fflush(stdout);

  }

  u64    cur_ms = get_cur_time();
  u64    et = (cur_ms - start_ms) / 1000;
  double speed =
      (cur_ms > start_ms) ? (items * 1000.0 / (cur_ms - start_ms)) : 0.0;

  SAYF(cGRA "\r    Processed %u/%u files (%.2f/sec) [elapsed %llus]\n" cRST,
       items, items, speed, et);

  for (u32 i = 0; i < update_workers; i++) {

    pthread_join(t[i], NULL);

  }

  ck_free(t);

  // sort by hash
  qsort(files, items, sizeof(cmin_file_t *), compare_hashes);

  // remove duplicates
  u32          unique = 0;
  cmin_file_t *prev = NULL;

  for (u32 i = 0; i < items; i++) {

    if (files[i]->size == 0) {

      ck_free(files[i]->name);
      ck_free(files[i]);
      continue;

    }

    if (prev && files[i]->size == prev->size &&
        memcmp(files[i]->sha1, prev->sha1, SHA1_SIZE) == 0) {

      ck_free(files[i]->name);
      ck_free(files[i]);
      continue;

    }

    prev = files[i];
    files[unique++] = files[i];

  }

  OKF("Remain %u files after dedup", unique);
  items = unique;
  files_capacity = items;
  if (items > unique) {

    files = ck_realloc(files, files_capacity * sizeof(cmin_file_t *));

  }

}

static u32  map_size = MAP_SIZE;
static u32 *best_files;

typedef struct {

  u32 tuple;
  u32 count;

} tuple_info_t;

static int compare_tuple_counts(const void *a, const void *b) {

  const tuple_info_t *ta = (const tuple_info_t *)a;
  const tuple_info_t *tb = (const tuple_info_t *)b;

  if (ta->count != tb->count) return ta->count - tb->count;  // ascending
  return ta->tuple - tb->tuple;

}

typedef struct {

  u32  len;
  u32 *tuples;

} trace_t;

typedef struct {

  u32              id;
  u32              start;
  u32              end;
  u32             *local_best;
  u32             *local_counts;
  afl_forkserver_t fsrv;
  sharedmem_t      shm;
  FILE            *trace_log;

} worker_data_t;

static u32 collect_coverage_counts(u8 *trace, u32 map_size, u32 *tuples) {

  u32 t_len = 0;

  if (edges_only) {

    for (u32 k = 0; k < map_size; k++) {

      if (trace[k]) { tuples[t_len++] = k; }

    }

  } else {

#if defined(__AVX2__)
    /* AVX2 Optimization: Check 32 bytes at a time */
    u32      i = 0;
    u32      map_size256 = map_size / 32;
    __m256i *trace256 = (__m256i *)trace;
    __m256i  zero_vec = _mm256_setzero_si256();

    for (i = 0; i < map_size256; i++) {

      __m256i v = _mm256_loadu_si256(&trace256[i]);

      /* Compare with zero: 0xFF where equal to zero, 0x00 where non-zero */
      __m256i cmp = _mm256_cmpeq_epi8(v, zero_vec);

      /* mask bit is 1 if byte is zero, 0 if non-zero */
      u32 mask = _mm256_movemask_epi8(cmp);

      /* Invert: bit is 1 if non-zero */
      mask = ~mask;

      /* Iterate set bits (non-zero bytes) */
      while (mask) {

        /* Get index of first set bit */
        u32 idx = __builtin_ctz(mask);

        /* Clear this bit */
        mask &= (mask - 1);

        u32 pos = i * 32 + idx;
        u8  valid_entry = trace[pos];

        /* trace[pos] is guaranteed non-zero by movemask, but double check not
         * strict necessary if trusting logic */
        u32 tuple = pos * 8 + (count_class_human[valid_entry] - 1);
        tuples[t_len++] = tuple;

      }

    }

    // Handle remaining bytes if any
    for (u32 k = i * 32; k < map_size; k++) {

      if (trace[k]) {

        u32 tuple = k * 8 + (count_class_human[trace[k]] - 1);
        tuples[t_len++] = tuple;

      }

    }

#else
    /* Optimized loop: Use u64 stride to skip zero blocks */
    u64 *trace64 = (u64 *)trace;
    u32  map_size64 = map_size / 8;

    for (u32 i = 0; i < map_size64; i++) {

      if (trace64[i]) {

        u32 base = i * 8;
        for (u32 j = 0; j < 8; j++) {

          u8 r = trace[base + j];
          if (r) {

            tuples[t_len++] = (base + j) * 8 + (count_class_human[r] - 1);

          }

        }

      }

    }

#endif

  }

  return t_len;

}

static fsrv_run_result_t run_target_file(afl_forkserver_t *fsrv, cmin_file_t *f,
                                         int dirfd, volatile u8 *stop_soon_p) {

  u8  stack_buf[65536];
  u8 *buf = NULL;
  u8 *file_data = NULL;
  u8  is_mmap = 0;
  u32 len = f->size;
  int fd;

  if (dirfd >= 0) {

    fd = openat(dirfd, f->name, O_RDONLY);

  } else {

    u8 *path = alloc_printf("%s/%s", f->dir, f->name);
    fd = open(path, O_RDONLY);
    ck_free(path);

  }

  if (fd < 0) {

    WARNF("Unable to open '%s/%s'", f->dir, f->name);
    return FSRV_RUN_ERROR;

  }

  if (len <= sizeof(stack_buf)) {

    if (read(fd, stack_buf, len) != (ssize_t)len) {

      WARNF("Partial read on '%s/%s'", f->dir, f->name);
      close(fd);
      return FSRV_RUN_ERROR;

    }

    buf = stack_buf;

  } else {

    file_data = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data != MAP_FAILED) {

      is_mmap = 1;

    } else {

      file_data = ck_alloc(len);
      ck_read(fd, file_data, len, f->name);

    }

    buf = file_data;

  }

  close(fd);

  afl_fsrv_write_to_testcase(fsrv, buf, len);

  if (file_data) {

    if (is_mmap)
      munmap(file_data, len);
    else
      ck_free(file_data);

  }

  return afl_fsrv_run_target(fsrv, time_limit, stop_soon_p);

}

static u32 scan_args(u8 **argv) {

  u32 i = 0;
  while (argv[i])
    i++;
  return i;

}

static void cleanup_fsrv_allocs(afl_forkserver_t *fsrv, char **argv) {

  if (fsrv->out_file) {

    ck_free(fsrv->out_file);
    fsrv->out_file = NULL;

  }

  if (fsrv->target_path && fsrv->target_path != target_bin) {

    free(fsrv->target_path);
    fsrv->target_path = NULL;

  }

  if (fsrv->out_fd >= 0) {

    close(fsrv->out_fd);
    fsrv->out_fd = -1;

  }

  if (fsrv->dev_null_fd >= 0) {

    close(fsrv->dev_null_fd);
    fsrv->dev_null_fd = -1;

  }

  if (argv && argv != (char **)target_args) {

    for (u32 i = 0; argv[i]; i++) {

      if (argv[i] != (char *)target_args[i]) { ck_free(argv[i]); }

    }

    ck_free(argv);

  }

}

static char **prepare_fsrv(afl_forkserver_t *fsrv, sharedmem_t *shm,
                           u32 use_map_size, u32 id, u8 *out_file_pattern) {

  // Init fsrv
  afl_fsrv_init(fsrv);
  set_sanitizer_defaults();
  afl_fsrv_setup_preload(fsrv, target_bin);

  // Init SHM
  memset(shm, 0, sizeof(sharedmem_t));
  shm->map = afl_shm_init(shm, use_map_size, 0, DEFAULT_PERMISSION, 0);
  if (!shm->map) FATAL("Unable to allocate shared memory");
  fsrv->trace_bits = shm->map;

  fsrv->map_size = use_map_size;
  fsrv->mem_limit = mem_limit;
  fsrv->exec_tmout = time_limit;
  if (!fsrv->exec_tmout) fsrv->exec_tmout = 120 * 1000;

  if (frida_mode) fsrv->frida_mode = 1;
  if (qemu_mode) fsrv->qemu_mode = 1;
  if (unicorn_mode) fsrv->unicorn_mode = 1;
  if (nyx_mode) {

#ifdef __linux__
    fsrv->nyx_mode = 1;
    fsrv->nyx_parent = true;
    fsrv->nyx_standalone = true;
    fsrv->nyx_id = id;
    fsrv->nyx_use_tmp_workdir = true;

    u8 *libnyx_binary = find_afl_binary(progname, "libnyx.so");
    fsrv->nyx_handlers = afl_load_libnyx_plugin(libnyx_binary);
    ck_free(libnyx_binary);

    if (!fsrv->nyx_handlers) { FATAL("failed to initialize libnyx.so..."); }
#else
    FATAL("Nyx mode is only supported on Linux");
#endif

  }

  fsrv->target_path = target_bin;

  char **argv = (char **)target_args;
  u8     has_at = 0;

  // We need to scan args for @@ to know if we need to copy them
  u32 argc = scan_args((u8 **)argv);
  for (u32 i = 0; i < argc; i++) {

    if (strstr(argv[i], "@@")) {

      has_at = 1;
      break;

    }

  }

  if (has_at) {

    // If we have @@, we MUST copy argv because we modify it
    u8 **new_argv = ck_alloc((sizeof(char *) * (argc + 2)));
    memcpy(new_argv, target_args, sizeof(char *) * (argc + 1));
    argv = (char **)new_argv;

  }

  if (stdin_file) {

    fsrv->out_file = strdup(stdin_file);
    fsrv->use_stdin = 0;

  } else {

    if (id == (u32)-1) {

      // test mode
      fsrv->out_file = alloc_printf("%s/.afl-cmin.test_input", out_dir);

    } else {

      // worker mode
      fsrv->out_file = alloc_printf(out_file_pattern, out_dir, id);

    }

    if (!has_at) fsrv->use_stdin = 1;

  }

  if (has_at) {

    fsrv->use_stdin = 0;
    for (u32 i = 0; i < argc; i++) {

      char *ret = strstr(argv[i], "@@");
      if (ret) {

        u8 *new_arg = alloc_printf("%.*s%s%s", (int)(ret - argv[i]), argv[i],
                                   fsrv->out_file, ret + 2);
        argv[i] = (char *)new_arg;

      }

    }

  }

  if (fsrv->use_stdin && fsrv->out_fd < 0) {

    fsrv->out_fd =
        open(fsrv->out_file, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
    if (fsrv->out_fd < 0) FATAL("Unable to open '%s'", fsrv->out_file);

  }

  char *abs_path = realpath(target_bin, NULL);
  if (abs_path) fsrv->target_path = abs_path;

  fsrv->dev_null_fd = open("/dev/null", O_RDWR);

  configure_afl_kill_signals(fsrv, NULL, NULL,
                             (fsrv->qemu_mode || fsrv->unicorn_mode
#ifdef __linux__
                              || fsrv->nyx_mode
#endif
                              )
                                 ? SIGKILL
                                 : SIGTERM);

  return argv;  // Caller should free if != target_args, but we simplify for
                // now.

}

static void exec_worker(worker_data_t *data, u32 *shared_cmin_idx) {

  afl_forkserver_t *fsrv = &data->fsrv;

  char **argv =
      prepare_fsrv(fsrv, &data->shm, map_size, data->id, "%s/.cur_input_%u");

  u8 stop_soon = 0;

  // Setup SHM fuzzing (testcase delivery via shared memory)
  sharedmem_t shm_fuzz;
  memset(&shm_fuzz, 0, sizeof(sharedmem_t));
  u8 *map =
      afl_shm_init(&shm_fuzz, MAX_FILE + sizeof(u32), 1, DEFAULT_PERMISSION, 0);

  if (map) {

    shm_fuzz.shmemfuzz_mode = 1;
    fsrv->support_shmem_fuzz = 1;
    fsrv->shmem_fuzz_len = (u32 *)map;
    fsrv->shmem_fuzz = map + sizeof(u32);

    u8 *shm_fuzz_map_size_str = alloc_printf("%lu", MAX_FILE + sizeof(u32));
    setenv(SHM_FUZZ_MAP_SIZE_ENV_VAR, shm_fuzz_map_size_str, 1);
    ck_free(shm_fuzz_map_size_str);

  }

  afl_fsrv_start(fsrv, argv, &stop_soon, debug_mode);

  u8 *last_exec_dir = NULL;
  int last_exec_dirfd = -1;

  u32 *tuples = NULL;
  if (!crashes_only) { tuples = ck_alloc(map_size * sizeof(u32)); }

  // Reuse buffer for queue message construction
  // [file_idx (4)] [tuple_count (4)] [tuples...]
  // We can write directly to queue or use intermediate buffer.
  // We use tuples buffer for collection first.

  u32  msg_max_size = (2 + map_size) * sizeof(u32);
  u32 *msg_buf = ck_alloc(msg_max_size);

  u32 i;
  while ((i = __sync_fetch_and_add(shared_cmin_idx, 1)) < items) {

    if (!last_exec_dir || strcmp(last_exec_dir, files[i]->dir)) {

      if (last_exec_dirfd >= 0) close(last_exec_dirfd);
      last_exec_dir = files[i]->dir;
      last_exec_dirfd = open(last_exec_dir, O_RDONLY | O_DIRECTORY);

    }

    fsrv_run_result_t ret =
        run_target_file(fsrv, files[i], last_exec_dirfd, &stop_soon);

    if (ret == FSRV_RUN_ERROR) continue;

    if (ret == FSRV_RUN_CRASH) {

      files[i]->is_crash = 1;
      if (crashes_only) continue;
      if (!allow_any) continue;

    } else if (ret == FSRV_RUN_TMOUT) {

      if (crashes_only) continue;
      if (!allow_any) continue;

    }

    if (crashes_only) continue;

    u8 *trace = fsrv->trace_bits;
    u32 t_len = collect_coverage_counts(trace, map_size, tuples);

    // Push to queue
    // Data: [file_idx] [tuple_count] [tuples...]

    u32 msg_size = (2 + t_len) * sizeof(u32);
    // msg_buf is pre-allocated
    msg_buf[0] = i;
    msg_buf[1] = t_len;
    if (t_len > 0) memcpy(&msg_buf[2], tuples, t_len * sizeof(u32));

    queue_push(QUEUE_MSG_DATA, msg_buf, msg_size);

  }

  ck_free(msg_buf);

  if (tuples) ck_free(tuples);
  if (last_exec_dirfd >= 0) close(last_exec_dirfd);

  afl_fsrv_deinit(fsrv);
  afl_shm_deinit(&data->shm);
  if (fsrv->support_shmem_fuzz) afl_shm_deinit(&shm_fuzz);
  cleanup_fsrv_allocs(fsrv, argv);

}

static void process_update_message(worker_data_t *data, u32 *unpack_buf) {

  u32  i = unpack_buf[0];
  u32  t_len = unpack_buf[1];
  u32 *tuples = &unpack_buf[2];

  u8 better = 0;
  for (u32 j = 0; j < t_len; j++) {

    u32 tuple = tuples[j];

    // Given files[cmin_sentinel_idx]->size == max, we don't need to
    // check if data->local_best[tuple] == cmin_sentinel_idx.
    if (files[i]->size < files[data->local_best[tuple]]->size) {

      data->local_best[tuple] = i;
      better = 1;

    }

    data->local_counts[tuple]++;

  }

  if (better && data->trace_log) {

    if (fwrite(&i, sizeof(u32), 1, data->trace_log) != 1) PFATAL("fwrite");
    if (fwrite(&t_len, sizeof(u32), 1, data->trace_log) != 1) PFATAL("fwrite");
    if (t_len > 0) {

      if (fwrite(tuples, sizeof(u32), t_len, data->trace_log) != t_len)
        PFATAL("fwrite");

    }

  }

}

static void update_worker(worker_data_t *data) {

  // allocate a large enough buffer for the largest possible message.
  u32 *unpack_buf = ck_alloc((2 + map_size) * sizeof(u32));

  while (1) {

    u32 type;
    u32 len = queue_pop(&type, unpack_buf, (2 + map_size) * sizeof(u32));

    if (type == QUEUE_MSG_STOP) { break; }

    if (type == QUEUE_MSG_DATA) {

      if (len < 8) FATAL("Invalid message length");
      process_update_message(data, unpack_buf);

    }

  }

  ck_free(unpack_buf);

}

static u32   effective_map_size;
static u32  *global_best_maps;
static u32  *global_counts_maps;
static u32  *shared_cmin_idx;
static pid_t worker_pids[MAX_WORKERS];

static void cmin_detect_map_size(void) {

  // Get map size
  u8 *env_map_size = getenv("AFL_MAP_SIZE");
  if (env_map_size) {

    map_size = atoi(env_map_size);

  } else if (nyx_mode) {

#ifdef __linux__
    map_size = get_nyx_map_size(target_bin);
    u8 *val = alloc_printf("%u", map_size);
    setenv("AFL_MAP_SIZE", val, 1);
    ck_free(val);
#else
    FATAL("Nyx mode is only supported on Linux");
#endif

  } else {

    afl_forkserver_t fsrv = {0};
    sharedmem_t      shm = {0};

    // Init fsrv
    afl_fsrv_init(&fsrv);
    set_sanitizer_defaults();
    afl_fsrv_setup_preload(&fsrv, target_bin);
    fsrv.target_path = target_bin;

    configure_afl_kill_signals(&fsrv, NULL, NULL,
                               (qemu_mode || unicorn_mode
#ifdef __linux__
                                || nyx_mode
#endif
                                )
                                   ? SIGKILL
                                   : SIGTERM);

    // Init dummy SHM
    u32 detection_size = DETECTION_MAP_SIZE;  // 16MB
    shm.map = afl_shm_init(&shm, detection_size, 0, DEFAULT_PERMISSION, 0);
    if (!shm.map) FATAL("Unable to allocate shared memory for detection");
    fsrv.trace_bits = shm.map;
    fsrv.map_size = detection_size;

    // We must set AFL_MAP_SIZE to avoid FS_ERROR_MAP_SIZE fatal exit in
    // forkserver
    u8 *det_size_str = alloc_printf("%u", detection_size);
    setenv("AFL_MAP_SIZE", det_size_str, 1);
    ck_free(det_size_str);

    u8 stop_soon = 0;
    OKF("Detecting map size...");

    // Simplified detection: just pass args directly, no dummy input needed
    // if target exits early during forkserver handshake
    u32 detected_map_size = afl_fsrv_get_mapsize(&fsrv, (char **)target_args,
                                                 &stop_soon, debug_mode);

    if (detected_map_size) { map_size = detected_map_size; }

    u8 *val = alloc_printf("%u", map_size);
    setenv("AFL_MAP_SIZE", val, 1);
    ck_free(val);

    afl_fsrv_deinit(&fsrv);

    afl_shm_deinit(&shm);

  }

  if (map_size < MAP_SIZE) map_size = MAP_SIZE;

  OKF("Map size: %u", map_size);

}

typedef enum { WORKER_EXEC, WORKER_UPDATE } worker_role_t;

static void cmin_worker_entry(u32 i, worker_role_t role) {

  if (!debug_mode) {

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {

      dup2(null_fd, 1);
      dup2(null_fd, 2);
      close(null_fd);

    }

  }

  worker_data_t data = {0};
  data.id = i;

  if (role == WORKER_UPDATE) {

    data.local_best = global_best_maps + (i * effective_map_size);
    data.local_counts = global_counts_maps + (i * effective_map_size);

    // Build trace log path
    u8 *trace_fn = alloc_printf("%s/.traces/worker_%u.dat", out_dir, i);
    data.trace_log = fopen(trace_fn, "w+b");
    if (!data.trace_log) PFATAL("Unable to open info info file %s", trace_fn);
    ck_free(trace_fn);

    update_worker(&data);

    fclose(data.trace_log);

  } else {

    exec_worker(&data, shared_cmin_idx);

  }

  _exit(0);

}

static void cmin_run_workers(void) {

  OKF("Spawning %u execution workers and %u update workers processing %u "
      "files...",
      exec_workers, update_workers, items);

  // Shared memory for results
  // We allocate best maps for UPDATE workers only (since they maintain local
  // bests)
  global_best_maps =
      mmap(NULL, update_workers * effective_map_size * sizeof(u32),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (global_best_maps == MAP_FAILED) PFATAL("mmap global_best_maps failed");
  for (u32 i = 0; i < update_workers * effective_map_size; i++)
    global_best_maps[i] = cmin_sentinel_idx;

  global_counts_maps =
      mmap(NULL, update_workers * effective_map_size * sizeof(u32),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (global_counts_maps == MAP_FAILED)
    PFATAL("mmap global_counts_maps failed");
  memset(global_counts_maps, 0,
         update_workers * effective_map_size * sizeof(u32));

  // Shared counter for coordination (Exec workers)
  shared_cmin_idx = mmap(NULL, sizeof(u32), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_cmin_idx == MAP_FAILED) PFATAL("mmap");
  *shared_cmin_idx = 0;

  // Init Queue (64MB)
  queue_init(QUEUE_CAPACITY);

  // Fork all workers (Exec: 0..exec_workers-1, Update:
  // exec_workers..total-1)
  for (u32 i = 0; i < exec_workers + update_workers; i++) {

    worker_pids[i] = fork();
    if (worker_pids[i] < 0) PFATAL("fork");

    if (worker_pids[i] == 0) {

      if (i < exec_workers)
        cmin_worker_entry(i, WORKER_EXEC);
      else
        cmin_worker_entry(i - exec_workers, WORKER_UPDATE);

    }

  }

  // Progress monitor (Parent side)
  usleep(100);

  u64 start_ms = get_cur_time();

  while (*shared_cmin_idx < items) {

    u32 cnt = *shared_cmin_idx;
    u32 p = (cnt * 100) / items;

    u64    cur_ms = get_cur_time();
    double speed =
        (cur_ms > start_ms) ? (cnt * 1000.0 / (cur_ms - start_ms)) : 0.0;
    u64 t = (cur_ms - start_ms) / 1000;

    fprintf(stderr,
            "\r" cGRA
            "    Processing %u/%u files (%u%%, %.2f/sec) [elapsed "
            "%llus]..." cRST,
            cnt, items, p, speed, t);
    fflush(stderr);
    usleep(250000);

    // Check if any child died unexpectedly?
    int   status;
    pid_t child_pid = waitpid(-1, &status, WNOHANG);
    if (child_pid > 0) {

      for (u32 i = 0; i < exec_workers + update_workers; i++) {

        // Ensure it is one of our workers
        if (child_pid == worker_pids[i]) {

          if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {

            FATAL("Worker process %d died unexpectedly (status %d)", child_pid,
                  status);

          }

          break;

        }

      }

    }

  }

  u64    cur_ms = get_cur_time();
  u64    t = (cur_ms - start_ms) / 1000;
  double speed =
      (cur_ms > start_ms) ? (items * 1000.0 / (cur_ms - start_ms)) : 0.0;

  fprintf(stderr,
          "\r" cGRA
          "    Processing %u/%u files (100%%, %.2f/sec) [elapsed "
          "%llus]\n" cRST,
          items, items, speed, t);

  // Wait for all EXEC workers
  for (u32 i = 0; i < exec_workers; i++) {

    waitpid(worker_pids[i], NULL, 0);

  }

  // Send STOP signals to Update Workers
  OKF("Waiting for update workers to finish...");
  for (u32 i = 0; i < update_workers; i++)
    queue_push(QUEUE_MSG_STOP, NULL, 0);

  // Wait for Update Workers
  for (u32 i = 0; i < update_workers; i++)
    waitpid(worker_pids[exec_workers + i], NULL, 0);

  munmap(shared_cmin_idx, sizeof(u32));
  munmap(queue, sizeof(cmin_queue_t) + queue->capacity);

}

static void merge_results(u32 *final_best, u32 *tuple_counts) {

  u32 *global_map = global_best_maps;
  u32 *global_cnt = global_counts_maps;

  for (u32 w = 0; w < update_workers; w++) {

    u32 *worker_map = global_map + (w * effective_map_size);
    u32 *worker_cnt = global_cnt + (w * effective_map_size);

    for (u32 i = 0; i < effective_map_size; i++) {

      tuple_counts[i] += worker_cnt[i];

      u32 idx = worker_map[i];
      if (idx == cmin_sentinel_idx) continue;

      if (final_best[i] == cmin_sentinel_idx) {

        final_best[i] = idx;

      } else {

        if (files[idx]->size < files[final_best[i]]->size) {

          final_best[i] = idx;

        }

      }

    }

  }

}

static u32 identify_candidates(u32 *final_best, u8 *is_candidate,
                               u32 *candidates_cnt_p) {

  u32 total_tuples = 0;
  *candidates_cnt_p = 0;

  for (u32 i = 0; i < effective_map_size; i++) {

    u32 idx = final_best[i];
    if (idx != cmin_sentinel_idx) {

      if (!is_candidate[idx]) {

        is_candidate[idx] = 1;
        (*candidates_cnt_p)++;

      }

      total_tuples++;

    }

  }

  return total_tuples;

}

static void load_traces(u8 *is_candidate, trace_t *candidate_traces) {

  for (u32 w = 0; w < update_workers; w++) {

    u8   *trace_fn = alloc_printf("%s/.traces/worker_%u.dat", out_dir, w);
    FILE *f = fopen(trace_fn, "rb");
    if (f) {

      while (1) {

        u32 idx, len;
        if (fread(&idx, sizeof(u32), 1, f) != 1) break;
        if (fread(&len, sizeof(u32), 1, f) != 1) break;

        if (is_candidate[idx] && !candidate_traces[idx].tuples) {

          candidate_traces[idx].len = len;
          candidate_traces[idx].tuples = ck_alloc(len * sizeof(u32));
          if (len > 0) {

            if (fread(candidate_traces[idx].tuples, sizeof(u32), len, f) != len)
              WARNF("Short read trace");

          }

        } else {

          fseek(f, len * sizeof(u32), SEEK_CUR);

        }

      }

      fclose(f);

    }

    unlink(trace_fn);
    ck_free(trace_fn);

  }

}

static void execute_set_cover(u32 *final_best, u32 *tuple_counts,
                              trace_t *candidate_traces, u32 total_tuples) {

  u8 *covered = ck_alloc(effective_map_size);  // 0 or 1
  u32 covered_cnt = 0;
  u32 written_cnt = 0;

  u64 start_ms = get_cur_time();

  // Prepare sortable tuples
  tuple_info_t *sorted_tuples = ck_alloc(total_tuples * sizeof(tuple_info_t));
  u32           st_idx = 0;
  for (u32 i = 0; i < effective_map_size; i++) {

    if (final_best[i] != cmin_sentinel_idx) {

      sorted_tuples[st_idx].tuple = i;
      sorted_tuples[st_idx].count = tuple_counts[i];
      st_idx++;

    }

  }

  qsort(sorted_tuples, total_tuples, sizeof(tuple_info_t),
        compare_tuple_counts);

  u8 *written_files = ck_alloc(items);

  for (u32 i = 0; i < total_tuples; i++) {

    u32 tuple = sorted_tuples[i].tuple;
    if (covered[tuple]) continue;

    u32 best_idx = final_best[tuple];
    if (written_files[best_idx])
      continue;  // Should have covered this tuple if written?

    written_files[best_idx] = 1;
    written_cnt++;

    // Mark all tuples covered by this file
    trace_t *t = &candidate_traces[best_idx];
    for (u32 k = 0; k < t->len; k++) {

      u32 t_idx = t->tuples[k];
      if (!covered[t_idx]) {

        covered[t_idx] = 1;
        covered_cnt++;

      }

    }

    // Link/Copy file
    cmin_file_t *f = files[best_idx];
    u8          *out_name;

    if (no_dedup) {

      if (as_queue)
        out_name = alloc_printf("%s/id:%06u,orig:%s", out_dir, written_cnt - 1,
                                f->name);
      else
        out_name = alloc_printf("%s/%s", out_dir, f->name);

    } else {

      u8 hash[SHA1_SIZE * 2 + 1];
      for (int x = 0; x < SHA1_SIZE; x++)
        sprintf((char *)hash + x * 2, "%02x", f->sha1[x]);
      hash[SHA1_SIZE * 2] = 0;
      if (as_queue)
        out_name =
            alloc_printf("%s/id:%06u,hash:%s", out_dir, written_cnt - 1, hash);
      else
        out_name = alloc_printf("%s/%s", out_dir, hash);

    }

    u8 *src_path = alloc_printf("%s/%s", f->dir, f->name);
    if (link(src_path, out_name) < 0) {

      if (errno == EEXIST) unlink(out_name);
      if (link(src_path, out_name) < 0) {

        int src = open(src_path, O_RDONLY);
        if (src < 0) PFATAL("Unable to open '%s'", src_path);

        int dst = open(out_name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (dst < 0) PFATAL("Unable to open '%s'", out_name);

        char    buf[4096];
        ssize_t n;
        while ((n = read(src, buf, sizeof(buf))) > 0)
          if (write(dst, buf, n) != n) PFATAL("Short write to %s", out_name);

        close(src);
        close(dst);

      }

    }

    ck_free(out_name);
    ck_free(src_path);

    if (written_cnt % 1000 == 0) {

      u64 t = (get_cur_time() - start_ms) / 1000;

      SAYF(cGRA
           "\r    Written %u files, covered %u/%u tuples [elapsed "
           "%llus]..." cRST,
           written_cnt, covered_cnt, total_tuples, t);
      fflush(stdout);

    }

  }

  ck_free(sorted_tuples);
  ck_free(covered);
  ck_free(written_files);

  u64    cur_ms = get_cur_time();
  u64    t = (cur_ms - start_ms) / 1000;
  double speed =
      (cur_ms > start_ms) ? (written_cnt * 1000.0 / (cur_ms - start_ms)) : 0.0;

  SAYF(cGRA
       "\r    Written %u files, covered %u/%u tuples (%.2f/sec) [elapsed "
       "%llus]\n" cRST,
       written_cnt, covered_cnt, total_tuples, speed, t);
  OKF("Wrote %u files.", written_cnt);

}

static void write_crash_files(void) {

  u32 count = 0;
  for (u32 i = 0; i < items; i++) {

    if (!files[i]->is_crash) continue;

    u8 *name = files[i]->name;
    u8  new_path[PATH_MAX];
    // Crashes don't strictly follow as_queue or not? Usually flat.
    snprintf(new_path, sizeof(new_path), "%s/%s", out_dir, name);

    u8 *src_path = alloc_printf("%s/%s", files[i]->dir, files[i]->name);
    if (link(src_path, new_path) != 0) {

      WARNF("Cannot add %s to minimization", src_path);

    }

    ck_free(src_path);
    count++;

  }

  OKF("Wrote %u crashing files.", count);

}

static void cmin_process_results(void) {

  // Merge results (already done above in collection loop)
  if (!crashes_only) {

    OKF("Merging traces and computing candidates...");

    // Step 1: Merge global best maps and counts
    u32 *final_best = ck_alloc(effective_map_size * sizeof(u32));
    u32 *tuple_counts = ck_alloc(effective_map_size * sizeof(u32));
    for (u32 i = 0; i < effective_map_size; i++) {

      final_best[i] = cmin_sentinel_idx;
      tuple_counts[i] = 0;

    }

    merge_results(final_best, tuple_counts);

    // Step 2: Identify candidates (files that are best for at least one tuple)
    u8 *is_candidate = ck_alloc(items);  // bool
    u32 candidates_cnt = 0;
    u32 total_tuples = 0;

    total_tuples =
        identify_candidates(final_best, is_candidate, &candidates_cnt);

    OKF("Found %u unique tuples across %u files. Candidates: %u", total_tuples,
        items, candidates_cnt);

    // Step 3: Load traces for candidates from temporary files
    trace_t *candidate_traces = ck_alloc(items * sizeof(trace_t));
    load_traces(is_candidate, candidate_traces);

    // Step 4: Rarest First Set Cover
    OKF("Performing Rarest First Set Cover...");
    execute_set_cover(final_best, tuple_counts, candidate_traces, total_tuples);

    ck_free(tuple_counts);
    if (global_counts_maps)
      munmap(global_counts_maps,
             update_workers * effective_map_size * sizeof(u32));

    for (u32 i = 0; i < items; i++) {

      if (candidate_traces[i].tuples) ck_free(candidate_traces[i].tuples);

    }

    ck_free(candidate_traces);
    ck_free(final_best);
    ck_free(is_candidate);

    if (global_best_maps)
      munmap(global_best_maps,
             update_workers * effective_map_size * sizeof(u32));

  } else {

    write_crash_files();

  }

}

static void test_target_binary(void) {

  OKF("Testing the target binary...");

  afl_forkserver_t fsrv = {0};
  sharedmem_t      shm = {0};
  u8               stop_soon = 0;

  char **argv = prepare_fsrv(&fsrv, &shm, map_size, (u32)-1, NULL);

  afl_fsrv_start(&fsrv, (char **)argv, &stop_soon, debug_mode ? 1 : 0);

  // Use the first file for testing
  cmin_file_t      *f = files[0];
  fsrv_run_result_t ret = run_target_file(&fsrv, f, -1, &stop_soon);

  if (ret == FSRV_RUN_ERROR)
    FATAL("Unable to open or read input file '%s/%s'", f->dir, f->name);

  if (ret == FSRV_RUN_CRASH) {

    if (!crashes_only && !allow_any)
      FATAL("Target crashed on input file '%s/%s', but -C or -A not specified.",
            f->dir, f->name);

  } else if (ret == FSRV_RUN_TMOUT) {

    if (!allow_any)
      FATAL("Target timed out on input file '%s/%s', but -A not specified.",
            f->dir, f->name);

  } else {

    if (crashes_only)
      FATAL("Target did not crash on input file '%s/%s', but -C specified.",
            f->dir, f->name);

  }

  u8  *trace = fsrv.trace_bits;
  u32 *tuples = ck_alloc(map_size * sizeof(u32));
  u32  t_len = collect_coverage_counts(trace, map_size, tuples);
  ck_free(tuples);

  if (!t_len && !crashes_only) {

    FATAL("No instrumentation detected");

  } else {

    OKF("ok, %u tuples recorded", t_len);

  }

  // Cleanup
  afl_fsrv_deinit(&fsrv);
  afl_shm_deinit(&shm);

  cleanup_fsrv_allocs(&fsrv, argv);

}

static void execute_cmin(void) {

  cmin_detect_map_size();
  test_target_binary();

  effective_map_size = map_size;
  if (!edges_only) effective_map_size *= 8;
  OKF("Effective map size: %u", effective_map_size);

  best_files = ck_alloc((effective_map_size) * sizeof(u32));  // Global best
  for (u32 i = 0; i < effective_map_size; i++)
    best_files[i] = cmin_sentinel_idx;

  // Create .traces directory
  u8 *trace_dir = alloc_printf("%s/.traces", out_dir);
  if (mkdir(trace_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", trace_dir);
  ck_free(trace_dir);

  cmin_run_workers();
  cmin_process_results();

  ck_free(best_files);

}

static void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -i dir      - input directory with the starting corpus (can be used "
      "multiple times)\n"
      "  -o dir      - output directory for minimized files\n\n"

      "Execution control settings:\n"
      "  -f file     - location read by the fuzzed program (stdin)\n"
      "  -m megs     - memory limit for child process (default: none)\n"
      "  -t msec     - timeout for each run (default: 5000ms)\n"
      "  -O          - use binary-only instrumentation (FRIDA mode)\n"
      "  -Q          - use binary-only instrumentation (QEMU mode)\n"
      "  -U          - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -X          - use Nyx mode\n\n"

      "Minimization settings:\n"
      "  --crash-dir=dir - move crashes to a separate dir, always "
      "deduplicated\n"
      "  -A          - allow crashes and timeouts (not recommended)\n"
      "  -C          - keep crashing inputs, reject everything else\n"
      "  -e          - solve for edge coverage only, ignore hit counts\n\n"

      "Misc:\n"
      "  -T workers  - number of concurrent workers (default: 1)\n"
      "  --as_queue  - output file name like \"id:000000,hash:value\"\n"
      "  --no-dedup  - skip deduplication step for corpus files\n"
      "  --debug     - debug mode\n\n"

      "For additional help, consult %s/README.md.\n\n",

      argv0, DOC_PATH);

  exit(1);

}

static void check_binary(u8 *fname) {

  if (nyx_mode) {

    target_bin = strdup(fname);
    return;

  }

  target_bin = find_binary(fname);

  if (frida_mode || qemu_mode || unicorn_mode || nyx_mode ||
      getenv("AFL_SKIP_BIN_CHECK"))
    return;

  check_binary_signatures(target_bin);

}

static void *collect_worker(void *arg) {

  (void)arg;

  while (1) {

    pthread_mutex_lock(&queue_mutex);

    while (!queue_head && !collection_done) {

      if (busy_collectors == 0) {

        collection_done = 1;
        pthread_cond_broadcast(&queue_cond);

      } else {

        pthread_cond_wait(&queue_cond, &queue_mutex);

      }

    }

    if (collection_done && !queue_head) {

      pthread_mutex_unlock(&queue_mutex);
      return NULL;

    }

    dir_queue_item_t *item = queue_head;
    if (item) {

      queue_head = item->next;
      if (!queue_head) queue_tail = NULL;
      busy_collectors++;

    }

    pthread_mutex_unlock(&queue_mutex);

    if (!item) continue;

    u8 *dir = item->dir;

    if (debug_mode) ACTF("Scanning '%s'...", dir);

    u32 files_added = 0;

    DIR *d = opendir(dir);
    if (!d) {

      if (errno != ENOENT && errno != ENOTDIR) {

        WARNF("Unable to open '%s'", dir);

      }

      ck_free(item->dir);
      ck_free(item);

      pthread_mutex_lock(&queue_mutex);
      busy_collectors--;
      if (!queue_head && busy_collectors == 0) {

        collection_done = 1;
        pthread_cond_broadcast(&queue_cond);

      }

      pthread_mutex_unlock(&queue_mutex);

      continue;  // Next item

    } else {

      struct dirent *entry;
      while ((entry = readdir(d))) {

        if (entry->d_name[0] == '.') continue;
        if (!strncmp(entry->d_name, "fastresume.bin", 14)) continue;

        u8 is_dir = 0;
        u8 is_reg = 0;

        if (entry->d_type == DT_DIR)
          is_dir = 1;
        else if (entry->d_type == DT_REG)
          is_reg = 1;
        else if (entry->d_type == DT_UNKNOWN) {

          struct stat st;
          u8         *fn = alloc_printf("%s/%s", dir, entry->d_name);
          if (!lstat(fn, &st)) {

            if (S_ISDIR(st.st_mode))
              is_dir = 1;
            else if (S_ISREG(st.st_mode))
              is_reg = 1;

          }

          ck_free(fn);

        }

        if (is_dir) {

          u8 *fn = alloc_printf("%s/%s", dir, entry->d_name);
          queue_add(fn);
          ck_free(fn);
          continue;

        }

        if (is_reg) {

          cmin_file_t *f = ck_alloc(sizeof(cmin_file_t));
          f->dir = dir;  // Shared string
          f->name = strdup(entry->d_name);
          f->size = 0;  // Defer size check

          pthread_mutex_lock(&files_mutex);

          if (items >= files_capacity) {

            if (files_capacity == 0)
              files_capacity = 1024;
            else
              files_capacity *= 2;
            files = ck_realloc(files, files_capacity * sizeof(cmin_file_t *));

          }

          files[items++] = f;
          files_added++;

          pthread_mutex_unlock(&files_mutex);

        }

      }

      closedir(d);

    }

    // We do NOT free item->dir here because we shared it with files.
    // However, if we found NO files, we should free it.
    // Subdirectories (queue_add) duplicate the string, so 'dir' is only needed
    // for files in THIS directory.

    if (!files_added) ck_free(item->dir);
    ck_free(item);

    pthread_mutex_lock(&queue_mutex);
    busy_collectors--;
    if (!queue_head && busy_collectors == 0) {

      collection_done = 1;
      pthread_cond_broadcast(&queue_cond);

    }

    pthread_mutex_unlock(&queue_mutex);

  }

}

static int compare_files(const void *a, const void *b) {

  cmin_file_t *fa = *(cmin_file_t **)a;
  cmin_file_t *fb = *(cmin_file_t **)b;

  if (fa->size != fb->size) return fa->size - fb->size;
  int d = strcmp(fa->dir, fb->dir);
  if (d) return d;
  return strcmp(fa->name, fb->name);

}

int main(int argc, char **argv) {

  progname = argv[0];

  s32 opt;
  int option_index = 0;

  static struct option long_options[] = {{"crash-dir", required_argument, 0, 0},
                                         {"as_queue", no_argument, 0, 0},
                                         {"no-dedup", no_argument, 0, 0},
                                         {"debug", no_argument, 0, 0},
                                         {0, 0, 0, 0}};

  SAYF(cCYA "afl-cmin" VERSION cRST " by AFL++ team\n");

  cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

  while ((opt = getopt_long(argc, argv, "+i:o:f:m:t:T:OQUXACeh", long_options,
                            &option_index)) != -1) {

    if (opt == 0) {

      if (!strcmp(long_options[option_index].name, "crash-dir")) {

        crash_dir = optarg;

      } else if (!strcmp(long_options[option_index].name, "as_queue")) {

        as_queue = 1;

      } else if (!strcmp(long_options[option_index].name, "no-dedup")) {

        no_dedup = 1;

      } else if (!strcmp(long_options[option_index].name, "debug")) {

        debug_mode = 1;

      }

      continue;

    }

    switch (opt) {

      case 'i': {

        glob_t g;
        int    ret = glob(optarg, GLOB_NOCHECK | GLOB_TILDE, NULL, &g);
        size_t pathc = (ret == 0) ? g.gl_pathc : 1;

        if (!in_dir) {

          in_dir_cap = pathc + 64;
          in_dir = ck_alloc(in_dir_cap * sizeof(u8 *));

        } else if (in_dir_cnt + pathc >= in_dir_cap) {

          in_dir_cap = ((in_dir_cnt + pathc) * 2) + 64;
          in_dir = ck_realloc(in_dir, in_dir_cap * sizeof(u8 *));

        }

        if (ret == 0) {

          for (size_t k = 0; k < g.gl_pathc; k++) {

            in_dir[in_dir_cnt++] = strdup(g.gl_pathv[k]);

          }

          globfree(&g);

        } else {

          in_dir[in_dir_cnt++] = strdup(optarg);

        }

      } break;

      case 'o':
        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'f':
        if (stdin_file) FATAL("Multiple -f options not supported");
        stdin_file = optarg;
        break;

      case 'm':
        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;
        if (!strcmp(optarg, "none")) {

          mem_limit = 0;

        } else {

          u8 suffix = 'M';
          if (sscanf(optarg, "%u%c", &mem_limit, &suffix) < 1)
            FATAL("Bad syntax used for -m");
          switch (suffix) {

            case 'T':
              mem_limit *= 1024 * 1024;
              break;
            case 'G':
              mem_limit *= 1024;
              break;
            case 'k':
              mem_limit /= 1024;
              break;
            case 'M':
              break;
            default:
              FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

        }

        break;

      case 't':
        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;
        if (!strcmp(optarg, "none")) {

          time_limit = 0;

        } else {

          time_limit = atoi(optarg);
          if (time_limit < 10) FATAL("Dangerously low timeout");

        }

        break;

      case 'T':
        if (!strcmp(optarg, "all")) {

          exec_workers = cpu_count;
          update_workers = cpu_count;

        } else {

          u8 *colon = strchr(optarg, ':');
          if (colon) {

            *colon = 0;
            exec_workers = atoi(optarg);
            update_workers = atoi(colon + 1);

          } else {

            exec_workers = atoi(optarg);
            update_workers = exec_workers;

          }

        }

        if (exec_workers < 1 || update_workers < 1)
          FATAL("Number of workers must be at least 1");
        if (exec_workers + update_workers > MAX_WORKERS)
          FATAL("Total number of workers exceeds %d", MAX_WORKERS);
        break;

      case 'O':
        frida_mode = 1;
        break;
      case 'Q':
        qemu_mode = 1;
        break;
      case 'U':
        unicorn_mode = 1;
        break;
      case 'X':
        nyx_mode = 1;
        break;

      case 'A':
        allow_any = 1;
        break;
      case 'C':
        crashes_only = 1;
        break;
      case 'e':
        edges_only = 1;
        break;

      case 'h':
        usage(argv[0]);
        break;

      default:
        usage(argv[0]);

    }

  }

  if (optind == argc || !out_dir || !in_dir_cnt) usage(argv[0]);

  target_bin = argv[optind];
  target_args = (u8 **)(argv + optind);

  if (stdin_file && exec_workers > 1) {

    WARNF("disabling parallel mode because of -f");
    exec_workers = 1;
    update_workers = 1;

  }

  setenv("AFL_NO_AUTODICT", "1", 1);

  // Create output directory
  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST)
      FATAL("Unable to create output directory '%s'", out_dir);

    DIR *d = opendir(out_dir);
    if (!d) FATAL("Unable to open output directory '%s'", out_dir);

    struct dirent *de;
    while ((de = readdir(d))) {

      if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
      FATAL("Output directory '%s' is not empty", out_dir);

    }

    closedir(d);

  }

  if (crash_dir && mkdir(crash_dir, 0700) && errno != EEXIST) {

    FATAL("Unable to create crash directory '%s'", crash_dir);

  }

  check_binary(target_bin);

  /* Parallel file collection */
  for (u32 i = 0; i < in_dir_cnt; i++) {

    queue_add(in_dir[i]);

  }

  pthread_t *threads = ck_alloc(sizeof(pthread_t) * update_workers);
  for (u32 i = 0; i < update_workers; i++) {

    pthread_create(&threads[i], NULL, collect_worker, NULL);

  }

  u64 start_ms = get_cur_time();

  while (!collection_done) {

    usleep(250000);
    u32 cnt = items;
    if (cnt > 0) {

      u64 t = (get_cur_time() - start_ms) / 1000;

      fprintf(stderr,
              "\r" cGRA
              "    Scanning... %u files found [elapsed "
              "%llus]" cRST,
              cnt, t);
      fflush(stderr);

    }

  }

  u64    cur_ms = get_cur_time();
  u64    t = (cur_ms - start_ms) / 1000;
  double speed =
      (cur_ms > start_ms) ? (items * 1000.0 / (cur_ms - start_ms)) : 0.0;

  fprintf(stderr,
          "\r" cGRA
          "    Scanning... %u files found (%.2f/sec) [elapsed "
          "%llus]" cRST "\n",
          items, speed, t);

  for (u32 i = 0; i < update_workers; i++) {

    pthread_join(threads[i], NULL);

  }

  ck_free(threads);

  if (!items) FATAL("No input files found");

  OKF("Found %u input files", items);

  if (!no_dedup) { dedup_files(); }

  qsort(files, items, sizeof(cmin_file_t *), compare_files);

  OKF("Sorted files by size");

  // Sentinel Optimization
  if (items >= files_capacity) {

    if (files_capacity == 0)
      files_capacity = 1024;
    else
      files_capacity *= 2;
    files = ck_realloc(files, files_capacity * sizeof(cmin_file_t *));

  }

  cmin_file_t *f = ck_alloc(sizeof(cmin_file_t));
  f->name = strdup("DUMMY_SENTINEL");
  f->dir = strdup("");
  f->size = 0xFFFFFFFF;  // Max size
  files[items] = f;
  cmin_sentinel_idx = items;

  OKF("Will use %u execution workers, %u update workers, %u input directories",
      exec_workers, update_workers, in_dir_cnt);

  execute_cmin();

  afl_fsrv_killall();

  return 0;

}

