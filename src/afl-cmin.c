/*
   american fuzzy lop++ - corpus minimization tool
   -----------------------------------------------

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   A tool to minimize the corpus.

 */

#define AFL_MAIN
#define AFL_CMIN

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  // u8  is_crash;

} cmin_file_t;

static u8 **in_dir;                    /* one or more input dirs            */
static u32  in_dir_cap;                /* capacity of in_dir                */
static u8  *out_dir,                   /* output directory                  */
    *crash_dir,                        /* crash directory                   */
    *tmp_dir,                          /* private work directory            */
    *target_bin,                       /* target binary                     */
    *stdin_file;                       /* stdin file                        */

static pid_t tmp_dir_pid;              /* owner of tmp_dir                  */

static u8  *progname;
static u8 **target_args;               /* target arguments                  */

static u32 in_dir_cnt,                 /* number of input directories       */
    cpu_count,                         /* number of usable CPU cores        */
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
    as_queue,                          /* save as queue?                    */
    sha1fn;                            /* save sha1 filenames?              */

static u8 debug_mode,                  /* debug mode                        */
    frida_mode,                        /* Frida mode                        */
    qemu_mode,                         /* QEMU mode                         */
    unicorn_mode,                      /* Unicorn mode                      */
    nyx_mode,                          /* Nyx mode                          */
    merge_mode, wine_mode;             /* Wine mode                         */

static cmin_file_t **files;
static u32           items;
static u32           files_capacity;
static u8           *crashing_files; /* marked by exec workers, --crash-dir */

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

/* Remember which directories were handed out already. Input dirs may be
   given twice and symlinks can form cycles, both of which would otherwise
   make the scan loop forever. Called with queue_mutex held. */

static struct {

  dev_t dev;
  ino_t ino;

} *seen_dirs;

static u32 seen_dirs_cnt, seen_dirs_cap;

static u8 dir_already_seen(u8 *dir) {

  struct stat st;
  if (stat((char *)dir, &st)) return 0;

  for (u32 i = 0; i < seen_dirs_cnt; i++) {

    if (seen_dirs[i].dev == st.st_dev && seen_dirs[i].ino == st.st_ino)
      return 1;

  }

  if (seen_dirs_cnt >= seen_dirs_cap) {

    seen_dirs_cap = seen_dirs_cap ? seen_dirs_cap * 2 : 256;
    seen_dirs = ck_realloc(seen_dirs, seen_dirs_cap * sizeof(*seen_dirs));

  }

  seen_dirs[seen_dirs_cnt].dev = st.st_dev;
  seen_dirs[seen_dirs_cnt].ino = st.st_ino;
  seen_dirs_cnt++;
  return 0;

}

static void queue_add(u8 *dir) {

  dir_queue_item_t *item = ck_alloc(sizeof(dir_queue_item_t));
  item->dir = strdup(dir);

  pthread_mutex_lock(&queue_mutex);

  if (dir_already_seen(dir)) {

    pthread_mutex_unlock(&queue_mutex);
    ck_free(item->dir);
    ck_free(item);
    return;

  }

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

  /* Mirror afl_fsrv_start()'s nyx setup: libnyx must write its files under
     <outer>/workdir/, otherwise remove_nyx_tmp_workdir() can't clean up and
     the next create_nyx_tmp_workdir() (same PID) fails with EEXIST. */
  char *outdir_path = create_nyx_tmp_workdir();
  char *workdir_path = alloc_printf("%s/workdir", outdir_path);
  nyx_handlers->nyx_config_set_workdir_path(nyx_config, workdir_path);
  nyx_handlers->nyx_config_set_process_role(nyx_config, StandAlone);

  void *nyx_runner = nyx_handlers->nyx_new(nyx_config, 0);

  if (!nyx_runner) { FATAL("nyx_new failed"); }

  u32 size = (u32)nyx_handlers->nyx_get_bitmap_buffer_size(nyx_runner);

  nyx_handlers->nyx_shutdown(nyx_runner);
  nyx_handlers->nyx_config_free(nyx_config);

  afl_forkserver_t fsrv = {0};
  fsrv.nyx_handlers = nyx_handlers;
  ck_free(workdir_path);
  remove_nyx_tmp_workdir(&fsrv, outdir_path);

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

static void queue_init(u64 capacity) {

  if (capacity > 0xF0000000ULL) FATAL("Requested queue size is too large");

  // Align to page size? sharedmem_t usually handles this but we need a custom
  // structure We use mmap anon shared
  size_t total_size = sizeof(cmin_queue_t) + capacity;
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

/* Strict unsigned parser: no signs, no empty strings, no trailing garbage and
   no out-of-range values - atoi()/sscanf() silently accept all of those. */

static u64 parse_u64_strict(const char *val, const char *what, u64 min,
                            u64 max) {

  if (!val || !*val) FATAL("Empty value given for %s", what);

  for (const char *p = val; *p; p++) {

    if (*p < '0' || *p > '9') FATAL("Bad syntax used for %s: '%s'", what, val);

  }

  errno = 0;
  char *end = NULL;
  u64   res = strtoull(val, &end, 10);

  if (errno || !end || *end) FATAL("Bad syntax used for %s: '%s'", what, val);
  if (res < min || res > max)
    FATAL("Value of %s must be between %llu and %llu, got '%s'", what, min, max,
          val);

  return res;

}

static u8 *unique_name_in(const u8 *dir, const u8 *name) {

  u8 *candidate = alloc_printf("%s/%s", dir, name);
  if (access(candidate, F_OK) != 0) { return candidate; }

  ck_free(candidate);

  for (u32 i = 0; i < 10000; i++) {

    u32 prefix = (AFL_R(0x10000) << 16) | AFL_R(0x10000);
    candidate = alloc_printf("%s/%08x_%s", dir, prefix, name);
    if (access(candidate, F_OK) != 0) { return candidate; }
    ck_free(candidate);

  }

  FATAL("Unable to find unique name for '%s' in '%s'", name, dir);

}

static u8 *unique_out_name(const u8 *name) {

  return unique_name_in(out_dir, name);

}

/* An existing destination is never replaced, and a partially written one is
   removed again. */

static u8 copy_file(u8 *src_path, u8 *dst_path) {

  int src = open(src_path, O_RDONLY);
  if (src < 0) return 1;

  int dst = open(dst_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                 DEFAULT_PERMISSION);
  if (dst < 0) {

    close(src);
    return 1;

  }

  u8      buf[4096];
  ssize_t n;
  u8      ret = 0;

  while ((n = read(src, buf, sizeof(buf))) > 0) {

    if (write(dst, buf, n) != n) {

      ret = 1;
      break;

    }

  }

  if (n < 0) ret = 1;

  close(src);
  if (close(dst)) ret = 1;

  if (ret) unlink(dst_path);

  return ret;

}

/* Decide whether an occupied destination already holds this very input. */

static u8 same_file_content(u8 *path_a, u8 *path_b) {

  struct stat sa, sb;
  u8          buf_a[4096], buf_b[4096];
  u8          ret = 0;

  int fa = open(path_a, O_RDONLY);
  if (fa < 0) return 0;
  int fb = open(path_b, O_RDONLY | O_NOFOLLOW);
  if (fb < 0) {

    close(fa);
    return 0;

  }

  if (fstat(fa, &sa) || fstat(fb, &sb) || !S_ISREG(sb.st_mode) ||
      sa.st_size != sb.st_size) {

    goto done;

  }

  if (sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino) {

    ret = 1;
    goto done;

  }

  while (1) {

    ssize_t na = read(fa, buf_a, sizeof(buf_a));
    ssize_t nb = read(fb, buf_b, sizeof(buf_b));

    if (na < 0 || nb < 0 || na != nb) goto done;
    if (!na) break;
    if (memcmp(buf_a, buf_b, na)) goto done;

  }

  ret = 1;

done:
  close(fa);
  close(fb);
  return ret;

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

  /* Broadcast: writers wait for different amounts of room, so waking just
     one of them can leave a writer that would fit asleep indefinitely. */
  pthread_cond_broadcast(&queue->cond_write);
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

    WARNF("Unable to open '%s/%s'", f->dir, f->name);
    f->size = 0;
    memset(f->sha1, 0, SHA1_SIZE);
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
    f->size = 0;
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

  int d = memcmp(fa->sha1, fb->sha1, SHA1_SIZE);
  if (d) return d;
  if (fa->size != fb->size) return fa->size < fb->size ? -1 : 1;
  d = strcmp(fa->dir, fb->dir);
  if (d) return d;
  return strcmp(fa->name, fb->name);

}

static void dedup_files(void) {

  OKF("Deduplicating inputs...");

  deduped_cnt = 0;
  next_dedup_idx = 0;
  pthread_t *t = ck_alloc(sizeof(pthread_t) * update_workers);

  for (u32 i = 0; i < update_workers; i++) {

    if (pthread_create(&t[i], NULL, dedup_worker, (void *)(size_t)i))
      PFATAL("pthread_create failed");

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

}

static u32 map_size = MAP_SIZE;
static u8 *baseline_covered;

typedef struct {

  u32 tuple;
  u32 count;
  u32 best;

} tuple_info_t;

/* Rarest tuple first; among equally rare ones start with those whose
   representative is the largest file (files[] is sorted by size), so that its
   coverage can absorb the cheaper tuples still to come. */

static int compare_tuple_counts(const void *a, const void *b) {

  const tuple_info_t *ta = (const tuple_info_t *)a;
  const tuple_info_t *tb = (const tuple_info_t *)b;

  if (ta->count != tb->count) return ta->count < tb->count ? -1 : 1;
  if (ta->best != tb->best) return ta->best > tb->best ? -1 : 1;
  if (ta->tuple == tb->tuple) return 0;
  return ta->tuple > tb->tuple ? -1 : 1;

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

    /* Coverage in a map whose size is not a multiple of the stride would
       otherwise be lost */
    for (u32 k = map_size64 * 8; k < map_size; k++) {

      if (trace[k]) {

        tuples[t_len++] = k * 8 + (count_class_human[trace[k]] - 1);

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
  int fd;

  /* Only MAX_FILE bytes ever reach the target - shared-memory delivery
     truncates there anyway, so all transports have to agree on it,
     otherwise coverage would depend on the negotiated transport. */
  u32 len = f->size > MAX_FILE ? MAX_FILE : f->size;

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

    /* Our own delivery files live in tmp_dir and are recreated exclusively by
       the next fork server, so they must not survive this one. A -f file
       belongs to the user. */
    if (!stdin_file) unlink(fsrv->out_file);

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
                           u32 use_map_size, u32 id) {

  // Init fsrv
  afl_fsrv_init(fsrv);
  set_sanitizer_defaults();

  /* Set binary-only mode flags before afl_fsrv_setup_preload() so the
     correct LD_PRELOAD (e.g. afl-frida-trace.so) is injected. */
  fsrv->frida_mode = frida_mode;
  fsrv->qemu_mode = qemu_mode;
  fsrv->unicorn_mode = unicorn_mode;
#ifdef __linux__
  fsrv->nyx_mode = nyx_mode;
#endif

  afl_fsrv_setup_preload(fsrv, target_bin);

  // Init SHM
  memset(shm, 0, sizeof(sharedmem_t));
  shm->map = afl_shm_init(shm, use_map_size, 0, DEFAULT_PERMISSION, -1);
  if (!shm->map) FATAL("Unable to allocate shared memory");
  fsrv->trace_bits = shm->map;
  fsrv->child_sync_offset = shm->child_sync_offset;

  fsrv->map_size = use_map_size;
  fsrv->mem_limit = mem_limit;
  fsrv->exec_tmout = time_limit;

  if (nyx_mode) {

#ifdef __linux__
    fsrv->nyx_mode = 1;
    fsrv->nyx_parent = true;
    fsrv->nyx_standalone = true;
    fsrv->nyx_id = id;
    fsrv->nyx_use_tmp_workdir = true;
    fsrv->nyx_bind_cpu_id = 0;

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

  char *placeholder = (char *)get_afl_env("AFL_INPUT_PLACEHOLDER");
  if (!placeholder || !*placeholder) placeholder = (char *)"@@";
  size_t placeholder_len = strlen(placeholder);

  // We need to scan args for placeholder to know if we need to copy them
  u32 argc = scan_args((u8 **)argv);
  for (u32 i = 0; i < argc; i++) {

    if (strstr(argv[i], placeholder)) {

      has_at = 1;
      break;

    }

  }

  if (has_at) {

    // If we have placeholder, we MUST copy argv because we modify it
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
      fsrv->out_file = alloc_printf("%s/test_input", tmp_dir);

    } else {

      // worker mode
      fsrv->out_file = alloc_printf("%s/cur_input_%u", tmp_dir, id);

    }

    if (!has_at) fsrv->use_stdin = 1;

  }

  if (has_at) {

    fsrv->use_stdin = 0;
    for (u32 i = 0; i < argc; i++) {

      char *ret = strstr(argv[i], placeholder);
      if (ret) {

        u8 *new_arg = alloc_printf("%.*s%s%s", (int)(ret - argv[i]), argv[i],
                                   fsrv->out_file, ret + placeholder_len);
        argv[i] = (char *)new_arg;

      }

    }

  }

  if (fsrv->use_stdin && fsrv->out_fd < 0) {

    /* O_EXCL|O_NOFOLLOW: the file lives in our own private directory, so
       anything already occupying the name is not ours to truncate. */
    fsrv->out_fd = open(fsrv->out_file, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
                        DEFAULT_PERMISSION);
    if (fsrv->out_fd < 0) PFATAL("Unable to create '%s'", fsrv->out_file);

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

/* Per-status result accounting, shared with the execution workers. */

typedef struct {

  u32 ok;
  u32 crash;
  u32 tmout;
  u32 error;
  u32 accepted;

} cmin_run_stats_t;

static cmin_run_stats_t *run_stats;
static u32               crashes_saved;

static void exec_worker(worker_data_t *data, u32 *shared_cmin_idx) {

  afl_forkserver_t *fsrv = &data->fsrv;

  char **argv = prepare_fsrv(fsrv, &data->shm, map_size, data->id);

  u8 stop_soon = 0;

  // Setup SHM fuzzing (testcase delivery via shared memory)
  sharedmem_t shm_fuzz;
  memset(&shm_fuzz, 0, sizeof(sharedmem_t));
  u8 *map = afl_shm_init(&shm_fuzz, MAX_FILE + sizeof(u32), 1,
                         DEFAULT_PERMISSION, -1);

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

  /* Post-handshake: if target did not negotiate shmem-fuzz (e.g. Frida
     non-persistent mode), tear down the allocation and fall back to
     out_fd/stdin delivery — mirrors afl-showmap.c behaviour. */
  if (fsrv->support_shmem_fuzz && !fsrv->use_shmem_fuzz) {

    afl_shm_deinit(&shm_fuzz);
    fsrv->support_shmem_fuzz = 0;
    fsrv->shmem_fuzz_len = NULL;
    fsrv->shmem_fuzz = NULL;

  }

  u8 *last_exec_dir = NULL;
  int last_exec_dirfd = -1;

  u32 *tuples = ck_alloc(map_size * sizeof(u32));

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

    if (ret == FSRV_RUN_ERROR) {

      __sync_fetch_and_add(&run_stats->error, 1);
      continue;

    }

    if (ret == FSRV_RUN_CRASH) {

      __sync_fetch_and_add(&run_stats->crash, 1);
      if (crashing_files) crashing_files[i] = 1;
      if (crash_dir || (!crashes_only && !allow_any)) continue;

    } else if (ret == FSRV_RUN_TMOUT) {

      __sync_fetch_and_add(&run_stats->tmout, 1);
      if (!allow_any) continue;

    } else if (ret != FSRV_RUN_OK) {

      __sync_fetch_and_add(&run_stats->error, 1);
      continue;

    } else {

      __sync_fetch_and_add(&run_stats->ok, 1);
      if (crashes_only) continue;

    }

    __sync_fetch_and_add(&run_stats->accepted, 1);

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
  if (fsrv->use_shmem_fuzz) afl_shm_deinit(&shm_fuzz);
  cleanup_fsrv_allocs(fsrv, argv);

}

static void process_update_message(worker_data_t *data, u32 *unpack_buf) {

  u32  i = unpack_buf[0];
  u32  t_len = unpack_buf[1];
  u32 *tuples = &unpack_buf[2];
  u32  size = files[i]->size;

  /* Track the smallest size seen per tuple and keep the trace of every file
     that reaches it. Which of the equally small files ends up representing a
     tuple can only be decided once all hit counts are in, so the choice is
     deferred to select_representatives() in the parent. */

  u8 better = 0;
  for (u32 j = 0; j < t_len; j++) {

    u32 tuple = tuples[j];

    if (size <= data->local_best[tuple]) {

      data->local_best[tuple] = size;
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

static u32    effective_map_size;
static size_t worker_map_bytes;
static u32   *global_best_maps;
static u32   *global_counts_maps;
static u32   *shared_cmin_idx;
static pid_t  worker_pids[MAX_WORKERS];

static u8 *trace_log_name(u32 worker) {

  return alloc_printf("%s/worker_%u.dat", tmp_dir, worker);

}

static void cmin_detect_map_size(void) {

  // Get map size
  u8 *env_map_size = getenv("AFL_MAP_SIZE");
  if (!env_map_size) env_map_size = getenv("AFL_MAPSIZE");

  if (env_map_size) {

    /* Same validation and rounding as get_map_size() in afl-common.c, so
       that an explicit map size behaves identically everywhere. */
    map_size = validate_map_size((u32)parse_u64_strict(
        (char *)env_map_size, "AFL_MAP_SIZE", 1, (1U << 29) - 1));

    if (map_size % 64) { map_size = (((map_size >> 6) + 1) << 6); }

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

    /* Propagate binary-only mode flags before preload setup. */
    fsrv.frida_mode = frida_mode;
    fsrv.qemu_mode = qemu_mode;
    fsrv.unicorn_mode = unicorn_mode;
#ifdef __linux__
    fsrv.nyx_mode = nyx_mode;
#endif

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
    shm.map = afl_shm_init(&shm, detection_size, 0, DEFAULT_PERMISSION, -1);
    if (!shm.map) FATAL("Unable to allocate shared memory for detection");
    fsrv.trace_bits = shm.map;
    fsrv.child_sync_offset = shm.child_sync_offset;
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

  /* The children have to agree with the size we ended up using */
  u8 *final_size = alloc_printf("%u", map_size);
  setenv("AFL_MAP_SIZE", final_size, 1);
  ck_free(final_size);

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

    data.local_best = global_best_maps + ((size_t)i * effective_map_size);
    data.local_counts = global_counts_maps + ((size_t)i * effective_map_size);

    // Build trace log path
    u8 *trace_fn = trace_log_name(i);
    int trace_fd = open(trace_fn, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (trace_fd < 0) PFATAL("Unable to create trace file %s", trace_fn);
    data.trace_log = fdopen(trace_fd, "w+b");
    if (!data.trace_log) PFATAL("Unable to open trace file %s", trace_fn);
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
  global_best_maps = mmap(NULL, worker_map_bytes, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (global_best_maps == MAP_FAILED) PFATAL("mmap global_best_maps failed");

  for (size_t i = 0; i < worker_map_bytes / sizeof(u32); i++)
    global_best_maps[i] = 0xFFFFFFFF;

  global_counts_maps = mmap(NULL, worker_map_bytes, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (global_counts_maps == MAP_FAILED)
    PFATAL("mmap global_counts_maps failed");
  memset(global_counts_maps, 0, worker_map_bytes);

  // Crash markers, set by the exec workers for --crash-dir
  if (crash_dir) {

    crashing_files = mmap(NULL, items, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (crashing_files == MAP_FAILED) PFATAL("mmap crashing_files failed");

  }

  // Per-status result counters, written by the exec workers
  run_stats = mmap(NULL, sizeof(cmin_run_stats_t), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (run_stats == MAP_FAILED) PFATAL("mmap run_stats failed");
  memset(run_stats, 0, sizeof(cmin_run_stats_t));

  // Shared counter for coordination (Exec workers)
  shared_cmin_idx = mmap(NULL, sizeof(u32), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_cmin_idx == MAP_FAILED) PFATAL("mmap");
  *shared_cmin_idx = 0;

  /* The ring has to hold at least one full trace message, otherwise
     queue_push() would reject it outright on targets with a large map. */
  u64 msg_max = ((u64)map_size + 2) * sizeof(u32);
  u64 cap = QUEUE_CAPACITY;
  if (cap < msg_max * 2) { cap = msg_max * 2; }
  queue_init(cap);

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

    int   status;
    pid_t pid = worker_pids[i];

    /* Forget the pid right away, the number can be reused by an unrelated
       process that cleanup_tmp_files() would then signal. */
    worker_pids[i] = 0;

    if (waitpid(pid, &status, 0) > 0 &&
        (!WIFEXITED(status) || WEXITSTATUS(status)))
      FATAL("Execution worker %d died unexpectedly (status %d)", pid, status);

  }

  // Send STOP signals to Update Workers
  OKF("Waiting for update workers to finish...");
  for (u32 i = 0; i < update_workers; i++)
    queue_push(QUEUE_MSG_STOP, NULL, 0);

  // Wait for Update Workers
  for (u32 i = 0; i < update_workers; i++) {

    int   status;
    pid_t pid = worker_pids[exec_workers + i];

    worker_pids[exec_workers + i] = 0;

    if (waitpid(pid, &status, 0) > 0 &&
        (!WIFEXITED(status) || WEXITSTATUS(status)))
      FATAL("Update worker %d died unexpectedly (status %d)", pid, status);

  }

  munmap(shared_cmin_idx, sizeof(u32));
  munmap(queue, sizeof(cmin_queue_t) + queue->capacity);

}

static void merge_results(u32 *min_size, u32 *tuple_counts) {

  u32 *global_map = global_best_maps;
  u32 *global_cnt = global_counts_maps;

  for (u32 w = 0; w < update_workers; w++) {

    u32 *worker_map = global_map + ((size_t)w * effective_map_size);
    u32 *worker_cnt = global_cnt + ((size_t)w * effective_map_size);

    for (u32 i = 0; i < effective_map_size; i++) {

      tuple_counts[i] += worker_cnt[i];
      if (worker_map[i] < min_size[i]) { min_size[i] = worker_map[i]; }

    }

  }

}

/* Second look at the traces on disk: now that all hit counts are known, elect
   the representative of every tuple among the smallest inputs covering it.
   Rarity decides - a file scores the sum of 1/count over its own tuples, so
   the input carrying the most hard-to-find coverage wins and the set cover
   below needs fewer files. */

static void select_representatives(u32 *final_best, u32 *tuple_counts,
                                   u32 *min_size) {

  double *best_score = ck_alloc(effective_map_size * sizeof(double));
  u32    *buf = ck_alloc(map_size * sizeof(u32));

  for (u32 w = 0; w < update_workers; w++) {

    u8   *trace_fn = trace_log_name(w);
    FILE *f = fopen(trace_fn, "rb");
    if (!f) {

      ck_free(trace_fn);
      continue;

    }

    u32 idx, len;

    while (fread(&idx, sizeof(u32), 1, f) == 1) {

      if (fread(&len, sizeof(u32), 1, f) != 1)
        FATAL("Truncated trace log '%s'", trace_fn);

      if (idx >= items || len > map_size)
        FATAL("Corrupt trace log '%s'", trace_fn);

      if (len && fread(buf, sizeof(u32), len, f) != len)
        FATAL("Truncated trace log '%s'", trace_fn);

      u32 size = files[idx]->size;

      double score = 0.0;
      for (u32 j = 0; j < len; j++) {

        u32 cnt = tuple_counts[buf[j]];
        if (cnt) { score += 1.0 / (double)cnt; }

      }

      for (u32 j = 0; j < len; j++) {

        u32 tuple = buf[j];
        if (size != min_size[tuple]) continue;

        if (final_best[tuple] == cmin_sentinel_idx ||
            score > best_score[tuple] ||
            (score == best_score[tuple] && idx < final_best[tuple])) {

          final_best[tuple] = idx;
          best_score[tuple] = score;

        }

      }

    }

    fclose(f);
    ck_free(trace_fn);

  }

  ck_free(buf);
  ck_free(best_score);

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

    u8   *trace_fn = trace_log_name(w);
    FILE *f = fopen(trace_fn, "rb");
    if (f) {

      while (1) {

        u32 idx, len;
        if (fread(&idx, sizeof(u32), 1, f) != 1) break;
        if (fread(&len, sizeof(u32), 1, f) != 1)
          FATAL("Truncated trace log '%s'", trace_fn);

        if (idx >= items || len > map_size)
          FATAL("Corrupt trace log '%s'", trace_fn);

        if (is_candidate[idx] && !candidate_traces[idx].tuples) {

          candidate_traces[idx].tuples = ck_alloc(len * sizeof(u32));
          if (len > 0) {

            if (fread(candidate_traces[idx].tuples, sizeof(u32), len, f) != len)
              FATAL("Truncated trace log '%s'", trace_fn);

          }

          candidate_traces[idx].len = len;

        } else {

          if (fseeko(f, (off_t)len * sizeof(u32), SEEK_CUR))
            PFATAL("Unable to seek in trace log '%s'", trace_fn);

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
  u32 existing_cnt = 0;
  u32 selected_cnt = 0;

  if (merge_mode && baseline_covered) {

    memcpy(covered, baseline_covered, effective_map_size);

  }

  u64 start_ms = get_cur_time();

  // Prepare sortable tuples
  tuple_info_t *sorted_tuples = ck_alloc(total_tuples * sizeof(tuple_info_t));
  u32           st_idx = 0;
  for (u32 i = 0; i < effective_map_size; i++) {

    if (final_best[i] != cmin_sentinel_idx) {

      sorted_tuples[st_idx].tuple = i;
      sorted_tuples[st_idx].count = tuple_counts[i];
      sorted_tuples[st_idx].best = final_best[i];
      st_idx++;

      /* Tuples the baseline corpus already covers are covered for real, so
         they belong in the progress numbers too */
      if (covered[i]) covered_cnt++;

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
    selected_cnt++;

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
    u8          *out_base;
    u8           hash[SHA1_SIZE * 2 + 1];

    /* Without the dedup pass the hashes were never computed, so do it now */
    if (sha1fn && no_dedup) { get_binary_hash_local(f, -1); }

    if (sha1fn) {

      for (int x = 0; x < SHA1_SIZE; x++)
        sprintf((char *)hash + x * 2, "%02x", f->sha1[x]);
      hash[SHA1_SIZE * 2] = 0;

    }

    if (!sha1fn) {

      if (as_queue)
        out_base = alloc_printf("id:%06u,orig:%s", selected_cnt - 1, f->name);
      else
        out_base = alloc_printf("%s", f->name);

    } else {

      if (as_queue)
        out_base = alloc_printf("id:%06u,hash:%s", selected_cnt - 1, hash);
      else
        out_base = alloc_printf("%s", hash);

    }

    /* An occupied destination is either this very input - then there is
       nothing to do - or an unrelated file that must not be touched. */

    u8 *out_name = alloc_printf("%s/%s", out_dir, out_base);
    u8 *src_path = alloc_printf("%s/%s", f->dir, f->name);
    u8  is_new = 0;

    while (1) {

      if (!link(src_path, out_name)) {

        is_new = 1;
        break;

      }

      if (errno == EEXIST) {

        if (same_file_content(src_path, out_name)) {

          existing_cnt++;
          break;

        }

        ck_free(out_name);
        out_name = unique_out_name(out_base);
        continue;

      }

      if (copy_file(src_path, out_name)) {

        PFATAL("Unable to copy '%s' to '%s'", src_path, out_name);

      }

      is_new = 1;
      break;

    }

    if (is_new) written_cnt++;

    ck_free(out_base);
    ck_free(out_name);
    ck_free(src_path);

    if (selected_cnt % 1000 == 0) {

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
      (cur_ms > start_ms) ? (selected_cnt * 1000.0 / (cur_ms - start_ms)) : 0.0;

  SAYF(cGRA
       "\r    Written %u files, covered %u/%u tuples (%.2f/sec) [elapsed "
       "%llus]\n" cRST,
       written_cnt, covered_cnt, total_tuples, speed, t);

  if (existing_cnt) {

    OKF("Wrote %u files, %u were already present in '%s'.", written_cnt,
        existing_cnt, out_dir);

  } else {

    OKF("Wrote %u files.", written_cnt);

  }

}

static void write_crash_files(void) {

  u32 count = 0, dup_cnt = 0, existing_cnt = 0, fail_cnt = 0;

  /* The crash set is always content-deduplicated, independently of
     --no-dedup, which only governs the corpus. */

  u32 crash_cnt = 0;
  for (u32 i = 0; i < items; i++)
    if (crashing_files[i]) crash_cnt++;

  if (!crash_cnt) {

    OKF("No crashing inputs to save in '%s'.", crash_dir);
    return;

  }

  cmin_file_t **crashes = ck_alloc(crash_cnt * sizeof(cmin_file_t *));
  u32           n = 0;

  for (u32 i = 0; i < items; i++) {

    if (!crashing_files[i]) continue;
    if (no_dedup) get_binary_hash_local(files[i], -1);
    crashes[n++] = files[i];

  }

  qsort(crashes, crash_cnt, sizeof(cmin_file_t *), compare_hashes);

  cmin_file_t *prev = NULL;

  for (u32 i = 0; i < crash_cnt; i++) {

    cmin_file_t *f = crashes[i];

    if (prev && f->size == prev->size &&
        !memcmp(f->sha1, prev->sha1, SHA1_SIZE)) {

      dup_cnt++;
      continue;

    }

    prev = f;

    u8 *out_base;

    if (sha1fn) {

      u8 hash[SHA1_SIZE * 2 + 1];
      for (int x = 0; x < SHA1_SIZE; x++)
        sprintf((char *)hash + x * 2, "%02x", f->sha1[x]);
      hash[SHA1_SIZE * 2] = 0;
      out_base = alloc_printf("%s", hash);

    } else {

      out_base = alloc_printf("%s", f->name);

    }

    u8 *out_name = alloc_printf("%s/%s", crash_dir, out_base);
    u8 *src_path = alloc_printf("%s/%s", f->dir, f->name);

    while (1) {

      if (!link(src_path, out_name)) {

        count++;
        break;

      }

      if (errno == EEXIST) {

        if (same_file_content(src_path, out_name)) {

          existing_cnt++;
          break;

        }

        ck_free(out_name);
        out_name = unique_name_in(crash_dir, out_base);
        continue;

      }

      if (copy_file(src_path, out_name)) {

        WARNF("Cannot save crash '%s' to '%s'", src_path, out_name);
        fail_cnt++;

      } else {

        count++;

      }

      break;

    }

    ck_free(src_path);
    ck_free(out_name);
    ck_free(out_base);

  }

  ck_free(crashes);
  crashes_saved = count + existing_cnt;

  OKF("Saved %u crashing files in '%s' (%u duplicates, %u already present, %u "
      "failed).",
      count, crash_dir, dup_cnt, existing_cnt, fail_cnt);

}

static void cmin_process_results(void) {

  // Merge results (already done above in collection loop)
  // if (!crashes_only) {

  OKF("Merging traces and computing candidates...");

  // Step 1: Merge the per-tuple minimum sizes and the hit counts
  u32 *final_best = ck_alloc(effective_map_size * sizeof(u32));
  u32 *tuple_counts = ck_alloc(effective_map_size * sizeof(u32));
  u32 *min_size = ck_alloc(effective_map_size * sizeof(u32));
  for (u32 i = 0; i < effective_map_size; i++) {

    final_best[i] = cmin_sentinel_idx;
    tuple_counts[i] = 0;
    min_size[i] = 0xFFFFFFFF;

  }

  merge_results(min_size, tuple_counts);

  // Step 2: Elect a representative per tuple, then identify candidates
  select_representatives(final_best, tuple_counts, min_size);
  ck_free(min_size);

  u8 *is_candidate = ck_alloc(items);  // bool
  u32 candidates_cnt = 0;
  u32 total_tuples = 0;

  total_tuples = identify_candidates(final_best, is_candidate, &candidates_cnt);

  OKF("Found %u unique tuples across %u files. Candidates: %u", total_tuples,
      items, candidates_cnt);

  // Step 3: Load traces for candidates from temporary files
  trace_t *candidate_traces = ck_alloc(items * sizeof(trace_t));
  load_traces(is_candidate, candidate_traces);

  // Step 4: Rarest First Set Cover
  OKF("Performing Rarest First Set Cover...");
  execute_set_cover(final_best, tuple_counts, candidate_traces, total_tuples);

  ck_free(tuple_counts);
  if (global_counts_maps) munmap(global_counts_maps, worker_map_bytes);

  for (u32 i = 0; i < items; i++) {

    if (candidate_traces[i].tuples) ck_free(candidate_traces[i].tuples);

  }

  ck_free(candidate_traces);
  ck_free(final_best);
  ck_free(is_candidate);

  if (global_best_maps) munmap(global_best_maps, worker_map_bytes);

  if (crashing_files) {

    write_crash_files();
    munmap(crashing_files, items);
    crashing_files = NULL;

  }

}

static void test_target_binary(void) {

  OKF("Testing the target binary...");

  afl_forkserver_t fsrv = {0};
  sharedmem_t      shm = {0};
  u8               stop_soon = 0;
  char           **argv;

#ifdef __linux__
  if (nyx_mode)
    argv = prepare_fsrv(&fsrv, &shm, map_size, 0);
  else
#endif
    argv = prepare_fsrv(&fsrv, &shm, map_size, (u32)-1);

  /* Set up shared-memory test-case delivery; the fork server negotiates
     shmem-fuzz support during the handshake (needed for Frida/QEMU). */
  sharedmem_t shm_fuzz = {0};
  u8         *fuzz_map = afl_shm_init(&shm_fuzz, MAX_FILE + sizeof(u32), 1,
                                      DEFAULT_PERMISSION, -1);

  if (fuzz_map) {

    shm_fuzz.shmemfuzz_mode = 1;
    fsrv.support_shmem_fuzz = 1;
    fsrv.shmem_fuzz_len = (u32 *)fuzz_map;
    fsrv.shmem_fuzz = fuzz_map + sizeof(u32);

    u8 *shm_fuzz_map_size_str = alloc_printf("%lu", MAX_FILE + sizeof(u32));
    setenv(SHM_FUZZ_MAP_SIZE_ENV_VAR, shm_fuzz_map_size_str, 1);
    ck_free(shm_fuzz_map_size_str);

  }

  afl_fsrv_start(&fsrv, (char **)argv, &stop_soon, debug_mode ? 1 : 0);

  /* Same post-handshake fallback as exec_worker() and afl-showmap. */
  if (fsrv.support_shmem_fuzz && !fsrv.use_shmem_fuzz) {

    afl_shm_deinit(&shm_fuzz);
    fsrv.support_shmem_fuzz = 0;
    fsrv.shmem_fuzz_len = NULL;
    fsrv.shmem_fuzz = NULL;

  }

  // Use the first file for testing
  cmin_file_t      *f = files[0];
  fsrv_run_result_t ret = run_target_file(&fsrv, f, -1, &stop_soon);

  if (ret == FSRV_RUN_ERROR)
    FATAL("Unable to open or read input file '%s/%s'", f->dir, f->name);
  else if (ret == FSRV_RUN_NOINST)
    FATAL("No instrumentation detected.");
  else if (ret == FSRV_RUN_NOBITS)
    FATAL("No instrumentation was gathered.");

  /*
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

  */

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
  if (fsrv.use_shmem_fuzz) afl_shm_deinit(&shm_fuzz);
  afl_fsrv_deinit(&fsrv);
  afl_shm_deinit(&shm);

  cleanup_fsrv_allocs(&fsrv, argv);

}

static void seed_baseline(void) {

  DIR *d = opendir(out_dir);
  if (!d) return;

  cmin_file_t  **bfiles = NULL;
  u32            bcnt = 0, bcap = 0;
  struct dirent *de;

  while ((de = readdir(d))) {

    if (de->d_name[0] == '.') continue;

    u8         *fn = alloc_printf("%s/%s", out_dir, de->d_name);
    struct stat st;
    if (stat(fn, &st) || !S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    ck_free(fn);

    if (bcnt >= bcap) {

      bcap = bcap ? bcap * 2 : 256;
      bfiles = ck_realloc(bfiles, bcap * sizeof(cmin_file_t *));

    }

    cmin_file_t *f = ck_alloc(sizeof(cmin_file_t));
    f->dir = out_dir;
    f->name = strdup(de->d_name);
    f->size = st.st_size;
    bfiles[bcnt++] = f;

  }

  closedir(d);

  if (!bcnt) {

    if (bfiles) ck_free(bfiles);
    return;

  }

  OKF("Seeding coverage baseline from %u existing files in '%s'...", bcnt,
      out_dir);

  afl_forkserver_t fsrv = {0};
  sharedmem_t      shm = {0};
  u8               stop_soon = 0;
  char           **argv;

#ifdef __linux__
  if (nyx_mode)
    argv = prepare_fsrv(&fsrv, &shm, map_size, 0);
  else
#endif
    argv = prepare_fsrv(&fsrv, &shm, map_size, (u32)-1);

  sharedmem_t shm_fuzz = {0};
  u8         *fuzz_map = afl_shm_init(&shm_fuzz, MAX_FILE + sizeof(u32), 1,
                                      DEFAULT_PERMISSION, -1);

  if (fuzz_map) {

    shm_fuzz.shmemfuzz_mode = 1;
    fsrv.support_shmem_fuzz = 1;
    fsrv.shmem_fuzz_len = (u32 *)fuzz_map;
    fsrv.shmem_fuzz = fuzz_map + sizeof(u32);

    u8 *shm_fuzz_map_size_str = alloc_printf("%lu", MAX_FILE + sizeof(u32));
    setenv(SHM_FUZZ_MAP_SIZE_ENV_VAR, shm_fuzz_map_size_str, 1);
    ck_free(shm_fuzz_map_size_str);

  }

  afl_fsrv_start(&fsrv, (char **)argv, &stop_soon, debug_mode ? 1 : 0);

  if (fsrv.support_shmem_fuzz && !fsrv.use_shmem_fuzz) {

    afl_shm_deinit(&shm_fuzz);
    fsrv.support_shmem_fuzz = 0;
    fsrv.shmem_fuzz_len = NULL;
    fsrv.shmem_fuzz = NULL;

  }

  int  dirfd = open(out_dir, O_RDONLY | O_DIRECTORY);
  u32 *tuples = ck_alloc(map_size * sizeof(u32));

  for (u32 i = 0; i < bcnt; i++) {

    fsrv_run_result_t ret =
        run_target_file(&fsrv, bfiles[i], dirfd, &stop_soon);
    if (ret == FSRV_RUN_ERROR) continue;

    u32 t_len = collect_coverage_counts(fsrv.trace_bits, map_size, tuples);
    for (u32 j = 0; j < t_len; j++)
      baseline_covered[tuples[j]] = 1;

    if (stop_soon) break;

  }

  ck_free(tuples);
  if (dirfd >= 0) close(dirfd);

  afl_fsrv_deinit(&fsrv);
  afl_shm_deinit(&shm);
  if (fsrv.use_shmem_fuzz) afl_shm_deinit(&shm_fuzz);
  cleanup_fsrv_allocs(&fsrv, argv);

  for (u32 i = 0; i < bcnt; i++) {

    ck_free(bfiles[i]->name);
    ck_free(bfiles[i]);

  }

  ck_free(bfiles);

  OKF("Coverage baseline established.");

}

/* Every name afl-cmin can create in tmp_dir, precomputed so that removing
   them needs no allocation and stays usable from a signal handler. */

static u8 **tmp_files;
static u32  tmp_files_cnt;

static void remove_tmp_files(void) {

  for (u32 i = 0; i < tmp_files_cnt; i++)
    unlink(tmp_files[i]);

  rmdir(tmp_dir);

}

static void kill_workers(void) {

  for (u32 i = 0; i < exec_workers + update_workers; i++) {

    if (worker_pids[i] > 0) kill(worker_pids[i], SIGKILL);

  }

}

/* Registered with atexit(), so a failing run does not leave state behind that
   blocks the next attempt. Only the process that created the directory may
   delete it. */

static void cleanup_tmp_files(void) {

  if (!tmp_dir || tmp_dir_pid != getpid()) return;

  kill_workers();
  remove_tmp_files();
  afl_shm_deinit_all();

}

static void cleanup_signal(int sig) {

  if (tmp_dir && tmp_dir_pid == getpid()) {

    kill_workers();
    remove_tmp_files();
    afl_shm_deinit_all();

  }

  _exit(128 + sig);

}

/* A fresh, unpredictable and exclusively created directory. Everything that
   afl-cmin writes for its own use goes in here, so no pre-existing name in
   out_dir can be followed or overwritten. */

static void create_tmp_dir(void) {

  u8 *template = alloc_printf("%s/.afl-cmin-XXXXXX", out_dir);

  if (!mkdtemp((char *)template))
    PFATAL("Unable to create a work directory in '%s'", out_dir);

  tmp_dir = template;

  tmp_files = ck_alloc((1 + exec_workers + update_workers) * sizeof(u8 *));
  tmp_files[tmp_files_cnt++] = alloc_printf("%s/test_input", tmp_dir);
  for (u32 i = 0; i < exec_workers; i++)
    tmp_files[tmp_files_cnt++] = alloc_printf("%s/cur_input_%u", tmp_dir, i);
  for (u32 i = 0; i < update_workers; i++)
    tmp_files[tmp_files_cnt++] = trace_log_name(i);

  tmp_dir_pid = getpid();

  atexit(cleanup_tmp_files);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = cleanup_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL);

}

/* All map allocations in one place, so their size is computed - and
   bounds-checked - exactly once. */

static void plan_memory(void) {

  u64 eff = map_size;
  if (!edges_only) eff *= 8;

  if (eff > UINT32_MAX)
    FATAL("Map size %u is too large for hit count mode, use -e", map_size);

  effective_map_size = (u32)eff;
  OKF("Effective map size: %u", effective_map_size);

  u64 per_worker = (u64)effective_map_size * sizeof(u32);
  u64 total = per_worker * update_workers * 2;

  if (per_worker > SIZE_MAX / update_workers || total > SIZE_MAX)
    FATAL("Memory required for %u update workers is not representable",
          update_workers);

#ifdef _SC_PHYS_PAGES
  s64 pages = sysconf(_SC_PHYS_PAGES);
  s64 psize = sysconf(_SC_PAGESIZE);

  if (pages > 0 && psize > 0) {

    u64 phys = (u64)pages * (u64)psize;

    if (total > phys)
      FATAL(
          "%llu MB are needed for %u update workers at a map size of %u, but "
          "only %llu MB exist - lower -T, or use -e",
          total / (1024 * 1024), update_workers, map_size,
          phys / (1024 * 1024));

    if (total > phys / 2)
      WARNF("%llu MB of %llu MB will be used for the coverage maps",
            total / (1024 * 1024), phys / (1024 * 1024));

  }

#endif

  worker_map_bytes = (size_t)(per_worker * update_workers);

}

static void execute_cmin(void) {

  create_tmp_dir();

  cmin_detect_map_size();
  test_target_binary();

  plan_memory();

  if (merge_mode) {

    baseline_covered = ck_alloc(effective_map_size);
    seed_baseline();

  }

  cmin_run_workers();
  cmin_process_results();

  if (baseline_covered) {

    ck_free(baseline_covered);
    baseline_covered = NULL;

  }

  /* Nothing was retained anywhere: the target, the timeout or the options are
     wrong, and an empty result must not look like a success. */

  OKF("Execution results: %u ok, %u crashed, %u timed out, %u failed to run; "
      "%u inputs matched the requested policy",
      run_stats->ok, run_stats->crash, run_stats->tmout, run_stats->error,
      run_stats->accepted);

  u8 nothing_accepted = !run_stats->accepted;
  munmap(run_stats, sizeof(cmin_run_stats_t));
  run_stats = NULL;

  cleanup_tmp_files();

  if (nothing_accepted && !crashes_saved) {

    if (crashes_only)
      FATAL("No input crashed the target, so -C selected nothing");
    else if (crash_dir)
      FATAL("No input could be used and no crash was saved");
    else
      FATAL(
          "No input file was usable: check the target, the timeout and -A/-C");

  }

}

static void usage(u8 *argv0, int status) {

  if (merge_mode) {

    SAYF(
        "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

        "Merge inputs that add new coverage into an output corpus, similar to\n"
        "libFuzzer's -merge=1. Only inputs whose coverage is not already "
        "present\n"
        "in the output corpus are added; existing output files are never "
        "changed\n"
        "or removed.\n\n"

        "Usage (any of):\n"
        "  %s -o out_dir -i in_dir [-i in_dir ...] -- /path/to/target [ ... ]\n"
        "  %s -o out_dir in_dir [in_dir ...]       -- /path/to/target [ ... ]\n"
        "  %s out_dir in_dir [in_dir ...]          -- /path/to/target [ ... ]\n"
        "\n"
        "In the last form the first directory is the output corpus and -i must "
        "not\n"
        "be used. -o may be given at the beginning or the end.\n\n"

        "Execution control settings:\n"
        "  -f file     - location read by the fuzzed program (stdin)\n"
        "  -m megs     - memory limit for child process (default: none)\n"
        "  -t msec     - timeout for each run (default: 5000ms)\n"
        "  -O          - use binary-only instrumentation (FRIDA mode)\n"
        "  -Q          - use binary-only instrumentation (QEMU mode)\n"
        "  -W          - use binary-only instrumentation (WINE mode)\n"
        "  -U          - use unicorn-based instrumentation (Unicorn mode)\n"
        "  -X          - use Nyx mode\n\n"

        "Input selection settings:\n"
        "  --crash-dir=dir - move crashes to a separate dir, always "
        "deduplicated\n"
        "  -A          - allow crashes and timeouts (not recommended)\n"
        "  -C          - only add crashing inputs, reject everything else\n"
        "  -e          - solve for edge coverage only, ignore hit counts\n"
        "  --no-dedup  - skip deduplication step for the input files\n\n"

        "Misc:\n"
        "  -T workers  - number of execution and of update workers, or\n"
        "                exec:update for both counts separately, or 'all'\n"
        "                (default: 1)\n"
        "  --as_queue  - name added files \"id:000000,orig:filename\", or\n"
        "                \"id:000000,hash:sha1\" with AFL_SHA1_FILENAMES; the\n"
        "                numbering restarts with every run\n"
        "  --debug     - debug mode\n\n"

        "Only the first %ld bytes of an input are given to the target.\n"
        "The exit status is 0 on success and 1 on any error, including a run\n"
        "in which no input matched the requested crash/timeout policy.\n\n"

        "afl-merge honors 'AFL_MAP_SIZE' and 'AFL_SHA1_FILENAMES'.\n\n"

        "For additional help, consult %s/README.md.\n\n",

        argv0, argv0, argv0, argv0, MAX_FILE, DOC_PATH);

    exit(status);

  }

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
      "  -W          - use binary-only instrumentation (WINE mode)\n"
      "  -U          - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -X          - use Nyx mode\n\n"

      "Minimization settings:\n"
      "  --crash-dir=dir - move crashes to a separate dir, always "
      "deduplicated\n"
      "  -A          - allow crashes and timeouts (not recommended)\n"
      "  -C          - keep crashing inputs, reject everything else\n"
      "  -e          - solve for edge coverage only, ignore hit counts\n\n"

      "Misc:\n"
      "  -T workers  - number of execution and of update workers, or\n"
      "                exec:update for both counts separately, or 'all'\n"
      "                (default: 1)\n"
      "  --as_queue  - name output files \"id:000000,orig:filename\", or\n"
      "                \"id:000000,hash:sha1\" with AFL_SHA1_FILENAMES\n"
      "  --no-dedup  - skip deduplication step for corpus files\n"
      "  --debug     - debug mode\n\n"

      "Metadata of an afl-fuzz output directory (fuzzer_stats, plot_data, "
      "...)\n"
      "is never used as an input, its queue/, crashes/ and hangs/ are.\n"
      "Only the first %ld bytes of an input are given to the target.\n"
      "The exit status is 0 on success and 1 on any error, including a run in\n"
      "which no input matched the requested crash/timeout policy.\n\n"

      "afl-cmin honors the 'AFL_MAP_SIZE' and 'AFL_SHA1_FILENAMES' "
      "environment variables.\n\n"

      "For additional help, consult %s/README.md.\n\n",

      argv0, MAX_FILE, DOC_PATH);

  exit(status);

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

static u8 has_entry(u8 *dir, const char *name, u8 want_dir) {

  struct stat st;
  u8         *fn = alloc_printf("%s/%s", dir, name);
  u8          ok = !stat((char *)fn, &st) &&
          (want_dir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
  ck_free(fn);
  return ok;

}

/* Recognize an afl-fuzz output directory, also when it is incomplete - an
   archived or interrupted run may be missing hangs/ or crashes/. */

static u8 is_afl_dir(u8 *dir) {

  return has_entry(dir, "queue", 1) && (has_entry(dir, "fuzzer_setup", 0) ||
                                        has_entry(dir, "fuzzer_stats", 0));

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

      /* An afl-fuzz output directory holds metadata files (fuzzer_stats,
         plot_data, cmdline, ...) next to the queue/crashes/hangs subdirs.
         Descend into the subdirs but never treat the metadata as inputs. */
      u8 skip_files = is_afl_dir(dir);

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
        else if (entry->d_type == DT_UNKNOWN || entry->d_type == DT_LNK) {

          /* Follow symlinks like afl-cmin.py does, cycles are caught by
             dir_already_seen() */

          struct stat st;
          u8         *fn = alloc_printf("%s/%s", dir, entry->d_name);
          if (!stat(fn, &st)) {

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

          if (skip_files) continue;

          u8         *fn = alloc_printf("%s/%s", dir, entry->d_name);
          struct stat st;
          if (stat(fn, &st)) {

            ck_free(fn);
            continue;

          }

          if (!st.st_size) {

            ck_free(fn);
            continue;

          }

          if ((u64)st.st_size >= UINT32_MAX) {

            WARNF("Skipping '%s', it is too large", fn);
            ck_free(fn);
            continue;

          }

          if (st.st_size > MAX_FILE) {

            WARNF("Input file '%s' is too large, only using %ld bytes", fn,
                  MAX_FILE);

          }

          ck_free(fn);

          cmin_file_t *f = ck_alloc(sizeof(cmin_file_t));
          f->dir = dir;  // Shared string
          f->name = strdup(entry->d_name);
          f->size = st.st_size;

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

  if (fa->size != fb->size) return fa->size < fb->size ? -1 : 1;
  int d = strcmp(fa->dir, fb->dir);
  if (d) return d;
  return strcmp(fa->name, fb->name);

}

static void add_input_dir(u8 *pattern) {

  glob_t g;
  int    ret = glob((char *)pattern, GLOB_NOCHECK | GLOB_TILDE, NULL, &g);
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

    in_dir[in_dir_cnt++] = strdup((char *)pattern);

  }

}

int main(int argc, char **argv) {

  progname = argv[0];
  SR(getpid() ^ (u32)time(NULL));

  u8 *cname = (u8 *)strrchr(argv[0], '/');
  cname = cname ? cname + 1 : (u8 *)argv[0];
  if (!strcmp((char *)cname, "afl-merge")) merge_mode = 1;

  s32 opt;
  int option_index = 0;
  if (getenv("AFL_SHA1_FILENAMES")) { sha1fn = 1; }

  static struct option long_options[] = {{"crash-dir", required_argument, 0, 0},
                                         {"as_queue", no_argument, 0, 0},
                                         {"no-dedup", no_argument, 0, 0},
                                         {"debug", no_argument, 0, 0},
                                         {0, 0, 0, 0}};

  SAYF(cCYA "%s" VERSION cRST "\n", merge_mode ? "afl-merge" : "afl-cmin");

  cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

#ifdef __linux__
  cpu_set_t cpu_mask;

  if (!sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask)) {

    int cpu_allowed = CPU_COUNT(&cpu_mask);
    if (cpu_allowed > 0) { cpu_count = (u32)cpu_allowed; }

  }

#endif

  s32 sep = argc;

  if (merge_mode) {

    for (s32 i = 1; i < argc; i++) {

      if (!strcmp(argv[i], "--")) {

        sep = i;
        break;

      }

    }

    if (sep == argc) {

      /* No -- at all: an explicit help request still succeeds, anything else
         is a usage error. */
      for (s32 i = 1; i < argc; i++) {

        if (argv[i][0] == '-' && argv[i][1] == 'h') usage(argv[0], 0);
        if (!strcmp(argv[i], "--help")) usage(argv[0], 0);

      }

      SAYF("\n%s: no target binary given, use -- /path/to/target\n", argv[0]);
      usage(argv[0], 1);

    }

    argv[sep] = NULL;

  }

  while ((opt = getopt_long(
              merge_mode ? sep : argc, argv,
              merge_mode ? "i:o:f:m:t:T:OQUWXACeh" : "+i:o:f:m:t:T:OQUWXACeh",
              long_options, &option_index)) != -1) {

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

      case 'i':
        add_input_dir((u8 *)optarg);
        break;

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

          u8     suffix = 'M';
          size_t len = strlen(optarg);
          u8    *digits = (u8 *)strdup(optarg);

          if (len && !isdigit((int)optarg[len - 1])) {

            suffix = optarg[len - 1];
            digits[len - 1] = 0;

          }

          u64 val = parse_u64_strict((char *)digits, "-m", 1, UINT32_MAX);
          ck_free(digits);

          switch (suffix) {

            case 'T':
              val *= 1024 * 1024;
              break;
            case 'G':
              val *= 1024;
              break;
            case 'k':
              val /= 1024;
              break;
            case 'M':
              break;
            default:
              FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (val > UINT32_MAX) FATAL("Value of -m is too large");
          if (val < 5) FATAL("Dangerously low value of -m");

          mem_limit = (u32)val;

        }

        break;

      case 't':
        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;
        if (!strcmp(optarg, "none")) {

          /* The forkserver has no way to run without a timeout, so use a very
             long one instead - same as afl-showmap does. */
          WARNF(
              "Setting an execution timeout of 120 seconds ('none' is not "
              "allowed).");
          time_limit = 120 * 1000;

        } else {

          time_limit = (u32)parse_u64_strict(optarg, "-t", 10, INT32_MAX);

        }

        break;

      case 'T':
        if (!strcmp(optarg, "all")) {

          u32 max_each = (MAX_WORKERS - 1) / 2;
          exec_workers = cpu_count > max_each ? max_each : cpu_count;
          update_workers = exec_workers;

        } else {

          u8 *colon = strchr(optarg, ':');
          if (colon) {

            *colon = 0;
            exec_workers =
                (u32)parse_u64_strict(optarg, "-T", 1, MAX_WORKERS - 1);
            update_workers =
                (u32)parse_u64_strict(colon + 1, "-T", 1, MAX_WORKERS - 1);

          } else {

            exec_workers =
                (u32)parse_u64_strict(optarg, "-T", 1, (MAX_WORKERS - 1) / 2);
            update_workers = exec_workers;

          }

        }

        if (exec_workers < 1 || update_workers < 1)
          FATAL("Number of workers must be at least 1");
        if ((u64)exec_workers + update_workers > MAX_WORKERS)
          FATAL("Total number of workers exceeds %d", MAX_WORKERS);
        break;

      case 'O':
        frida_mode = 1;
        setenv("AFL_FRIDA_INST_SEED", "1", 1);
        break;

      case 'W':
        wine_mode = 1;
        qemu_mode = 1;
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
        usage(argv[0], 0);
        break;

      default:
        usage(argv[0], 1);

    }

  }

  s32 tgt_idx;

  if (merge_mode) {

    s32 first_pos = optind;

    if (!out_dir) {

      if (in_dir_cnt)
        FATAL(
            "In merge mode without -o do not use -i; pass the output corpus as "
            "the first directory");
      if (first_pos >= sep) FATAL("No output directory specified");
      out_dir = argv[first_pos];
      first_pos++;

    }

    for (s32 i = first_pos; i < sep; i++)
      add_input_dir((u8 *)argv[i]);

    if (!in_dir_cnt) FATAL("No input directories specified");
    if (sep + 1 >= argc) FATAL("No target binary specified after --");
    tgt_idx = sep + 1;

  } else {

    if (optind == argc || !out_dir || !in_dir_cnt) usage(argv[0], 1);
    tgt_idx = optind;

  }

  target_bin = argv[tgt_idx];
  target_args = (u8 **)(argv + tgt_idx);
  if (qemu_mode) {

    if (wine_mode) {

      target_args = (u8 **)get_wine_argv(argv[0], &target_bin, argc - tgt_idx,
                                         argv + tgt_idx);

    } else {

      target_args = (u8 **)get_qemu_argv(argv[0], &target_bin, argc - tgt_idx,
                                         argv + tgt_idx);

    }

  }

  if (crash_dir && crashes_only)
    FATAL("-C and --crash-dir are mutually exclusive");

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

    if (!merge_mode) {

      DIR *d = opendir(out_dir);
      if (!d) FATAL("Unable to open output directory '%s'", out_dir);

      struct dirent *de;
      while ((de = readdir(d))) {

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        FATAL("Output directory '%s' is not empty", out_dir);

      }

      closedir(d);

    }

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

    if (pthread_create(&threads[i], NULL, collect_worker, NULL))
      PFATAL("pthread_create failed");

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

  if (!items) FATAL("No usable input files left");

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

