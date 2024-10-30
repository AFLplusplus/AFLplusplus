/*
   american fuzzy lop++ - instrumentation bootstrap
   ------------------------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0


*/

#ifdef __AFL_CODE_COVERAGE
  #ifndef _GNU_SOURCE
    #define _GNU_SOURCE
  #endif
  #ifndef __USE_GNU
    #define __USE_GNU
  #endif
  #include <dlfcn.h>

__attribute__((weak)) void __sanitizer_symbolize_pc(void *, const char *fmt,
                                                    char  *out_buf,
                                                    size_t out_buf_size);
#endif

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "cmplog.h"
#include "llvm-alternative-coverage.h"

#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>

#include <sys/mman.h>
#if !defined(__HAIKU__) && !defined(__OpenBSD__)
  #include <sys/syscall.h>
#endif
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>

#if !__GNUC__
  #include "llvm/Config/llvm-config.h"
#endif

#ifdef __linux__
  #include "snapshot-inl.h"
#endif

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifndef MAP_FIXED_NOREPLACE
  #ifdef MAP_EXCL
    #define MAP_FIXED_NOREPLACE MAP_EXCL | MAP_FIXED
  #else
    #define MAP_FIXED_NOREPLACE MAP_FIXED
  #endif
#endif

#define CTOR_PRIO 3
#define EARLY_FS_PRIO 5

#include <sys/mman.h>
#include <fcntl.h>

#ifdef AFL_PERSISTENT_RECORD
  #include "afl-persistent-replay.h"
#endif

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to
   run. It will end up as .comm, so it shouldn't be too wasteful. */

#if defined(__HAIKU__)
extern ssize_t _kern_write(int fd, off_t pos, const void *buffer,
                           size_t bufferSize);
#endif  // HAIKU

char *strcasestr(const char *haystack, const char *needle);

static u8  __afl_area_initial[MAP_INITIAL_SIZE];
static u8 *__afl_area_ptr_dummy = __afl_area_initial;
static u8 *__afl_area_ptr_backup = __afl_area_initial;

u8        *__afl_area_ptr = __afl_area_initial;
u8        *__afl_dictionary;
u8        *__afl_fuzz_ptr;
static u32 __afl_fuzz_len_dummy;
u32       *__afl_fuzz_len = &__afl_fuzz_len_dummy;
int        __afl_sharedmem_fuzzing __attribute__((weak));

u32 __afl_final_loc;
u32 __afl_map_size = MAP_SIZE;
u32 __afl_dictionary_len;
u64 __afl_map_addr;
u32 __afl_first_final_loc;
u32 __afl_old_forkserver;

#ifdef __AFL_CODE_COVERAGE
typedef struct afl_module_info_t afl_module_info_t;

struct afl_module_info_t {

  // A unique id starting with 0
  u32 id;

  // Name and base address of the module
  char     *name;
  uintptr_t base_address;

  // PC Guard start/stop
  u32 *start;
  u32 *stop;

  // PC Table begin/end
  const uintptr_t *pcs_beg;
  const uintptr_t *pcs_end;

  u8 mapped;

  afl_module_info_t *next;

};

typedef struct {

  uintptr_t PC, PCFlags;

} PCTableEntry;

afl_module_info_t *__afl_module_info = NULL;

u32        __afl_pcmap_size = 0;
uintptr_t *__afl_pcmap_ptr = NULL;

typedef struct {

  uintptr_t start;
  u32       len;

} FilterPCEntry;

u32            __afl_filter_pcs_size = 0;
FilterPCEntry *__afl_filter_pcs = NULL;
u8            *__afl_filter_pcs_module = NULL;

#endif  // __AFL_CODE_COVERAGE

/* 1 if we are running in afl, and the forkserver was started, else 0 */
u32 __afl_connected = 0;

// for the __AFL_COVERAGE_ON/__AFL_COVERAGE_OFF features to work:
int        __afl_selective_coverage __attribute__((weak));
int        __afl_selective_coverage_start_off __attribute__((weak));
static int __afl_selective_coverage_temp = 1;

#if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
PREV_LOC_T __afl_prev_caller[CTX_MAX_K];
u32        __afl_prev_ctx;
#else
__thread PREV_LOC_T __afl_prev_loc[NGRAM_SIZE_MAX];
__thread PREV_LOC_T __afl_prev_caller[CTX_MAX_K];
__thread u32        __afl_prev_ctx;
#endif

struct cmp_map *__afl_cmp_map;
struct cmp_map *__afl_cmp_map_backup;

static u8 __afl_cmplog_max_len = 32;  // 16-32

/* Child pid? */

static s32 child_pid;
static void (*old_sigterm_handler)(int) = 0;

/* Running in persistent mode? */

static u8 is_persistent;

/* Are we in sancov mode? */

static u8 _is_sancov;

/* Debug? */

/*static*/ u32 __afl_debug;

/* Already initialized markers */

u32 __afl_already_initialized_shm;
u32 __afl_already_initialized_forkserver;
u32 __afl_already_initialized_first;
u32 __afl_already_initialized_second;
u32 __afl_already_initialized_early;
u32 __afl_already_initialized_init;

/* Dummy pipe for area_is_valid() */

static int __afl_dummy_fd[2] = {2, 2};

/* ensure we kill the child on termination */

static void at_exit(int signal) {

  if (unlikely(child_pid > 0)) {

    kill(child_pid, SIGKILL);
    waitpid(child_pid, NULL, 0);
    child_pid = -1;

  }

  _exit(0);

}

#define default_hash(a, b) XXH3_64bits(a, b)

/* Uninspired gcc plugin instrumentation */

void __afl_trace(const u32 x) {

  PREV_LOC_T prev = __afl_prev_loc[0];
  __afl_prev_loc[0] = (x >> 1);

  u8 *p = &__afl_area_ptr[prev ^ x];

#if 1                                      /* enable for neverZero feature. */
  #if __GNUC__
  u8 c = __builtin_add_overflow(*p, 1, p);
  *p += c;
  #else
  *p += 1 + ((u8)(1 + *p) == 0);
  #endif
#else
  ++*p;
#endif

  return;

}

/* Error reporting to forkserver controller */

static void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_NEW_ERROR | error);
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) { return; }

}

/* SHM fuzzing setup. */

static void __afl_map_shm_fuzz() {

  char *id_str = getenv(SHM_FUZZ_ENV_VAR);

  if (__afl_debug) {

    fprintf(stderr, "DEBUG: fuzzcase shmem %s\n", id_str ? id_str : "none");

  }

  if (id_str) {

    u8 *map = NULL;

#ifdef USEMMAP
    const char *shm_file_path = id_str;
    int         shm_fd = -1;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed for fuzz\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    map =
        (u8 *)mmap(0, MAX_FILE + sizeof(u32), PROT_READ, MAP_SHARED, shm_fd, 0);

#else
    u32 shm_id = atoi(id_str);
    map = (u8 *)shmat(shm_id, NULL, 0);

#endif

    /* Whooooops. */

    if (!map || map == (void *)-1) {

      perror("Could not access fuzzing shared memory");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    __afl_fuzz_len = (u32 *)map;
    __afl_fuzz_ptr = map + sizeof(u32);

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: successfully got fuzzing shared memory\n");

    }

  } else {

    fprintf(stderr, "Error: variable for fuzzing shared memory is not set\n");
    send_forkserver_error(FS_ERROR_SHM_OPEN);
    exit(1);

  }

}

/* SHM setup. */

static void __afl_map_shm(void) {

  if (__afl_already_initialized_shm) return;
  __afl_already_initialized_shm = 1;

  // if we are not running in afl ensure the map exists
  if (!__afl_area_ptr) { __afl_area_ptr = __afl_area_ptr_dummy; }

  char *id_str = getenv(SHM_ENV_VAR);

  if (__afl_final_loc) {

    __afl_map_size = ++__afl_final_loc;  // as we count starting 0

    if (getenv("AFL_DUMP_MAP_SIZE")) {

      printf("%u\n", __afl_map_size);
      exit(-1);

    }

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: AFL_MAP_SIZE=%u\n", __afl_map_size);

    }

    if (__afl_final_loc > MAP_SIZE) {

      char *ptr;
      u32   val = 0;
      if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) { val = atoi(ptr); }
      if (val < __afl_final_loc) {

        if (__afl_final_loc > MAP_INITIAL_SIZE && !getenv("AFL_QUIET")) {

          fprintf(stderr,
                  "Warning: AFL++ tools might need to set AFL_MAP_SIZE to %u "
                  "to be able to run this instrumented program if this "
                  "crashes!\n",
                  __afl_final_loc);

        }

      }

    }

  }

  if (__afl_sharedmem_fuzzing && (!id_str || !getenv(SHM_FUZZ_ENV_VAR) ||
                                  fcntl(FORKSRV_FD, F_GETFD) == -1 ||
                                  fcntl(FORKSRV_FD + 1, F_GETFD) == -1)) {

    if (__afl_debug) {

      fprintf(stderr,
              "DEBUG: running not inside afl-fuzz, disabling shared memory "
              "testcases\n");

    }

    __afl_sharedmem_fuzzing = 0;

  }

  if (!id_str) {

    u32 val = 0;
    u8 *ptr;

    if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) { val = atoi(ptr); }

    if (val > MAP_INITIAL_SIZE && val > __afl_final_loc) {

      __afl_map_size = val;

    } else {

      if (__afl_first_final_loc > MAP_INITIAL_SIZE) {

        // done in second stage constructor
        __afl_map_size = __afl_first_final_loc;

      } else {

        __afl_map_size = MAP_INITIAL_SIZE;

      }

    }

    if (__afl_map_size > MAP_INITIAL_SIZE && __afl_final_loc < __afl_map_size) {

      __afl_final_loc = __afl_map_size;

    }

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: (0) init map size is %u to %p\n", __afl_map_size,
              __afl_area_ptr_dummy);

    }

  }

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (__afl_debug) {

    fprintf(stderr,
            "DEBUG: (1) id_str %s, __afl_area_ptr %p, __afl_area_initial %p, "
            "__afl_area_ptr_dummy %p, __afl_map_addr 0x%llx, MAP_SIZE %u, "
            "__afl_final_loc %u, __afl_map_size %u\n",
            id_str == NULL ? "<null>" : id_str, __afl_area_ptr,
            __afl_area_initial, __afl_area_ptr_dummy, __afl_map_addr, MAP_SIZE,
            __afl_final_loc, __afl_map_size);

  }

  if (id_str) {

    if (__afl_area_ptr && __afl_area_ptr != __afl_area_initial &&
        __afl_area_ptr != __afl_area_ptr_dummy) {

      if (__afl_map_addr) {

        munmap((void *)__afl_map_addr, __afl_final_loc);

      } else {

        free(__afl_area_ptr);

      }

      __afl_area_ptr = __afl_area_ptr_dummy;

    }

#ifdef USEMMAP
    const char    *shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    if (__afl_map_addr) {

      shm_base =
          mmap((void *)__afl_map_addr, __afl_map_size, PROT_READ | PROT_WRITE,
               MAP_FIXED_NOREPLACE | MAP_SHARED, shm_fd, 0);

    } else {

      shm_base = mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                      shm_fd, 0);

    }

    close(shm_fd);
    shm_fd = -1;

    if (shm_base == MAP_FAILED) {

      fprintf(stderr, "mmap() failed\n");
      perror("mmap for map");

      if (__afl_map_addr)
        send_forkserver_error(FS_ERROR_MAP_ADDR);
      else
        send_forkserver_error(FS_ERROR_MMAP);

      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    if (__afl_map_size && __afl_map_size > MAP_SIZE) {

      u8 *map_env = (u8 *)getenv("AFL_MAP_SIZE");
      if (!map_env || atoi((char *)map_env) < MAP_SIZE) {

        fprintf(stderr, "FS_ERROR_MAP_SIZE\n");
        send_forkserver_error(FS_ERROR_MAP_SIZE);
        _exit(1);

      }

    }

    __afl_area_ptr = (u8 *)shmat(shm_id, (void *)__afl_map_addr, 0);

    /* Whooooops. */

    if (!__afl_area_ptr || __afl_area_ptr == (void *)-1) {

      if (__afl_map_addr)
        send_forkserver_error(FS_ERROR_MAP_ADDR);
      else
        send_forkserver_error(FS_ERROR_SHMAT);

      perror("shmat for map");
      _exit(1);

    }

#endif

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  } else if ((!__afl_area_ptr || __afl_area_ptr == __afl_area_initial) &&

             __afl_map_addr) {

    __afl_area_ptr = (u8 *)mmap(
        (void *)__afl_map_addr, __afl_map_size, PROT_READ | PROT_WRITE,
        MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (__afl_area_ptr == MAP_FAILED) {

      fprintf(stderr, "can not acquire mmap for address %p\n",
              (void *)__afl_map_addr);
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

  } else if (__afl_final_loc > MAP_INITIAL_SIZE &&

             __afl_final_loc > __afl_first_final_loc) {

    if (__afl_area_initial != __afl_area_ptr_dummy) {

      free(__afl_area_ptr_dummy);

    }

    __afl_area_ptr_dummy = (u8 *)malloc(__afl_final_loc);
    __afl_area_ptr = __afl_area_ptr_dummy;
    __afl_map_size = __afl_final_loc;

    if (!__afl_area_ptr_dummy) {

      fprintf(stderr,
              "Error: AFL++ could not acquire %u bytes of memory, exiting!\n",
              __afl_final_loc);
      exit(-1);

    }

  }  // else: nothing to be done

  __afl_area_ptr_backup = __afl_area_ptr;

  if (__afl_debug) {

    fprintf(stderr,
            "DEBUG: (2) id_str %s, __afl_area_ptr %p, __afl_area_initial %p, "
            "__afl_area_ptr_dummy %p, __afl_map_addr 0x%llx, MAP_SIZE "
            "%u, __afl_final_loc %u, __afl_map_size %u\n",
            id_str == NULL ? "<null>" : id_str, __afl_area_ptr,
            __afl_area_initial, __afl_area_ptr_dummy, __afl_map_addr, MAP_SIZE,
            __afl_final_loc, __afl_map_size);

  }

  if (__afl_selective_coverage) {

    if (__afl_map_size > MAP_INITIAL_SIZE) {

      __afl_area_ptr_dummy = (u8 *)malloc(__afl_map_size);

    }

    if (__afl_area_ptr_dummy) {

      if (__afl_selective_coverage_start_off) {

        __afl_area_ptr = __afl_area_ptr_dummy;

      }

    } else {

      fprintf(stderr, "Error: __afl_selective_coverage failed!\n");
      __afl_selective_coverage = 0;
      // continue;

    }

  }

  id_str = getenv(CMPLOG_SHM_ENV_VAR);

  if (__afl_debug) {

    fprintf(stderr, "DEBUG: cmplog id_str %s\n",
            id_str == NULL ? "<null>" : id_str);

  }

  if (id_str) {

    // /dev/null doesn't work so we use /dev/urandom
    if ((__afl_dummy_fd[1] = open("/dev/urandom", O_WRONLY)) < 0) {

      if (pipe(__afl_dummy_fd) < 0) { __afl_dummy_fd[1] = 1; }

    }

#ifdef USEMMAP
    const char     *shm_file_path = id_str;
    int             shm_fd = -1;
    struct cmp_map *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
    if (shm_fd == -1) {

      perror("shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    shm_base = mmap(0, sizeof(struct cmp_map), PROT_READ | PROT_WRITE,
                    MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(2);

    }

    __afl_cmp_map = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_cmp_map = (struct cmp_map *)shmat(shm_id, NULL, 0);
#endif

    __afl_cmp_map_backup = __afl_cmp_map;

    if (!__afl_cmp_map || __afl_cmp_map == (void *)-1) {

      perror("shmat for cmplog");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      _exit(1);

    }

  }

#ifdef __AFL_CODE_COVERAGE
  char *pcmap_id_str = getenv("__AFL_PCMAP_SHM_ID");

  if (pcmap_id_str) {

    __afl_pcmap_size = __afl_map_size * sizeof(void *);
    u32 shm_id = atoi(pcmap_id_str);

    __afl_pcmap_ptr = (uintptr_t *)shmat(shm_id, NULL, 0);

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: Received %p via shmat for pcmap\n",
              __afl_pcmap_ptr);

    }

  }

#endif  // __AFL_CODE_COVERAGE

  if (!__afl_cmp_map && getenv("AFL_CMPLOG_DEBUG")) {

    __afl_cmp_map_backup = __afl_cmp_map = malloc(sizeof(struct cmp_map));

  }

  if (getenv("AFL_CMPLOG_MAX_LEN")) {

    int tmp = atoi(getenv("AFL_CMPLOG_MAX_LEN"));
    if (tmp >= 16 && tmp <= 32) { __afl_cmplog_max_len = tmp; }

  }

}

/* unmap SHM. */

static void __afl_unmap_shm(void) {

  if (!__afl_already_initialized_shm) return;

#ifdef __AFL_CODE_COVERAGE
  if (__afl_pcmap_size) {

    shmdt((void *)__afl_pcmap_ptr);
    __afl_pcmap_ptr = NULL;
    __afl_pcmap_size = 0;

  }

#endif  // __AFL_CODE_COVERAGE

  char *id_str = getenv(SHM_ENV_VAR);

  if (id_str) {

#ifdef USEMMAP

    munmap((void *)__afl_area_ptr, __afl_map_size);

#else

    shmdt((void *)__afl_area_ptr);

#endif

  } else if ((!__afl_area_ptr || __afl_area_ptr == __afl_area_initial) &&

             __afl_map_addr) {

    munmap((void *)__afl_map_addr, __afl_map_size);

  }

  __afl_area_ptr = __afl_area_ptr_dummy;

  id_str = getenv(CMPLOG_SHM_ENV_VAR);

  if (id_str) {

#ifdef USEMMAP

    munmap((void *)__afl_cmp_map, __afl_map_size);

#else

    shmdt((void *)__afl_cmp_map);

#endif

    __afl_cmp_map = NULL;
    __afl_cmp_map_backup = NULL;

  }

  __afl_already_initialized_shm = 0;

}

#define write_error(text) write_error_with_location(text, __FILE__, __LINE__)

void write_error_with_location(char *text, char *filename, int linenumber) {

  u8   *o = getenv("__AFL_OUT_DIR");
  char *e = strerror(errno);

  if (o) {

    char buf[4096];
    snprintf(buf, sizeof(buf), "%s/error.txt", o);
    FILE *f = fopen(buf, "a");

    if (f) {

      fprintf(f, "File %s, line %d: Error(%s): %s\n", filename, linenumber,
              text, e);
      fclose(f);

    }

  }

  fprintf(stderr, "File %s, line %d: Error(%s): %s\n", filename, linenumber,
          text, e);

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  if (__afl_already_initialized_forkserver) return;
  __afl_already_initialized_forkserver = 1;

  struct sigaction orig_action;
  sigaction(SIGTERM, NULL, &orig_action);
  old_sigterm_handler = orig_action.sa_handler;
  signal(SIGTERM, at_exit);

  u32 already_read_first = 0;
  u32 was_killed = 0;
  u32 version = 0x41464c00 + FS_NEW_VERSION_MAX;
  u32 tmp = version ^ 0xffffffff, status2, status = version;
  u8 *msg = (u8 *)&status;
  u8 *reply = (u8 *)&status2;

  u8 child_stopped = 0;

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  if (getenv("AFL_OLD_FORKSERVER")) {

    __afl_old_forkserver = 1;
    status = 0;

    if (__afl_final_loc > MAP_SIZE) {

      fprintf(stderr,
              "Warning: AFL_OLD_FORKSERVER is used with a target compiled with "
              "non-colliding coverage instead of AFL_LLVM_INSTRUMENT=CLASSIC - "
              "this target may crash!\n");

    }

  }

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (!__afl_old_forkserver) {

    // return because possible non-forkserver usage
    if (write(FORKSRV_FD + 1, msg, 4) != 4) { return; }

    if (read(FORKSRV_FD, reply, 4) != 4) { _exit(1); }
    if (tmp != status2) {

      write_error("wrong forkserver message from AFL++ tool");
      _exit(1);

    }

    // send the set/requested options to forkserver
    status = FS_NEW_OPT_MAPSIZE;  // we always send the map size
    if (__afl_sharedmem_fuzzing) { status |= FS_NEW_OPT_SHDMEM_FUZZ; }
    if (__afl_dictionary_len && __afl_dictionary) {

      status |= FS_NEW_OPT_AUTODICT;

    }

    if (write(FORKSRV_FD + 1, msg, 4) != 4) { _exit(1); }

    // Now send the parameters for the set options, increasing by option number

    // FS_NEW_OPT_MAPSIZE - we always send the map size
    status = __afl_map_size;
    if (write(FORKSRV_FD + 1, msg, 4) != 4) { _exit(1); }

    // FS_NEW_OPT_SHDMEM_FUZZ - no data

    // FS_NEW_OPT_AUTODICT - send autodictionary
    if (__afl_dictionary_len && __afl_dictionary) {

      // pass the dictionary through the forkserver FD
      u32 len = __afl_dictionary_len, offset = 0;

      if (write(FORKSRV_FD + 1, &len, 4) != 4) {

        write(2, "Error: could not send dictionary len\n",
              strlen("Error: could not send dictionary len\n"));
        _exit(1);

      }

      while (len != 0) {

        s32 ret;
        ret = write(FORKSRV_FD + 1, __afl_dictionary + offset, len);

        if (ret < 1) {

          write_error("could not send dictionary");
          _exit(1);

        }

        len -= ret;
        offset += ret;

      }

    }

    // send welcome message as final message
    status = version;
    if (write(FORKSRV_FD + 1, msg, 4) != 4) { _exit(1); }

  }

  // END forkserver handshake

  __afl_connected = 1;

  if (__afl_sharedmem_fuzzing) { __afl_map_shm_fuzz(); }

  while (1) {

    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (unlikely(already_read_first)) {

      already_read_first = 0;

    } else {

      if (unlikely(read(FORKSRV_FD, &was_killed, 4) != 4)) {

        write_error("read from AFL++ tool");
        _exit(1);

      }

    }

#ifdef _AFL_DOCUMENT_MUTATIONS
    if (__afl_fuzz_ptr) {

      static uint32_t counter = 0;
      char            fn[32];
      sprintf(fn, "%09u:forkserver", counter);
      s32 fd_doc = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
      if (fd_doc >= 0) {

        if (write(fd_doc, __afl_fuzz_ptr, *__afl_fuzz_len) != *__afl_fuzz_len) {

          fprintf(stderr, "write of mutation file failed: %s\n", fn);
          unlink(fn);

        }

        close(fd_doc);

      }

      counter++;

    }

#endif

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (unlikely(child_stopped && was_killed)) {

      child_stopped = 0;
      if (unlikely(waitpid(child_pid, &status, 0) < 0)) {

        write_error("child_stopped && was_killed");
        _exit(1);

      }

    }

    if (unlikely(!child_stopped)) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (unlikely(child_pid < 0)) {

        write_error("fork");
        _exit(1);

      }

      /* In child process: close fds, resume execution. */

      if (unlikely(!child_pid)) {  // just to signal afl-fuzz faster

        //(void)nice(-20);

        signal(SIGCHLD, old_sigchld_handler);
        signal(SIGTERM, old_sigterm_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;

      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (unlikely(write(FORKSRV_FD + 1, &child_pid, 4) != 4)) {

      write_error("write to afl-fuzz");
      _exit(1);

    }

    if (unlikely(waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) <
                 0)) {

      write_error("waitpid");
      _exit(1);

    }

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (likely(WIFSTOPPED(status))) { child_stopped = 1; }

    /* Relay wait status to pipe, then loop back. */

    if (unlikely(write(FORKSRV_FD + 1, &status, 4) != 4)) {

      write_error("writing to afl-fuzz");
      _exit(1);

    }

  }

}

/* A simplified persistent mode handler, used as explained in
 * README.llvm.md. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

#ifdef AFL_PERSISTENT_RECORD
  char tcase[PATH_MAX];
#endif

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    memset(__afl_area_ptr, 0, __afl_map_size);
    __afl_area_ptr[0] = 1;
    memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));

    first_pass = 0;
    __afl_selective_coverage_temp = 1;

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(is_replay_record)) {

      cycle_cnt = replay_record_cnt;
      goto persistent_record;

    } else

#endif
    {

      cycle_cnt = max_cnt;

    }

    return 1;

  } else if (--cycle_cnt) {

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(is_replay_record)) {

    persistent_record:

      snprintf(tcase, PATH_MAX, "%s/%s",
               replay_record_dir ? replay_record_dir : "./",
               record_list[replay_record_cnt - cycle_cnt]->d_name);

  #ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
      if (unlikely(record_arg)) {

        *record_arg = tcase;

      } else

  #endif  // AFL_PERSISTENT_REPLAY_ARGPARSE
      {

        int fd = open(tcase, O_RDONLY);
        dup2(fd, 0);
        close(fd);

      }

      return 1;

    }

#endif

    raise(SIGSTOP);

    __afl_area_ptr[0] = 1;
    memset(__afl_prev_loc, 0, NGRAM_SIZE_MAX * sizeof(PREV_LOC_T));
    __afl_selective_coverage_temp = 1;

    return 1;

  } else {

    /* When exiting __AFL_LOOP(), make sure that the subsequent code that
        follows the loop is not traced. We do that by pivoting back to the
        dummy output region. */

    __afl_area_ptr = __afl_area_ptr_dummy;

    return 0;

  }

}

/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) {

    init_done = 1;
    is_persistent = 0;
    __afl_sharedmem_fuzzing = 0;
    if (__afl_area_ptr == NULL) __afl_area_ptr = __afl_area_ptr_dummy;

    if (__afl_debug) {

      fprintf(stderr,
              "DEBUG: disabled instrumentation because of "
              "AFL_DISABLE_LLVM_INSTRUMENTATION\n");

    }

  }

  if (!init_done) {

    __afl_start_forkserver();
    init_done = 1;

  }

}

/* Initialization of the forkserver - latest possible */

__attribute__((constructor())) void __afl_auto_init(void) {

  if (__afl_already_initialized_init) { return; }

#ifdef __ANDROID__
  // Disable handlers in linker/debuggerd, check include/debuggerd/handler.h
  signal(SIGABRT, SIG_DFL);
  signal(SIGBUS, SIG_DFL);
  signal(SIGFPE, SIG_DFL);
  signal(SIGILL, SIG_DFL);
  signal(SIGSEGV, SIG_DFL);
  signal(SIGSTKFLT, SIG_DFL);
  signal(SIGSYS, SIG_DFL);
  signal(SIGTRAP, SIG_DFL);
#endif

  __afl_already_initialized_init = 1;

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}

/* Optionally run an early forkserver */

__attribute__((constructor(EARLY_FS_PRIO))) void __early_forkserver(void) {

  if (getenv("AFL_EARLY_FORKSERVER")) { __afl_auto_init(); }

}

/* Initialization of the shmem - earliest possible because of LTO fixed mem. */

__attribute__((constructor(CTOR_PRIO))) void __afl_auto_early(void) {

  if (__afl_already_initialized_early) return;
  __afl_already_initialized_early = 1;

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

  __afl_map_shm();

}

/* preset __afl_area_ptr #2 */

__attribute__((constructor(1))) void __afl_auto_second(void) {

  if (__afl_already_initialized_second) return;
  __afl_already_initialized_second = 1;

  if (getenv("AFL_DEBUG")) {

    __afl_debug = 1;
    fprintf(stderr, "DEBUG: debug enabled\n");
    fprintf(stderr, "DEBUG: AFL++ afl-compiler-rt" VERSION "\n");

  }

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;
  u8 *ptr;

  if (__afl_final_loc > MAP_INITIAL_SIZE) {

    __afl_first_final_loc = __afl_final_loc + 1;

    if (__afl_area_ptr && __afl_area_ptr != __afl_area_initial)
      free(__afl_area_ptr);

    if (__afl_map_addr)
      ptr = (u8 *)mmap((void *)__afl_map_addr, __afl_first_final_loc,
                       PROT_READ | PROT_WRITE,
                       MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    else
      ptr = (u8 *)malloc(__afl_first_final_loc);

    if (ptr && (ssize_t)ptr != -1) {

      __afl_area_ptr = ptr;
      __afl_area_ptr_dummy = __afl_area_ptr;
      __afl_area_ptr_backup = __afl_area_ptr;

    }

  }

}  // ptr memleak report is a false positive

/* preset __afl_area_ptr #1 - at constructor level 0 global variables have
   not been set */

__attribute__((constructor(0))) void __afl_auto_first(void) {

  if (__afl_already_initialized_first) return;
  __afl_already_initialized_first = 1;

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

  /*
    u8 *ptr = (u8 *)malloc(MAP_INITIAL_SIZE);

    if (ptr && (ssize_t)ptr != -1) {

      __afl_area_ptr = ptr;
      __afl_area_ptr_backup = __afl_area_ptr;

    }

  */

}  // ptr memleak report is a false positive

/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.md.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {

  // For stability analysis, if you want to know to which function unstable
  // edge IDs belong - uncomment, recompile+install llvm_mode, recompile
  // the target. libunwind and libbacktrace are better solutions.
  // Set AFL_DEBUG_CHILD=1 and run afl-fuzz with 2>file to capture
  // the backtrace output
  /*
  uint32_t unstable[] = { ... unstable edge IDs };
  uint32_t idx;
  char bt[1024];
  for (idx = 0; i < sizeof(unstable)/sizeof(uint32_t); i++) {

    if (unstable[idx] == __afl_area_ptr[*guard]) {

      int bt_size = backtrace(bt, 256);
      if (bt_size > 0) {

        char **bt_syms = backtrace_symbols(bt, bt_size);
        if (bt_syms) {

          fprintf(stderr, "DEBUG: edge=%u caller=%s\n", unstable[idx],
  bt_syms[0]);
          free(bt_syms);

        }

      }

    }

  }

  */

#if (LLVM_VERSION_MAJOR < 9)

  __afl_area_ptr[*guard]++;

#else

  __afl_area_ptr[*guard] =
      __afl_area_ptr[*guard] + 1 + (__afl_area_ptr[*guard] == 255 ? 1 : 0);

#endif

}

#ifdef __AFL_CODE_COVERAGE
void afl_read_pc_filter_file(const char *filter_file) {

  FILE *file;
  char  ch;

  file = fopen(filter_file, "r");
  if (file == NULL) {

    perror("Error opening file");
    return;

  }

  // Check how many PCs we expect to read
  while ((ch = fgetc(file)) != EOF) {

    if (ch == '\n') { __afl_filter_pcs_size++; }

  }

  // Rewind to actually read the PCs
  fseek(file, 0, SEEK_SET);

  __afl_filter_pcs = malloc(__afl_filter_pcs_size * sizeof(FilterPCEntry));
  if (!__afl_filter_pcs) {

    perror("Error allocating PC array");
    return;

  }

  for (size_t i = 0; i < __afl_filter_pcs_size; i++) {

    fscanf(file, "%lx", &(__afl_filter_pcs[i].start));
    ch = fgetc(file);  // Read tab
    fscanf(file, "%u", &(__afl_filter_pcs[i].len));
    ch = fgetc(file);  // Read tab

    if (!__afl_filter_pcs_module) {

      // Read the module name and store it.
      // TODO: We only support one module here right now although
      // there is technically no reason to support multiple modules
      // in one go.
      size_t max_module_len = 255;
      size_t i = 0;
      __afl_filter_pcs_module = malloc(max_module_len);
      while (i < max_module_len - 1 &&
             (__afl_filter_pcs_module[i] = fgetc(file)) != '\t') {

        ++i;

      }

      __afl_filter_pcs_module[i] = '\0';
      fprintf(stderr, "DEBUGXXX: Read module name %s\n",
              __afl_filter_pcs_module);

    }

    while ((ch = fgetc(file)) != '\n' && ch != EOF)
      ;

  }

  fclose(file);

}

u32 locate_in_pcs(uintptr_t needle, u32 *index) {

  size_t lower_bound = 0;
  size_t upper_bound = __afl_filter_pcs_size - 1;

  while (lower_bound < __afl_filter_pcs_size && lower_bound <= upper_bound) {

    size_t current_index = lower_bound + (upper_bound - lower_bound) / 2;

    if (__afl_filter_pcs[current_index].start <= needle) {

      if (__afl_filter_pcs[current_index].start +
              __afl_filter_pcs[current_index].len >
          needle) {

        // Hit
        *index = current_index;
        return 1;

      } else {

        lower_bound = current_index + 1;

      }

    } else {

      if (!current_index) { break; }
      upper_bound = current_index - 1;

    }

  }

  return 0;

}

void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end) {

  // If for whatever reason, we cannot get dlinfo here, then pc_guard_init also
  // couldn't get it and we'd end up attributing to the wrong module.
  Dl_info dlinfo;
  if (!dladdr(__builtin_return_address(0), &dlinfo)) {

    fprintf(stderr,
            "WARNING: Ignoring __sanitizer_cov_pcs_init callback due to "
            "missing module info\n");
    return;

  }

  if (__afl_debug) {

    fprintf(
        stderr,
        "DEBUG: (%u) __sanitizer_cov_pcs_init called for module %s with %ld "
        "PCs\n",
        getpid(), dlinfo.dli_fname, pcs_end - pcs_beg);

  }

  afl_module_info_t *last_module_info = __afl_module_info;
  while (last_module_info && last_module_info->next) {

    last_module_info = last_module_info->next;

  }

  if (!last_module_info) {

    fprintf(stderr,
            "ERROR: __sanitizer_cov_pcs_init called with no module info?!\n");
    abort();

  }

  if (strcmp(dlinfo.dli_fname, last_module_info->name)) {

    // This can happen with modules being loaded after the forkserver
    // where we decide to not track the module. In that case we must
    // not track it here either.
    fprintf(
        stderr,
        "WARNING: __sanitizer_cov_pcs_init module info mismatch: %s vs %s\n",
        dlinfo.dli_fname, last_module_info->name);
    return;

  }

  last_module_info->pcs_beg = pcs_beg;
  last_module_info->pcs_end = pcs_end;

  // This is a direct filter based on symbolizing inside the runtime.
  // It should only be used with smaller binaries to avoid long startup
  // times. Currently, this only supports a single token to scan for.
  const char *pc_filter = getenv("AFL_PC_FILTER");

  // This is a much faster PC filter based on pre-symbolized input data
  // that is sorted for fast lookup through binary search. This method
  // of filtering is suitable even for very large binaries.
  const char *pc_filter_file = getenv("AFL_PC_FILTER_FILE");
  if (pc_filter_file && !__afl_filter_pcs) {

    afl_read_pc_filter_file(pc_filter_file);

  }

  // Now update the pcmap. If this is the last module coming in, after all
  // pre-loaded code, then this will also map all of our delayed previous
  // modules.
  //
  for (afl_module_info_t *mod_info = __afl_module_info; mod_info;
       mod_info = mod_info->next) {

    if (mod_info->mapped) { continue; }

    if (!mod_info->start) {

      fprintf(stderr,
              "ERROR: __sanitizer_cov_pcs_init called with mod_info->start == "
              "NULL (%s)\n",
              mod_info->name);
      abort();

    }

    PCTableEntry *start = (PCTableEntry *)(mod_info->pcs_beg);
    PCTableEntry *end = (PCTableEntry *)(mod_info->pcs_end);

    if (!*mod_info->stop) { continue; }

    u32 in_module_index = 0;

    while (start < end) {

      if (*mod_info->start + in_module_index >= __afl_map_size) {

        fprintf(stderr,
                "ERROR: __sanitizer_cov_pcs_init out of bounds?! Start: %u "
                "Stop: %u Map Size: %u (%s)\n",
                *mod_info->start, *mod_info->stop, __afl_map_size,
                mod_info->name);
        abort();

      }

      u32 orig_start_index = *mod_info->start;

      uintptr_t PC = start->PC;

      // This is what `GetPreviousInstructionPc` in sanitizer runtime does
      // for x86/x86-64. Needs more work for ARM and other archs.
      PC = PC - 1;

      // Calculate relative offset in module
      PC = PC - mod_info->base_address;

      if (__afl_pcmap_ptr) {

        __afl_pcmap_ptr[orig_start_index + in_module_index] = PC;

      }

      if (pc_filter && !mod_info->next) {

        char PcDescr[1024];
        // This function is a part of the sanitizer run-time.
        // To use it, link with AddressSanitizer or other sanitizer.
        __sanitizer_symbolize_pc((void *)start->PC, "%p %F %L", PcDescr,
                                 sizeof(PcDescr));

        if (strstr(PcDescr, pc_filter)) {

          if (__afl_debug)
            fprintf(
                stderr,
                "DEBUG: Selective instrumentation match: %s (PC %p Index %u)\n",
                PcDescr, (void *)start->PC,
                *(mod_info->start + in_module_index));
          // No change to guard needed

        } else {

          // Null out the guard to disable this edge
          *(mod_info->start + in_module_index) = 0;

        }

      }

      if (__afl_filter_pcs && !mod_info->next &&
          strstr(mod_info->name, __afl_filter_pcs_module)) {

        u32 result_index;
        if (locate_in_pcs(PC, &result_index)) {

          if (__afl_debug)
            fprintf(stderr,
                    "DEBUG: Selective instrumentation match: (PC %lx File "
                    "Index %u PC Index %u)\n",
                    PC, result_index, in_module_index);

        } else {

          // Null out the guard to disable this edge
          *(mod_info->start + in_module_index) = 0;

        }

      }

      start++;
      in_module_index++;

    }

    if (__afl_pcmap_ptr) { mod_info->mapped = 1; }

    if (__afl_debug) {

      fprintf(stderr,
              "DEBUG: __sanitizer_cov_pcs_init successfully mapped %s with %u "
              "PCs\n",
              mod_info->name, in_module_index);

    }

  }

}

#endif  // __AFL_CODE_COVERAGE

/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {

  u32   inst_ratio = 100;
  char *x;

  _is_sancov = 1;

  if (!getenv("AFL_DUMP_MAP_SIZE")) {

    __afl_auto_first();
    __afl_auto_second();
    __afl_auto_early();

  }

  if (__afl_debug) {

    fprintf(
        stderr,
        "DEBUG: Running __sanitizer_cov_trace_pc_guard_init: %p-%p (%lu edges) "
        "after_fs=%u *start=%u\n",
        start, stop, (unsigned long)(stop - start),
        __afl_already_initialized_forkserver, *start);

  }

  if (start == stop || *start) { return; }

#ifdef __AFL_CODE_COVERAGE
  u32               *orig_start = start;
  afl_module_info_t *mod_info = NULL;

  Dl_info dlinfo;
  if (dladdr(__builtin_return_address(0), &dlinfo)) {

    if (__afl_already_initialized_forkserver) {

      fprintf(stderr, "[pcmap] Error: Module was not preloaded: %s\n",
              dlinfo.dli_fname);

    } else {

      afl_module_info_t *last_module_info = __afl_module_info;
      while (last_module_info && last_module_info->next) {

        last_module_info = last_module_info->next;

      }

      mod_info = malloc(sizeof(afl_module_info_t));

      mod_info->id = last_module_info ? last_module_info->id + 1 : 0;
      mod_info->name = strdup(dlinfo.dli_fname);
      mod_info->base_address = (uintptr_t)dlinfo.dli_fbase;
      mod_info->start = NULL;
      mod_info->stop = NULL;
      mod_info->pcs_beg = NULL;
      mod_info->pcs_end = NULL;
      mod_info->mapped = 0;
      mod_info->next = NULL;

      if (last_module_info) {

        last_module_info->next = mod_info;

      } else {

        __afl_module_info = mod_info;

      }

      if (__afl_debug) {

        fprintf(stderr, "[pcmap] Module: %s Base Address: %p\n",
                dlinfo.dli_fname, dlinfo.dli_fbase);

      }

    }

  } else {

    fprintf(stderr, "[pcmap] dladdr call failed\n");

  }

#endif  // __AFL_CODE_COVERAGE

  x = getenv("AFL_INST_RATIO");
  if (x) {

    inst_ratio = (u32)atoi(x);

    if (!inst_ratio || inst_ratio > 100) {

      fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
      abort();

    }

  }

  // If a dlopen of an instrumented library happens after the forkserver then
  // we have a problem as we cannot increase the coverage map anymore.
  if (__afl_already_initialized_forkserver) {

    if (!getenv("AFL_IGNORE_PROBLEMS")) {

      fprintf(
          stderr,
          "[-] FATAL: forkserver is already up, but an instrumented dlopen() "
          "library loaded afterwards. You must AFL_PRELOAD such libraries to "
          "be able to fuzz them or LD_PRELOAD to run outside of afl-fuzz.\n"
          "To ignore this set AFL_IGNORE_PROBLEMS=1 but this will lead to "
          "ambiguous coverage data.\n"
          "In addition, you can set AFL_IGNORE_PROBLEMS_COVERAGE=1 to "
          "ignore the additional coverage instead (use with caution!).\n");
      abort();

    } else {

      u8 ignore_dso_after_fs = !!getenv("AFL_IGNORE_PROBLEMS_COVERAGE");
      if (__afl_debug && ignore_dso_after_fs) {

        fprintf(stderr,
                "DEBUG: Ignoring coverage from dynamically loaded code\n");

      }

      static u32 offset = 5;

      while (start < stop) {

        if (!ignore_dso_after_fs &&
            (likely(inst_ratio == 100) || R(100) < inst_ratio)) {

          *(start++) = offset;

        } else {

          *(start++) = 0;  // write to map[0]

        }

        if (unlikely(++offset >= __afl_final_loc)) { offset = 5; }

      }

    }

    return;  // we are done for this special case

  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  if (__afl_final_loc < 4) __afl_final_loc = 4;  // we skip the first 5 entries

  *(start++) = ++__afl_final_loc;

  while (start < stop) {

    if (likely(inst_ratio == 100) || R(100) < inst_ratio) {

      *(start++) = ++__afl_final_loc;

    } else {

      *(start++) = 0;  // write to map[0]

    }

  }

#ifdef __AFL_CODE_COVERAGE
  if (mod_info) {

    if (!mod_info->start) {

      mod_info->start = orig_start;
      mod_info->stop = stop - 1;

    }

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: [pcmap] Start Index: %u Stop Index: %u\n",
              *(mod_info->start), *(mod_info->stop));

    }

  }

#endif  // __AFL_CODE_COVERAGE

  if (__afl_debug) {

    fprintf(stderr,
            "DEBUG: Done __sanitizer_cov_trace_pc_guard_init: __afl_final_loc "
            "= %u\n",
            __afl_final_loc);

  }

  if (__afl_already_initialized_shm) {

    if (__afl_final_loc > __afl_map_size) {

      if (__afl_debug) {

        fprintf(stderr, "DEBUG: Reinit shm necessary (+%u)\n",
                __afl_final_loc - __afl_map_size);

      }

      __afl_unmap_shm();
      __afl_map_shm();

    }

    __afl_map_size = __afl_final_loc + 1;

  }

}

///// CmpLog instrumentation

void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook1 arg0=%02x arg1=%02x attr=%u\n",
  //         (u8) arg1, (u8) arg2, attr);

  return;

  /*

  if (unlikely(!__afl_cmp_map || arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

  */

}

void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr) {

  if (likely(!__afl_cmp_map)) return;
  if (unlikely(arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 1;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (!__afl_cmp_map->headers[k].shape) {

      __afl_cmp_map->headers[k].shape = 1;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook4 arg0=%x arg1=%x attr=%u\n", arg1, arg2, attr);

  if (likely(!__afl_cmp_map)) return;
  if (unlikely(arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 3;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 3) {

      __afl_cmp_map->headers[k].shape = 3;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr) {

  // fprintf(stderr, "hook8 arg0=%lx arg1=%lx attr=%u\n", arg1, arg2, attr);

  if (likely(!__afl_cmp_map)) return;
  if (unlikely(arg1 == arg2)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 7;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 7) {

      __afl_cmp_map->headers[k].shape = 7;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

#ifdef WORD_SIZE_64
// support for u24 to u120 via llvm _ExitInt(). size is in bytes minus 1
void __cmplog_ins_hookN(uint128_t arg1, uint128_t arg2, uint8_t attr,
                        uint8_t size) {

  // fprintf(stderr, "hookN arg0=%llx:%llx arg1=%llx:%llx bytes=%u attr=%u\n",
  // (u64)(arg1 >> 64), (u64)arg1, (u64)(arg2 >> 64), (u64)arg2, size + 1,
  // attr);

  if (likely(!__afl_cmp_map)) return;
  if (unlikely(arg1 == arg2 || size > __afl_cmplog_max_len)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = size;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < size) {

      __afl_cmp_map->headers[k].shape = size;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = (u64)arg1;
  __afl_cmp_map->log[k][hits].v1 = (u64)arg2;

  if (size > 7) {

    __afl_cmp_map->log[k][hits].v0_128 = (u64)(arg1 >> 64);
    __afl_cmp_map->log[k][hits].v1_128 = (u64)(arg2 >> 64);

  }

}

void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2, uint8_t attr) {

  if (likely(!__afl_cmp_map)) return;
  if (16 > __afl_cmplog_max_len) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
    hits = 0;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = 15;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < 15) {

      __afl_cmp_map->headers[k].shape = 15;

    }

  }

  __afl_cmp_map->headers[k].attribute = attr;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = (u64)arg1;
  __afl_cmp_map->log[k][hits].v1 = (u64)arg2;
  __afl_cmp_map->log[k][hits].v0_128 = (u64)(arg1 >> 64);
  __afl_cmp_map->log[k][hits].v1_128 = (u64)(arg2 >> 64);

}

#endif

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {

  //__cmplog_ins_hook1(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {

  //__cmplog_ins_hook1(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  __cmplog_ins_hook2(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {

  __cmplog_ins_hook2(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  __cmplog_ins_hook4(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {

  __cmplog_ins_hook4(arg1, arg2, 0);

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  __cmplog_ins_hook8(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {

  __cmplog_ins_hook8(arg1, arg2, 0);

}

#ifdef WORD_SIZE_64
void __sanitizer_cov_trace_cmp16(uint128_t arg1, uint128_t arg2) {

  __cmplog_ins_hook16(arg1, arg2, 0);

}

void __sanitizer_cov_trace_const_cmp16(uint128_t arg1, uint128_t arg2) {

  __cmplog_ins_hook16(arg1, arg2, 0);

}

#endif

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  if (likely(!__afl_cmp_map)) return;

  for (uint64_t i = 0; i < cases[0]; i++) {

    uintptr_t k = (uintptr_t)__builtin_return_address(0) + i;
    k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) &
                    (CMP_MAP_W - 1));

    u32 hits;

    if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {

      __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
      hits = 0;
      __afl_cmp_map->headers[k].hits = 1;
      __afl_cmp_map->headers[k].shape = 7;

    } else {

      hits = __afl_cmp_map->headers[k].hits++;

      if (__afl_cmp_map->headers[k].shape < 7) {

        __afl_cmp_map->headers[k].shape = 7;

      }

    }

    __afl_cmp_map->headers[k].attribute = 1;

    hits &= CMP_MAP_H - 1;
    __afl_cmp_map->log[k][hits].v0 = val;
    __afl_cmp_map->log[k][hits].v1 = cases[i + 2];

  }

}

__attribute__((weak)) void *__asan_region_is_poisoned(void *beg, size_t size) {

  return NULL;

}

// POSIX shenanigan to see if an area is mapped.
// If it is mapped as X-only, we have a problem, so maybe we should add a check
// to avoid to call it on .text addresses
static int area_is_valid(void *ptr, size_t len) {

  if (unlikely(!ptr || __asan_region_is_poisoned(ptr, len))) { return 0; }

#ifdef __HAIKU__
  long r = _kern_write(__afl_dummy_fd[1], -1, ptr, len);
#elif defined(__OpenBSD__)
  long r = write(__afl_dummy_fd[1], ptr, len);
#else
  long r = syscall(SYS_write, __afl_dummy_fd[1], ptr, len);
#endif  // HAIKU, OPENBSD

  if (r <= 0 || r > len) return 0;

  // even if the write succeed this can be a false positive if we cross
  // a page boundary. who knows why.

  char *p = (char *)ptr;
  long  page_size = sysconf(_SC_PAGE_SIZE);
  char *page = (char *)((uintptr_t)p & ~(page_size - 1)) + page_size;

  if (page > p + len) {

    // no, not crossing a page boundary
    return (int)r;

  } else {

    // yes it crosses a boundary, hence we can only return the length of
    // rest of the first page, we cannot detect if the next page is valid
    // or not, neither by SYS_write nor msync() :-(
    return (int)(page - p);

  }

}

/* hook for string with length functions, eg. strncmp, strncasecmp etc.
   Note that we ignore the len parameter and take longer strings if present. */
void __cmplog_rtn_hook_strn(u8 *ptr1, u8 *ptr2, u64 len) {

  // fprintf(stderr, "RTN1 %p %p %u\n", ptr1, ptr2, len);
  if (likely(!__afl_cmp_map)) return;
  if (unlikely(!len || len > __afl_cmplog_max_len)) return;

  int len0 = MIN(len, 32);

  int len1 = strnlen(ptr1, len0);
  if (len1 <= 32) len1 = area_is_valid(ptr1, len1 + 1);
  if (len1 > __afl_cmplog_max_len) len1 = 0;

  int len2 = strnlen(ptr2, len0);
  if (len2 <= 32) len2 = area_is_valid(ptr2, len2 + 1);
  if (len2 > __afl_cmplog_max_len) len2 = 0;

  int l;
  if (!len1)
    l = len2;
  else if (!len2)
    l = len1;
  else
    l = MAX(len1, len2);
  if (l < 2) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = l - 1;
    hits = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < l) {

      __afl_cmp_map->headers[k].shape = l - 1;

    }

  }

  struct cmpfn_operands *cmpfn = (struct cmpfn_operands *)__afl_cmp_map->log[k];
  hits &= CMP_MAP_RTN_H - 1;

  cmpfn[hits].v0_len = 0x80 + l;
  cmpfn[hits].v1_len = 0x80 + l;
  __builtin_memcpy(cmpfn[hits].v0, ptr1, len1);
  __builtin_memcpy(cmpfn[hits].v1, ptr2, len2);
  // fprintf(stderr, "RTN3\n");

}

/* hook for string functions, eg. strcmp, strcasecmp etc. */
void __cmplog_rtn_hook_str(u8 *ptr1, u8 *ptr2) {

  // fprintf(stderr, "RTN1 %p %p\n", ptr1, ptr2);
  if (likely(!__afl_cmp_map)) return;
  if (unlikely(!ptr1 || !ptr2)) return;
  int len1 = strnlen(ptr1, 31) + 1;
  int len2 = strnlen(ptr2, 31) + 1;
  if (len1 > __afl_cmplog_max_len) len1 = 0;
  if (len2 > __afl_cmplog_max_len) len2 = 0;
  int l;
  if (!len1)
    l = len2;
  else if (!len2)
    l = len1;
  else
    l = MAX(len1, len2);
  if (l < 2) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = l - 1;
    hits = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < l) {

      __afl_cmp_map->headers[k].shape = l - 1;

    }

  }

  struct cmpfn_operands *cmpfn = (struct cmpfn_operands *)__afl_cmp_map->log[k];
  hits &= CMP_MAP_RTN_H - 1;

  cmpfn[hits].v0_len = 0x80 + len1;
  cmpfn[hits].v1_len = 0x80 + len2;
  __builtin_memcpy(cmpfn[hits].v0, ptr1, len1);
  __builtin_memcpy(cmpfn[hits].v1, ptr2, len2);
  // fprintf(stderr, "RTN3\n");

}

/* hook function for all other func(ptr, ptr, ...) variants */
void __cmplog_rtn_hook(u8 *ptr1, u8 *ptr2) {

  /*
    u32 i;
    if (area_is_valid(ptr1, 32) <= 0 || area_is_valid(ptr2, 32) <= 0) return;
    fprintf(stderr, "rtn arg0=");
    for (i = 0; i < 32; i++)
      fprintf(stderr, "%02x", ptr1[i]);
    fprintf(stderr, " arg1=");
    for (i = 0; i < 32; i++)
      fprintf(stderr, "%02x", ptr2[i]);
    fprintf(stderr, "\n");
  */

  // fprintf(stderr, "RTN1 %p %p\n", ptr1, ptr2);
  if (likely(!__afl_cmp_map)) return;
  int l1, l2;
  if ((l1 = area_is_valid(ptr1, 32)) <= 0 ||
      (l2 = area_is_valid(ptr2, 32)) <= 0)
    return;
  int len = MIN(__afl_cmplog_max_len, MIN(l1, l2));

  // fprintf(stderr, "RTN2 %u\n", len);
  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = len - 1;
    hits = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < len) {

      __afl_cmp_map->headers[k].shape = len - 1;

    }

  }

  struct cmpfn_operands *cmpfn = (struct cmpfn_operands *)__afl_cmp_map->log[k];
  hits &= CMP_MAP_RTN_H - 1;

  cmpfn[hits].v0_len = len;
  cmpfn[hits].v1_len = len;
  __builtin_memcpy(cmpfn[hits].v0, ptr1, len);
  __builtin_memcpy(cmpfn[hits].v1, ptr2, len);
  // fprintf(stderr, "RTN3\n");

}

/* hook for func(ptr, ptr, len, ...) looking functions.
   Note that for the time being we ignore len as this could be wrong
   information and pass it on to the standard binary rtn hook */
void __cmplog_rtn_hook_n(u8 *ptr1, u8 *ptr2, u64 len) {

  (void)(len);
  __cmplog_rtn_hook(ptr1, ptr2);

#if 0
  /*
    u32 i;
    if (area_is_valid(ptr1, 32) <= 0 || area_is_valid(ptr2, 32) <= 0) return;
    fprintf(stderr, "rtn_n len=%u arg0=", len);
    for (i = 0; i < len; i++)
      fprintf(stderr, "%02x", ptr1[i]);
    fprintf(stderr, " arg1=");
    for (i = 0; i < len; i++)
      fprintf(stderr, "%02x", ptr2[i]);
    fprintf(stderr, "\n");
  */

  // fprintf(stderr, "RTN1 %p %p %u\n", ptr1, ptr2, len);
  if (likely(!__afl_cmp_map)) return;
  if (!len) return;
  int l = MIN(32, len), l1, l2;

  if ((l1 = area_is_valid(ptr1, l)) <= 0 || (l2 = area_is_valid(ptr2, l)) <= 0)
    return;

  len = MIN(l1, l2);
  if (len > __afl_cmplog_max_len) return;

  // fprintf(stderr, "RTN2 %u\n", l);
  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (uintptr_t)(default_hash((u8 *)&k, sizeof(uintptr_t)) & (CMP_MAP_W - 1));

  u32 hits;

  if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {

    __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
    __afl_cmp_map->headers[k].hits = 1;
    __afl_cmp_map->headers[k].shape = l - 1;
    hits = 0;

  } else {

    hits = __afl_cmp_map->headers[k].hits++;

    if (__afl_cmp_map->headers[k].shape < l) {

      __afl_cmp_map->headers[k].shape = l - 1;

    }

  }

  struct cmpfn_operands *cmpfn = (struct cmpfn_operands *)__afl_cmp_map->log[k];
  hits &= CMP_MAP_RTN_H - 1;

  cmpfn[hits].v0_len = l;
  cmpfn[hits].v1_len = l;
  __builtin_memcpy(cmpfn[hits].v0, ptr1, l);
  __builtin_memcpy(cmpfn[hits].v1, ptr2, l);
  // fprintf(stderr, "RTN3\n");
#endif

}

// gcc libstdc++
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc
static u8 *get_gcc_stdstring(u8 *string) {

  u32 *len = (u32 *)(string + 8);

  if (*len < 16) {  // in structure

    return (string + 16);

  } else {  // in memory

    u8 **ptr = (u8 **)string;
    return (*ptr);

  }

}

// llvm libc++ _ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocator
//             IcEEE7compareEmmPKcm
static u8 *get_llvm_stdstring(u8 *string) {

  // length is in: if ((string[0] & 1) == 0) u8 len = (string[0] >> 1);
  // or: if (string[0] & 1) u32 *len = (u32 *) (string + 8);

  if (string[0] & 1) {  // in memory

    u8 **ptr = (u8 **)(string + 16);
    return (*ptr);

  } else {  // in structure

    return (string + 1);

  }

}

void __cmplog_rtn_gcc_stdstring_cstring(u8 *stdstring, u8 *cstring) {

  if (likely(!__afl_cmp_map)) return;
  if (area_is_valid(stdstring, 32) <= 0 || area_is_valid(cstring, 32) <= 0)
    return;

  __cmplog_rtn_hook(get_gcc_stdstring(stdstring), cstring);

}

void __cmplog_rtn_gcc_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2) {

  if (likely(!__afl_cmp_map)) return;
  if (area_is_valid(stdstring1, 32) <= 0 || area_is_valid(stdstring2, 32) <= 0)
    return;

  __cmplog_rtn_hook(get_gcc_stdstring(stdstring1),
                    get_gcc_stdstring(stdstring2));

}

void __cmplog_rtn_llvm_stdstring_cstring(u8 *stdstring, u8 *cstring) {

  if (likely(!__afl_cmp_map)) return;
  if (area_is_valid(stdstring, 32) <= 0 || area_is_valid(cstring, 32) <= 0)
    return;

  __cmplog_rtn_hook(get_llvm_stdstring(stdstring), cstring);

}

void __cmplog_rtn_llvm_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2) {

  if (likely(!__afl_cmp_map)) return;
  if (area_is_valid(stdstring1, 32) <= 0 || area_is_valid(stdstring2, 32) <= 0)
    return;

  __cmplog_rtn_hook(get_llvm_stdstring(stdstring1),
                    get_llvm_stdstring(stdstring2));

}

/* COVERAGE manipulation features */

// this variable is then used in the shm setup to create an additional map
// if __afl_map_size > MAP_SIZE or cmplog is used.
// Especially with cmplog this would result in a ~260MB mem increase per
// target run.

// disable coverage from this point onwards until turned on again
void __afl_coverage_off() {

  if (likely(__afl_selective_coverage)) {

    __afl_area_ptr = __afl_area_ptr_dummy;
    __afl_cmp_map = NULL;

  }

}

// enable coverage
void __afl_coverage_on() {

  if (likely(__afl_selective_coverage && __afl_selective_coverage_temp)) {

    __afl_area_ptr = __afl_area_ptr_backup;
    if (__afl_cmp_map_backup) { __afl_cmp_map = __afl_cmp_map_backup; }

  }

}

// discard all coverage up to this point
void __afl_coverage_discard() {

  memset(__afl_area_ptr_backup, 0, __afl_map_size);
  __afl_area_ptr_backup[0] = 1;

  if (__afl_cmp_map) { memset(__afl_cmp_map, 0, sizeof(struct cmp_map)); }

}

// discard the testcase
void __afl_coverage_skip() {

  __afl_coverage_discard();

  if (likely(is_persistent && __afl_selective_coverage)) {

    __afl_coverage_off();
    __afl_selective_coverage_temp = 0;

  } else {

    exit(0);

  }

}

// mark this area as especially interesting
void __afl_coverage_interesting(u8 val, u32 id) {

  __afl_area_ptr[id % __afl_map_size] = val;

}

void __afl_set_persistent_mode(u8 mode) {

  is_persistent = mode;

}

// Marker: ADD_TO_INJECTIONS

void __afl_injection_sql(u8 *buf) {

  if (likely(buf)) {

    if (unlikely(strstr((char *)buf, "'\"\"'"))) {

      fprintf(stderr, "ALERT: Detected SQL injection in query: %s\n", buf);
      abort();

    }

  }

}

void __afl_injection_ldap(u8 *buf) {

  if (likely(buf)) {

    if (unlikely(strstr((char *)buf, "*)(1=*))(|"))) {

      fprintf(stderr, "ALERT: Detected LDAP injection in query: %s\n", buf);
      abort();

    }

  }

}

void __afl_injection_xss(u8 *buf) {

  if (likely(buf)) {

    if (unlikely(strstr((char *)buf, "1\"><\""))) {

      fprintf(stderr, "ALERT: Detected XSS injection in content: %s\n", buf);
      abort();

    }

  }

}

#undef write_error

