/*
   american fuzzy lop++ - instrumentation bootstrap
   ------------------------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

*/

#ifdef __linux__
  #ifndef _GNU_SOURCE
    #define _GNU_SOURCE
  #endif
  #include <dlfcn.h>
  #include <link.h>
#endif

#ifdef __AFL_CODE_COVERAGE
  #ifndef _GNU_SOURCE
    #define _GNU_SOURCE
  #endif
  #ifndef __USE_GNU
    #define __USE_GNU
  #endif
  #include <dlfcn.h>
  #include <stddef.h>                            /* size_t, used just below */

/* Part of the sanitizer runtime, so it is only there when the target was
   linked with one. Mach-O needs weak_import for an undefined weak symbol - a
   plain weak declaration still makes its linker demand a definition (same as
   for __asan_region_is_poisoned further down). */
  #ifdef __APPLE__
__attribute__((weak_import)) void __sanitizer_symbolize_pc(void *,
                                                           const char *fmt,
                                                           char       *out_buf,
                                                           size_t out_buf_size);
  #else
__attribute__((weak)) void __sanitizer_symbolize_pc(void *, const char *fmt,
                                                    char  *out_buf,
                                                    size_t out_buf_size);
  #endif
#endif

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "hash.h"
#include "bitops.h"
#include "cmplog.h"
#include "value-profile.h"
#include "afl-ijon-min.h"

/* For backtrace() support in ijon_hashstack */
#if (defined(__linux__) && defined(__GLIBC__)) || defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #include <execinfo.h>
#endif

/* FreeBSD, as of FreeBSD 15.1, has no support for MAP_NORESERVE for mmap */
#ifndef MAP_NORESERVE
  #define MAP_NORESERVE 0
#endif

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
#include <math.h>

#include <sys/mman.h>
#ifdef __linux__
  #include <linux/futex.h>
  #include <sys/prctl.h>
  #include <sys/syscall.h>

static inline long sys_futex(void *uaddr, int op, int val,
                             const struct timespec *timeout, void *uaddr2,
                             int val3) {

  return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);

}

static inline void afl_sync_wake(void *uaddr) {

  sys_futex(uaddr, FUTEX_WAKE, 1, NULL, NULL, 0);

}

#elif defined(__APPLE__)
  #include <os/os_sync_wait_on_address.h>
  #include <mach/mach_time.h>
  #include <sys/syscall.h>

static inline void afl_sync_wake(void *uaddr) {

  os_sync_wake_by_address_any(uaddr, sizeof(u32),
                              OS_SYNC_WAKE_BY_ADDRESS_SHARED);

}

#elif !defined(__HAIKU__) && !defined(__OpenBSD__)
  #include <sys/syscall.h>
#endif
#if !defined(__HAIKU__) && !defined(__OpenBSD__) && defined(SYS_writev)
  #include <sys/uio.h>
  #define AFL_HAVE_RAW_WRITEV 1
#endif
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#if (defined(__linux__) && defined(__GLIBC__)) || defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #include <execinfo.h>
#endif

/*
#ifdef __llvm__
  #include "llvm/Config/llvm-config.h"
#endif
*/

/*
#ifdef __linux__
  #include "snapshot-inl.h"
#endif
*/

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

#if defined(__has_include)
  #if __has_include(<sanitizer/common_interface_defs.h>)
    #include <sanitizer/common_interface_defs.h>
  #endif
#endif

#ifdef AFL_PERSISTENT_RECORD
  #include "afl-persistent-replay.h"
#endif

#if !defined(__has_attribute)
  #define __has_attribute(x) 0
#endif

/* Portable "no ASan" attribute */
#if defined(__clang__)
  #if __has_attribute(no_sanitize)
    #define NOASAN __attribute__((no_sanitize("address")))
  #elif __has_attribute(no_sanitize_address)
    #define NOASAN __attribute__((no_sanitize_address))
  #else
    #define NOASAN
  #endif
#elif defined(__GNUC__)
  /* GCC: uses no_sanitize_address */
  #if __has_attribute(no_sanitize_address) || (__GNUC__ >= 5)
    #define NOASAN __attribute__((no_sanitize_address))
  #else
    #define NOASAN
  #endif
#else
  #define NOASAN
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define FORCEINLINE __attribute__((always_inline)) inline
#else
  #define FORCEINLINE inline
#endif

// lowers to inline memset, no libc call to interpose
static FORCEINLINE NOASAN void *memset_noasan(void *dst, int c, size_t n) {

  return __builtin_memset(dst, c, n);

}

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

u8  *__afl_area_ptr = __afl_area_initial;
u8  *__afl_dictionary;
u32 *__afl_child_sync = NULL;
/* Byte offset of the child_sync word inside the trace_bits shared map (0 if
   none). */
static u32 __afl_child_sync_off = 0;
/* Lengths we mmap()ed for each shared region, so __afl_unmap_shm() can undo
   exactly what was done. A length of 0 means the region was not mmap()ed -
   either it was never attached, or it came in as a SysV segment that has to be
   released with shmdt() instead. The trace_bits length can exceed
   __afl_map_size because that map carries the child_sync word behind it. */
static size_t __afl_shm_map_len = 0;
static size_t __afl_cmp_map_len = 0;
static size_t __afl_vp_map_len = 0;
#ifdef __AFL_CODE_COVERAGE
static size_t __afl_pcmap_map_len = 0;
static size_t __afl_modmap_map_len = 0;
#endif
u8        *__afl_fuzz_ptr;
static u32 __afl_fuzz_len_dummy;
u32       *__afl_fuzz_len = &__afl_fuzz_len_dummy;
int        __afl_sharedmem_fuzzing __attribute__((weak));

// Weak so the LTO instrumentation can override with a strong static
// initializer (see SanitizerCoverageLTO). On macOS this makes the
// map size visible at load time, before any constructor runs --
// otherwise AFL_DUMP_MAP_SIZE would always print MAP_SIZE because the
// LTO-bitcode constructor that previously stored __afl_final_loc runs
// after afl-compiler-rt.o's constructors on Mach-O.
__attribute__((weak)) u32 __afl_final_loc;
u32                       __afl_map_size = MAP_SIZE;
u32                       __afl_cov_map_size = MAP_SIZE;
u32                       __afl_set_map_size = MAP_SIZE;
u32                       __afl_dictionary_len;
u64                       __afl_map_addr;
u32                       __afl_first_final_loc;
u32                       __afl_old_forkserver;

u8 __afl_forkserver_setenv = 0;

/* IJON max tracking globals */
static u64 __afl_ijon_initial[MAP_SIZE_IJON_ENTRIES];
u64 *__afl_ijon_bits = __afl_ijon_initial;  // Initial buffer, will point to
                                            // shared memory at MAP_SIZE offset
u32 __afl_ijon_map_size = MAP_SIZE_IJON_ENTRIES;
u32 __afl_ijon_map_increased = 0;
u32 __afl_ijon_enabled __attribute__((weak)) = 0;

u32 __afl_c11_enabled __attribute__((weak)) = 0;

/* Bug-pass runtime globals (afl-llvm-bug-pass.so support) */
#include "../include/bug-pass.h"
u8         __afl_bug_active = 0;
u32       *__afl_bug_map = NULL;
static u32 __afl_bug_map_local[MAP_SIZE_BUG_ENTRIES];
u32        __afl_bug_mode __attribute__((weak)) = 0;
static u8  __afl_bug_runtime_configured = 0;
static u32 __afl_bug_configured_mode = 0;
static u8  __afl_bug_map_active = 0;
static u8  __afl_bug_map_increased = 0;
/* Per-thread stack of nested BUDGET / SIZEFILL frames.
   Previously begin/check used a single global (base, max_off), so an
   inner instrumented call's wsBegin overwrote the outer frame and the
   outer wsCheck became a silent no-op — losing real budget violations
   in nested call patterns. With a stack, every store updates EVERY
   active frame (so an outer call's contract correctly includes writes
   done by its callees) and each call's check inspects its own frame.

   `cap` is the upper bound for stores under this frame: writes at or
   past `base + cap` are not the buffer's writes and must be ignored so
   their max_off doesn't pollute the frame's contract check. BUDGET
   doesn't know the buffer cap (it's the function's contract that
   determines it), so BUDGET frames set cap=UINT64_MAX. SIZEFILL knows
   the caller buffer size and uses it. */
#define __AFL_BUG_FRAME_STACK_DEPTH 16
typedef struct __afl_bug_frame {

  const void *base;
  u64         max_off;
  u64         total;
  u64         cap;

} __afl_bug_frame;

#if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
static __afl_bug_frame __afl_bug_ws_stack[__AFL_BUG_FRAME_STACK_DEPTH];
static int             __afl_bug_ws_top = -1;
static __afl_bug_frame __afl_bug_sf_stack[__AFL_BUG_FRAME_STACK_DEPTH];
static int             __afl_bug_sf_top = -1;
#else
static __thread __afl_bug_frame __afl_bug_ws_stack[__AFL_BUG_FRAME_STACK_DEPTH];
static __thread int             __afl_bug_ws_top = -1;
static __thread __afl_bug_frame __afl_bug_sf_stack[__AFL_BUG_FRAME_STACK_DEPTH];
static __thread int             __afl_bug_sf_top = -1;
#endif

/* Signal-safe violation reporting.  Instrumented stores can be reached
   from inside signal handlers; fprintf(stderr,…) takes the stdio lock
   (deadlock if the signal interrupted another fprintf) and abort()
   re-enters libc abort logic.  write(2) + _exit(134) avoids both.
   Numeric fields are printed via the small in-place formatters below
   since snprintf is also not async-signal-safe. */
static void __afl_bug_writes(const char *s) {

  size_t n = 0;
  while (s[n])
    ++n;
  (void)!write(2, s, n);

}

static void __afl_bug_writeu(unsigned long long v) {

  char buf[24];
  int  n = 0;
  if (!v) {

    buf[n++] = '0';

  } else {

    while (v) {

      buf[n++] = (char)('0' + (v % 10));
      v /= 10;

    }

  }

  for (int i = 0, j = n - 1; i < j; ++i, --j) {

    char t = buf[i];
    buf[i] = buf[j];
    buf[j] = t;

  }

  (void)!write(2, buf, (size_t)n);

}

static void __afl_bug_writep(const void *p) {

  char      buf[20];
  int       n = 0;
  uintptr_t v = (uintptr_t)p;
  __afl_bug_writes("0x");
  if (!v) {

    (void)!write(2, "0", 1);
    return;

  }

  while (v) {

    unsigned d = (unsigned)(v & 0xf);
    buf[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    v >>= 4;

  }

  for (int i = 0, j = n - 1; i < j; ++i, --j) {

    char t = buf[i];
    buf[i] = buf[j];
    buf[j] = t;

  }

  (void)!write(2, buf, (size_t)n);

}

/* AllocSizeOracle (AFL_LLVM_BUG_ALLOCSIZE) runtime globals.
   Exposed (non-static) on purpose so tests and inspection tools can read
   the live record table — same convention as __afl_bug_map / __afl_area_ptr.
   AllocSizeRecord layout lives in include/bug-pass.h so consumers see
   the canonical fields without copy-pasting. */

u8 __afl_allocsize_active = 0;
u8 __afl_size_derive_active = 0;
/* Shadow byte is u16 so it can index up to MAP_SIZE_ALLOCRECORDS - 1.
   `__afl_alloc_shadow` is the primary 16 GiB window pinned at the first
   registered allocation's base.  Up to __AFL_ALLOC_SHADOW_EXTRAS additional
   windows (total = 1 + EXTRAS) cover allocations whose address is more
   than 16 GiB from the primary origin — common under ASLR with mmap heaps
   and shared libraries.  Lookup is a linear scan over up to 4 origins
   (branch-predictor-friendly); register lazily mmaps a new window on miss
   until the cap is reached. */
u16 *__afl_alloc_shadow = NULL;
_Static_assert(MAP_SIZE_ALLOCRECORDS <= (1U << 16) - 1,
               "u16 shadow byte cannot index more than 65535 records");
uintptr_t __afl_alloc_shadow_origin = 0;

#define __AFL_ALLOC_SHADOW_EXTRAS 3
typedef struct {

  uintptr_t origin;
  u16      *table;

} AflAllocShadowExtra;

static AflAllocShadowExtra __afl_alloc_shadow_extra[__AFL_ALLOC_SHADOW_EXTRAS];
static u32                 __afl_alloc_shadow_extra_count = 0;
static u8                  __afl_alloc_shadow_oom_warned = 0;

AllocSizeRecord    __afl_alloc_records[MAP_SIZE_ALLOCRECORDS];
static u32         __afl_alloc_next_idx = 1;                  /* 0 reserved */
static void        __afl_alloc_persistent_reset(u8 flush_derive);
static inline u16 *__afl_alloc_shadow_find(uintptr_t a, uintptr_t *off_out);
static u16 *__afl_alloc_shadow_get_or_init(uintptr_t a, uintptr_t *off_out);

/* AllocSizeRecord.in_use state. AFL++ fuzzing targets are single-
   threaded by design, so no atomic synchronisation is required. */
#define __AFL_ALLOC_INUSE_FREE ((u8)0)
#define __AFL_ALLOC_INUSE_LIVE ((u8)1)

/* IJON state tracking globals */
#if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
u32 __afl_ijon_state = 0;      // Current IJON state
u32 __afl_ijon_state_log = 0;  // State history log
#else
__thread u32 __afl_ijon_state = 0;
__thread u32 __afl_ijon_state_log = 0;
#endif

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

u32             __afl_modmap_size = 0;
module_entry_t *__afl_modmap_ptr = NULL;

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

/* __afl_prev_loc is the previous-location accumulator used by the gcc plugin
   instrumentation (__afl_trace). __afl_prev_ctx is the context ID used by the
   LTO CTX/CALLER instrumentation. */
#if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
u32 __afl_prev_loc;
u32 __afl_prev_ctx;
#else
__thread u32 __afl_prev_loc;
__thread u32 __afl_prev_ctx;
#endif

struct cmp_map *__afl_cmp_map;
struct cmp_map *__afl_cmp_map_backup;
static u32      __afl_cmp_cursor[CMP_MAP_W];
vp_map_t       *__afl_vp_map;
vp_map_t       *__afl_vp_map_backup;
u8              __afl_vp_enabled_fallback;
u8             *__afl_vp_enabled_ptr = &__afl_vp_enabled_fallback;
#ifndef __APPLE__
extern const u8 __afl_vp_instrumented __attribute__((weak));
#else
  #include <dlfcn.h>
#endif

static u8 __afl_cmplog_max_len = 32;  // 16-32

/* Child pid? */

static s32 child_pid;
static void (*old_sigterm_handler)(int) = 0;

/* Running in persistent mode? */

static u8 is_persistent;

/* Are we in sancov mode? */
// static u8 _is_sancov;

static inline void __afl_vp_refresh_enabled_ptr(void) {

  __afl_vp_enabled_ptr =
      __afl_vp_map ? (u8 *)&__afl_vp_map->enabled : &__afl_vp_enabled_fallback;

}

static inline u8 __afl_vp_target_supports_runtime(void) {

#ifdef __APPLE__
  return (u8)(dlsym(RTLD_DEFAULT, "__afl_vp_instrumented") != NULL);
#else
  return (u8)((uintptr_t)&__afl_vp_instrumented != 0);
#endif

}

/* Debug? */

/*static*/ u32 __afl_debug;

/* Already initialized markers */

u32 __afl_already_initialized_shm;
u32 __afl_already_initialized_forkserver;
// u32 __afl_already_initialized_first;
u32 __afl_already_initialized_second;
u32 __afl_already_initialized_early;
u32 __afl_already_initialized_init;

/* Dummy pipe for area_is_valid() */

static int __afl_dummy_fd[2] = {-1, -1};

#ifdef __linux__
static u8 addr_table_prepare(void);
#endif

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

  u32 prev = __afl_prev_loc;
  __afl_prev_loc = (x >> 1);

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

/* Never map past the end of a shared memory object: macOS rejects such an
   mmap() outright with EINVAL, and where it is accepted (Linux) every access
   past the end raises SIGBUS anyway. The tool sizes its object from what this
   target reported, so a short object means the two disagree - and the map size
   negotiation in the forkserver handshake is what resolves that, by restarting
   the target against a big enough map. Until then, mapping what is really
   there is what keeps the handshake itself alive. */

static size_t __afl_shm_clamp_len(int fd, size_t len, const char *what) {

  struct stat st;

  if (fstat(fd, &st) != 0 || st.st_size <= 0 || (size_t)st.st_size >= len) {

    return len;

  }

  if (__afl_debug) {

    fprintf(stderr,
            "DEBUG: the shared map %s is %lld bytes, %zu were requested - "
            "mapping what is there\n",
            what, (long long)st.st_size, len);

  }

  return (size_t)st.st_size;

}

/* Map a shared region that the tool handed over as an inherited descriptor.

   Recent AFL++ tools create their shared maps with shm_open(), mmap() them and
   shm_unlink() the name straight away, so nothing is left behind if the tool
   is SIGKILLed. All the target gets is the still-open descriptor, whose number
   arrives in `env`. `len` bytes are mapped - exactly as many as the name based
   path would map, the tool's object is regularly larger than that - and the
   length is reported back through `mapped_len` for the matching munmap().

   `fixed_addr` requests a mapping at a specific address (AFL_LLVM_MAP_ADDR);
   NULL lets the kernel place it.

   Returns NULL when the variable is not set or the descriptor is unusable,
   which puts the caller back on the shm_open(name) / shmat(id) path - that is
   what happens with a tool that predates the descriptor handover. The
   descriptor is deliberately left open: __afl_map_shm() can be run a second
   time when a late module grows the map (see
   __sanitizer_cov_trace_pc_guard_init
   -> __afl_unmap_shm/__afl_map_shm). */

static void *__afl_map_shm_fd(const char *env, size_t len, int prot,
                              void *fixed_addr, size_t *mapped_len) {

  const char *fd_str = getenv(env);

  if (!fd_str || !*fd_str) { return NULL; }

  char *endptr = NULL;
  errno = 0;
  long parsed = strtol(fd_str, &endptr, 10);

  if (errno || endptr == fd_str || *endptr || parsed < 0 ||
      parsed > (long)INT_MAX) {

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: %s=\"%s\" is not a descriptor number\n", env,
              fd_str);

    }

    return NULL;

  }

  int fd = (int)parsed;

  /* The descriptor has to still be open - a target that closes every
     descriptor at startup ends up here, and can then only be served by name. */

  struct stat st;

  errno = 0;

  if (fstat(fd, &st) != 0 || st.st_size <= 0) {

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: %s=%d is not a usable shared map: %s\n", env, fd,
              errno ? strerror(errno) : "it is empty");

    }

    return NULL;

  }

  size_t map_len = __afl_shm_clamp_len(fd, len, env);
  void  *ret;

  if (fixed_addr) {

    ret = mmap(fixed_addr, map_len, prot, MAP_FIXED_NOREPLACE | MAP_SHARED, fd,
               0);

  } else {

    ret = mmap(NULL, map_len, prot, MAP_SHARED, fd, 0);

  }

  if (ret == MAP_FAILED) {

    fprintf(stderr, "Error: mmap() of %s (fd %d, %zu bytes) failed: %s\n", env,
            fd, map_len, strerror(errno));
    send_forkserver_error(fixed_addr ? FS_ERROR_MAP_ADDR : FS_ERROR_MMAP);
    _exit(1);

  }

  if (mapped_len) { *mapped_len = map_len; }

  if (__afl_debug) {

    fprintf(stderr, "DEBUG: %s=%d mapped %zu bytes at %p\n", env, fd, map_len,
            ret);

  }

  return ret;

}

/* SHM fuzzing setup. */

static void __afl_map_shm_fuzz() {

  char *id_str = getenv(SHM_FUZZ_ENV_VAR);

  if (__afl_debug) {

    fprintf(stderr, "DEBUG: fuzzcase shmem %s\n", id_str ? id_str : "none");

  }

  if (id_str || getenv(SHM_FUZZ_FD_ENV_VAR)) {

    u8 *map = NULL;

    // Newer afl-fuzz versions will set a shm_fuzz page size env, else fall back
    size_t shm_fuzz_map_size = SHM_FUZZ_MAP_SIZE_DEFAULT;
    char  *map_size_env = getenv(SHM_FUZZ_MAP_SIZE_ENV_VAR);
    if (map_size_env != NULL) {

      char *endptr;
      errno = 0;
      shm_fuzz_map_size = (size_t)strtoul(map_size_env, &endptr, 10);
      if (errno != 0 || shm_fuzz_map_size == 0) {

        perror("shm_fuzz mapping size parsing");
        send_forkserver_error(FS_ERROR_SHM_OPEN);
        _exit(1);

      }

    }

    /* Preferred path: the map was handed to us as an inherited descriptor. */

    map = (u8 *)__afl_map_shm_fd(SHM_FUZZ_FD_ENV_VAR, shm_fuzz_map_size,
                                 PROT_READ, NULL, NULL);

    if (!map && id_str) {

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

      map = (u8 *)mmap(0, shm_fuzz_map_size, PROT_READ, MAP_SHARED, shm_fd, 0);
      close(shm_fd);

#else
      u32 shm_id = atoi(id_str);
      map = (u8 *)shmat(shm_id, NULL, 0);

#endif

    }

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

/* ASAN coexistence probe.  If ASAN is loaded, ALLOCSIZE conflicts with
   its allocator/shadow (ASAN-malloc'd pointers registered in our own
   64-byte-granule shadow, two oracles disagreeing on what's OOB).
   dlsym lookup is portable across linkers; weak undef references behave
   differently across macOS/ELF and interact badly with the AFL++
   self-test link step. */
#include <dlfcn.h>

static int __afl_bug_asan_present(void) {

  return dlsym(RTLD_DEFAULT, "__asan_address_is_poisoned") != NULL;

}

static void __afl_bug_configure_runtime(void) {

  u32 mode = __afl_bug_mode;
  if (likely(__afl_bug_runtime_configured &&
             mode == __afl_bug_configured_mode &&
             (!__afl_bug_map_active || __afl_bug_map)))
    return;
  __afl_bug_runtime_configured = 1;
  __afl_bug_configured_mode = mode;

  /* Disable ALLOCSIZE/DERIVE under ASAN: ASAN already enforces byte-
     granular OOB and reserves the low address space for its shadow.
     Running both produces conflicting verdicts and may collide on
     shadow mmap.  One-shot stderr note (signal-safe). */
  if (__afl_bug_asan_present() &&
      (mode & (AFL_BUG_MODE_ALLOCSIZE | AFL_BUG_MODE_DERIVE))) {

    static const char msg[] =
        "[afl-bug] ASAN detected; ALLOCSIZE/DERIVE modes disabled to "
        "avoid double-instrumentation. Use AFL_USE_ASAN without "
        "AFL_LLVM_BUG_ALLOCSIZE, or run a non-ASAN binary for ALLOCSIZE.\n";
    (void)!write(2, msg, sizeof msg - 1);
    mode &= ~(AFL_BUG_MODE_ALLOCSIZE | AFL_BUG_MODE_DERIVE);

  }

  __afl_bug_mode = mode;
  __afl_bug_active = !!(mode & (AFL_BUG_MODE_SCALAR | AFL_BUG_MODE_BUDGET |
                                AFL_BUG_MODE_SIZEFILL | AFL_BUG_MODE_ALLOCSIZE |
                                AFL_BUG_MODE_SLACK));
  __afl_bug_map_active =
      !!(mode &
         (AFL_BUG_MODE_SCALAR | AFL_BUG_MODE_ALLOCSIZE | AFL_BUG_MODE_SLACK));
  if (__afl_bug_map_active) {

    if (!__afl_bug_map) {

      __afl_bug_map = __afl_bug_map_local;
      memset_noasan(__afl_bug_map, 0, MAP_SIZE_BUG_BYTES);

    }

  } else {

    __afl_bug_map = NULL;

  }

  if (mode & AFL_BUG_MODE_ALLOCSIZE) { __afl_allocsize_active = 1; }
  if (mode & AFL_BUG_MODE_DERIVE) { __afl_size_derive_active = 1; }

}

static inline void __afl_bug_ensure_runtime(void) {

  if (unlikely(!__afl_bug_runtime_configured ||
               (__afl_bug_map_active && !__afl_bug_map) ||
               __afl_bug_mode != __afl_bug_configured_mode))
    __afl_bug_configure_runtime();

}

static void __afl_bug_append_map(void) {

  if (likely(!__afl_bug_map_active || __afl_bug_map_increased)) return;
  /* Bug map sits at the very end of trace_bits, AFTER any IJON region.
     Only __afl_map_size grows; __afl_set_map_size (the persistent-reset
     memset boundary and the IJON-tail offset) stays unchanged so IJON
     addressing isn't shifted by the bug-map insertion. */
  __afl_map_size += MAP_SIZE_BUG_BYTES;
  __afl_bug_map_increased = 1;

}

static void __afl_bug_bind_map(void) {

  /* Only bind once a real append has grown __afl_map_size by the bug tail
     (__afl_bug_map_increased).  Without this, the PCGUARD-deferred path (where
     __afl_map_size is still the MAP_SIZE placeholder) would memset the bug map
     past the end of the actual shared region.  The bind happens for real after
     __afl_bug_append_map() in the resize / forkserver-start paths. */
  if (likely(!__afl_bug_map_active || !__afl_bug_map_increased ||
             !__afl_area_ptr || !__afl_map_size ||
             __afl_map_size < MAP_SIZE_BUG_BYTES)) {

    return;

  }

  /* Bug map is the trailing region of trace_bits. */
  __afl_bug_map =
      (u32 *)(void *)(__afl_area_ptr + __afl_map_size - MAP_SIZE_BUG_BYTES);
  memset_noasan(__afl_bug_map, 0, MAP_SIZE_BUG_BYTES);

}

/* Scratch descriptor for the operand-readability probes. /dev/null does not
   work: the kernel never reads the source buffer, so the probe would report
   unmapped memory as valid - which is also why there is no fallback to the
   target's own stdout or stderr, whose sink the target does not control and
   which afl-fuzz points at /dev/null. The pipe fallback is set non-blocking
   because nothing ever drains it: once the 64K buffer is full the probes fail
   closed and stop collecting instead of blocking the target forever. Runs at
   most once - until it does, the descriptor stays -1 and the probes fail
   closed. */
static void __afl_open_dummy_fd(void) {

  static u8 attempted = 0;

  if (attempted) { return; }
  attempted = 1;

#if defined(__APPLE__) && defined(__MACH__)
  /* The readability probe (area_is_valid) writes the tested bytes to this fd so
     the kernel faults on unmapped source pages. On macOS neither sink used on
     other platforms works: write() to /dev/urandom always returns -1, and
     write() to /dev/null never faults (it reports success for unmapped memory).
     A pipe faults correctly, so use it directly. Set both ends non-blocking so
     that once the 64 KiB buffer fills the read end can be drained and the write
     retried instead of blocking (see area_is_valid / __afl_drain_dummy_fd). */
  if (pipe(__afl_dummy_fd) < 0) {

    __afl_dummy_fd[0] = __afl_dummy_fd[1] = -1;

  } else {

    for (int i = 0; i < 2; ++i) {

      int flags = fcntl(__afl_dummy_fd[i], F_GETFL, 0);
      if (flags >= 0) { fcntl(__afl_dummy_fd[i], F_SETFL, flags | O_NONBLOCK); }

    }

  }

#else
  if ((__afl_dummy_fd[1] = open("/dev/urandom", O_WRONLY)) < 0) {

    if (pipe(__afl_dummy_fd) < 0) {

      __afl_dummy_fd[1] = -1;

    } else {

      int flags = fcntl(__afl_dummy_fd[1], F_GETFL, 0);
      if (flags >= 0) { fcntl(__afl_dummy_fd[1], F_SETFL, flags | O_NONBLOCK); }

    }

  }

#endif

}

/* SHM setup. */

static void __afl_map_shm(void) {

  if (__afl_already_initialized_shm) return;
  __afl_already_initialized_shm = 1;

#if defined(__linux__) || defined(__APPLE__)
  /* The child_sync word is embedded in the trace_bits shared map. The fuzzer
     passes its byte offset via AFL_CHILD_SYNC_SHM; the pointer is set once the
     map is attached below (see __afl_area_ptr_backup). */
  __afl_child_sync = NULL;
  {

    char *child_sync_off = getenv("AFL_CHILD_SYNC_SHM");
    __afl_child_sync_off =
        child_sync_off ? (u32)strtoul(child_sync_off, NULL, 10) : 0;

  }

#endif

  // if we are not running in afl ensure the map exists
  if (!__afl_area_ptr) { __afl_area_ptr = __afl_area_ptr_dummy; }
  __afl_bug_configure_runtime();

  if (getenv("AFL_NO_IJON")) {

    __afl_ijon_enabled = 0;
    __afl_ijon_map_increased = 1;

  }

  if (getenv("AFL_NO_C11")) { __afl_c11_enabled = 0; }

  char *id_str = getenv(SHM_ENV_VAR);
  /* Newer tools hand the coverage map over as an inherited descriptor and
     unlink its name, so either variable means "a tool attached a map". */
  char *fd_str = getenv(SHM_FD_ENV_VAR);

  if (__afl_final_loc) {

    __afl_map_size = __afl_final_loc + 1;  // as we count starting 0

    if (__afl_ijon_enabled && !__afl_ijon_map_increased) {

      __afl_map_size = (((__afl_map_size + 63) >> 6) << 6);
      __afl_cov_map_size = __afl_map_size;
      __afl_map_size += MAP_SIZE_IJON_MAP + MAP_SIZE_IJON_BYTES;
      __afl_set_map_size = __afl_map_size - MAP_SIZE_IJON_BYTES;
      __afl_ijon_map_increased = 1;
      __afl_bug_append_map();

    } else {

      __afl_set_map_size = __afl_cov_map_size = __afl_map_size;
      __afl_bug_append_map();

    }

    if (getenv("AFL_DUMP_MAP_SIZE")) {

      printf("%u\n", __afl_map_size);
      fflush(stdout);
      /* The dumped size covers the IJON regions too, which is not what a
         reader comparing it against an uninstrumented build expects. The
         breakdown goes to stderr so the number on stdout stays parsable. */
      if (__afl_ijon_enabled) {

        fprintf(stderr, "%u = coverage %u + ijon %u + ijon max %u\n",
                __afl_map_size, __afl_cov_map_size, (u32)MAP_SIZE_IJON_MAP,
                (u32)MAP_SIZE_IJON_BYTES);

      }

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

  } else {

    __afl_set_map_size = __afl_cov_map_size = __afl_map_size;

    // IJON SUPPORT: Defer expansion until __afl_final_loc is set by
    // __sanitizer_cov_pcs_init This will be handled in __afl_map_shm_resize()
    // when the actual coverage size is known.
    //
    // Bug-pass map: ALSO defer. __afl_final_loc is 0 here (PCGUARD before
    // pcs_init), so __afl_map_size is only the MAP_SIZE placeholder.  If we
    // appended the bug map now, __afl_bug_bind_map() below would place it at
    // (MAP_SIZE_placeholder) and memset MAP_SIZE_BUG_BYTES there — but the
    // shared map afl-fuzz allocates is sized to (real_coverage + bug) which is
    // smaller than (placeholder + bug) whenever real_coverage < MAP_SIZE.  That
    // memset then runs off the end of the shared region and SIGSEGVs the
    // forkserver child on the post-handshake re-init.  The append+bind happens
    // for real in __afl_map_shm_resize() once __afl_final_loc is known.

  }

  if (getenv("AFL_DUMP_MAP_SIZE")) {

    printf("%u\n", __afl_map_size);
    fflush(stdout);
    exit(-1);

  }

  if (__afl_sharedmem_fuzzing &&
      ((!id_str && !fd_str) ||
       (!getenv(SHM_FUZZ_ENV_VAR) && !getenv(SHM_FUZZ_FD_ENV_VAR)) ||
       fcntl(FORKSRV_FD, F_GETFD) == -1 ||
       fcntl(FORKSRV_FD + 1, F_GETFD) == -1)) {

    if (__afl_debug) {

      fprintf(stderr,
              "DEBUG: running not inside afl-fuzz, disabling shared memory "
              "testcases\n");

    }

    __afl_sharedmem_fuzzing = 0;

  }

  if (!id_str && !fd_str) {

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

  char *vp_id_str = getenv(VP_SHM_ENV_VAR);

  if (__afl_debug) {

    fprintf(stderr, "DEBUG: vp id_str %s\n",
            vp_id_str == NULL ? "<null>" : vp_id_str);

  }

  if ((vp_id_str || getenv(VP_SHM_FD_ENV_VAR)) &&
      __afl_vp_target_supports_runtime()) {

    __afl_open_dummy_fd();

    __afl_vp_map = (vp_map_t *)__afl_map_shm_fd(
        VP_SHM_FD_ENV_VAR, sizeof(vp_map_t), PROT_READ | PROT_WRITE, NULL,
        &__afl_vp_map_len);

    if (!__afl_vp_map && vp_id_str) {

#ifdef USEMMAP
      const char *shm_file_path = vp_id_str;
      int         shm_fd = -1;
      vp_map_t   *shm_base = NULL;

      shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
      if (shm_fd == -1) {

        perror("shm_open() failed\n");
        send_forkserver_error(FS_ERROR_SHM_OPEN);
        exit(1);

      }

      shm_base = mmap(0, sizeof(vp_map_t), PROT_READ | PROT_WRITE, MAP_SHARED,
                      shm_fd, 0);
      if (shm_base == MAP_FAILED) {

        close(shm_fd);
        shm_fd = -1;

        fprintf(stderr, "mmap() failed\n");
        send_forkserver_error(FS_ERROR_SHM_OPEN);
        exit(2);

      }

      close(shm_fd);
      shm_fd = -1;
      __afl_vp_map = shm_base;
      __afl_vp_map_len = sizeof(vp_map_t);
#else
      u32 shm_id = atoi(vp_id_str);

      __afl_vp_map = (vp_map_t *)shmat(shm_id, NULL, 0);
#endif

    }

    if (!__afl_vp_map || __afl_vp_map == (void *)-1) {

      perror("shmat for value-profile");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      _exit(1);

    }

    __afl_vp_map_backup = __afl_vp_map;
    __afl_vp_refresh_enabled_ptr();

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

  if (id_str || fd_str) {

    if (__afl_area_ptr && __afl_area_ptr != __afl_area_initial &&
        __afl_area_ptr != __afl_area_ptr_dummy) {

      if (__afl_map_addr) {

        munmap((void *)__afl_map_addr, __afl_final_loc);

      } else {

        free(__afl_area_ptr);

      }

      __afl_area_ptr = __afl_area_ptr_dummy;

    }

    /* The tool reserved the child_sync word past the coverage region, so the
       segment can be larger than __afl_map_size; map enough to reach it. */
    size_t shm_map_len = __afl_map_size;
#if defined(__linux__) || defined(__APPLE__)
    if (__afl_child_sync_off &&
        __afl_child_sync_off + sizeof(u32) > shm_map_len) {

      shm_map_len = __afl_child_sync_off + sizeof(u32);

    }

#endif

    /* Preferred path: the map was handed to us as an inherited descriptor. */

    __afl_area_ptr = (u8 *)__afl_map_shm_fd(
        SHM_FD_ENV_VAR, shm_map_len, PROT_READ | PROT_WRITE,
        (void *)(uintptr_t)__afl_map_addr, &__afl_shm_map_len);

    if (!__afl_area_ptr && id_str) {

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

      shm_map_len = __afl_shm_clamp_len(shm_fd, shm_map_len, shm_file_path);
      __afl_shm_map_len = shm_map_len;

      /* map the shared memory segment to the address space of the process */
      if (__afl_map_addr) {

        shm_base =
            mmap((void *)__afl_map_addr, shm_map_len, PROT_READ | PROT_WRITE,
                 MAP_FIXED_NOREPLACE | MAP_SHARED, shm_fd, 0);

      } else {

        shm_base =
            mmap(0, shm_map_len, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

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

        // IJON SUPPORT: For IJON targets using new forkserver protocol,
        // skip this check as map size is communicated via FS_NEW_OPT_MAPSIZE
        if (__afl_ijon_enabled) {

          // Skip the check for IJON targets - let the fuzzer handle validation
          // via forkserver protocol

        } else {

          // Original check for non-IJON targets
          if (!map_env || atoi((char *)map_env) < MAP_SIZE) {

            fprintf(stderr, "FS_ERROR_MAP_SIZE\n");
            send_forkserver_error(FS_ERROR_MAP_SIZE);
            _exit(1);

          }

        }

      }

      __afl_area_ptr = (u8 *)shmat(shm_id, (void *)__afl_map_addr, 0);

#endif

    }

    /* Whooooops. */

    if (!__afl_area_ptr || __afl_area_ptr == (void *)-1) {

      if (__afl_map_addr)
        send_forkserver_error(FS_ERROR_MAP_ADDR);
      else
        send_forkserver_error(FS_ERROR_SHMAT);

      perror("attaching the coverage map");
      _exit(1);

    }

    /* DEFERRED IJON SETUP: Initialize on first use when actual map size is
     * known */
    /* This fixes PCGUARD mode where __afl_final_loc=0 at initialization time */
    __afl_ijon_bits =
        NULL;  // Mark as uninitialized - will init on first ijon_max() call

    /* IJON STATE RESET: Reset state for each execution */
    ijon_reset_state();
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

    __afl_map_size = __afl_final_loc + 1;
    __afl_area_ptr_dummy = (u8 *)malloc(__afl_map_size);
    __afl_area_ptr = __afl_area_ptr_dummy;

    if (!__afl_area_ptr_dummy) {

      fprintf(stderr,
              "Error: AFL++ could not acquire %u bytes of memory, exiting!\n",
              __afl_final_loc);
      exit(-1);

    }

  }  // else: nothing to be done

  __afl_area_ptr_backup = __afl_area_ptr;
  __afl_bug_bind_map();

#if defined(__linux__) || defined(__APPLE__)
  /* The sync word lives in the shared trace_bits map (only valid when we
     actually attached one, i.e. id_str was present). Derive it from the real
     map base before any selective-coverage redirection of __afl_area_ptr. */
  if (__afl_child_sync_off && (id_str || fd_str)) {

    __afl_child_sync =
        (u32 *)(void *)(__afl_area_ptr_backup + __afl_child_sync_off);

  }

#endif

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

  if (id_str || getenv(CMPLOG_SHM_FD_ENV_VAR)) {

    __afl_open_dummy_fd();

    __afl_cmp_map = (struct cmp_map *)__afl_map_shm_fd(
        CMPLOG_SHM_FD_ENV_VAR, sizeof(struct cmp_map), PROT_READ | PROT_WRITE,
        NULL, &__afl_cmp_map_len);

    if (!__afl_cmp_map && id_str) {

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

      close(shm_fd);
      shm_fd = -1;
      __afl_cmp_map = shm_base;
      __afl_cmp_map_len = sizeof(struct cmp_map);
#else
      u32 shm_id = atoi(id_str);

      __afl_cmp_map = (struct cmp_map *)shmat(shm_id, NULL, 0);
#endif

    }

    if (!__afl_cmp_map || __afl_cmp_map == (void *)-1) {

      perror("attaching the cmplog map");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      _exit(1);

    }

    __afl_cmp_map_backup = __afl_cmp_map;

  }

#ifdef __AFL_CODE_COVERAGE
  char *pcmap_id_str = getenv("__AFL_PCMAP_SHM_ID");

  if (pcmap_id_str || getenv("__AFL_PCMAP_SHM_FD")) {

    size_t pcmap_len = __afl_map_size * sizeof(void *);
    void  *pcmap =
        __afl_map_shm_fd("__AFL_PCMAP_SHM_FD", pcmap_len,
                         PROT_READ | PROT_WRITE, NULL, &__afl_pcmap_map_len);

    if (!pcmap && pcmap_id_str) {

  #ifndef USEMMAP
      u32 shm_id = atoi(pcmap_id_str);

      pcmap = shmat(shm_id, NULL, 0);
      if (pcmap == (void *)-1) { pcmap = NULL; }
  #endif

    }

    __afl_pcmap_ptr = (uintptr_t *)pcmap;
    __afl_pcmap_size = pcmap ? __afl_map_size * sizeof(void *) : 0;

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: Received %p for pcmap\n", __afl_pcmap_ptr);

    }

  }

  char *modmap_id_str = getenv("__AFL_MODMAP_SHM_ID");

  if (modmap_id_str || getenv("__AFL_MODMAP_SHM_FD")) {

    // Allocate space for module_entry_t array
    size_t modmap_len = sizeof(module_entry_t) * MAX_AFL_MODULES;
    void  *modmap =
        __afl_map_shm_fd("__AFL_MODMAP_SHM_FD", modmap_len,
                         PROT_READ | PROT_WRITE, NULL, &__afl_modmap_map_len);

    if (!modmap && modmap_id_str) {

  #ifndef USEMMAP
      u32 shm_id = atoi(modmap_id_str);

      modmap = shmat(shm_id, NULL, 0);
      if (modmap == (void *)-1) { modmap = NULL; }
  #endif

    }

    __afl_modmap_ptr = (module_entry_t *)modmap;
    __afl_modmap_size = modmap ? MAX_AFL_MODULES : 0;

    if (__afl_debug) {

      fprintf(stderr, "DEBUG: Received %p for modmap (%u entries)\n",
              __afl_modmap_ptr, __afl_modmap_size);

    }

  }

#endif  // __AFL_CODE_COVERAGE

  if (!__afl_cmp_map && getenv("AFL_CMPLOG_DEBUG")) {

    __afl_cmp_map_backup = __afl_cmp_map = calloc(1, sizeof(struct cmp_map));

  }

  if (getenv("AFL_CMPLOG_MAX_LEN")) {

    int tmp = atoi(getenv("AFL_CMPLOG_MAX_LEN"));
    if (tmp >= 16 && tmp <= 32) { __afl_cmplog_max_len = tmp; }

  }

  __afl_bug_configure_runtime();

}

/* unmap SHM. */

static void __afl_unmap_shm(void) {

  if (!__afl_already_initialized_shm) return;

#ifdef __AFL_CODE_COVERAGE
  if (__afl_pcmap_size) {

    if (__afl_pcmap_map_len) {

      munmap((void *)__afl_pcmap_ptr, __afl_pcmap_map_len);
      __afl_pcmap_map_len = 0;

    } else {

  #ifndef USEMMAP
      shmdt((void *)__afl_pcmap_ptr);
  #endif

    }

    __afl_pcmap_ptr = NULL;
    __afl_pcmap_size = 0;

  }

  if (__afl_modmap_size) {

    if (__afl_modmap_map_len) {

      munmap((void *)__afl_modmap_ptr, __afl_modmap_map_len);
      __afl_modmap_map_len = 0;

    } else {

  #ifndef USEMMAP
      shmdt((void *)__afl_modmap_ptr);
  #endif

    }

    __afl_modmap_ptr = NULL;
    __afl_modmap_size = 0;

  }

#endif  // __AFL_CODE_COVERAGE

  char *id_str = getenv(SHM_ENV_VAR);

  /* A recorded length means the region was mmap()ed - from the inherited
     descriptor or from shm_open() - and has to be unmapped exactly as it was
     mapped (that may include the trailing child_sync word past
     __afl_map_size). Without one it is a SysV attachment, if it is anything. */

  if (__afl_shm_map_len) {

    munmap((void *)__afl_area_ptr, __afl_shm_map_len);
    __afl_shm_map_len = 0;
    __afl_child_sync = NULL;

  } else if (id_str) {

#ifndef USEMMAP

    shmdt((void *)__afl_area_ptr);

#endif

    __afl_child_sync = NULL;

  } else if ((!__afl_area_ptr || __afl_area_ptr == __afl_area_initial) &&

             __afl_map_addr) {

    munmap((void *)__afl_map_addr, __afl_map_size);

  }

  __afl_area_ptr = __afl_area_ptr_dummy;
  __afl_bug_map = __afl_bug_map_active ? __afl_bug_map_local : NULL;
  __afl_bug_map_increased = 0;

  id_str = getenv(CMPLOG_SHM_ENV_VAR);

  if (__afl_cmp_map_len) {

    munmap((void *)__afl_cmp_map, __afl_cmp_map_len);
    __afl_cmp_map_len = 0;
    __afl_cmp_map = NULL;
    __afl_cmp_map_backup = NULL;

  } else if (id_str) {

#ifndef USEMMAP

    shmdt((void *)__afl_cmp_map);

#endif

    __afl_cmp_map = NULL;
    __afl_cmp_map_backup = NULL;

  }

  id_str = getenv(VP_SHM_ENV_VAR);

  if (__afl_vp_map && (__afl_vp_map_len || id_str)) {

    if (__afl_vp_map_len) {

      munmap((void *)__afl_vp_map, __afl_vp_map_len);
      __afl_vp_map_len = 0;

    } else {

#ifndef USEMMAP

      shmdt((void *)__afl_vp_map);

#endif

    }

    __afl_vp_map = NULL;
    __afl_vp_map_backup = NULL;
    __afl_vp_refresh_enabled_ptr();

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

#ifdef __linux__
  if (__afl_cmp_map) { addr_table_prepare(); }
#endif

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

  if (getenv("AFL_NO_C11")) { __afl_c11_enabled = 0; }

  if (getenv("AFL_NO_IJON")) {

    __afl_ijon_enabled = 0;
    __afl_ijon_map_increased = 1;

  }

  if (__afl_ijon_enabled && !__afl_ijon_map_increased) {

    /* Reachable in PCGUARD mode when __afl_final_loc was 0 at
       __afl_map_shm time: that call's else branch ran __afl_bug_append_map
       but skipped the IJON expansion, leaving __afl_bug_map pointing at
       what is about to become the IJON_MAP region.  Detach and re-bind
       the bug map AFTER the IJON expansion so the layout ends up as
       [cov | IJON_MAP | IJON_BYTES | BUG] — matching the fuzzer's
       trim-BUG-then-trim-IJON_BYTES sequence. */
    __afl_map_size = (((__afl_map_size + 63) >> 6) << 6);
    if (__afl_bug_map_increased) {

      /* Strip the trailing BUG region we already appended; we'll
         re-append after the IJON bump. */
      __afl_map_size -= MAP_SIZE_BUG_BYTES;
      __afl_bug_map_increased = 0;
      __afl_bug_map = NULL;

    }

    __afl_cov_map_size = __afl_map_size;
    __afl_map_size += MAP_SIZE_IJON_MAP + MAP_SIZE_IJON_BYTES;
    __afl_set_map_size = __afl_map_size - MAP_SIZE_IJON_BYTES;
    __afl_ijon_map_increased = 1;
    __afl_bug_append_map();
    __afl_bug_bind_map();

  } else if (!__afl_cov_map_size) {

    __afl_set_map_size = __afl_cov_map_size = __afl_map_size;

  }

  /* Disable as this seems to create problems in corner cases
    if (getenv("LD_BIND_LAZY") == NULL) {

      // prevent further executed programs to fuck up the coverage
      setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 1);

    }

  */

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

  if (getenv("AFL_PRELOAD_DISCRIMINATE_FORKSERVER_PARENT") != NULL) {

    __afl_forkserver_setenv = 1;

  }

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  // return because possible non-forkserver usage
  if (write(FORKSRV_FD + 1, msg, 4) != 4) {

    /* No forkserver parent. A tool that attached a shared map still watches
       this run - afl-showmap on a single input and afl-cmin.bash through it
       execve the target directly - and that map was sized from what this
       target reported, IJON areas included, so the IJON channels stay live
       for it. Without a shared map there is nobody to read them. */
    if (!getenv(SHM_ENV_VAR) && !getenv(SHM_FD_ENV_VAR)) {

      __afl_ijon_enabled = 0;
      __afl_ijon_map_increased = 1;

    }

    return;

  }

  if (!__afl_old_forkserver) {

    if (read(FORKSRV_FD, reply, 4) != 4) { _exit(1); }
    if (tmp != status2) {

      write_error("wrong forkserver message from AFL++ tool");
      _exit(1);

    }

    // send the set/requested options to forkserver
    status = FS_NEW_OPT_MAPSIZE;  // we always send the map size
    if (__afl_sharedmem_fuzzing) { status |= FS_NEW_OPT_SHDMEM_FUZZ; }
#if defined(__linux__) || defined(__APPLE__)
    /* __afl_map_size is final here (coverage + any IJON + any bug map). The
       fuzzer places the sync word past the whole map, but guard against ever
       letting it overlap that region: if it would, drop futex sync (fall back
       to file descriptors) rather than corrupt IJON/bug data. */
    if (__afl_child_sync && __afl_child_sync_off < __afl_map_size) {

      __afl_child_sync = NULL;

    }

#endif
    if (__afl_child_sync) { status |= FS_NEW_OPT_FUTEX; }
    if (__afl_bug_mode & AFL_BUG_MODE_DERIVE) {

      status |= FS_NEW_OPT_ALLOCSIZE_DERIVE;

    }

    if (__afl_vp_map && __afl_vp_target_supports_runtime()) {

      status |= FS_NEW_OPT_VALUE_PROFILE;

      /* Fault the whole VP map into the forkserver parent once, so forked
         children inherit its page table entries instead of faulting each page
         in per execution. The read-then-write matters: a pure read leaves the
         shared pages mapped read-only and children still fault on first write.
         The pointer must stay volatile or the self-assignment is elided. */
      volatile u8 *vp_pages = (volatile u8 *)__afl_vp_map;
      long         vp_page_size = sysconf(_SC_PAGE_SIZE);
      if (vp_page_size > 0) {

        for (size_t off = 0; off < sizeof(vp_map_t);
             off += (size_t)vp_page_size) {

          vp_pages[off] = vp_pages[off];

        }

      }

    }

    if (__afl_dictionary_len && __afl_dictionary) {

      status |= FS_NEW_OPT_AUTODICT;

    }

    /* Add IJON capability flag if IJON is enabled */
    if (__afl_ijon_enabled) { status |= FS_OPT_IJON; }

    /* Add C11 capability flag if C11 is enabled */
    if (__afl_c11_enabled) { status |= FS_OPT_C11; }

    /* Signal that the last MAP_SIZE_BUG_BYTES of trace_bits are the bug
       map, not coverage.  The fuzzer subtracts this in
       configure_bug_runtime(); without the flag it would treat the bug
       map as coverage edges and report bogus new-edges every run. */
    if (__afl_bug_map_active && __afl_bug_map_increased) {

      status |= FS_NEW_OPT_BUG_MAP;

    }

    if (write(FORKSRV_FD + 1, msg, 4) != 4) {

      errno = 0;
      _exit(1);

    }

    // Now send the parameters for the set options, increasing by option number

    // FS_NEW_OPT_MAPSIZE - we always send the map size
    status = __afl_map_size;
    if (write(FORKSRV_FD + 1, msg, 4) != 4) { _exit(1); }

    // FS_NEW_OPT_SHDMEM_FUZZ - no data

    // FS_NEW_OPT_FUTEX - no data

    // FS_NEW_OPT_ALLOCSIZE_DERIVE - no data

    // FS_NEW_OPT_BUG_MAP - no data

    // FS_NEW_OPT_VALUE_PROFILE - no data

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

#if defined(__linux__) || defined(__APPLE__)
      /* Clear any stale AFL_CHILD_EXITED in the futex before forking the
         new child.  Our previous-iteration EXITED write (above) and the
         fuzzer's IDLE write (at end of run_target) are unordered, so the
         futex could hold either.  We do this AFTER reading ctl (which
         sequences us past the previous EXITED write -- ctl read happens
         after that write in this loop body) and BEFORE fork(), so the
         new child sees AFL_CHILD_IDLE on its first __afl_persistent_loop
         CAS.  Otherwise the fuzzer would see stale EXITED on entry to
         afl_futex_wait, return immediately without setting
         last_run_timed_out, and the SIGKILL escalation in the fuzzer
         would kill the innocent new child and misclassify the timeout
         as a crash. */
      if (likely(__afl_child_sync)) {

        __atomic_store_n(__afl_child_sync, AFL_CHILD_IDLE, __ATOMIC_RELEASE);

      }

#endif

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

        if (unlikely(__afl_forkserver_setenv)) {

          unsetenv("AFL_FORKSERVER_PARENT");

        }

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

    /* Relay wait status to pipe BEFORE signaling via futex.  The fuzzer reads
       the pipe immediately after waking on AFL_CHILD_EXITED; writing first
       guarantees the data is already there and avoids a blocking pipe read. */
    if (unlikely(write(FORKSRV_FD + 1, &status, 4) != 4)) {

      write_error("writing to afl-fuzz");
      _exit(1);

    }

#if defined(__linux__) || defined(__APPLE__)
    if (!child_stopped && likely(__afl_child_sync)) {

      /* Child exited (crash or normal cycle end). Signal the fuzzer
         via futex; pipe data is already written above. */
      __atomic_store_n(__afl_child_sync, AFL_CHILD_EXITED, __ATOMIC_RELEASE);
      afl_sync_wake(__afl_child_sync);

    }

#endif

  }

}

/* A simplified persistent mode handler, used as explained in
 * README.llvm.md. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;
#ifdef __APPLE__
  static pid_t afl_orig_ppid = 0;
#endif

#ifdef AFL_PERSISTENT_RECORD
  char tcase[PATH_MAX];
#endif

  if (unlikely(first_pass)) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    memset_noasan(__afl_area_ptr, 0, __afl_set_map_size);
    /* Bug map lives past __afl_set_map_size (trailing tail of trace_bits);
       it needs an explicit zero or stale MAX-channel values persist. */
    if (unlikely(__afl_cmp_map)) {

      memset_noasan(__afl_cmp_cursor, 0, sizeof(__afl_cmp_cursor));

    }

    if (unlikely(__afl_bug_map_active && __afl_bug_map &&
                 __afl_bug_map == (u32 *)(__afl_area_ptr + __afl_map_size -
                                          MAP_SIZE_BUG_BYTES))) {

      memset_noasan(__afl_bug_map, 0, MAP_SIZE_BUG_BYTES);

    }

    __afl_area_ptr[0] = 1;
    __afl_prev_loc = 0;
    __afl_alloc_persistent_reset(0);

    first_pass = 0;
#ifdef __APPLE__
    afl_orig_ppid = getppid();
#endif
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

      __afl_alloc_persistent_reset(1);

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

    __afl_alloc_persistent_reset(1);

#if defined(__linux__) || defined(__APPLE__)
    if (likely(__afl_child_sync)) {

      /* Signal the fuzzer that this iteration is complete.
         A blind store would deadlock the next FUTEX_WAIT in the race where
         the fuzzer just wrote AFL_CHILD_EXITED on a timeout: we would
         overwrite EXITED with DONE, then sleep in FUTEX_WAIT(DONE), and
         the fuzzer (already past its wake) never writes anything again.
         This bites whenever child_kill_signal is non-fatal (SIGTERM is the
         default in persistent mode) and the target catches or blocks it.
         CAS so we exit cleanly instead of overwriting EXITED. The loop
         iterates at most twice -- once on the very first call when the
         futex is still AFL_CHILD_IDLE because the fuzzer hasn't written
         RUN yet, then once with the updated expected value. */
      u32 expected = AFL_CHILD_RUN;
      while (!__atomic_compare_exchange_n(__afl_child_sync, &expected,
                                          AFL_CHILD_DONE, 0, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE)) {

        if (unlikely(expected == AFL_CHILD_EXITED)) { _exit(0); }

      }

      afl_sync_wake(__afl_child_sync);

      /* Wait until the fuzzer signals us to run the next test case.
         On Linux no timeout is needed: PR_SET_PDEATHSIG ensures the kernel
         delivers SIGKILL if the forkserver (our parent) dies. */
      u32 sync_val;
      while ((sync_val = __atomic_load_n(__afl_child_sync, __ATOMIC_ACQUIRE)) ==
             AFL_CHILD_DONE) {

  #ifdef __linux__
        sys_futex(__afl_child_sync, FUTEX_WAIT, AFL_CHILD_DONE, NULL, NULL, 0);
  #else
        int r = os_sync_wait_on_address_with_timeout(
            __afl_child_sync, (uint64_t)AFL_CHILD_DONE, sizeof(u32),
            OS_SYNC_WAIT_ON_ADDRESS_SHARED, OS_CLOCK_MACH_ABSOLUTE_TIME,
            250ULL * 1000ULL * 1000ULL);
        if (r == -1 && errno == ETIMEDOUT && getppid() != afl_orig_ppid) {

          _exit(0);

        }

  #endif

      }

      /* The fuzzer may set EXITED (e.g. timeout with a non-fatal kill signal
         such as SIGTERM) to request a clean exit instead of another run. */
      if (unlikely(sync_val == AFL_CHILD_EXITED)) { _exit(0); }

    } else

#endif
      raise(SIGSTOP);

    __afl_area_ptr[0] = 1;
    if (unlikely(__afl_ijon_state)) { __afl_ijon_state = 0; }
    if (unlikely(__afl_selective_coverage_temp)) {

      __afl_selective_coverage_temp = 0;

    }

    __afl_prev_loc = 0;

    return 1;

  } else {

    /* When exiting __AFL_LOOP(), make sure that the subsequent code that
        follows the loop is not traced. We do that by pivoting back to the
        dummy output region. */

    __afl_alloc_persistent_reset(1);
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

  if (getenv("AFL_LLVM_ONLY_FSRV") || getenv("AFL_GCC_ONLY_FSRV") ||
      getenv("AFL_GCC_ONLY_FRSV")) {

    fprintf(stderr,
            "DEBUG: Overwrite area_ptr to dummy due to "
            "AFL_LLVM_ONLY_FSRV/AFL_GCC_ONLY_FSRV\n");
    __afl_area_ptr = __afl_area_ptr_dummy;

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

    if (__afl_map_addr)
      ptr = (u8 *)mmap((void *)__afl_map_addr, __afl_first_final_loc,
                       PROT_READ | PROT_WRITE,
                       MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    else
      ptr = (u8 *)malloc(__afl_first_final_loc);

    if (ptr && (ssize_t)ptr != -1) {

      u8 *old_area = __afl_area_ptr;
      __afl_area_ptr = ptr;
      __afl_area_ptr_dummy = __afl_area_ptr;
      __afl_area_ptr_backup = __afl_area_ptr;

      if (old_area && old_area != __afl_area_initial) free(old_area);

    }

  }

}  // ptr memleak report is a false positive

/* preset __afl_area_ptr #1 - at constructor level 0 global variables have
   not been set */

/*
__attribute__((constructor(0))) void __afl_auto_first(void) {

  if (__afl_already_initialized_first) return;
  __afl_already_initialized_first = 1;

  if (getenv("AFL_DISABLE_LLVM_INSTRUMENTATION")) return;

}  // ptr memleak report is a false positive

*/

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

  __afl_area_ptr[*guard] =
      __afl_area_ptr[*guard] + 1 + (__afl_area_ptr[*guard] == 255 ? 1 : 0);

}

#ifdef __AFL_CODE_COVERAGE
void afl_read_pc_filter_file(const char *filter_file) {

  FILE *file;
  int   ch;

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

    fclose(file);
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

/* Write a single module's info to the modmap shared memory */

static void afl_write_mod_map(const char *name, u32 start_id, u32 stop_id) {

  if (!__afl_modmap_ptr || !__afl_modmap_size) { return; }

  // First, check if module already exists
  for (u32 i = 0; i < __afl_modmap_size; i++) {

    if (__afl_modmap_ptr[i].loaded &&
        strcmp(__afl_modmap_ptr[i].name, name) == 0) {

      // Module already exists, skip adding
      if (__afl_debug) {

        fprintf(
            stderr,
            "DEBUG: Module already in modmap, skipping: %s (existing: %u-%u, "
            "new: %u-%u)\n",
            name, __afl_modmap_ptr[i].start_id, __afl_modmap_ptr[i].stop_id,
            start_id, stop_id);

      }

      return;

    }

  }

  // Find first empty slot
  for (u32 i = 0; i < __afl_modmap_size; i++) {

    if (!__afl_modmap_ptr[i].loaded) {

      // Copy module info to this slot
      strncpy(__afl_modmap_ptr[i].name, name,
              sizeof(__afl_modmap_ptr[i].name) - 1);
      __afl_modmap_ptr[i].name[sizeof(__afl_modmap_ptr[i].name) - 1] = '\0';
      __afl_modmap_ptr[i].start_id = start_id;
      __afl_modmap_ptr[i].stop_id = stop_id;
      __afl_modmap_ptr[i].loaded = 1;

      if (__afl_debug) {

        fprintf(stderr, "DEBUG: Added module to modmap[%u]: %s %u %u\n", i,
                name, start_id, stop_id);

      }

      return;

    }

  }

  // No empty slots available
  fprintf(stderr,
          "ERROR: Module map is full (%u entries). Cannot add module: %s\n",
          __afl_modmap_size, name);
  abort();

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

    // Save the module edge IDs in case they are nulled out by filtering
    u32 mod_start_id = *mod_info->start;
    u32 mod_stop_id = *mod_info->stop;

    u32 in_module_index = 0;

    while (start < end) {

      uintptr_t PC = start->PC;

      // Calculate relative offset in module
      PC = PC - mod_info->base_address;

      // Read the guard value at this position
      u32 guard_val = *(mod_info->start + in_module_index);

      // Map edge ID to PC (pcmap)
      if (__afl_pcmap_ptr) {

        // Skip guards that are disabled (set to 0)
        if (guard_val != 0) {

          if (guard_val < __afl_map_size) {

            __afl_pcmap_ptr[guard_val] = PC;

          } else {

            fprintf(
                stderr,
                "ERROR: __sanitizer_cov_pcs_init guard value %u >= map_size "
                "%u at in_module_index %u (pcmap) (%s)\n",
                guard_val, __afl_map_size, in_module_index, mod_info->name);
            abort();

          }

        }

      }

      if (pc_filter && !mod_info->next) {

        char PcDescr[1024];

        // This function is a part of the sanitizer run-time, so it is only
        // there if the target was linked with one. Without it there is nothing
        // to match the filter against, and calling through the null weak
        // symbol would just crash here.
        if (!__sanitizer_symbolize_pc) {

          fprintf(stderr,
                  "Error: AFL_PC_FILTER needs __sanitizer_symbolize_pc(), "
                  "which is part of the sanitizer runtime - rebuild the "
                  "target with AFL_USE_ASAN=1 (or another sanitizer).\n");
          abort();

        }

        __sanitizer_symbolize_pc((void *)start->PC, "%p %F %L", PcDescr,
                                 sizeof(PcDescr));

        if (strstr(PcDescr, pc_filter)) {

          if (__afl_debug)
            fprintf(
                stderr,
                "DEBUG: Selective instrumentation match: %s (PC %p Index %u)\n",
                PcDescr, (void *)start->PC, guard_val);
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

    // Mark as mapped when pcmap buffer is ready
    if (__afl_pcmap_ptr) { mod_info->mapped = 1; }

    // Write modmap only if module is marked as mapped (i.e., fully processed)
    // Use original edge IDs before filtering modified them
    if (mod_info->mapped && __afl_modmap_ptr && __afl_modmap_size &&
        mod_info->stop) {

      afl_write_mod_map(mod_info->name, mod_start_id, mod_stop_id);

    }

    if (__afl_debug) {

      fprintf(stderr,
              "DEBUG: __sanitizer_cov_pcs_init successfully mapped %s with %u "
              "PCs\n",
              mod_info->name, in_module_index);

    }

    // If PC filter is active and module doesn't match, disable all guards
    if (__afl_filter_pcs && mod_info->start && mod_info->stop &&
        !strstr(mod_info->name, __afl_filter_pcs_module)) {

      if (__afl_debug)
        fprintf(stderr,
                "DEBUG: Disabling all %u guards for non-matching module: %s\n",
                *(mod_info->stop) - *(mod_info->start) + 1, mod_info->name);

      // Null out all guards for this module
      for (u32 *guard = mod_info->start; guard <= mod_info->stop; guard++) {

        *guard = 0;

      }

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

  //_is_sancov = 1;

  if (!getenv("AFL_DUMP_MAP_SIZE")) {

    //__afl_auto_first();
    __afl_auto_second();
    __afl_auto_early();

  }

  if (__afl_debug) {

    fprintf(
        stderr,
        "DEBUG: Running __sanitizer_cov_trace_pc_guard_init: %p-%p (%lu edges) "
        "after_fs=%u *start=%u\n",
        start, stop, (unsigned long)(stop - start),
        __afl_already_initialized_forkserver, start ? *start : 0);

  }

  if (!start || start == stop || *start) { return; }

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
            (likely(inst_ratio == 100) || AFL_R(100) < inst_ratio)) {

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

    if (likely(inst_ratio == 100) || AFL_R(100) < inst_ratio) {

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

  /*
  // IJON SUPPORT: Apply deferred IJON expansion now that __afl_final_loc is
  known if (__afl_ijon_enabled && __afl_final_loc
  > 0) { u32 coverage_size = __afl_final_loc + 1;

    // If we're still using the default MAP_SIZE, update to actual coverage +
  IJON if (__afl_map_size == MAP_SIZE) {

      __afl_map_size = coverage_size + MAP_SIZE_IJON_MAP + MAP_SIZE_IJON_BYTES;

    }

  }

  */

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
    __afl_set_map_size = __afl_cov_map_size = __afl_map_size;
    __afl_bug_map_increased = 0;
    /* The reset above dropped the IJON regions from __afl_map_size, so the
       expansion has to run again - a second instrumented module (a shared
       library plus the executable) reaches this after an earlier module
       already expanded once. */
    __afl_ijon_map_increased = 0;

    // IJON SUPPORT: Re-apply IJON expansion after reinit
    if (__afl_ijon_enabled && !__afl_ijon_map_increased) {

      __afl_map_size = (((__afl_map_size + 63) >> 6) << 6);
      __afl_cov_map_size = __afl_map_size;
      __afl_map_size += MAP_SIZE_IJON_MAP + MAP_SIZE_IJON_BYTES;
      __afl_set_map_size = __afl_map_size - MAP_SIZE_IJON_BYTES;
      __afl_ijon_map_increased = 1;

    }

    __afl_bug_configure_runtime();
    __afl_bug_append_map();
    __afl_bug_bind_map();

    if (__afl_debug) {

      fprintf(stderr,
              "DEBUG: after guard init: __afl_map_size %u, __afl_cov_map_size "
              "%u, __afl_set_map_size %u\n",
              __afl_map_size, __afl_cov_map_size, __afl_set_map_size);

    }

  }

}

///// CmpLog instrumentation

static inline u32 cmplog_reserve(u64 site, u8 type, u8 shape, u8 attr,
                                 u32 capacity, u32 *slot, u32 *occurrence) {

  u32 key = cmp_map_select(__afl_cmp_map, site);
  if (unlikely(key == CMP_MAP_W)) { return key; }

  struct cmp_header *header = &__afl_cmp_map->headers[key];
  if (unlikely(header->hits &&
               (header->type != type ||
                cmp_map_attribute(__afl_cmp_map, key) != attr))) {

    return CMP_MAP_W;

  }

  if (!header->hits) {

    header->type = type;
    header->shape = shape;
    cmp_map_set_attribute(__afl_cmp_map, key, attr);

  } else if (header->shape < shape) {

    header->shape = shape;

  }

  *slot = cmp_map_reserve(header, &__afl_cmp_cursor[key], capacity, occurrence);
  return key;

}

static inline void cmplog_ins1(u64 site, uint8_t arg1, uint8_t arg2,
                               uint8_t attr) {

  if (likely(!__afl_cmp_map) || unlikely(arg1 == arg2)) return;
  u32 slot, occurrence;
  u32 key = cmplog_reserve(site, CMP_TYPE_INS, 0, attr, CMP_MAP_H, &slot,
                           &occurrence);
  if (unlikely(key == CMP_MAP_W)) { return; }
  __afl_cmp_map->log[key][slot].v0 = arg1;
  __afl_cmp_map->log[key][slot].v1 = arg2;
  __afl_cmp_map->log[key][slot].occurrence = occurrence;

}

static inline void cmplog_ins2(u64 site, uint16_t arg1, uint16_t arg2,
                               uint8_t attr) {

  if (likely(!__afl_cmp_map) || unlikely(arg1 == arg2)) return;
  u32 slot, occurrence;
  u32 key = cmplog_reserve(site, CMP_TYPE_INS, 1, attr, CMP_MAP_H, &slot,
                           &occurrence);
  if (unlikely(key == CMP_MAP_W)) { return; }
  __afl_cmp_map->log[key][slot].v0 = arg1;
  __afl_cmp_map->log[key][slot].v1 = arg2;
  __afl_cmp_map->log[key][slot].occurrence = occurrence;

}

static inline void cmplog_ins4(u64 site, uint32_t arg1, uint32_t arg2,
                               uint8_t attr) {

  if (likely(!__afl_cmp_map) || unlikely(arg1 == arg2)) return;
  u32 slot, occurrence;
  u32 key = cmplog_reserve(site, CMP_TYPE_INS, 3, attr, CMP_MAP_H, &slot,
                           &occurrence);
  if (unlikely(key == CMP_MAP_W)) { return; }
  __afl_cmp_map->log[key][slot].v0 = arg1;
  __afl_cmp_map->log[key][slot].v1 = arg2;
  __afl_cmp_map->log[key][slot].occurrence = occurrence;

}

static inline void cmplog_ins8(u64 site, uint64_t arg1, uint64_t arg2,
                               uint8_t attr) {

  if (likely(!__afl_cmp_map) || unlikely(arg1 == arg2)) return;
  u32 slot, occurrence;
  u32 key = cmplog_reserve(site, CMP_TYPE_INS, 7, attr, CMP_MAP_H, &slot,
                           &occurrence);
  if (unlikely(key == CMP_MAP_W)) { return; }
  __afl_cmp_map->log[key][slot].v0 = arg1;
  __afl_cmp_map->log[key][slot].v1 = arg2;
  __afl_cmp_map->log[key][slot].occurrence = occurrence;

}

void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr) {

  cmplog_ins1((u64)(uintptr_t)__builtin_return_address(0), arg1, arg2, attr);

}

void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr) {

  cmplog_ins2((u64)(uintptr_t)__builtin_return_address(0), arg1, arg2, attr);

}

void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr) {

  cmplog_ins4((u64)(uintptr_t)__builtin_return_address(0), arg1, arg2, attr);

}

void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr) {

  cmplog_ins8((u64)(uintptr_t)__builtin_return_address(0), arg1, arg2, attr);

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

  u32 slot, occurrence;
  u32 k =
      cmplog_reserve((u64)(uintptr_t)__builtin_return_address(0), CMP_TYPE_INS,
                     size, attr, CMP_MAP_H, &slot, &occurrence);
  if (unlikely(k == CMP_MAP_W)) { return; }

  __afl_cmp_map->log[k][slot].v0 = (u64)arg1;
  __afl_cmp_map->log[k][slot].v1 = (u64)arg2;
  __afl_cmp_map->log[k][slot].occurrence = occurrence;

  if (size > 7) {

    __afl_cmp_map->log[k][slot].v0_128 = (u64)(arg1 >> 64);
    __afl_cmp_map->log[k][slot].v1_128 = (u64)(arg2 >> 64);

  }

}

static inline void cmplog_ins16(u64 site, uint128_t arg1, uint128_t arg2,
                                uint8_t attr) {

  if (likely(!__afl_cmp_map)) return;
  if (16 > __afl_cmplog_max_len || unlikely(arg1 == arg2)) return;

  u32 slot, occurrence;
  u32 k = cmplog_reserve(site, CMP_TYPE_INS, 15, attr, CMP_MAP_H, &slot,
                         &occurrence);
  if (unlikely(k == CMP_MAP_W)) { return; }

  __afl_cmp_map->log[k][slot].v0 = (u64)arg1;
  __afl_cmp_map->log[k][slot].v1 = (u64)arg2;
  __afl_cmp_map->log[k][slot].v0_128 = (u64)(arg1 >> 64);
  __afl_cmp_map->log[k][slot].v1_128 = (u64)(arg2 >> 64);
  __afl_cmp_map->log[k][slot].occurrence = occurrence;

}

void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2, uint8_t attr) {

  cmplog_ins16((u64)(uintptr_t)__builtin_return_address(0), arg1, arg2, attr);

}

#endif

#ifdef WORD_SIZE_64
/* Bit length for uint128_t (0 for input 0). */
static inline u32 vp_bitlen_u128(uint128_t v) {

  u64 hi = (u64)(v >> 64);
  if (hi) return 64U + bit_length_u64(hi);
  return bit_length_u64((u64)v);

}

/* Popcount for uint128_t. */
static inline u32 vp_popcnt_u128(uint128_t v) {

  return popcount_u64((u64)v) + popcount_u64((u64)(v >> 64));

}

/* Keep only the lowest `bits` bits from a 128-bit operand.
   This aligns VP distance calculations with the real compare width. */
static inline uint128_t vp_mask_u128(uint128_t v, u8 bits) {

  if (bits >= 128) return v;
  if (bits <= 64) {

    if (!bits) return 0;
    u64 mask = (bits == 64) ? ~(u64)0 : ((1ULL << bits) - 1ULL);
    return (uint128_t)((u64)v & mask);

  }

  u8  hi_bits = bits - 64;
  u64 lo = (u64)v;
  u64 hi = (u64)(v >> 64);
  if (hi_bits < 64) { hi &= ((1ULL << hi_bits) - 1ULL); }

  return ((uint128_t)hi << 64) | lo;

}

static inline u16 vp_runtime_abs_dist_u128(uint128_t arg1, uint128_t arg2,
                                           u8 bits, u8 attr) {

  if (!bits) return 0;
  arg1 = vp_mask_u128(arg1, bits);
  arg2 = vp_mask_u128(arg2, bits);

  if (attr >= CMP_ATTR_ICMP_SGT && attr <= CMP_ATTR_ICMP_SLE) {

    /* Map two's-complement signed order to unsigned order before computing
       the absolute bucket distance. */
    uint128_t sign = ((uint128_t)1) << (bits - 1);
    arg1 ^= sign;
    arg2 ^= sign;

  }

  uint128_t diff = arg1 >= arg2 ? arg1 - arg2 : arg2 - arg1;
  return (u16)vp_bitlen_u128(diff);

}

#endif

/* Runtime predicate gate. Records all predicates today; this is the seam for
   future filtering experiments, such as EQ/NE-only collection. */
static inline u8 vp_runtime_allow_predicate(u8 attr) {

  (void)attr;
  return 1;

}

static inline u64 vp_runtime_site_token_pc(uintptr_t pc, u64 salt) {

  return hash_fmix64((u64)pc ^ salt);

}

#define VP_RUNTIME_INS1_SALT 0x56505254494e5301ULL
#define VP_RUNTIME_INS2_SALT 0x56505254494e5302ULL
#define VP_RUNTIME_INS4_SALT 0x56505254494e5304ULL
#define VP_RUNTIME_INS8_SALT 0x56505254494e5308ULL
#define VP_RUNTIME_INS16_SALT 0x56505254494e5310ULL
#define VP_RUNTIME_SWITCH_SALT 0x5650525453574954ULL
#define VP_RUNTIME_RTN_SALT 0x5650525452544e00ULL

/* Append a touched site to control[] for this execution; track drops when full.
 */
static inline void vp_runtime_append_control(vp_map_t *vp, u16 site_id) {

  if (vp->control_len < VP_CONTROL_CAP) {

    vp->control[vp->control_len++] = site_id;

  }

}

/* Select a physical site and prepare its per-exec state. Strictly filtered
   observation may only reuse assignments established by normal campaign
   execution; the focus set still lets unseen sites claim a key. */
static inline vp_site_t *vp_runtime_prepare_site(vp_map_t *vp, u64 site_token,
                                                 u16 *site_id) {

  u8  filter = vp->filter_mode;
  u32 key = vp_map_select(vp, site_token, (u8)(filter != VP_FILTER_STRICT));
  if (unlikely(key == VP_MAP_INVALID)) return NULL;
  *site_id = (u16)key;

  if (unlikely(filter) &&
      !(vp->filter_bitmap[key >> 6] & (1ULL << (key & 63)))) {

    return NULL;

  }

  vp_site_t *site = &vp->site[key];
  if (unlikely(site->flags & VP_SITE_RETIRED)) return NULL;

  if (unlikely(site->exec_seen != vp->exec_id)) {

    /* Lazy per-site reset: only clear metadata for sites touched in this
       execution, avoiding a full VP_MAP_W sweep every run. */
    site->exec_seen = vp->exec_id;
    site->hit_count = 0;
    site->touched_mask = 0;

  }

  return site;

}

static inline void vp_runtime_store_dist_pair(vp_map_t *vp, u16 site_id,
                                              vp_site_t *site, u16 slot_idx,
                                              u16 dist0, u16 dist1) {

  u16 touched = site->touched_mask;
  if (touched != VP_SLOT_MASK) {

    u16 pair_mask = (u16)(3U << slot_idx);
    /* Adjacent metric slots are initialized as one pair. */
    if (!(touched & pair_mask)) {

      site->slots[slot_idx].best_dist = dist0;
      site->slots[slot_idx + 1U].best_dist = dist1;
      site->touched_mask = touched | pair_mask;
      if (!touched) { vp_runtime_append_control(vp, site_id); }
      return;

    }

  }

  if (unlikely(dist0 < site->slots[slot_idx].best_dist)) {

    site->slots[slot_idx].best_dist = dist0;

  }

  if (unlikely(dist1 < site->slots[slot_idx + 1U].best_dist)) {

    site->slots[slot_idx + 1U].best_dist = dist1;

  }

}

static inline u8 vp_runtime_u64_has_zero_byte(u64 v) {

  return (u8)(((v - 0x0101010101010101ULL) & ~v & 0x8080808080808080ULL) != 0);

}

static inline u32 vp_runtime_hamming_sum_bytes(const u8 *ptr1, const u8 *ptr2,
                                               u32 len) {

  u32 total = 0;
  while (len >= sizeof(u64)) {

    u64 lhs = 0, rhs = 0;
    memcpy((void *)&lhs, (const void *)ptr1, sizeof(lhs));
    memcpy((void *)&rhs, (const void *)ptr2, sizeof(rhs));
    total += popcount_u64(lhs ^ rhs);
    ptr1 += sizeof(u64);
    ptr2 += sizeof(u64);
    len -= sizeof(u64);

  }

  while (len--) {

    total += popcount_u8(*ptr1 ^ *ptr2);
    ++ptr1;
    ++ptr2;

  }

  return total;

}

static inline u32 vp_runtime_hamming_sum_bytes_stop_at_zero(const u8 *ptr1,
                                                            const u8 *ptr2,
                                                            u32       len) {

  u32 total = 0;
  while (len >= sizeof(u64)) {

    u64 lhs = 0, rhs = 0;
    memcpy((void *)&lhs, (const void *)ptr1, sizeof(lhs));
    memcpy((void *)&rhs, (const void *)ptr2, sizeof(rhs));
    if (vp_runtime_u64_has_zero_byte(lhs | rhs)) break;
    total += popcount_u64(lhs ^ rhs);
    ptr1 += sizeof(u64);
    ptr2 += sizeof(u64);
    len -= sizeof(u64);

  }

  while (len--) {

    if (!*ptr1 && !*ptr2) break;
    total += popcount_u8(*ptr1 ^ *ptr2);
    ++ptr1;
    ++ptr2;

  }

  return total;

}

static inline u64 vp_mask_u64_bits(u64 v, u8 bits) {

  if (!bits) return 0;
  if (bits >= 64) return v;
  return v & ((1ULL << bits) - 1ULL);

}

static inline u16 vp_runtime_abs_dist_u64(u64 arg1, u64 arg2, u8 bits,
                                          u8 attr) {

  if (!bits) return 0;
  arg1 = vp_mask_u64_bits(arg1, bits);
  arg2 = vp_mask_u64_bits(arg2, bits);

  if (attr >= CMP_ATTR_ICMP_SGT && attr <= CMP_ATTR_ICMP_SLE) {

    /* Map two's-complement signed order to unsigned order before computing
       the absolute bucket distance. */
    u64 sign = 1ULL << (bits - 1);
    arg1 ^= sign;
    arg2 ^= sign;

  }

  u64 diff = arg1 >= arg2 ? arg1 - arg2 : arg2 - arg1;
  return (u16)bit_length_u64(diff);

}

static inline u32 vp_runtime_float_order_key(u32 raw) {

  /* IEEE-754 bit patterns are not ordered across the sign boundary. This
     radix-sort key makes adjacent finite values adjacent in unsigned order. */
  return (raw & 0x80000000U) ? ~raw : (raw ^ 0x80000000U);

}

static inline u64 vp_runtime_double_order_key(u64 raw) {

  /* Same ordered-key transform as vp_runtime_float_order_key(), for doubles. */
  return (raw & 0x8000000000000000ULL) ? ~raw : (raw ^ 0x8000000000000000ULL);

}

/* Each dynamic hit at a selected physical site owns one adjacent metric pair.
   VP_SLOTS is an even power of two, so pair_count wraps cheaply via a mask.
   The u16 hit ordinal wraps seamlessly because its 2^16 values are an exact
   multiple of VP_PAIR_COUNT. */
static inline u16 vp_runtime_scalar_pair_start_slot(u16 hit_ordinal) {

#if VP_PAIR_COUNT <= 1U
  (void)hit_ordinal;
  return 0;
#else
  return (u16)((hit_ordinal & (VP_PAIR_COUNT - 1U)) << 1);
#endif

}

/* Scalar compares benefit from keeping bitwise and numeric gradients
   independent. This avoids low-hamming but numerically distant values
   crowding out inputs that actually reduce the absolute difference. */
static inline void vp_runtime_record_scalar_dists(u64 site_token,
                                                  u16 hamming_dist,
                                                  u16 abs_dist) {

  vp_map_t *vp = __afl_vp_map;
  if (likely(!vp || !vp->enabled)) return;

  u16        site_id;
  vp_site_t *site = vp_runtime_prepare_site(vp, site_token, &site_id);
  if (unlikely(!site)) return;
  u16 hit_ordinal = site->hit_count++;

  u16 slot = vp_runtime_scalar_pair_start_slot(hit_ordinal);
  vp_runtime_store_dist_pair(vp, site_id, site, slot, hamming_dist, abs_dist);

}

static inline void vp_runtime_record_switch_candidate(vp_map_t *vp, u16 site_id,
                                                      vp_site_t *site,
                                                      u64        val_masked,
                                                      u64        case_val,
                                                      u16 pseudo_hit_ordinal) {

  u64 diff =
      val_masked >= case_val ? val_masked - case_val : case_val - val_masked;
  u16 hamming_dist = (u16)popcount_u64(val_masked ^ case_val);
  u16 abs_dist = (u16)bit_length_u64(diff);
  u16 slot = vp_runtime_scalar_pair_start_slot(pseudo_hit_ordinal);
  vp_runtime_store_dist_pair(vp, site_id, site, slot, hamming_dist, abs_dist);

}

void __valueprofile_switch(uint64_t val, uint64_t *cases, uint64_t site_token) {

  vp_map_t *vp = __afl_vp_map;
  if (likely(!vp || !vp->enabled || !cases)) return;

  u64 case_count = cases[0];
  u64 bit_width = cases[1];
  if (unlikely(!case_count || !bit_width || bit_width > 64)) return;

  u16        site_id;
  vp_site_t *site = vp_runtime_prepare_site(vp, site_token, &site_id);
  if (unlikely(!site)) return;

  u64 mask =
      bit_width == 64 ? 0xffffffffffffffffULL : ((1ULL << bit_width) - 1ULL);
  u64 val_masked = val & mask;
  u64 smaller = 0;
  u64 larger = 0;
  u8  have_smaller = 0;
  u8  have_larger = 0;
  u8  exact_match = 0;

  for (u64 i = 0; i < case_count; ++i) {

    u64 case_val = cases[i + 2] & mask;
    if (val_masked == case_val) {

      smaller = case_val;
      have_smaller = 1;
      exact_match = 1;
      break;

    }

    if (case_val < val_masked) {

      if (!have_smaller || smaller < case_val) {

        smaller = case_val;
        have_smaller = 1;

      }

    } else if (!have_larger || case_val < larger) {

      larger = case_val;
      have_larger = 1;

    }

  }

  u16 dynamic_hit = site->hit_count++;
  u16 pseudo_hit = (u16)(dynamic_hit << 1);

  if (have_smaller) {

    vp_runtime_record_switch_candidate(vp, site_id, site, val_masked, smaller,
                                       pseudo_hit++);

  }

  if (have_larger && !exact_match) {

    vp_runtime_record_switch_candidate(vp, site_id, site, val_masked, larger,
                                       pseudo_hit);

  }

}

void __valueprofile_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr,
                          uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);

  } else {

    u32 hamming = popcount_u8(arg1 ^ arg2);
    u16 abs_dist = vp_runtime_abs_dist_u64((u64)arg1, (u64)arg2, 8, attr);
    vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

  }

}

void __valueprofile_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr,
                          uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);

  } else {

    u32 hamming = popcount_u32((u32)(arg1 ^ arg2));
    u16 abs_dist = vp_runtime_abs_dist_u64((u64)arg1, (u64)arg2, 16, attr);
    vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

  }

}

void __valueprofile_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr,
                          uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);

  } else {

    u32 hamming = popcount_u32(arg1 ^ arg2);
    u16 abs_dist = vp_runtime_abs_dist_u64((u64)arg1, (u64)arg2, 32, attr);
    vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

  }

}

void __valueprofile_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr,
                          uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);

  } else {

    u32 hamming = popcount_u64(arg1 ^ arg2);
    u16 abs_dist = vp_runtime_abs_dist_u64(arg1, arg2, 64, attr);
    vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

  }

}

#ifdef WORD_SIZE_64
void __valueprofile_hook16(uint128_t arg1, uint128_t arg2, uint8_t attr,
                           uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;

  arg1 = vp_mask_u128(arg1, 128);
  arg2 = vp_mask_u128(arg2, 128);

  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);

  } else {

    u32 hamming = vp_popcnt_u128(arg1 ^ arg2);
    u16 abs_dist = vp_runtime_abs_dist_u128(arg1, arg2, 128, attr);
    vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

  }

}

void __valueprofile_hookN(uint128_t arg1, uint128_t arg2, uint8_t attr,
                          uint8_t bits_minus_1, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  u32 bits_u32 = ((u32)bits_minus_1 + 1U) * 8U;
  if (bits_u32 > 128U) bits_u32 = 128U;
  u8 bits = (u8)bits_u32;

  arg1 = vp_mask_u128(arg1, bits);
  arg2 = vp_mask_u128(arg2, bits);

  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);

  } else {

    u32 hamming = vp_popcnt_u128(arg1 ^ arg2);
    u16 abs_dist = vp_runtime_abs_dist_u128(arg1, arg2, bits, attr);
    vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

  }

}

#endif

void __valueprofile_hook_float(float arg1, float arg2, uint8_t attr,
                               uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  if (isnan(arg1) || isnan(arg2)) return;
  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);
    return;

  }

  u32 b0 = 0, b1 = 0;
  memcpy((void *)&b0, (void *)&arg1, sizeof(b0));
  memcpy((void *)&b1, (void *)&arg2, sizeof(b1));
  u32 hamming = popcount_u32(b0 ^ b1);
  u32 k0 = vp_runtime_float_order_key(b0);
  u32 k1 = vp_runtime_float_order_key(b1);
  u32 diff = k0 >= k1 ? k0 - k1 : k1 - k0;
  u16 abs_dist = (u16)bit_length_u64((u64)diff);
  vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

}

void __valueprofile_hook_double(double arg1, double arg2, uint8_t attr,
                                uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (unlikely(!vp_runtime_allow_predicate(attr))) return;
  if (isnan(arg1) || isnan(arg2)) return;
  if (arg1 == arg2) {

    vp_runtime_record_scalar_dists(site_token, 0, 0);
    return;

  }

  u64 b0 = 0, b1 = 0;
  memcpy((void *)&b0, (void *)&arg1, sizeof(b0));
  memcpy((void *)&b1, (void *)&arg2, sizeof(b1));
  u32 hamming = popcount_u64(b0 ^ b1);
  u64 k0 = vp_runtime_double_order_key(b0);
  u64 k1 = vp_runtime_double_order_key(b1);
  u64 diff = k0 >= k1 ? k0 - k1 : k1 - k0;
  u16 abs_dist = (u16)bit_length_u64(diff);
  vp_runtime_record_scalar_dists(site_token, (u16)hamming, abs_dist);

}

#define VP_RTN_STOP_AT_ZERO 1u
#define VP_RTN_FOLD_CASE 2u

static inline u8 vp_runtime_fold(u8 c) {

  return (c >= 'A' && c <= 'Z') ? (u8)(c + 32) : c;

}

static inline u32 vp_runtime_hamming_sum_folded(const u8 *ptr1, const u8 *ptr2,
                                                u32 len, u8 stop_at_zero) {

  u32 total = 0;
  while (len--) {

    u8 a = vp_runtime_fold(*ptr1);
    u8 b = vp_runtime_fold(*ptr2);
    if (stop_at_zero && !a && !b) break;
    total += popcount_u8(a ^ b);
    ++ptr1;
    ++ptr2;

  }

  return total;

}

/* Compute routine-compare distance (memcmp/strcmp-style) and record it
   into runtime VP state. */
static inline void vp_runtime_record_rtn(u64 site_token, u8 *ptr1, u8 *ptr2,
                                         u32 max_len, u32 flags) {

  vp_map_t *vp = __afl_vp_map;
  if (likely(!vp || !vp->enabled)) return;
  if (unlikely(!ptr1 || !ptr2 || max_len < 1)) return;
  if (max_len > 32) max_len = 32;

  u8 stop_at_zero = (flags & VP_RTN_STOP_AT_ZERO) != 0;
  u8 fold = (flags & VP_RTN_FOLD_CASE) != 0;

  u16        site;
  vp_site_t *s = vp_runtime_prepare_site(vp, site_token, &site);
  if (unlikely(!s)) return;

  u32 prefix_len = 0;
  u8  solved = 0;
  while (prefix_len < max_len &&
         (fold ? vp_runtime_fold(ptr1[prefix_len]) ==
                     vp_runtime_fold(ptr2[prefix_len])
               : ptr1[prefix_len] == ptr2[prefix_len])) {

    if (stop_at_zero && ptr1[prefix_len] == 0) {

      solved = 1;
      break;

    }

    ++prefix_len;

  }

  if (prefix_len == max_len) solved = 1;

  u16 prefix_dist;
  u16 allbytes_dist;
  if (solved) {

    prefix_dist = 0;
    allbytes_dist = 0;

  } else {

    /* Metric 1: prefix-based (sequential gradient). */
    u32 rem = max_len - prefix_len;
    u8  b1 = fold ? vp_runtime_fold(ptr1[prefix_len]) : ptr1[prefix_len];
    u8  b2 = fold ? vp_runtime_fold(ptr2[prefix_len]) : ptr2[prefix_len];
    u32 first_diff_hamming = popcount_u8(b1 ^ b2);
    prefix_dist = (u16)(((rem - 1U) * 8U) + first_diff_hamming);

    /* Metric 2: sum-of-hamming across ALL differing bytes.
       Gives gradient for every byte, not just the first mismatch.
       Range 1..256 for max_len up to 32 (32 * 8 = 256). */
    u32 total_hamming =
        fold ? vp_runtime_hamming_sum_folded(ptr1 + prefix_len,
                                             ptr2 + prefix_len,
                                             max_len - prefix_len, stop_at_zero)
             : (stop_at_zero ? vp_runtime_hamming_sum_bytes_stop_at_zero(
                                   ptr1 + prefix_len, ptr2 + prefix_len,
                                   max_len - prefix_len)
                             : vp_runtime_hamming_sum_bytes(
                                   ptr1 + prefix_len, ptr2 + prefix_len,
                                   max_len - prefix_len));

    allbytes_dist = (u16)(total_hamming > 0 ? total_hamming : 1);

  }

  u16 hit_ordinal = s->hit_count++;

  u16 slot = vp_runtime_scalar_pair_start_slot(hit_ordinal);
  vp_runtime_store_dist_pair(vp, site, s, slot, prefix_dist, allbytes_dist);

}

/* Substring distance: the minimum of both metrics over every offset the needle
   could sit at, so a haystack that actually contains the needle records zero
   rather than the distance to offset 0. Callers pass the searchable haystack
   length, already truncated at a terminating nul where their routine stops
   there, so VP_RTN_STOP_AT_ZERO has no meaning here. */
static inline void vp_runtime_record_sub(u64 site_token, u8 *hay, u32 hay_len,
                                         u8 *needle, u32 needle_len,
                                         u32 flags) {

  vp_map_t *vp = __afl_vp_map;
  if (likely(!vp || !vp->enabled)) return;
  if (unlikely(!hay || !needle || needle_len < 1 || hay_len < needle_len))
    return;

  /* Claim the site before the O(hay_len * needle_len) scan so a full set
     skips the work instead of discarding it afterwards. */
  u16        site;
  vp_site_t *s = vp_runtime_prepare_site(vp, site_token, &site);
  if (unlikely(!s)) return;

  u8  fold = (flags & VP_RTN_FOLD_CASE) != 0;
  u32 best_prefix = 0xffffffffU;
  u32 best_total = 0xffffffffU;
  u32 last_off = hay_len - needle_len;

  for (u32 off = 0; off <= last_off; ++off) {

    u32 prefix = 0;
    u32 total = 0;
    while (prefix < needle_len) {

      u8 a = fold ? vp_runtime_fold(hay[off + prefix]) : hay[off + prefix];
      u8 b = fold ? vp_runtime_fold(needle[prefix]) : needle[prefix];
      if (a != b) break;
      ++prefix;

    }

    for (u32 i = prefix; i < needle_len; ++i) {

      u8 a = fold ? vp_runtime_fold(hay[off + i]) : hay[off + i];
      u8 b = fold ? vp_runtime_fold(needle[i]) : needle[i];
      total += popcount_u8(a ^ b);

    }

    u32 prefix_dist;
    if (prefix == needle_len) {

      prefix_dist = 0;

    } else {

      u8 a = fold ? vp_runtime_fold(hay[off + prefix]) : hay[off + prefix];
      u8 b = fold ? vp_runtime_fold(needle[prefix]) : needle[prefix];
      prefix_dist =
          (u16)(((needle_len - prefix - 1U) * 8U) + popcount_u8(a ^ b));

    }

    if (prefix_dist < best_prefix) { best_prefix = prefix_dist; }
    if (total < best_total) { best_total = total; }
    if (unlikely(!best_prefix && !best_total)) break;

  }

  u16 hit_ordinal = s->hit_count++;
  u16 slot = vp_runtime_scalar_pair_start_slot(hit_ordinal);
  vp_runtime_store_dist_pair(vp, site, s, slot, (u16)best_prefix,
                             (u16)best_total);

}

static inline u8 __afl_vp_collection_enabled(void) {

  return __afl_vp_map && __afl_vp_map->enabled;

}

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {

  (void)arg1;
  (void)arg2;

}

void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook1(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS1_SALT));
  else
    cmplog_ins1(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook2(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS2_SALT));
  else
    cmplog_ins2(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook2(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS2_SALT));
  else
    cmplog_ins2(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook4(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS4_SALT));
  else
    cmplog_ins4(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook4(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS4_SALT));
  else
    cmplog_ins4(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook8(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS8_SALT));
  else
    cmplog_ins8(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook8(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS8_SALT));
  else
    cmplog_ins8(site, arg1, arg2, CMP_ATTR_NONE);

}

#ifdef WORD_SIZE_64
void __sanitizer_cov_trace_cmp16(uint128_t arg1, uint128_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook16(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS16_SALT));
  else
    cmplog_ins16(site, arg1, arg2, CMP_ATTR_NONE);

}

void __sanitizer_cov_trace_const_cmp16(uint128_t arg1, uint128_t arg2) {

  u64 site = (u64)(uintptr_t)__builtin_return_address(0);
  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_hook16(
        arg1, arg2, CMP_ATTR_NONE,
        vp_runtime_site_token_pc((uintptr_t)site, VP_RUNTIME_INS16_SALT));
  else
    cmplog_ins16(site, arg1, arg2, CMP_ATTR_NONE);

}

#endif

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  if (unlikely(__afl_vp_collection_enabled())) {

    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    __valueprofile_switch(val, cases,
                          vp_runtime_site_token_pc(pc, VP_RUNTIME_SWITCH_SALT));

    return;

  }

  if (likely(!__afl_cmp_map)) return;

  for (uint64_t i = 0; i < cases[0]; i++) {

    u64 site = (u64)(uintptr_t)__builtin_return_address(0) + i;
    switch (cases[1]) {

      case 8:
        cmplog_ins1(site, (u8)val, (u8)cases[i + 2], CMP_ATTR_ICMP_EQ);
        break;
      case 16:
        cmplog_ins2(site, (u16)val, (u16)cases[i + 2], CMP_ATTR_ICMP_EQ);
        break;
      case 32:
        cmplog_ins4(site, (u32)val, (u32)cases[i + 2], CMP_ATTR_ICMP_EQ);
        break;
      default:
        cmplog_ins8(site, val, cases[i + 2], CMP_ATTR_ICMP_EQ);

    }

  }

}

#ifdef __APPLE__
__attribute__((weak_import)) void *__asan_region_is_poisoned(void  *beg,
                                                             size_t size);
#else
__attribute__((weak)) void *__asan_region_is_poisoned(void *beg, size_t size);
#endif

#if defined(__APPLE__) && defined(__MACH__)
/* Empty the probe pipe (see __afl_open_dummy_fd). Both ends are non-blocking,
   so the read loop stops at EAGAIN once the buffer is drained. */
static void __afl_drain_dummy_fd(void) {

  if (__afl_dummy_fd[0] < 0) { return; }
  u8 buf[256];
  while (read(__afl_dummy_fd[0], buf, sizeof(buf)) > 0) {}

}

#endif

// POSIX shenanigan to see if an area is mapped.
// If it is mapped as X-only, we have a problem, so maybe we should add a check
// to avoid to call it on .text addresses
static int area_is_valid(void *ptr, size_t len) {

  if (unlikely(!ptr || (__asan_region_is_poisoned &&
                        __asan_region_is_poisoned(ptr, len)))) {

    return 0;

  }

  if (unlikely(__afl_dummy_fd[1] < 0)) {

    __afl_open_dummy_fd();
    if (__afl_dummy_fd[1] < 0) { return 0; }

  }

#ifdef __HAIKU__
  long r = _kern_write(__afl_dummy_fd[1], -1, ptr, len);
#elif defined(__OpenBSD__)
  long r = write(__afl_dummy_fd[1], ptr, len);
#elif defined(__APPLE__) && defined(__MACH__)
  /* syscall(2) is flagged deprecated on modern macOS, but the BSD numbers
     in <sys/syscall.h> remain stable and we deliberately want the raw
     syscall here to avoid libc/sanitizer interception on this hot path. */
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  long r = syscall(SYS_write, __afl_dummy_fd[1], ptr, len);
  if (unlikely(r < 0 && errno == EAGAIN)) {

    /* probe pipe buffer is full; drain it and retry the fault probe once */
    __afl_drain_dummy_fd();
    r = syscall(SYS_write, __afl_dummy_fd[1], ptr, len);

  }

  #pragma GCC diagnostic pop
#else
  long r = syscall(SYS_write, __afl_dummy_fd[1], ptr, len);
#endif  // HAIKU, OPENBSD, APPLE

  if (r <= 0 || (size_t)r > len) return 0;
  return (int)r;

}

/* Return the common readable prefix of two operand ranges. Use one kernel
   entry where raw writev is available and preserve the established checks
   elsewhere. */
static u32 area_pair_valid_len(void *ptr1, void *ptr2, size_t len) {

#ifdef AFL_HAVE_RAW_WRITEV
  if (unlikely(!ptr1 || !ptr2 || !len ||
               (__asan_region_is_poisoned &&
                (__asan_region_is_poisoned(ptr1, len) ||
                 __asan_region_is_poisoned(ptr2, len))))) {

    return 0;

  }

  if (unlikely(__afl_dummy_fd[1] < 0)) {

    __afl_open_dummy_fd();
    if (__afl_dummy_fd[1] < 0) { return 0; }

  }

  long page_size = sysconf(_SC_PAGE_SIZE);
  if (unlikely(page_size <= 0)) return 0;

  size_t page_mask = (size_t)page_size - 1U;
  size_t len1 = MIN(len, (size_t)page_size - ((uintptr_t)ptr1 & page_mask));
  size_t len2 = MIN(len, (size_t)page_size - ((uintptr_t)ptr2 & page_mask));
  struct iovec iov[2] = {{ptr1, len1}, {ptr2, len2}};

  #if defined(__APPLE__) && defined(__MACH__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  #endif
  long r = syscall(SYS_writev, __afl_dummy_fd[1], iov, 2);
  #if defined(__APPLE__) && defined(__MACH__)
  if (unlikely(r < 0 && errno == EAGAIN)) {

    /* probe pipe buffer is full; drain it and retry the fault probe once */
    __afl_drain_dummy_fd();
    r = syscall(SYS_writev, __afl_dummy_fd[1], iov, 2);

  }

    #pragma GCC diagnostic pop
  #endif

  if (unlikely(r != (long)(len1 + len2))) return 0;
  return (u32)MIN(len1, len2);
#else
  int len1 = area_is_valid(ptr1, len);
  int len2 = area_is_valid(ptr2, len);
  if (unlikely(len1 <= 0 || len2 <= 0)) return 0;
  return (u32)MIN(len1, len2);
#endif

}

/* Attribute of whether the Buffer points to the memory area mapped by the
   program image (ELF on Linux, Mach-O on macOS). This lets cmplog tell a
   real program constant (e.g. a builtin name compared via strncmp) apart from
   bytes that merely came from the fuzz input, so the former can be promoted to
   the auto-dictionary. */

#ifdef __linux__

// From
// https://github.com/google/honggfuzz/blob/ded8c87bcf3cc32f64c1097746a3461d6da1c24a/libhfcommon/util.c#L963
static int addr_static_cb(struct dl_phdr_info *info, size_t size, void *data) {

  for (size_t i = 0; i < info->dlpi_phnum; i++) {

    if (info->dlpi_phdr[i].p_type != PT_LOAD) { continue; }
    uintptr_t addr_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
    uintptr_t addr_end = addr_start + MIN(info->dlpi_phdr[i].p_memsz,
                                          info->dlpi_phdr[i].p_filesz);
    if (((uintptr_t)data >= addr_start) && ((uintptr_t)data < addr_end)) {

      if ((info->dlpi_phdr[i].p_flags & PF_W) == 0) {

        return ADDR_ATTR_RO;

      } else {

        return ADDR_ATTR_RW;

      }

    }

  }

  return ADDR_ATTR_NOTFOUND;

}

  // Immutable interval table of program-image segments, published after one
  // build. Non-image address chunks use a bounded negative cache to avoid
  // repeated loader queries.
  #define AFL_ADDR_TABLE_MAX 4096
  #define AFL_ADDR_NEGATIVE_CACHE_SIZE 256

typedef struct {

  uintptr_t start;
  uintptr_t end;
  u8        attr;
  u8        readable;
  u8        stable;

} afl_addr_interval_t;

static afl_addr_interval_t afl_addr_table[AFL_ADDR_TABLE_MAX];
static u32                 afl_addr_table_count;
static u8 afl_addr_table_state;  // 0=unbuilt 1=building 2=ready 3=fallback
static u8 afl_addr_build_overflow;
static uintptr_t afl_addr_negative_cache[AFL_ADDR_NEGATIVE_CACHE_SIZE];

static int addr_table_build_cb(struct dl_phdr_info *info, size_t size,
                               void *data) {

  (void)size;
  (void)data;

  for (size_t i = 0; i < info->dlpi_phnum; i++) {

    if (info->dlpi_phdr[i].p_type != PT_LOAD) { continue; }

    if (afl_addr_table_count >= AFL_ADDR_TABLE_MAX) {

      afl_addr_build_overflow = 1;
      return 1;

    }

    uintptr_t addr_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
    uintptr_t addr_end = addr_start + MIN(info->dlpi_phdr[i].p_memsz,
                                          info->dlpi_phdr[i].p_filesz);
    afl_addr_table[afl_addr_table_count].start = addr_start;
    afl_addr_table[afl_addr_table_count].end = addr_end;
    afl_addr_table[afl_addr_table_count].attr =
        (info->dlpi_phdr[i].p_flags & PF_W) ? ADDR_ATTR_RW : ADDR_ATTR_RO;
    afl_addr_table[afl_addr_table_count].readable =
        (info->dlpi_phdr[i].p_flags & PF_R) != 0;
    afl_addr_table[afl_addr_table_count].stable =
        !info->dlpi_name || !info->dlpi_name[0];
    afl_addr_table_count++;

  }

  return 0;

}

static int addr_interval_cmp(const void *a, const void *b) {

  uintptr_t sa = ((const afl_addr_interval_t *)a)->start;
  uintptr_t sb = ((const afl_addr_interval_t *)b)->start;
  if (sa < sb) { return -1; }
  if (sa > sb) { return 1; }
  return 0;

}

static void addr_table_build(void) {

  afl_addr_table_count = 0;
  afl_addr_build_overflow = 0;
  dl_iterate_phdr(addr_table_build_cb, NULL);
  if (unlikely(afl_addr_build_overflow)) {

    __atomic_store_n(&afl_addr_table_state, 3, __ATOMIC_RELEASE);
    return;

  }

  qsort(afl_addr_table, afl_addr_table_count, sizeof(afl_addr_interval_t),
        addr_interval_cmp);
  __atomic_store_n(&afl_addr_table_state, 2, __ATOMIC_RELEASE);

}

static const afl_addr_interval_t *addr_table_lookup(const void *addr) {

  uintptr_t a = (uintptr_t)addr;
  u32       lo = 0;
  u32       hi = afl_addr_table_count;
  while (lo < hi) {

    u32 mid = lo + (hi - lo) / 2;
    if (a < afl_addr_table[mid].start) {

      hi = mid;

    } else if (a >= afl_addr_table[mid].end) {

      lo = mid + 1;

    } else {

      return &afl_addr_table[mid];

    }

  }

  return NULL;

}

static u8 addr_negative_cache_lookup(const void *addr) {

  uintptr_t tag = ((uintptr_t)addr >> 12) + 1;
  return __atomic_load_n(
             &afl_addr_negative_cache[tag & (AFL_ADDR_NEGATIVE_CACHE_SIZE - 1)],
             __ATOMIC_RELAXED) == tag;

}

static void addr_negative_cache_store(const void *addr) {

  uintptr_t tag = ((uintptr_t)addr >> 12) + 1;
  __atomic_store_n(
      &afl_addr_negative_cache[tag & (AFL_ADDR_NEGATIVE_CACHE_SIZE - 1)], tag,
      __ATOMIC_RELAXED);

}

static u8 get_prog_addr_attr_slow(const void *addr) {

  if (addr_negative_cache_lookup(addr)) { return ADDR_ATTR_NOTFOUND; }

  Dl_info info;
  if (!dladdr(addr, &info) || !info.dli_fbase) {

    addr_negative_cache_store(addr);
    return ADDR_ATTR_NOTFOUND;

  }

  u8 attr = dl_iterate_phdr(addr_static_cb, (void *)addr);
  if (attr == ADDR_ATTR_NOTFOUND) { addr_negative_cache_store(addr); }
  return attr;

}

static u8 addr_table_prepare(void) {

  u8 state = __atomic_load_n(&afl_addr_table_state, __ATOMIC_ACQUIRE);
  if (unlikely(!state)) {

    u8 expected = 0;
    if (__atomic_compare_exchange_n(&afl_addr_table_state, &expected, 1, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {

      addr_table_build();
      state = __atomic_load_n(&afl_addr_table_state, __ATOMIC_ACQUIRE);

    } else {

      state = expected;

    }

  }

  return state;

}

static size_t get_prog_addr_info(const void *addr, size_t len, u8 *attr) {

  u8 state = addr_table_prepare();
  if (unlikely(state != 2)) {

    *attr = get_prog_addr_attr_slow(addr);
    return 0;

  }

  const afl_addr_interval_t *interval = addr_table_lookup(addr);
  if (unlikely(!interval)) {

    *attr = get_prog_addr_attr_slow(addr);
    return 0;

  }

  *attr = interval->attr;
  if (!interval->readable || !interval->stable) { return 0; }

  size_t available = interval->end - (uintptr_t)addr;
  return MIN(available, len);

}

  #define AFL_HAVE_ADDR_ATTR 1

#elif defined(__APPLE__) && defined(__MACH__)

  #include <dlfcn.h>
  #include <mach-o/loader.h>
  #include <mach/vm_prot.h>

// Walk the Mach-O segments of the image that contains `addr` and report
// whether the address falls in a writable (RW) or read-only (RO) segment.
// Addresses that are not part of any loaded image (heap/stack input buffers)
// return ADDR_ATTR_NOTFOUND, exactly like the Linux dl_iterate_phdr path.
static u8 get_prog_addr_attr(const void *addr) {

  Dl_info info;
  if (!dladdr(addr, &info) || !info.dli_fbase) { return ADDR_ATTR_NOTFOUND; }

  const struct mach_header_64 *hdr =
      (const struct mach_header_64 *)info.dli_fbase;
  if (hdr->magic != MH_MAGIC_64 && hdr->magic != MH_CIGAM_64) {

    return ADDR_ATTR_NOTFOUND;

  }

  uintptr_t target = (uintptr_t)addr;
  const u8 *p = (const u8 *)(hdr + 1);

  /* The slide is the difference between where the image was actually loaded
     (dli_fbase, the start of __TEXT) and the __TEXT vmaddr recorded in the
     file. __TEXT is the first segment with fileoff == 0 and a non-empty file
     mapping (__PAGEZERO has filesize 0 and is skipped). */
  uintptr_t text_vmaddr = 0;
  u8        have_text = 0;
  const u8 *q = p;
  for (uint32_t i = 0; i < hdr->ncmds; i++) {

    const struct load_command *c = (const struct load_command *)q;
    if (c->cmd == LC_SEGMENT_64) {

      const struct segment_command_64 *seg =
          (const struct segment_command_64 *)c;
      if (!have_text && seg->fileoff == 0 && seg->filesize != 0) {

        text_vmaddr = (uintptr_t)seg->vmaddr;
        have_text = 1;

      }

    }

    q += c->cmdsize;

  }

  uintptr_t slide = (uintptr_t)hdr - text_vmaddr;

  for (uint32_t i = 0; i < hdr->ncmds; i++) {

    const struct load_command *c = (const struct load_command *)p;
    if (c->cmd == LC_SEGMENT_64) {

      const struct segment_command_64 *seg =
          (const struct segment_command_64 *)c;
      uintptr_t start = (uintptr_t)seg->vmaddr + slide;
      uintptr_t end = start + (uintptr_t)seg->vmsize;
      if (target >= start && target < end) {

        if (seg->initprot & VM_PROT_WRITE) {

          return ADDR_ATTR_RW;

        } else {

          return ADDR_ATTR_RO;

        }

      }

    }

    p += c->cmdsize;

  }

  return ADDR_ATTR_NOTFOUND;

}

  #define AFL_HAVE_ADDR_ATTR 1

#endif

static inline int cmplog_area_is_valid(void *ptr, size_t len, u8 *attr) {

  *attr = ADDR_ATTR_NOTFOUND;
  if (unlikely(!ptr)) { return 0; }

  if (__afl_fuzz_ptr) {

    uintptr_t base = (uintptr_t)__afl_fuzz_ptr;
    uintptr_t addr = (uintptr_t)ptr;
    size_t    fuzz_len = *__afl_fuzz_len;
    if (addr >= base && addr - base <= fuzz_len) {

      size_t offset = addr - base;
      if (len > fuzz_len - offset) { return 0; }
      if (unlikely(__asan_region_is_poisoned &&
                   __asan_region_is_poisoned(ptr, len))) {

        return 0;

      }

      return (int)len;

    }

  }

#ifdef AFL_HAVE_ADDR_ATTR
  #ifdef __linux__
  size_t valid_len = get_prog_addr_info(ptr, len, attr);
  if (valid_len == len) {

    if (unlikely(__asan_region_is_poisoned &&
                 __asan_region_is_poisoned(ptr, len))) {

      return 0;

    }

    return (int)valid_len;

  }

  #else
  *attr = get_prog_addr_attr(ptr);
  #endif
#endif

  return area_is_valid(ptr, len);

}

static inline u32 cmplog_string_len_with_nul(u32 len, u32 cap) {

  return len < cap ? len + 1U : cap;

}

static inline u32 cmplog_string_len(u8 *ptr, u32 cap, u8 *attr) {

  if (unlikely(!ptr || !cap)) { return 0; }

  if (__afl_fuzz_ptr) {

    uintptr_t base = (uintptr_t)__afl_fuzz_ptr;
    uintptr_t addr = (uintptr_t)ptr;
    size_t    fuzz_len = *__afl_fuzz_len;
    if (addr >= base && addr - base <= fuzz_len) {

      cap = (u32)MIN((size_t)cap, fuzz_len - (addr - base));

    }

  }

  if (__asan_region_is_poisoned) {

    u8 *poisoned = __asan_region_is_poisoned(ptr, cap);
    if (poisoned) { cap = (u32)(poisoned - ptr); }

  }

  if (!cap) { return 0; }
  int valid = cmplog_area_is_valid(ptr, cap, attr);
  if (valid <= 0) { return 0; }
  cap = (u32)valid;
  return cmplog_string_len_with_nul((u32)strnlen((char *)ptr, cap), cap);

}

static inline void cmplog_rtn_store(u64 site, u8 *ptr1, u32 len1, u8 *ptr2,
                                    u32 len2, u8 semantic_len, u8 attr1,
                                    u8 attr2, u8 string) {

  u32 shape = MAX(len1, len2);
  if (unlikely(!shape)) { return; }

  u32 slot, occurrence;
  u32 key = cmplog_reserve(site, CMP_TYPE_RTN, shape - 1, CMP_ATTR_NONE,
                           CMP_MAP_RTN_H, &slot, &occurrence);
  if (unlikely(key == CMP_MAP_W)) { return; }

  struct cmpfn_operands *cmpfn =
      (struct cmpfn_operands *)__afl_cmp_map->log[key];
  memset_noasan(&cmpfn[slot], 0, sizeof(cmpfn[slot]));
  cmpfn[slot].v0_len = len1 + (string ? 0x80 : 0);
  cmpfn[slot].v1_len = len2 + (string ? 0x80 : 0);
  cmpfn[slot].addr_attr = ADDR_ATTR_COMBINE(attr1, attr2);
  cmpfn[slot].occurrence = occurrence;
  cmpfn[slot].unused = semantic_len;
  __builtin_memcpy(cmpfn[slot].v0, ptr1, len1);
  __builtin_memcpy(cmpfn[slot].v1, ptr2, len2);

}

static inline void cmplog_rtn_strn(u64 site, u8 *ptr1, u8 *ptr2, u64 len) {

  if (likely(!__afl_cmp_map) || unlikely(!len)) return;
  u32 cap = (u32)__afl_cmplog_max_len;
  u8  attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  u32 len1 = cmplog_string_len(ptr1, cap, &attr1);
  u32 len2 = cmplog_string_len(ptr2, cap, &attr2);
  if (!len1 || !len2) { return; }
  cmplog_rtn_store(site, ptr1, len1, ptr2, len2, (u8)MIN((u64)cap, len), attr1,
                   attr2, 1);

}

static inline void cmplog_rtn_str(u64 site, u8 *ptr1, u8 *ptr2) {

  if (likely(!__afl_cmp_map)) return;
  u32 cap = (u32)__afl_cmplog_max_len;
  u8  attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  u32 len1 = cmplog_string_len(ptr1, cap, &attr1);
  u32 len2 = cmplog_string_len(ptr2, cap, &attr2);
  if (!len1 || !len2) { return; }
  cmplog_rtn_store(site, ptr1, len1, ptr2, len2, 0, attr1, attr2, 1);

}

static inline void cmplog_rtn(u64 site, u8 *ptr1, u8 *ptr2) {

  if (likely(!__afl_cmp_map)) return;
  u32 cap = (u32)__afl_cmplog_max_len;
  u8  attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  int len1 = cmplog_area_is_valid(ptr1, cap, &attr1);
  int len2 = cmplog_area_is_valid(ptr2, cap, &attr2);
  if (len1 <= 0 || len2 <= 0) { return; }
  u32 len = MIN((u32)len1, (u32)len2);
  cmplog_rtn_store(site, ptr1, len, ptr2, len, (u8)len, attr1, attr2, 0);

}

static inline void cmplog_rtn_n(u64 site, u8 *ptr1, u8 *ptr2, u64 len) {

  if (likely(!__afl_cmp_map) || unlikely(!len)) return;
  u32 cap = (u32)MIN((u64)__afl_cmplog_max_len, len);
  u8  attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  int len1 = cmplog_area_is_valid(ptr1, cap, &attr1);
  int len2 = cmplog_area_is_valid(ptr2, cap, &attr2);
  if (len1 != (int)cap || len2 != (int)cap) { return; }
  cmplog_rtn_store(site, ptr1, cap, ptr2, cap, (u8)cap, attr1, attr2, 0);

}

/* hook for string with length functions, eg. strncmp, strncasecmp etc. */
void __cmplog_rtn_hook_strn(u8 *ptr1, u8 *ptr2, u64 len) {

  cmplog_rtn_strn((u64)(uintptr_t)__builtin_return_address(0), ptr1, ptr2, len);

}

/* hook for string functions, eg. strcmp, strcasecmp etc. */
void __cmplog_rtn_hook_str(u8 *ptr1, u8 *ptr2) {

  cmplog_rtn_str((u64)(uintptr_t)__builtin_return_address(0), ptr1, ptr2);

}

/* hook function for all other func(ptr, ptr, ...) variants */
void __cmplog_rtn_hook(u8 *ptr1, u8 *ptr2) {

  cmplog_rtn((u64)(uintptr_t)__builtin_return_address(0), ptr1, ptr2);

}

/* hook for func(ptr, ptr, len, ...) looking functions. */
void __cmplog_rtn_hook_n(u8 *ptr1, u8 *ptr2, u64 len) {

  cmplog_rtn_n((u64)(uintptr_t)__builtin_return_address(0), ptr1, ptr2, len);

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
  u8 attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  if (cmplog_area_is_valid(stdstring, 32, &attr1) <= 0 ||
      cmplog_area_is_valid(cstring, 32, &attr2) <= 0)
    return;

  cmplog_rtn((u64)(uintptr_t)__builtin_return_address(0),
             get_gcc_stdstring(stdstring), cstring);

}

void __cmplog_rtn_gcc_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2) {

  if (likely(!__afl_cmp_map)) return;
  u8 attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  if (cmplog_area_is_valid(stdstring1, 32, &attr1) <= 0 ||
      cmplog_area_is_valid(stdstring2, 32, &attr2) <= 0)
    return;

  cmplog_rtn((u64)(uintptr_t)__builtin_return_address(0),
             get_gcc_stdstring(stdstring1), get_gcc_stdstring(stdstring2));

}

void __cmplog_rtn_llvm_stdstring_cstring(u8 *stdstring, u8 *cstring) {

  if (likely(!__afl_cmp_map)) return;
  u8 attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  if (cmplog_area_is_valid(stdstring, 32, &attr1) <= 0 ||
      cmplog_area_is_valid(cstring, 32, &attr2) <= 0)
    return;

  cmplog_rtn((u64)(uintptr_t)__builtin_return_address(0),
             get_llvm_stdstring(stdstring), cstring);

}

void __cmplog_rtn_llvm_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2) {

  if (likely(!__afl_cmp_map)) return;
  u8 attr1 = ADDR_ATTR_NOTFOUND, attr2 = ADDR_ATTR_NOTFOUND;
  if (cmplog_area_is_valid(stdstring1, 32, &attr1) <= 0 ||
      cmplog_area_is_valid(stdstring2, 32, &attr2) <= 0)
    return;

  cmplog_rtn((u64)(uintptr_t)__builtin_return_address(0),
             get_llvm_stdstring(stdstring1), get_llvm_stdstring(stdstring2));

}

void __valueprofile_rtn_hook_strn(u8 *ptr1, u8 *ptr2, u64 len,
                                  uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 max_len = area_pair_valid_len(ptr1, ptr2, (size_t)MIN(len, 32ULL));
  if (max_len < 2) return;
  vp_runtime_record_rtn(site_token, ptr1, ptr2, max_len, VP_RTN_STOP_AT_ZERO);

}

void __valueprofile_rtn_hook_str(u8 *ptr1, u8 *ptr2, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 cap = area_pair_valid_len(ptr1, ptr2, 32);
  if (cap < 2) return;
  u32 n1 = (u32)strnlen((char *)ptr1, cap);
  u32 n2 = (u32)strnlen((char *)ptr2, cap);
  u32 max_len = MIN(MAX(n1, n2) + 1U, cap);
  if (max_len < 2) return;
  vp_runtime_record_rtn(site_token, ptr1, ptr2, max_len, VP_RTN_STOP_AT_ZERO);

}

void __valueprofile_rtn_hook(u8 *ptr1, u8 *ptr2, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 max_len = area_pair_valid_len(ptr1, ptr2, 32);
  if (max_len < 2) return;
  vp_runtime_record_rtn(site_token, ptr1, ptr2, max_len, 0);

}

void __valueprofile_rtn_hook_n(u8 *ptr1, u8 *ptr2, u64 len,
                               uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 max_len = area_pair_valid_len(ptr1, ptr2, (size_t)MIN(len, 32ULL));
  if (max_len < 2) return;
  vp_runtime_record_rtn(site_token, ptr1, ptr2, max_len, 0);

}

void __valueprofile_rtn_hook_str_ci(u8 *ptr1, u8 *ptr2, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 cap = area_pair_valid_len(ptr1, ptr2, 32);
  if (cap < 2) return;
  u32 n1 = (u32)strnlen((char *)ptr1, cap);
  u32 n2 = (u32)strnlen((char *)ptr2, cap);
  u32 max_len = MIN(MAX(n1, n2) + 1U, cap);
  if (max_len < 2) return;
  vp_runtime_record_rtn(site_token, ptr1, ptr2, max_len,
                        VP_RTN_STOP_AT_ZERO | VP_RTN_FOLD_CASE);

}

void __valueprofile_rtn_hook_strn_ci(u8 *ptr1, u8 *ptr2, u64 len,
                                     uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 max_len = area_pair_valid_len(ptr1, ptr2, (size_t)MIN(len, 32ULL));
  if (max_len < 2) return;
  vp_runtime_record_rtn(site_token, ptr1, ptr2, max_len,
                        VP_RTN_STOP_AT_ZERO | VP_RTN_FOLD_CASE);

}

void __valueprofile_rtn_gcc_stdstring_cstring(u8 *stdstring, u8 *cstring,
                                              uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (!area_pair_valid_len(stdstring, cstring, 32)) return;

  __valueprofile_rtn_hook_str(get_gcc_stdstring(stdstring), cstring,
                              site_token);

}

void __valueprofile_rtn_gcc_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2,
                                                uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (!area_pair_valid_len(stdstring1, stdstring2, 32)) return;

  __valueprofile_rtn_hook(get_gcc_stdstring(stdstring1),
                          get_gcc_stdstring(stdstring2), site_token);

}

void __valueprofile_rtn_llvm_stdstring_cstring(u8 *stdstring, u8 *cstring,
                                               uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (!area_pair_valid_len(stdstring, cstring, 32)) return;

  __valueprofile_rtn_hook_str(get_llvm_stdstring(stdstring), cstring,
                              site_token);

}

void __valueprofile_rtn_llvm_stdstring_stdstring(u8 *stdstring1, u8 *stdstring2,
                                                 uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;
  if (!area_pair_valid_len(stdstring1, stdstring2, 32)) return;

  __valueprofile_rtn_hook(get_llvm_stdstring(stdstring1),
                          get_llvm_stdstring(stdstring2), site_token);

}

void __valueprofile_rtn_hook_sub(u8 *hay, u8 *needle, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 cap = area_pair_valid_len(hay, needle, 32);
  if (cap < 2) return;
  u32 hay_len = (u32)strnlen((char *)hay, cap);
  u32 needle_len = (u32)strnlen((char *)needle, cap);
  if (needle_len < 1 || hay_len < needle_len) return;
  vp_runtime_record_sub(site_token, hay, hay_len, needle, needle_len, 0);

}

void __valueprofile_rtn_hook_sub_ci(u8 *hay, u8 *needle, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 cap = area_pair_valid_len(hay, needle, 32);
  if (cap < 2) return;
  u32 hay_len = (u32)strnlen((char *)hay, cap);
  u32 needle_len = (u32)strnlen((char *)needle, cap);
  if (needle_len < 1 || hay_len < needle_len) return;
  vp_runtime_record_sub(site_token, hay, hay_len, needle, needle_len,
                        VP_RTN_FOLD_CASE);

}

void __valueprofile_rtn_hook_sub_n(u8 *hay, u64 hay_len, u8 *needle,
                                   u64 needle_len, uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  u32 cap = area_pair_valid_len(hay, needle, (size_t)MIN(hay_len, 32ULL));
  if (cap < 2) return;
  u32 n_len = (u32)MIN(needle_len, 32ULL);
  if (n_len < 1 || cap < n_len) return;
  vp_runtime_record_sub(site_token, hay, cap, needle, n_len, 0);

}

static inline void vp_rtn_sub_hn(u8 *hay, u64 hay_len, u8 *needle,
                                 uint64_t site_token, u32 flags) {

  u32 cap = area_pair_valid_len(hay, needle, 32);
  if (cap < 2) return;

  /* A negative length is the "haystack is nul-terminated" convention used by
     g_strstr_len(-1) and unbounded strnstr callers; derive the real length
     instead of treating the whole validated window as content. Both routines
     also stop at a nul inside a bounded haystack, so truncate there either
     way - otherwise a match found past the nul reports a solved constraint
     for a call that returns NULL. */
  u32 hay_len_real = (u32)strnlen(
      (char *)hay,
      (s64)hay_len < 0 ? (size_t)cap : (size_t)MIN(hay_len, (u64)cap));
  u32 needle_len = (u32)strnlen((char *)needle, cap);
  if (needle_len < 1 || hay_len_real < needle_len) return;
  vp_runtime_record_sub(site_token, hay, hay_len_real, needle, needle_len,
                        flags);

}

void __valueprofile_rtn_hook_sub_hn(u8 *hay, u64 hay_len, u8 *needle,
                                    uint64_t site_token) {

  if (likely(!__afl_vp_map || !__afl_vp_map->enabled)) return;

  vp_rtn_sub_hn(hay, hay_len, needle, site_token, 0);

}

/* llvm weak hooks */

#if defined(__has_include)
  #if __has_include(<sanitizer/common_interface_defs.h>)
    #include <sanitizer/common_interface_defs.h>
  #endif
#endif

void __sanitizer_weak_hook_memcmp(void *pc, const void *s1, const void *s2,
                                  size_t n, int result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_n(
        (u8 *)s1, (u8 *)s2, (u64)n,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_n((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2, (u64)n);
  (void)result;

}

void __sanitizer_weak_hook_memmem(void *pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_sub_n(
        (u8 *)s1, (u64)len1, (u8 *)s2, (u64)len2,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_n((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2,
                 len1 < len2 ? (u64)len1 : (u64)len2);
  (void)result;

}

void __sanitizer_weak_hook_strncasecmp(void *pc, const char *s1, const char *s2,
                                       size_t n, int result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_strn_ci(
        (u8 *)s1, (u8 *)s2, (u64)n,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_strn((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2, (u64)n);
  (void)result;

}

void __sanitizer_weak_hook_strncasestr(void *pc, const void *s1, const void *s2,
                                       size_t n, char *result) {

  if (unlikely(__afl_vp_collection_enabled()))
    vp_rtn_sub_hn((u8 *)s1, (u64)n, (u8 *)s2,
                  vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT),
                  VP_RTN_FOLD_CASE);
  else
    cmplog_rtn_strn((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2, (u64)n);
  (void)result;

}

void __sanitizer_weak_hook_strncmp(void *pc, const char *s1, const char *s2,
                                   size_t n, int result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_strn(
        (u8 *)s1, (u8 *)s2, (u64)n,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_strn((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2, (u64)n);
  (void)result;

}

void __sanitizer_weak_hook_strcasecmp(void *pc, const char *s1, const char *s2,
                                      int result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_str_ci(
        (u8 *)s1, (u8 *)s2,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_str((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2);
  (void)result;

}

void __sanitizer_weak_hook_strcasestr(void *pc, const char *s1, const char *s2,
                                      char *result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_sub_ci(
        (u8 *)s1, (u8 *)s2,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_str((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2);
  (void)result;

}

void __sanitizer_weak_hook_strcmp(void *pc, const char *s1, const char *s2,
                                  int result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_str(
        (u8 *)s1, (u8 *)s2,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_str((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2);
  (void)result;

}

void __sanitizer_weak_hook_strstr(void *pc, const char *s1, const char *s2,
                                  char *result) {

  if (unlikely(__afl_vp_collection_enabled()))
    __valueprofile_rtn_hook_sub(
        (u8 *)s1, (u8 *)s2,
        vp_runtime_site_token_pc((uintptr_t)pc, VP_RUNTIME_RTN_SALT));
  else
    cmplog_rtn_str((u64)(uintptr_t)pc, (u8 *)s1, (u8 *)s2);
  (void)result;

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
    __afl_vp_map = NULL;
    __afl_vp_refresh_enabled_ptr();

  }

}

// enable coverage
void __afl_coverage_on() {

  if (likely(__afl_selective_coverage && __afl_selective_coverage_temp)) {

    __afl_area_ptr = __afl_area_ptr_backup;
    if (__afl_cmp_map_backup) { __afl_cmp_map = __afl_cmp_map_backup; }
    if (__afl_vp_map_backup) { __afl_vp_map = __afl_vp_map_backup; }
    __afl_vp_refresh_enabled_ptr();

  }

}

// discard all coverage up to this point
void __afl_coverage_discard() {

  memset_noasan(__afl_area_ptr_backup, 0, __afl_map_size);
  __afl_area_ptr_backup[0] = 1;

  if (__afl_cmp_map) {

    memset_noasan(__afl_cmp_map, 0, sizeof(struct cmp_map));
    memset_noasan(__afl_cmp_cursor, 0, sizeof(__afl_cmp_cursor));

  }

  if (__afl_vp_map) {

    /* vp_runtime_prepare_site() resets per-exec fields only when
       site->exec_seen != vp->exec_id, so bump the epoch to force lazy reset
       without wiping persistent slot frontier state. */
    ++__afl_vp_map->exec_id;
    if (unlikely(!__afl_vp_map->exec_id)) { ++__afl_vp_map->exec_id; }
    __afl_vp_map->control_len = 0;

  }

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

/* IJON max tracking runtime functions */

#include <stdarg.h>
#include <time.h>

/* Supporting hash functions */
uint64_t ijon_simple_hash(uint64_t x) {

  const uint64_t golden_ratio = 0x9E3779B97F4A7C15ULL;
  return x * golden_ratio;

}

uint32_t ijon_hashint(uint32_t old, uint32_t val) {

  // PERFECT HASH: Bit-interleaving approach for coordinate pairs
  // Guarantees no hash collisions for coordinates < 65536
  // Interleave bits of x and y to create unique 32-bit hash

  uint32_t x = old;
  uint32_t y = val;
  uint32_t result = 0;

  // Interleave the lower 16 bits of x and y
  for (int i = 0; i < 16; i++) {

    result |= ((x & (1U << i)) << i) | ((y & (1U << i)) << (i + 1));

  }

  // Apply mixing for better distribution in coverage map
  result ^= result >> 16;
  result *= 0x85ebca6b;
  result ^= result >> 13;
  result *= 0xc2b2ae35;
  result ^= result >> 16;

  return result;

}

uint32_t ijon_hashstr(uint32_t old, char *val) {

  return ijon_hashmem(old, val, strlen(val));

}

uint32_t ijon_hashmem(uint32_t old, char *val, size_t len) {

  old = ijon_hashint(old, len);
  for (size_t i = 0; i < len; i++) {

    old = ijon_hashint(old, (u8)val[i]);

  }

  return old;

}

void ijon_max(uint32_t addr, u64 val) {

  if (unlikely(!__afl_ijon_enabled)) { return; }

  if (unlikely(__afl_ijon_bits == NULL && __afl_area_ptr)) {

    __afl_ijon_bits = (u64 *)(__afl_area_ptr + __afl_set_map_size);

    /* Clear IJON max area on first initialization to avoid processing
     * uninitialized data */
    memset_noasan(__afl_ijon_bits, 0, MAP_SIZE_IJON_ENTRIES * sizeof(u64));

  }

  if (unlikely(!__afl_ijon_bits)) { return; }

  u32 var_id = (u32)(ijon_simple_hash((uint64_t)addr) % MAP_SIZE_IJON_ENTRIES);
  // u32 var_id = (u32)(addr % MAP_SIZE_IJON_ENTRIES);

  if (__afl_ijon_bits[var_id] < val) { __afl_ijon_bits[var_id] = val; }

}

void ijon_min(uint32_t addr, u64 val) {

  val = 0xffffffffffffffff - val;
  ijon_max(addr, val);

}

void ijon_max_until(uint32_t addr, u64 val, u64 limit) {

  u64 encoded = val >= limit ? UINT64_MAX : UINT64_MAX - limit + val;
  ijon_max(addr, encoded);

}

void ijon_set(uint32_t loc_addr, uint32_t val) {

  if (unlikely(!__afl_ijon_enabled)) return;

  // ORIGINAL IJON APPROACH: XOR location hash with value to create unique
  // coverage point This follows the original:
  // ijon_map_set(ijon_hashstr(__LINE__,__FILE__)^(x))
  u32 combined_hash = loc_addr ^ val;
  u32 coverage_id = combined_hash % MAP_SIZE_IJON_MAP;

  __afl_area_ptr[__afl_cov_map_size + coverage_id] = 1;

}

void ijon_inc(uint32_t loc_addr, uint32_t val) {

  if (unlikely(!__afl_ijon_enabled)) return;

  // ORIGINAL IJON APPROACH: XOR location hash with value to create unique
  // coverage point This follows the original:
  // ijon_map_set(ijon_hashstr(__LINE__,__FILE__)^(x))
  uint32_t combined_hash = loc_addr ^ val;

  u32 coverage_id = combined_hash % MAP_SIZE_IJON_MAP;

  // Memory-safe: Use actual available shared memory size
  // Use AFL's incremental coverage approach (same as __afl_trace)
  __afl_area_ptr[__afl_cov_map_size + coverage_id] += 1;

}

/* Variadic runtime functions */
void ijon_max_variadic(uint32_t addr, ...) {

  va_list args;
  va_start(args, addr);

  u64 combined = 1;  // Start with 1 for Java-style hash
  u64 value;
  int arg_count = 0;

  // Process all arguments until we hit the sentinel (0)
  // Using Java-style hash: hash = 31 * hash + value
  while ((value = va_arg(args, u64)) != 0) {

    combined = combined * 31 + value;
    arg_count++;

    // CRITICAL: Prevent infinite loops if sentinel is missing
    if (arg_count > 20) { break; }

  }

  va_end(args);

  // Call the basic ijon_max function
  ijon_max(addr, combined);

}

void ijon_min_variadic(uint32_t addr, ...) {

  va_list args;
  va_start(args, addr);

  u64 combined = 1;  // Start with 1 for Java-style hash
  u64 value;
  int arg_count = 0;

  // Process all arguments until we hit the sentinel (0)
  // Using Java-style hash: hash = 31 * hash + value
  while ((value = va_arg(args, u64)) != 0) {

    combined = combined * 31 + value;
    arg_count++;

    // CRITICAL: Prevent infinite loops if sentinel is missing
    if (arg_count > 20) { break; }

  }

  va_end(args);

  // Call the basic ijon_min function
  ijon_min(addr, combined);

}

/* IJON state management functions */

void ijon_xor_state(uint32_t val) {

  __afl_ijon_state = (__afl_ijon_state ^ val) % (u32)MAP_SIZE_IJON_MAP;

}

void ijon_reset_state(void) {

  __afl_ijon_state = 0;
  __afl_ijon_state_log = 0;

}

/* Cross-platform stack hashing using backtrace() - supports both 32-bit and
 * 64-bit */
uint32_t ijon_hashstack_backtrace(void) {

#if (defined(__linux__) && defined(__GLIBC__)) || defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  void *buffer[16] = {

      0,

  };

  int num = backtrace(buffer, 16);

  // Ensure we don't exceed buffer size
  if (num > 16) num = 16;
  if (num <= 0) return 0;

  uint64_t res = 0;
  for (int i = 0; i < num; i++) {

  // Cast pointer to appropriate integer type based on architecture
  #if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || \
      defined(__aarch64__) || defined(__arm64__)
    // 64-bit architecture
    res ^= ijon_simple_hash((uint64_t)(uintptr_t)buffer[i]);
  #elif defined(__i386__) || defined(_M_IX86) || defined(__arm__)
    // 32-bit architecture - mask to 32-bit to avoid issues
    res ^= ijon_simple_hash((uint64_t)((uintptr_t)buffer[i] & 0xFFFFFFFF));
  #else
    // Generic fallback for other architectures
    res ^= ijon_simple_hash((uint64_t)(uintptr_t)buffer[i]);
  #endif

  }

  return (uint32_t)res;
#else
  // Fallback for systems without backtrace support
  return 0;
#endif

}

/* Alias for compatibility with existing IJON code */
uint32_t ijon_hashstack(void) {

  return ijon_hashstack_backtrace();

}

/* String and memory distance functions */

#define IJON_DIST_MAX_LEN 1024
#define IJON_DIST_FUNC ijon_memprogress_prefix

static inline uint32_t ijon_memprogress_prefix(const char *a, const char *b,
                                               uint32_t len) {

  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;

  uint32_t matches = 0;
  while (matches < len && pa[matches] == pb[matches])
    ++matches;

  return matches;

}

/* maybe switch to this:

static inline uint32_t ijon_memprogress_matches(const char *a, const char *b,
                                                uint32_t len) {

  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;

  uint32_t matches = 0;
  for (uint32_t i = 0; i < len; ++i) {

    matches += (uint32_t)(pa[i] == pb[i]);

  }

  return matches;

}

*/

uint32_t ijon_memdist(char *a, char *b, size_t len) {

  if (unlikely(!a && !b)) return 0;
  if (unlikely(!a || !b))
    return len > (size_t)UINT32_MAX ? UINT32_MAX : (uint32_t)len;
  if (unlikely(len == 0)) return 0;

  return IJON_DIST_FUNC(a, b,
                        len >= IJON_DIST_MAX_LEN ? IJON_DIST_MAX_LEN : len);

}

uint32_t ijon_strdist(char *a, char *b) {

  if (!a && !b) return 0;
  if (!a) return strlen(b);
  if (!b) return strlen(a);

  size_t len_a = strlen(a);
  size_t len_b = strlen(b);

  uint32_t len = (uint32_t)MIN(MAX(len_a, len_b), IJON_DIST_MAX_LEN);

  return IJON_DIST_FUNC(a, b, len);

}

/* ===========================================================
 * afl-llvm-bug-pass runtime support
 * Three modes (scalar, budget, sizefill) sharing this section.
 * Globals are declared up top alongside the IJON globals.
 * =========================================================== */

void __afl_bug_scalar_max(uint32_t id, uint64_t val) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active || !__afl_bug_map) return;
  /* Bucket as ceil(log2(val+1)) so equal-magnitude values collapse to one
     slot but growth produces new coverage. Cap at 63. */
  u32 bucket = 0;
  if (val) { bucket = 64u - (u32)__builtin_clzll(val); }
  id &= (MAP_SIZE_BUG_ENTRIES - 1);
  if (__afl_bug_map[id] < bucket) __afl_bug_map[id] = bucket;

}

void __afl_bug_loop_iter_flush(uint32_t id, uint32_t local_count) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active || !__afl_bug_map) return;
  u32 bucket = 0;
  if (local_count) bucket = 32u - (u32)__builtin_clz(local_count);
  id &= (MAP_SIZE_BUG_ENTRIES - 1);
  if (__afl_bug_map[id] < bucket) __afl_bug_map[id] = bucket;

}

void __afl_bug_ws_begin(const void *ptr_before) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active) return;
  /* Stack overflow: silently drop the frame. The matching check below
     won't find a matching base and will become a no-op — preferable to
     stomping the deepest frame and reporting wrong violations. */
  if (__afl_bug_ws_top + 1 >= __AFL_BUG_FRAME_STACK_DEPTH) return;
  ++__afl_bug_ws_top;
  __afl_bug_ws_stack[__afl_bug_ws_top].base = ptr_before;
  __afl_bug_ws_stack[__afl_bug_ws_top].max_off = 0;
  __afl_bug_ws_stack[__afl_bug_ws_top].total = 0;
  __afl_bug_ws_stack[__afl_bug_ws_top].cap = (u64)-1;          /* unbounded */

}

void __afl_bug_ws_store(const void *addr, uint32_t size) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active || __afl_bug_ws_top < 0) return;
  uintptr_t a = (uintptr_t)addr;
  /* Update every active frame whose base is at or before addr AND the
     write end fits under the frame's cap. The cap test prevents an
     unrelated higher-address store inside the callee from inflating
     the tracked max_off — exactly the false-positive class that
     motivated SIZEFILL's size-bounded sf_begin. BUDGET frames have
     cap=UINT64_MAX so this is a no-op for them. */
  for (int i = 0; i <= __afl_bug_ws_top; ++i) {

    uintptr_t base = (uintptr_t)__afl_bug_ws_stack[i].base;
    if (a < base) continue;
    uint64_t off = (uint64_t)(a - base);
    uint64_t end = off + size;
    if (end > __afl_bug_ws_stack[i].cap) continue;
    if (end > __afl_bug_ws_stack[i].max_off)
      __afl_bug_ws_stack[i].max_off = end;
    __afl_bug_ws_stack[i].total += size;

  }

}

void __afl_bug_ws_check_budget(const void *ptr_before, uint64_t ret_size) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active || __afl_bug_ws_top < 0) return;
  /* Match against the nearest frame with this base. Walking from top
     down handles direct recursion (the closer frame is ours); on
     unmatched nesting (e.g., an inlined wsBegin without a paired
     wsCheck, or a wsBegin we silently dropped due to overflow) we
     return without touching the stack. */
  int matched = -1;
  for (int i = __afl_bug_ws_top; i >= 0; --i) {

    if (__afl_bug_ws_stack[i].base == ptr_before) {

      matched = i;
      break;

    }

  }

  if (matched < 0) return;
  u64 max_off = __afl_bug_ws_stack[matched].max_off;
  if (max_off > ret_size) {

    /* Signal-safe report — see __afl_bug_writes/writeu near top of file. */
    __afl_bug_writes("[afl-bug] BUDGET violation: function wrote ");
    __afl_bug_writeu((unsigned long long)max_off);
    __afl_bug_writes(" bytes past ptr_before, returned size ");
    __afl_bug_writeu((unsigned long long)ret_size);
    __afl_bug_writes(" (delta=");
    __afl_bug_writeu((unsigned long long)(max_off - ret_size));
    __afl_bug_writes(")\n");
    _exit(134);

  }

  /* Pop the matched frame and any orphans above it (those lost their
     matching check; discarding keeps the stack consistent for outer
     frames still pending). */
  __afl_bug_ws_top = matched - 1;

}

/* Independent SIZEFILL stack so it can coexist with BUDGET under
   AFL_LLVM_BUG=1 without clobbering each other. Same begin/store/
   check discipline as ws_*. */
void __afl_bug_sf_begin(const void *ptr_arg, uint64_t caller_buf_size) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active) return;
  if (__afl_bug_sf_top + 1 >= __AFL_BUG_FRAME_STACK_DEPTH) return;
  ++__afl_bug_sf_top;
  __afl_bug_sf_stack[__afl_bug_sf_top].base = ptr_arg;
  __afl_bug_sf_stack[__afl_bug_sf_top].max_off = 0;
  __afl_bug_sf_stack[__afl_bug_sf_top].total = 0;

  /* Cap derivation, in order of preference:
       1. If the ALLOCSIZE shadow is initialized AND ptr_arg falls inside
          a tracked allocation, use that allocation's actual remaining
          extent (end - ptr_arg). This is the PRINCIPLED filter: writes
          inside the allocation count, writes outside (different malloc
          chunks, stack frames, etc.) are dropped. Catches in-allocation
          OOBs of the SIZEFILL-tracked buffer; ignores unrelated buffers.
       2. Else fall back to caller_buf_size + UNRELATED_SLACK (64 KiB).
          Still catches OOBs up to 64 KiB; still false-positives on
          adjacent allocations within that window. Acceptable when no
          shadow is available (ALLOCSIZE disabled).
       3. caller_buf_size == 0 → unbounded (legacy behavior). */
#define __AFL_BUG_SF_UNRELATED_SLACK ((u64)(64 * 1024))
  u64 cap = (u64)-1;
  int resolved = 0;

  if (__afl_allocsize_active) {

    uintptr_t a = (uintptr_t)ptr_arg;
    uintptr_t off = 0;
    u16      *tbl = __afl_alloc_shadow_find(a, &off);
    if (tbl) {

      u16 idx = tbl[off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2];
      if (idx) {

        AllocSizeRecord *r = &__afl_alloc_records[idx];
        if (r->in_use == __AFL_ALLOC_INUSE_LIVE && a >= r->base &&
            a < r->base + r->size) {

          cap = (r->base + r->size) - a;
          resolved = 1;

        }

      }

    }

  }

  if (!resolved) {

    if (caller_buf_size == 0) {

      cap = (u64)-1;

    } else if (caller_buf_size > (u64)-1 - __AFL_BUG_SF_UNRELATED_SLACK) {

      cap = (u64)-1;

    } else {

      cap = caller_buf_size + __AFL_BUG_SF_UNRELATED_SLACK;

    }

  }

  __afl_bug_sf_stack[__afl_bug_sf_top].cap = cap;

}

void __afl_bug_sf_store(const void *addr, uint32_t size) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active || __afl_bug_sf_top < 0) return;
  uintptr_t a = (uintptr_t)addr;
  for (int i = 0; i <= __afl_bug_sf_top; ++i) {

    uintptr_t base = (uintptr_t)__afl_bug_sf_stack[i].base;
    if (a < base) continue;
    uint64_t off = (uint64_t)(a - base);
    uint64_t end = off + size;
    if (end > __afl_bug_sf_stack[i].cap) continue;
    if (end > __afl_bug_sf_stack[i].max_off)
      __afl_bug_sf_stack[i].max_off = end;

  }

}

void __afl_bug_sizefill_check(const void *ptr_arg, uint64_t ret_size,
                              uint64_t caller_buf_size) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active) return;
  if (ret_size > caller_buf_size) {

    __afl_bug_writes("[afl-bug] SIZEFILL violation: function returned size ");
    __afl_bug_writeu((unsigned long long)ret_size);
    __afl_bug_writes(" but caller buffer is ");
    __afl_bug_writeu((unsigned long long)caller_buf_size);
    __afl_bug_writes(" bytes (ptr=");
    __afl_bug_writep(ptr_arg);
    __afl_bug_writes(")\n");
    _exit(134);

  }

  if (__afl_bug_sf_top < 0) return;
  int matched = -1;
  for (int i = __afl_bug_sf_top; i >= 0; --i) {

    if (__afl_bug_sf_stack[i].base == ptr_arg) {

      matched = i;
      break;

    }

  }

  if (matched < 0) return;
  u64 max_off = __afl_bug_sf_stack[matched].max_off;
  if (max_off > caller_buf_size) {

    __afl_bug_writes("[afl-bug] SIZEFILL violation: writes extended to ");
    __afl_bug_writeu((unsigned long long)max_off);
    __afl_bug_writes(" bytes past buffer head, caller buffer only ");
    __afl_bug_writeu((unsigned long long)caller_buf_size);
    __afl_bug_writes(" (ptr=");
    __afl_bug_writep(ptr_arg);
    __afl_bug_writes(")\n");
    _exit(134);

  }

  __afl_bug_sf_top = matched - 1;

}

/* SLACK: |op0 - op1| per icmp site. Designed to coexist with the MAX-based
   scalar/loop hooks on the same __afl_bug_map:
     - We invert the bucket (small slack -> large stored value) so a MAX
       update preserves the tightest match seen.
     - The pass already hashes (function-name, site-index, mode salt) to
       produce `id`, so the SLACK channel does not collide with SCALAR's
       slot 0 even for the lowest-numbered sites. We simply mask here —
       the pass owns slot distribution.
   Net: a smaller-than-ever slack at a given site wins; large slack from
   other paths can't overwrite it. */
void __afl_bug_slack_min(uint32_t id, uint64_t slack) {

  __afl_bug_ensure_runtime();
  if (!__afl_bug_active || !__afl_bug_map) return;
  /* ceil(log2(slack+1)), capped at 64. Slack==0 (tight equality) -> 0. */
  u32 log_slack = slack ? (64u - (u32)__builtin_clzll(slack)) : 0;
  u32 inv = 64u - log_slack;     /* 64 for slack==0, shrinks as slack grows */
  u32 slot = id & (MAP_SIZE_BUG_ENTRIES - 1);
  if (__afl_bug_map[slot] < inv) __afl_bug_map[slot] = inv;

}

/* ----- AllocSizeOracle runtime ----- */

static void __afl_alloc_shadow_init(uintptr_t hint) {

  if (__afl_alloc_shadow) return;
  /* Anchor the primary shadow at `hint` rounded down to the 16 GB tracked
     range.  Additional windows are spawned by __afl_alloc_shadow_get_or_init
     on demand when allocations land outside the primary 16 GiB span. */
  uintptr_t origin = hint & ~((uintptr_t)MAP_SIZE_ALLOCSHADOW_RANGE - 1);
  void     *m = mmap(NULL, MAP_SIZE_ALLOCSHADOW_BYTES, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (m == MAP_FAILED) {

    fprintf(stderr,
            "[afl-bug] ALLOCSIZE: shadow mmap failed (%zu bytes); disabling\n",
            (size_t)MAP_SIZE_ALLOCSHADOW_BYTES);
    __afl_allocsize_active = 0;
    return;

  }

  __afl_alloc_shadow = (u16 *)m;
  __afl_alloc_shadow_origin = origin;

}

/* Read-path lookup.  Returns the u16 *table covering `a` and writes
   `(a - origin)` to `*off_out`, or NULL if `a` is not in any active
   window.  Primary window is checked first so the common case is a
   single subtract+compare. */
static inline u16 *__afl_alloc_shadow_find(uintptr_t a, uintptr_t *off_out) {

  if (__afl_alloc_shadow && a >= __afl_alloc_shadow_origin) {

    uintptr_t off = a - __afl_alloc_shadow_origin;
    if (off < MAP_SIZE_ALLOCSHADOW_RANGE) {

      *off_out = off;
      return __afl_alloc_shadow;

    }

  }

  for (u32 i = 0; i < __afl_alloc_shadow_extra_count; ++i) {

    AflAllocShadowExtra *s = &__afl_alloc_shadow_extra[i];
    if (a < s->origin) continue;
    uintptr_t off = a - s->origin;
    if (off < MAP_SIZE_ALLOCSHADOW_RANGE) {

      *off_out = off;
      return s->table;

    }

  }

  return NULL;

}

/* Write-path: like _find but lazily creates a new window if `a` falls
   outside every existing one.  Returns NULL if both the primary window
   cannot be created (initial mmap failure) and the extras table is full. */
static u16 *__afl_alloc_shadow_get_or_init(uintptr_t a, uintptr_t *off_out) {

  u16 *t = __afl_alloc_shadow_find(a, off_out);
  if (t) return t;

  /* No window covers `a`. Create the primary first if it isn't up yet, even
     if `a` would land outside the primary's range: subsequent registers
     for addresses in this primary's range get the cheaper hot path. */
  if (!__afl_alloc_shadow) {

    __afl_alloc_shadow_init(a);
    if (!__afl_alloc_shadow) return NULL;
    t = __afl_alloc_shadow_find(a, off_out);
    if (t) return t;
    /* Primary just landed on a different range than `a` — fall through to
       spawn an extra window for `a`. */

  }

  if (__afl_alloc_shadow_extra_count >= __AFL_ALLOC_SHADOW_EXTRAS) {

    if (!__afl_alloc_shadow_oom_warned) {

      fprintf(stderr,
              "[afl-bug] ALLOCSIZE: shadow window cap (%u + 1 primary) "
              "reached; subsequent allocations outside existing windows "
              "will not be tracked\n",
              (unsigned)__AFL_ALLOC_SHADOW_EXTRAS);
      __afl_alloc_shadow_oom_warned = 1;

    }

    return NULL;

  }

  uintptr_t origin = a & ~((uintptr_t)MAP_SIZE_ALLOCSHADOW_RANGE - 1);
  void     *m = mmap(NULL, MAP_SIZE_ALLOCSHADOW_BYTES, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (m == MAP_FAILED) {

    fprintf(stderr,
            "[afl-bug] ALLOCSIZE: extra-window mmap failed (%zu bytes)\n",
            (size_t)MAP_SIZE_ALLOCSHADOW_BYTES);
    return NULL;

  }

  AflAllocShadowExtra *s =
      &__afl_alloc_shadow_extra[__afl_alloc_shadow_extra_count++];
  s->origin = origin;
  s->table = (u16 *)m;
  *off_out = a - origin;
  return s->table;

}

static u32 __afl_alloc_pick_idx(void) {

  /* Round-robin claim. AFL++ fuzzing targets are single-threaded; we
     intentionally do not synchronise here. */
  for (u32 i = 0; i < MAP_SIZE_ALLOCRECORDS; ++i) {

    u32 idx = __afl_alloc_next_idx % MAP_SIZE_ALLOCRECORDS;
    __afl_alloc_next_idx++;
    if (idx == 0) continue;                              /* skip reserved 0 */
    if (__afl_alloc_records[idx].in_use == __AFL_ALLOC_INUSE_FREE) {

      __afl_alloc_records[idx].in_use = __AFL_ALLOC_INUSE_LIVE;
      return idx;

    }

  }

  return 0;                                                   /* table full */

}

/* Paint up to `size` bytes starting at `base` with shadow byte `idx`.
   When `idx == 0` (unregister), look the address up in any existing
   window; do NOT mmap a new one for unpainting. When `idx != 0`
   (register), lazily mmap a window covering `base` if none exists. */
static void __afl_alloc_shadow_paint(uintptr_t base, uint64_t size, u16 idx) {

  if (size > MAP_SIZE_ALLOCSHADOW_RANGE) return;
  uintptr_t off = 0;
  u16      *table = idx ? __afl_alloc_shadow_get_or_init(base, &off)
                        : __afl_alloc_shadow_find(base, &off);
  if (!table) return;
  if (off > MAP_SIZE_ALLOCSHADOW_RANGE - size) return;
  uint64_t g_start = off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  /* Paint exactly the allocation's granules, not one past: a +1
     sentinel byte would stomp the first granule of any immediately-
     adjacent allocation, mis-identifying its idx and poisoning the
     oracle's max_observed_off for that neighbour.  The oracle's
     `a + sz > end` check on r->size catches OOB at base+size precisely
     without needing a sentinel granule. */
  uint64_t g_end =
      (off + size + ((1ULL << MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2) - 1)) >>
      MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  if (g_end > MAP_SIZE_ALLOCSHADOW_GRANULES)
    g_end = MAP_SIZE_ALLOCSHADOW_GRANULES;
  if (g_end <= g_start) return;
  /* memset only works for u8; we need a per-granule u16 store loop. The
     compiler vectorizes this on x86_64 / arm64. */
  for (uint64_t g = g_start; g < g_end; ++g)
    table[g] = idx;

}

static inline int __afl_alloc_record_contains(AllocSizeRecord *r, uintptr_t a) {

  return r && r->in_use == __AFL_ALLOC_INUSE_LIVE && a >= r->base &&
         (uint64_t)(a - r->base) < r->size;

}

static int __afl_alloc_record_granules(AllocSizeRecord *r, u16 **table_out,
                                       uint64_t *g_start_out,
                                       uint64_t *g_end_out) {

  if (!r || r->in_use != __AFL_ALLOC_INUSE_LIVE || !r->size) return 0;
  if (r->size > MAP_SIZE_ALLOCSHADOW_RANGE) return 0;
  uintptr_t off = 0;
  u16      *table = __afl_alloc_shadow_find(r->base, &off);
  if (!table) return 0;
  if (off > MAP_SIZE_ALLOCSHADOW_RANGE - r->size) return 0;

  uint64_t g_start = off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  uint64_t g_end =
      (off + r->size + ((1ULL << MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2) - 1)) >>
      MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  if (g_end > MAP_SIZE_ALLOCSHADOW_GRANULES)
    g_end = MAP_SIZE_ALLOCSHADOW_GRANULES;
  if (g_end <= g_start) return 0;

  if (table_out) *table_out = table;
  if (g_start_out) *g_start_out = g_start;
  if (g_end_out) *g_end_out = g_end;
  return 1;

}

static void __afl_alloc_shadow_repaint_overlaps(uintptr_t base, uint64_t size) {

  if (!size || size > MAP_SIZE_ALLOCSHADOW_RANGE) return;
  uintptr_t off = 0;
  u16      *table = __afl_alloc_shadow_find(base, &off);
  if (!table) return;
  if (off > MAP_SIZE_ALLOCSHADOW_RANGE - size) return;

  uint64_t clear_start = off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  uint64_t clear_end =
      (off + size + ((1ULL << MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2) - 1)) >>
      MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  if (clear_end > MAP_SIZE_ALLOCSHADOW_GRANULES)
    clear_end = MAP_SIZE_ALLOCSHADOW_GRANULES;

  for (u32 i = 1; i < MAP_SIZE_ALLOCRECORDS; ++i) {

    AllocSizeRecord *cand = &__afl_alloc_records[i];
    u16             *cand_table = NULL;
    uint64_t         cand_start = 0, cand_end = 0;
    if (!__afl_alloc_record_granules(cand, &cand_table, &cand_start, &cand_end))
      continue;
    if (cand_table != table) continue;
    if (cand_end <= clear_start || cand_start >= clear_end) continue;
    __afl_alloc_shadow_paint(cand->base, cand->size, (u16)i);

  }

}

static inline int __afl_alloc_range_is_whole_granules(uintptr_t base,
                                                      uint64_t  size) {

  const uintptr_t mask =
      ((uintptr_t)1 << MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2) - 1;
  return size && ((base | (uintptr_t)size) & mask) == 0;

}

static AllocSizeRecord *__afl_alloc_find_oracle_record(uintptr_t a, u16 *table,
                                                       uintptr_t off, u16 idx) {

  if (!table) return NULL;
  if (idx && idx < MAP_SIZE_ALLOCRECORDS) {

    AllocSizeRecord *fast = &__afl_alloc_records[idx];
    if (__afl_alloc_record_contains(fast, a)) return fast;

  }

  uint64_t         g = off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2;
  AllocSizeRecord *best = NULL;
  for (u32 i = 1; i < MAP_SIZE_ALLOCRECORDS; ++i) {

    AllocSizeRecord *cand = &__afl_alloc_records[i];
    u16             *cand_table = NULL;
    uint64_t         cand_start = 0, cand_end = 0;
    if (!__afl_alloc_record_granules(cand, &cand_table, &cand_start, &cand_end))
      continue;
    if (cand_table != table) continue;
    if (g < cand_start || g >= cand_end) continue;

    if (__afl_alloc_record_contains(cand, a)) return cand;
    if (a >= cand->base && (!best || cand->base > best->base)) best = cand;

  }

  return best;

}

void __afl_alloc_register(void *ptr, uint64_t size, uint32_t alloc_site_id) {

  __afl_bug_ensure_runtime();
  if (!__afl_allocsize_active || !ptr || !size) return;
  /* shadow_paint with non-zero idx lazily creates the appropriate window
     (primary if first call, or an extra if `ptr` is outside the primary
     16 GiB span). No need for an explicit _init call here. */

  u32 idx = __afl_alloc_pick_idx();
  if (!idx) return;
  /* pick_idx already marked the slot LIVE. Fill fields and paint shadow. */
  AllocSizeRecord *r = &__afl_alloc_records[idx];
  r->base = (uintptr_t)ptr;
  r->size = size;
  r->alloc_site_id = alloc_site_id;
  r->max_observed_off = 0;
  r->derive_logged = 0;
  r->first_elem_size = 0;
  r->first_elem_align = 0;
  r->type_warned = 0;
  __afl_alloc_shadow_paint((uintptr_t)ptr, size, (u16)idx);

}

/* Size-derive: when a tracked allocation is freed (or unregistered), log
   (computed_size, max_observed_off) into a CmpLog routine slot keyed by
   alloc_site_id. The fuzzer's existing CMP_TYPE_RTN dictionary mining will
   pick up `computed_size` as a magic dictionary entry, propagating the
   input bytes that produced that exact size into havoc. */
static void __afl_size_derive_log(AllocSizeRecord *r) {

  if (!__afl_size_derive_active) return;
  if (!__afl_cmp_map) return;
  if (r->derive_logged) return;
  if (!r->size) return;

  /* Per-(site, log2(size)) identity keeps hot allocator size classes separate
     while sharing the CmpLog collision policy with ordinary observations. */
  u32 lg = r->size ? (64u - (u32)__builtin_clzll(r->size)) : 0;
  u64 site = ((u64)r->alloc_site_id << 32) | lg;
  u32 key = cmp_map_select(__afl_cmp_map, site);
  if (key == CMP_MAP_W) return;
  struct cmp_header *h = &__afl_cmp_map->headers[key];
  if (h->hits && (h->type != CMP_TYPE_RTN ||
                  cmp_map_attribute(__afl_cmp_map, key) != CMP_ATTR_NONE))
    return;
  if (h->hits >= CMP_MAP_RTN_H) return;                 /* slot full — skip */
  u32 slot, occurrence;
  key = cmplog_reserve(site, CMP_TYPE_RTN, 7, CMP_ATTR_NONE, CMP_MAP_RTN_H,
                       &slot, &occurrence);
  if (key == CMP_MAP_W) return;

  struct cmpfn_operands *op =
      (struct cmpfn_operands *)&__afl_cmp_map->log[key][slot];
  memset_noasan(op, 0, sizeof(*op));
  /* Bytewise little-endian copy of the two u64s into v0/v1. */
  for (u32 i = 0; i < 8; ++i) {

    op->v0[i] = (u8)(r->size >> (i * 8));
    op->v1[i] = (u8)(r->max_observed_off >> (i * 8));

  }

  op->v0_len = 8;
  op->v1_len = 8;
  op->addr_attr = 0;
  op->occurrence = occurrence;
  op->unused = 8;
  r->derive_logged = 1;

}

static inline void __afl_alloc_persistent_reset(u8 flush_derive) {

  if (likely(!__afl_bug_active)) return;

  /* Reset per-iteration bug-pass state at the __AFL_LOOP boundary:
       - BUDGET / SIZEFILL frame stacks: a longjmp out of an
         instrumented site can leave orphan frames whose ptr_before
         would match a future call by accident, triggering spurious
         aborts.
       - Local bug map when no shared mem is bound: never zeroed
         between iterations otherwise -> stale MAX-channel coverage.
       - Per-record counters (max_observed_off etc.): per-input data,
         not allocation state. */

  /* (1) Per-iteration bug-pass frame stacks. */
  __afl_bug_ws_top = -1;
  __afl_bug_sf_top = -1;

  /* (2) Local bug map (when we couldn't bind to shared mem). The shared-mem
         path lives at the tail of __afl_area_ptr, which afl-fuzz / the
         forkserver already memsets between runs; that case is a no-op. */
  if (__afl_bug_map_active && __afl_bug_map == __afl_bug_map_local) {

    memset_noasan(__afl_bug_map_local, 0, MAP_SIZE_BUG_BYTES);

  }

  /* (3) ALLOCSIZE per-record reset. Long-lived allocations (those that
     persist across __AFL_LOOP iterations by design — e.g. a buffer the
     persistent harness allocates once and reuses) must keep in_use=1 so
     find_record still resolves to them; we only reset per-iteration
     counters (max_observed_off, derive_logged, type-confusion state). */
  if (likely(!__afl_allocsize_active)) return;
  for (u32 i = 1; i < MAP_SIZE_ALLOCRECORDS; ++i) {

    AllocSizeRecord *r = &__afl_alloc_records[i];
    if (r->in_use != __AFL_ALLOC_INUSE_LIVE) continue;
    if (flush_derive) __afl_size_derive_log(r);
    r->max_observed_off = 0;
    r->derive_logged = 0;
    r->first_elem_size = 0;
    r->first_elem_align = 0;
    r->type_warned = 0;

  }

}

void __afl_alloc_unregister(void *ptr) {

  if (!__afl_allocsize_active || !ptr) return;

  uintptr_t a = (uintptr_t)ptr;
  uintptr_t off = 0;
  u16      *tbl = __afl_alloc_shadow_find(a, &off);

  /* Fast path: the granule's shadow byte points directly at our record.
     Granules are 64 bytes; malloc returns 16-byte-aligned chunks, so
     several small allocations can share one granule and the shadow
     holds only the most recently registered idx.  If the fast lookup
     mismatches (different base), fall through to a bounded linear scan
     to find the record whose base matches.  Without the fallback the
     older allocation's slot leaks until the table fills.
     Also fall through if tbl is NULL — ptr might be from a window that
     was never created or has been exhausted; the records table still
     has the live entry, find it by linear scan. */
  AllocSizeRecord *r = NULL;
  u16 idx = tbl ? tbl[off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2] : 0;
  if (idx && idx < MAP_SIZE_ALLOCRECORDS &&
      __afl_alloc_records[idx].in_use == __AFL_ALLOC_INUSE_LIVE &&
      __afl_alloc_records[idx].base == a) {

    r = &__afl_alloc_records[idx];

  } else {

    for (u32 i = 1; i < MAP_SIZE_ALLOCRECORDS; ++i) {

      AllocSizeRecord *cand = &__afl_alloc_records[i];
      if (cand->in_use == __AFL_ALLOC_INUSE_LIVE && cand->base == a) {

        r = cand;
        break;

      }

    }

  }

  if (!r) return;                         /* not tracked (or already freed) */

  uintptr_t old_base = r->base;
  uint64_t  old_size = r->size;
  __afl_size_derive_log(r);
  r->in_use = __AFL_ALLOC_INUSE_FREE;
  __afl_alloc_shadow_paint(old_base, old_size, 0);
  if (!__afl_alloc_range_is_whole_granules(old_base, old_size))
    __afl_alloc_shadow_repaint_overlaps(old_base, old_size);

}

void *__afl_track_malloc(uint64_t size, uint32_t alloc_site_id) {

  void *p = malloc((size_t)size);
  __afl_alloc_register(p, size, alloc_site_id);
  return p;

}

void *__afl_track_calloc(uint64_t nmemb, uint64_t size,
                         uint32_t alloc_site_id) {

  /* Check for size_t overflow BEFORE calling calloc.  Checking after
     the call uses u64 math that no longer reflects what libc actually
     allocated (size_t truncation on 32-bit; libc-internal NULL on
     overflow), leaving the runtime free to register a fictitious
     extent. */
  size_t n = (size_t)nmemb, s = (size_t)size;
  if (n && s && n > ((size_t)-1) / s) return NULL;
  size_t total = n * s;
  void  *p = calloc(n, s);
  if (!p) return p;
  __afl_alloc_register(p, (uint64_t)total, alloc_site_id);
  return p;

}

void *__afl_track_realloc(void *ptr, uint64_t size, uint32_t alloc_site_id) {

  /* Call realloc first, then act on its outcome.
       p != NULL              - new buffer (possibly same address):
                                unregister old, register new.
       p == NULL              - either realloc failed (ptr still valid
                                per C11) OR realloc(p, 0) was issued.
                                On glibc >= 2.32 (and C23) realloc(p, 0)
                                returns NULL without freeing ptr;
                                older glibc freed it.  We cannot tell
                                the two outcomes apart, so we leave the
                                registration in place — the caller is
                                expected to free(ptr) itself.  Cost:
                                under old glibc this leaks one record
                                slot per realloc(p,0); under new glibc
                                it's correct. */
  size_t s = (size_t)size;
  void  *p = realloc(ptr, s);

  if (p != NULL) {

    if (ptr) __afl_alloc_unregister(ptr);
    __afl_alloc_register(p, size, alloc_site_id);

  }

  return p;

}

int __afl_track_posix_memalign(void **memptr, uint64_t alignment, uint64_t size,
                               uint32_t alloc_site_id) {

  int rc = posix_memalign(memptr, (size_t)alignment, (size_t)size);
  if (rc == 0) __afl_alloc_register(*memptr, size, alloc_site_id);
  return rc;

}

/* C++17 aligned-new replacement. Unlike __afl_track_malloc (which would
   discard the alignment requirement and hand out an under-aligned buffer
   that subsequent SIMD stores can fault on), this goes through
   posix_memalign and respects the C++ contract. Returns NULL on failure
   instead of throwing — the same observable difference as the throwing-
   new -> __afl_track_malloc rewrite documented in the pass. */
void *__afl_track_aligned_alloc(uint64_t size, uint64_t alignment,
                                uint32_t alloc_site_id) {

  void *p = NULL;
  /* posix_memalign requires alignment to be a power of two AND a multiple
     of sizeof(void*); enforce the floor here so a bogus align_val_t can't
     wedge the call. C++ aligned new already passes a valid value, so this
     just hardens against malformed IR. */
  if (alignment < sizeof(void *)) alignment = sizeof(void *);
  if (posix_memalign(&p, (size_t)alignment, (size_t)size) != 0) return NULL;
  __afl_alloc_register(p, size, alloc_site_id);
  return p;

}

void *__afl_track_reallocarray(void *ptr, uint64_t nmemb, uint64_t size,
                               uint32_t alloc_site_id) {

  /* Saturating overflow check in size_t to match libc. */
  size_t n = (size_t)nmemb, sz = (size_t)size;
  if (n && sz && n > ((size_t)-1) / sz) return NULL;
  size_t total = n * sz;

  /* Same outcome-driven flow as __afl_track_realloc.  p==NULL leaves the
     registration in place (libc-dependent semantics for total==0). */
  void *p = realloc(ptr, total);
  if (p != NULL) {

    if (ptr) __afl_alloc_unregister(ptr);
    __afl_alloc_register(p, (uint64_t)total, alloc_site_id);

  }

  return p;

}

char *__afl_track_strdup(const char *s, uint32_t alloc_site_id) {

  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char  *p = (char *)malloc(n);
  if (!p) return NULL;
  memcpy(p, s, n);
  __afl_alloc_register(p, n, alloc_site_id);
  return p;

}

char *__afl_track_strndup(const char *s, uint64_t n, uint32_t alloc_site_id) {

  if (!s) return NULL;
  /* strndup copies at most n bytes, stopping at the first NUL, and always
     appends one. The malloc size is (effective_len + 1). */
  size_t len = 0;
  while (len < (size_t)n && s[len])
    ++len;
  char *p = (char *)malloc(len + 1);
  if (!p) return NULL;
  memcpy(p, s, len);
  p[len] = '\0';
  __afl_alloc_register(p, len + 1, alloc_site_id);
  return p;

}

void __afl_track_free(void *ptr) {

  __afl_alloc_unregister(ptr);
  free(ptr);

}

/* Shared oracle body. Takes a u64 length so the i32 and i64 callers can
   funnel into one implementation; lengths beyond the tracked buffer's
   end still produce a single soft-OOB abort. */
static void __afl_alloc_oracle_impl(const void *ptr, uint64_t store_size) {

  __afl_bug_ensure_runtime();
  if (!__afl_allocsize_active) return;
  uintptr_t a = (uintptr_t)ptr;
  uintptr_t off = 0;
  u16      *tbl = __afl_alloc_shadow_find(a, &off);
  if (!tbl) return;
  u16              idx = tbl[off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2];
  AllocSizeRecord *r = NULL;
  if (idx) {

    r = __afl_alloc_find_oracle_record(a, tbl, off, idx);

  } else if (a) {

    /* The store-start granule is unpainted.  A 1-byte soft-OOB write that
       begins exactly at a tracked allocation's end is invisible here when that
       end is granule-aligned: the end byte falls in the next, unpainted
       granule (paint stops at the allocation's last granule, deliberately, to
       avoid stomping a neighbour's idx).  Probe the granule of the byte just
       before the store; if it belongs to a live allocation whose end is <= a,
       this store starts at (or past) that end -> soft-OOB. */
    uintptr_t off_prev = 0;
    u16      *tbl_prev = __afl_alloc_shadow_find(a - 1, &off_prev);
    if (tbl_prev) {

      u16 idx_prev = tbl_prev[off_prev >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2];
      if (idx_prev) {

        AllocSizeRecord *rp =
            __afl_alloc_find_oracle_record(a - 1, tbl_prev, off_prev, idx_prev);
        /* rp contains a-1 by construction; require a >= end so we only fire
           when the store genuinely starts at or past the allocation's end. */
        if (rp && a >= rp->base + rp->size) r = rp;

      }

    }

  }

  if (!r) return;
  uintptr_t end = r->base + r->size;
  /* Treat zero-width (e.g. struct-of-size-0 or unknown) as one byte so the
     oracle still has a defined tripwire. */
  uint64_t sz = store_size ? store_size : 1;
  /* Track the byte just past the store (off + sz). */
  uint64_t off_now = (uint64_t)(a - r->base) + sz;
  if (off_now > r->max_observed_off) r->max_observed_off = off_now;
  /* (3) Soft-OOB tripwire: store extends past end. A 4-byte store one byte
     before the end of the buffer is OOB; the old `a >= end` check missed
     it. Use `a + sz > end`, written as `sz > end - a` to avoid wrap when
     `a` is far past `end`. */
  if (a >= end || sz > (uint64_t)(end - a)) {

    __afl_bug_writes("[afl-bug] ALLOCSIZE soft-OOB: ");
    __afl_bug_writeu((unsigned long long)sz);
    __afl_bug_writes("-byte write at ");
    __afl_bug_writep(ptr);
    __afl_bug_writes(", allocation [");
    __afl_bug_writep((void *)r->base);
    __afl_bug_writes("..");
    __afl_bug_writep((void *)end);
    __afl_bug_writes(") (size=");
    __afl_bug_writeu((unsigned long long)r->size);
    __afl_bug_writes(", site=");
    __afl_bug_writeu((unsigned long long)r->alloc_site_id);
    __afl_bug_writes(", off=");
    __afl_bug_writeu((unsigned long long)(a - r->base));
    __afl_bug_writes(")\n");
    _exit(134);

  }

  uint64_t headroom = end - a;
  /* (1) Headroom max-rule: small headroom -> large value, so the max-rule
     keeps the closest approach to the end. */
  u32 log_hr = headroom ? (64u - (u32)__builtin_clzll(headroom)) : 0;
  u32 inv = 64u - log_hr;
  if (!__afl_bug_map) return;
  /* The bug map is partitioned: SCALAR/loop occupy [0, half), SLACK
     occupies [half, MAP_SIZE_BUG_ENTRIES).  Mask ALLOCSIZE writes into
     the SCALAR half so they don't clobber SLACK's tight-comparison
     signal.  Collisions with SCALAR are accepted (different channel
     classes; allocator-bound vs arithmetic-bound sites rarely overlap
     for the same site_id). */
  const u32 half = MAP_SIZE_BUG_ENTRIES / 2;
  u32       slot1 = (r->alloc_site_id * 31u) & (half - 1);
  if (__afl_bug_map[slot1] < inv) __afl_bug_map[slot1] = inv;
  /* (2) Proximity bucket as synthetic edge: hash(site, log2(headroom)). */
  u32 bucket = log_hr > 15 ? 15 : log_hr;
  u32 slot2 = ((r->alloc_site_id * 1009u) ^ (bucket * 17u)) & (half - 1);
  if (__afl_bug_map[slot2] < (bucket + 1u)) __afl_bug_map[slot2] = bucket + 1u;

}

void __afl_alloc_oracle(const void *ptr, uint32_t store_size) {

  __afl_alloc_oracle_impl(ptr, (uint64_t)store_size);

}

void __afl_alloc_oracle_n(const void *ptr, uint64_t store_size) {

  __afl_alloc_oracle_impl(ptr, store_size);

}

/* Type-confusion smell. We remember the first observed (elem_size,
   alignment) pair per allocation; any later store whose elem_size
   differs triggers a one-shot warning on stderr. This is informational,
   not fatal — type-punning is legal in C/C++ and we don't want to
   abort benign programs, only flag the smell so the fuzzer's stderr
   pickups can correlate with crashes downstream. */
void __afl_alloc_oracle_typed(const void *ptr, uint32_t elem_size,
                              uint32_t alignment) {

  __afl_bug_ensure_runtime();
  if (!__afl_allocsize_active) return;
  if (!elem_size) return;         /* zero-width stores carry no type signal */
  uintptr_t a = (uintptr_t)ptr;
  uintptr_t off = 0;
  u16      *tbl = __afl_alloc_shadow_find(a, &off);
  if (!tbl) return;
  u16 idx = tbl[off >> MAP_SIZE_ALLOCSHADOW_GRANULE_LOG2];
  if (!idx || idx >= MAP_SIZE_ALLOCRECORDS) return;
  AllocSizeRecord *r = __afl_alloc_find_oracle_record(a, tbl, off, idx);
  if (!r) return;
  if (a != r->base) return;

  /* First-elem-size wins: only the first store at this allocation
     stamps the (size, align) pair; later stores compare against it. */
  if (r->first_elem_size == 0) {

    r->first_elem_size = elem_size;
    r->first_elem_align = alignment;
    return;

  }

  if (r->first_elem_size == elem_size) return;

  /* Mismatch. One-shot warning gate. */
  if (r->type_warned) return;
  r->type_warned = 1;

  /* Signal-safe report (matches the soft-OOB / BUDGET / SIZEFILL sites).
     Typed-oracle is informational and does NOT _exit; it just emits the
     diagnostic via write(2) so reentering stdio from a signal-handler-
     instrumented store can't deadlock. */
  __afl_bug_writes("[afl-bug] ALLOCSIZE type-confusion: site=");
  __afl_bug_writeu((unsigned long long)r->alloc_site_id);
  __afl_bug_writes(" first elem_size=");
  __afl_bug_writeu((unsigned long long)r->first_elem_size);
  __afl_bug_writes(" (align=");
  __afl_bug_writeu((unsigned long long)r->first_elem_align);
  __afl_bug_writes("), later elem_size=");
  __afl_bug_writeu((unsigned long long)elem_size);
  __afl_bug_writes(" (align=");
  __afl_bug_writeu((unsigned long long)alignment);
  __afl_bug_writes(") at ");
  __afl_bug_writep(ptr);
  __afl_bug_writes("\n");

}

