/*

   american fuzzy lop++ - dislocator, an abusive allocator
   -----------------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2016 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is a companion library that can be used as a drop-in replacement
   for the libc allocator in the fuzzed binaries. See README.dislocator.md for
   more info.

 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>

#ifdef __APPLE__
  #include <mach/vm_statistics.h>
#endif

#ifdef __FreeBSD__
  #include <sys/param.h>
#endif

#if (defined(__linux__) && !defined(__ANDROID__)) || defined(__HAIKU__)
  #include <unistd.h>
  #include <sys/prctl.h>
  #ifdef __linux__
    #include <sys/syscall.h>
    #include <malloc.h>
  #endif
  #ifdef __NR_getrandom
    #define arc4random_buf(p, l)                       \
      do {                                             \
                                                       \
        ssize_t rd = syscall(__NR_getrandom, p, l, 0); \
        if (rd != l) DEBUGF("getrandom failed");       \
                                                       \
      } while (0)

  #else
    #include <time.h>
    #define arc4random_buf(p, l)     \
      do {                           \
                                     \
        srand(time(NULL));           \
        u32 i;                       \
        u8 *ptr = (u8 *)p;           \
        for (i = 0; i < l; i++)      \
          ptr[i] = rand() % INT_MAX; \
                                     \
      } while (0)

  #endif
  #ifndef PR_SET_VMA
    #define PR_SET_VMA 0x53564d41
    #define PR_SET_VMA_ANON_NAME 0
  #endif
#endif

#include "config.h"
#include "types.h"

#if __STDC_VERSION__ < 201112L || \
    (defined(__FreeBSD__) && __FreeBSD_version < 1200000)
// use this hack if not C11
typedef struct {

  long long   __ll;
  long double __ld;

} max_align_t;

#endif

#define ALLOC_ALIGN_SIZE (_Alignof(max_align_t))

#ifndef PAGE_SIZE
  #define PAGE_SIZE 4096
#endif                                                        /* !PAGE_SIZE */

#ifndef MAP_ANONYMOUS
  #define MAP_ANONYMOUS MAP_ANON
#endif                                                    /* !MAP_ANONYMOUS */

#define SUPER_PAGE_SIZE 1 << 21

/* Error / message handling: */

#define DEBUGF(_x...)                 \
  do {                                \
                                      \
    if (alloc_verbose) {              \
                                      \
      if (++call_depth == 1) {        \
                                      \
        fprintf(stderr, "[AFL] " _x); \
        fprintf(stderr, "\n");        \
                                      \
      }                               \
      call_depth--;                   \
                                      \
    }                                 \
                                      \
  } while (0)

#define FATAL(_x...)                    \
  do {                                  \
                                        \
    if (++call_depth == 1) {            \
                                        \
      fprintf(stderr, "*** [AFL] " _x); \
      fprintf(stderr, " ***\n");        \
      abort();                          \
                                        \
    }                                   \
    call_depth--;                       \
                                        \
  } while (0)

/* Macro to count the number of pages needed to store a buffer: */

#define PG_COUNT(_l) (((_l) + (PAGE_SIZE - 1)) / PAGE_SIZE)

/* Canary & clobber bytes: */

#define ALLOC_CANARY 0xAACCAACC
#define ALLOC_CLOBBER 0xCC

#define TAIL_ALLOC_CANARY 0xAC

#define PTR_C(_p) (((u32 *)(_p))[-1])
#define PTR_L(_p) (((u32 *)(_p))[-2])

/* Configurable stuff (use AFL_LD_* to set): */

static size_t max_mem = MAX_ALLOC;      /* Max heap usage to permit         */
static u8     alloc_verbose,            /* Additional debug messages        */
    hard_fail,                          /* abort() when max_mem exceeded?   */
    no_calloc_over,                     /* abort() on calloc() overflows?   */
    align_allocations;                  /* Force alignment to sizeof(void*) */

#if defined __OpenBSD__ || defined __APPLE__
  #define __thread
  #warning no thread support available
#endif
static _Atomic size_t total_mem;        /* Currently allocated mem          */

static __thread u32 call_depth;         /* To avoid recursion via fprintf() */
static u32          alloc_canary;

/* This is the main alloc function. It allocates one page more than necessary,
   sets that tailing page to PROT_NONE, and then increments the return address
   so that it is right-aligned to that boundary. Since it always uses mmap(),
   the returned memory will be zeroed. */

static void *__dislocator_alloc(size_t len) {

  u8    *ret, *base;
  size_t tlen;
  int    flags, protflags, fd, sp;

  if (total_mem + len > max_mem || total_mem + len < total_mem) {

    if (hard_fail) FATAL("total allocs exceed %zu MB", max_mem / 1024 / 1024);

    DEBUGF("total allocs exceed %zu MB, returning NULL", max_mem / 1024 / 1024);

    return NULL;

  }

  size_t rlen;
  if (align_allocations && (len & (ALLOC_ALIGN_SIZE - 1)))
    rlen = (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
  else
    rlen = len;

  /* We will also store buffer length and a canary below the actual buffer, so
     let's add 8 bytes for that. */

  base = NULL;
  tlen = (1 + PG_COUNT(rlen + 8)) * PAGE_SIZE;
  protflags = PROT_READ | PROT_WRITE;
  flags = MAP_PRIVATE | MAP_ANONYMOUS;
  fd = -1;
#if defined(PROT_MAX)
  // apply when sysctl vm.imply_prot_max is set to 1
  // no-op otherwise
  protflags |= PROT_MAX(PROT_READ | PROT_WRITE);
#endif
#if defined(USEHUGEPAGE)
  sp = (rlen >= SUPER_PAGE_SIZE && !(rlen % SUPER_PAGE_SIZE));

  #if defined(__APPLE__)
  if (sp) fd = VM_FLAGS_SUPERPAGE_SIZE_2MB;
  #elif defined(__linux__)
  if (sp) flags |= MAP_HUGETLB;
  #elif defined(__FreeBSD__)
  if (sp) flags |= MAP_ALIGNED_SUPER;
  #elif defined(__sun)
  if (sp) {

    base = (void *)(caddr_t)(1 << 21);
    flags |= MAP_ALIGN;

  }

  #endif
#else
  (void)sp;
#endif

  ret = (u8 *)mmap(base, tlen, protflags, flags, fd, 0);
#if defined(USEHUGEPAGE)
  /* We try one more time with regular call */
  if (ret == MAP_FAILED) {

  #if defined(__APPLE__)
    fd = -1;
  #elif defined(__linux__)
    flags &= -MAP_HUGETLB;
  #elif defined(__FreeBSD__)
    flags &= -MAP_ALIGNED_SUPER;
  #elif defined(__sun)
    flags &= -MAP_ALIGN;
  #endif
    ret = (u8 *)mmap(NULL, tlen, protflags, flags, fd, 0);

  }

#endif

  if (ret == MAP_FAILED) {

    if (hard_fail) FATAL("mmap() failed on alloc (OOM?)");

    DEBUGF("mmap() failed on alloc (OOM?)");

    return NULL;

  }

#if defined(USENAMEDPAGE)
  #if defined(__linux__)
  // in the /proc/<pid>/maps file, the anonymous page appears as
  // `<start>-<end> ---p 00000000 00:00 0 [anon:libdislocator]`
  if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)ret, tlen,
            (unsigned long)"libdislocator") < 0) {

    DEBUGF("prctl() failed");

  }

  #endif
#endif

  /* Set PROT_NONE on the last page. */

  if (mprotect(ret + PG_COUNT(rlen + 8) * PAGE_SIZE, PAGE_SIZE, PROT_NONE))
    FATAL("mprotect() failed when allocating memory");

  /* Offset the return pointer so that it's right-aligned to the page
     boundary. */

  ret += PAGE_SIZE * PG_COUNT(rlen + 8) - rlen - 8;

  /* Store allocation metadata. */

  ret += 8;

  PTR_L(ret) = len;
  PTR_C(ret) = alloc_canary;

  total_mem += len;

  if (rlen != len) {

    size_t i;
    for (i = len; i < rlen; ++i)
      ret[i] = TAIL_ALLOC_CANARY;

  }

  return ret;

}

/* The "user-facing" wrapper for calloc(). This just checks for overflows and
   displays debug messages if requested. */

void *calloc(size_t elem_len, size_t elem_cnt) {

  void *ret;

  size_t len = elem_len * elem_cnt;

  /* Perform some sanity checks to detect obvious issues... */

  if (elem_cnt && len / elem_cnt != elem_len) {

    if (no_calloc_over) {

      DEBUGF("calloc(%zu, %zu) would overflow, returning NULL", elem_len,
             elem_cnt);
      return NULL;

    }

    FATAL("calloc(%zu, %zu) would overflow", elem_len, elem_cnt);

  }

  ret = __dislocator_alloc(len);

  DEBUGF("calloc(%zu, %zu) = %p [%zu total]", elem_len, elem_cnt, ret,
         total_mem);

  return ret;

}

/* The wrapper for malloc(). Roughly the same, also clobbers the returned
   memory (unlike calloc(), malloc() is not guaranteed to return zeroed
   memory). */

void *malloc(size_t len) {

  void *ret;

  ret = __dislocator_alloc(len);

  DEBUGF("malloc(%zu) = %p [%zu total]", len, ret, total_mem);

  if (ret && len) memset(ret, ALLOC_CLOBBER, len);

  return ret;

}

/* The wrapper for free(). This simply marks the entire region as PROT_NONE.
   If the region is already freed, the code will segfault during the attempt to
   read the canary. Not very graceful, but works, right? */

void free(void *ptr) {

  u32 len;

  DEBUGF("free(%p)", ptr);

  if (!ptr) return;

  if (PTR_C(ptr) != alloc_canary) FATAL("bad allocator canary on free()");

  len = PTR_L(ptr);

  total_mem -= len;
  u8 *ptr_ = ptr;

  if (align_allocations && (len & (ALLOC_ALIGN_SIZE - 1))) {

    size_t rlen = (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
    for (; len < rlen; ++len)
      if (ptr_[len] != TAIL_ALLOC_CANARY)
        FATAL("bad tail allocator canary on free()");

  }

  /* Protect everything. Note that the extra page at the end is already
     set as PROT_NONE, so we don't need to touch that. */

  ptr_ -= PAGE_SIZE * PG_COUNT(len + 8) - len - 8;

  if (mprotect(ptr_ - 8, PG_COUNT(len + 8) * PAGE_SIZE, PROT_NONE))
    FATAL("mprotect() failed when freeing memory");

  ptr = ptr_;

  /* Keep the mapping; this is wasteful, but prevents ptr reuse. */

}

/* Realloc is pretty straightforward, too. We forcibly reallocate the buffer,
   move data, and then free (aka mprotect()) the original one. */

void *realloc(void *ptr, size_t len) {

  void *ret;

  ret = malloc(len);

  if (ret && ptr) {

    if (PTR_C(ptr) != alloc_canary) FATAL("bad allocator canary on realloc()");
    // Here the tail canary check is delayed to free()

    memcpy(ret, ptr, MIN(len, PTR_L(ptr)));
    free(ptr);

  }

  DEBUGF("realloc(%p, %zu) = %p [%zu total]", ptr, len, ret, total_mem);

  return ret;

}

/* posix_memalign we mainly check the proper alignment argument
   if the requested size fits within the alignment we do
   a normal request */

int posix_memalign(void **ptr, size_t align, size_t len) {

  // if (*ptr == NULL) return EINVAL; // (andrea) Why? I comment it out for now
  if ((align % 2) || (align % sizeof(void *))) return EINVAL;
  if (len == 0) {

    *ptr = NULL;
    return 0;

  }

  size_t rem = len % align;
  if (rem) len += align - rem;

  *ptr = __dislocator_alloc(len);

  if (*ptr && len) memset(*ptr, ALLOC_CLOBBER, len);

  DEBUGF("posix_memalign(%p %zu, %zu) [*ptr = %p]", ptr, align, len, *ptr);

  return 0;

}

/* just the non-posix fashion */

void *memalign(size_t align, size_t len) {

  void *ret = NULL;

  if (posix_memalign(&ret, align, len)) {

    DEBUGF("memalign(%zu, %zu) failed", align, len);

  }

  return ret;

}

/* sort of C11 alias of memalign only more severe, alignment-wise */

void *aligned_alloc(size_t align, size_t len) {

  void *ret = NULL;

  if ((len % align)) return NULL;

  if (posix_memalign(&ret, align, len)) {

    DEBUGF("aligned_alloc(%zu, %zu) failed", align, len);

  }

  return ret;

}

/* specific BSD api mainly checking possible overflow for the size */

void *reallocarray(void *ptr, size_t elem_len, size_t elem_cnt) {

  const size_t elem_lim = 1UL << (sizeof(size_t) * 4);
  const size_t elem_tot = elem_len * elem_cnt;
  void        *ret = NULL;

  if ((elem_len >= elem_lim || elem_cnt >= elem_lim) && elem_len > 0 &&
      elem_cnt > (SIZE_MAX / elem_len)) {

    DEBUGF("reallocarray size overflow (%zu)", elem_tot);

  } else {

    ret = realloc(ptr, elem_tot);

  }

  return ret;

}

#if defined(__APPLE__)
size_t malloc_size(const void *ptr) {

#elif !defined(__ANDROID__)
size_t malloc_usable_size(void *ptr) {

#else
size_t malloc_usable_size(const void *ptr) {

#endif

  return ptr ? PTR_L(ptr) : 0;

}

#if defined(__APPLE__)
size_t malloc_good_size(size_t len) {

  return (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;

}

#endif

__attribute__((constructor)) void __dislocator_init(void) {

  char *tmp = getenv("AFL_LD_LIMIT_MB");

  if (tmp) {

    char              *tok;
    unsigned long long mmem = strtoull(tmp, &tok, 10);
    if (*tok != '\0' || errno == ERANGE || mmem > SIZE_MAX / 1024 / 1024)
      FATAL("Bad value for AFL_LD_LIMIT_MB");
    max_mem = mmem * 1024 * 1024;

  }

  alloc_canary = ALLOC_CANARY;
  tmp = getenv("AFL_RANDOM_ALLOC_CANARY");

  if (tmp) arc4random_buf(&alloc_canary, sizeof(alloc_canary));

  alloc_verbose = !!getenv("AFL_LD_VERBOSE");
  hard_fail = !!getenv("AFL_LD_HARD_FAIL");
  no_calloc_over = !!getenv("AFL_LD_NO_CALLOC_OVER");
  align_allocations = !!getenv("AFL_ALIGNED_ALLOC");

}

/* NetBSD fault handler specific api subset */

void (*esetfunc(void (*fn)(int, const char *, ...)))(int, const char *, ...) {

  /* Might not be meaningful to implement; upper calls already report errors */
  return NULL;

}

void *emalloc(size_t len) {

  return malloc(len);

}

void *ecalloc(size_t elem_len, size_t elem_cnt) {

  return calloc(elem_len, elem_cnt);

}

void *erealloc(void *ptr, size_t len) {

  return realloc(ptr, len);

}

