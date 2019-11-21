/*

   american fuzzy lop - dislocator, an abusive allocator
   -----------------------------------------------------

   Written by Michal Zalewski

   Copyright 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is a companion library that can be used as a drop-in replacement
   for the libc allocator in the fuzzed binaries. See README.dislocator.md for
   more info.

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>

#ifdef __APPLE__
#include <mach/vm_statistics.h>
#endif

#include "config.h"
#include "types.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif                                                        /* !PAGE_SIZE */

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif                                                    /* !MAP_ANONYMOUS */

#define SUPER_PAGE_SIZE 1<<21

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

#define PTR_C(_p) (((u32*)(_p))[-1])
#define PTR_L(_p) (((u32*)(_p))[-2])

/* Configurable stuff (use AFL_LD_* to set): */

static u32 max_mem = MAX_ALLOC;         /* Max heap usage to permit         */
static u8  alloc_verbose,               /* Additional debug messages        */
    hard_fail,                          /* abort() when max_mem exceeded?   */
    no_calloc_over;                     /* abort() on calloc() overflows?   */

#if	defined	__OpenBSD__ || defined __APPLE__
#define __thread
#warning no thread support available
#endif
static __thread size_t total_mem;       /* Currently allocated mem          */

static __thread u32 call_depth;         /* To avoid recursion via fprintf() */

/* This is the main alloc function. It allocates one page more than necessary,
   sets that tailing page to PROT_NONE, and then increments the return address
   so that it is right-aligned to that boundary. Since it always uses mmap(),
   the returned memory will be zeroed. */

static void* __dislocator_alloc(size_t len) {

  void* ret;
  size_t tlen;
  int flags, fd, sp;

  if (total_mem + len > max_mem || total_mem + len < total_mem) {

    if (hard_fail) FATAL("total allocs exceed %u MB", max_mem / 1024 / 1024);

    DEBUGF("total allocs exceed %u MB, returning NULL", max_mem / 1024 / 1024);

    return NULL;

  }

  tlen = (1 + PG_COUNT(len + 8)) * PAGE_SIZE;
  flags = MAP_PRIVATE | MAP_ANONYMOUS;
  fd = -1;
#if defined(USEHUGEPAGE)
  sp = (len >= SUPER_PAGE_SIZE && !(len % SUPER_PAGE_SIZE));

#if defined(__APPLE__)
  if (sp) fd = VM_FLAGS_SUPERPAGE_SIZE_2MB;
#elif defined(__linux__)
  if (sp) flags |= MAP_HUGETLB;
#elif defined(__FreeBSD__)
  if (sp) flags |= MAP_ALIGNED_SUPER;
#endif
#else
  (void)sp;
#endif

  /* We will also store buffer length and a canary below the actual buffer, so
     let's add 8 bytes for that. */

  ret = mmap(NULL, tlen, PROT_READ | PROT_WRITE,
             flags, fd, 0);
#if defined(USEHUGEPAGE)
  /* We try one more time with regular call */
  if (ret == MAP_FAILED) {
#if defined(__APPLE__)
  fd = -1;
#elif defined(__linux__)
  flags &= -MAP_HUGETLB;
#elif defined(__FreeBSD__)
  flags &= -MAP_ALIGNED_SUPER;
#endif
     ret = mmap(NULL, tlen, PROT_READ | PROT_WRITE,
                flags, fd, 0);
  }
#endif

  if (ret == MAP_FAILED) {

    if (hard_fail) FATAL("mmap() failed on alloc (OOM?)");

    DEBUGF("mmap() failed on alloc (OOM?)");

    return NULL;

  }

  /* Set PROT_NONE on the last page. */

  if (mprotect(ret + PG_COUNT(len + 8) * PAGE_SIZE, PAGE_SIZE, PROT_NONE))
    FATAL("mprotect() failed when allocating memory");

  /* Offset the return pointer so that it's right-aligned to the page
     boundary. */

  ret += PAGE_SIZE * PG_COUNT(len + 8) - len - 8;

  /* Store allocation metadata. */

  ret += 8;

  PTR_L(ret) = len;
  PTR_C(ret) = ALLOC_CANARY;

  total_mem += len;

  return ret;

}

/* The "user-facing" wrapper for calloc(). This just checks for overflows and
   displays debug messages if requested. */

void* calloc(size_t elem_len, size_t elem_cnt) {

  void* ret;

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

/* TODO: add a wrapper for posix_memalign, otherwise apps who use it,
   will fail when freeing the memory.
*/

/* The wrapper for malloc(). Roughly the same, also clobbers the returned
   memory (unlike calloc(), malloc() is not guaranteed to return zeroed
   memory). */

void* malloc(size_t len) {

  void* ret;

  ret = __dislocator_alloc(len);

  DEBUGF("malloc(%zu) = %p [%zu total]", len, ret, total_mem);

  if (ret && len) memset(ret, ALLOC_CLOBBER, len);

  return ret;

}

/* The wrapper for free(). This simply marks the entire region as PROT_NONE.
   If the region is already freed, the code will segfault during the attempt to
   read the canary. Not very graceful, but works, right? */

void free(void* ptr) {

  u32 len;

  DEBUGF("free(%p)", ptr);

  if (!ptr) return;

  if (PTR_C(ptr) != ALLOC_CANARY) FATAL("bad allocator canary on free()");

  len = PTR_L(ptr);

  total_mem -= len;

  /* Protect everything. Note that the extra page at the end is already
     set as PROT_NONE, so we don't need to touch that. */

  ptr -= PAGE_SIZE * PG_COUNT(len + 8) - len - 8;

  if (mprotect(ptr - 8, PG_COUNT(len + 8) * PAGE_SIZE, PROT_NONE))
    FATAL("mprotect() failed when freeing memory");

  /* Keep the mapping; this is wasteful, but prevents ptr reuse. */

}

/* Realloc is pretty straightforward, too. We forcibly reallocate the buffer,
   move data, and then free (aka mprotect()) the original one. */

void* realloc(void* ptr, size_t len) {

  void* ret;

  ret = malloc(len);

  if (ret && ptr) {

    if (PTR_C(ptr) != ALLOC_CANARY) FATAL("bad allocator canary on realloc()");

    memcpy(ret, ptr, MIN(len, PTR_L(ptr)));
    free(ptr);

  }

  DEBUGF("realloc(%p, %zu) = %p [%zu total]", ptr, len, ret, total_mem);

  return ret;

}

/* posix_memalign we mainly check the proper alignment argument
   if the requested size fits within the alignment we do
   a normal request */

int posix_memalign(void** ptr, size_t align, size_t len) {
   if (*ptr == NULL) 
     return EINVAL;
   if ((align % 2) || (align % sizeof(void *)))
     return EINVAL;
   if (len == 0) {
     *ptr = NULL;
     return 0;
   }
   if (align >= 4 * sizeof(size_t)) len += align -1;

   *ptr = malloc(len);

   DEBUGF("posix_memalign(%p %zu, %zu)", ptr, align, len);

   return 0;
}

/* just the non-posix fashion */

void *memalign(size_t align, size_t len) {
   void* ret = NULL;

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

__attribute__((constructor)) void __dislocator_init(void) {

  u8* tmp = (u8 *)getenv("AFL_LD_LIMIT_MB");

  if (tmp) {

    max_mem = atoi((char *)tmp) * 1024 * 1024;
    if (!max_mem) FATAL("Bad value for AFL_LD_LIMIT_MB");

  }

  alloc_verbose = !!getenv("AFL_LD_VERBOSE");
  hard_fail = !!getenv("AFL_LD_HARD_FAIL");
  no_calloc_over = !!getenv("AFL_LD_NO_CALLOC_OVER");

}

