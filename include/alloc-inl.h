/*
   american fuzzy lop++ - error-checking, memory-zeroing alloc routines
   --------------------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This allocator is not designed to resist malicious attackers (the canaries
   are small and predictable), but provides a robust and portable way to detect
   use-after-free, off-by-one writes, stale pointers, and so on.

 */

#ifndef _HAVE_ALLOC_INL_H
#define _HAVE_ALLOC_INL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "config.h"
#include "types.h"
#include "debug.h"

/* Initial size used for afl_realloc */
#define INITIAL_GROWTH_SIZE (64)

// Be careful! _WANT_ORIGINAL_AFL_ALLOC is not compatible with custom mutators

#ifndef _WANT_ORIGINAL_AFL_ALLOC
  // afl++ stuff without memory corruption checks - for speed

  /* User-facing macro to sprintf() to a dynamically allocated buffer. */

  #define alloc_printf(_str...)                        \
    ({                                                 \
                                                       \
      u8 *_tmp;                                        \
      s32 _len = snprintf(NULL, 0, _str);              \
      if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
      _tmp = ck_alloc(_len + 1);                       \
      snprintf((char *)_tmp, _len + 1, _str);          \
      _tmp;                                            \
                                                       \
    })

  /* Macro to enforce allocation limits as a last-resort defense against
     integer overflows. */

  #define ALLOC_CHECK_SIZE(_s)                                          \
    do {                                                                \
                                                                        \
      if ((_s) > MAX_ALLOC) ABORT("Bad alloc request: %u bytes", (_s)); \
                                                                        \
    } while (0)

  /* Macro to check malloc() failures and the like. */

  #define ALLOC_CHECK_RESULT(_r, _s)                                    \
    do {                                                                \
                                                                        \
      if (!(_r)) ABORT("Out of memory: can't allocate %u bytes", (_s)); \
                                                                        \
    } while (0)

/* Allocate a buffer, explicitly not zeroing it. Returns NULL for zero-sized
   requests. */

static inline void *DFL_ck_alloc_nozero(u32 size) {

  void *ret;

  if (!size) { return NULL; }

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return (void *)ret;

}

/* Allocate a buffer, returning zeroed memory.
  Returns null for 0 size */

static inline void *DFL_ck_alloc(u32 size) {

  void *mem;

  if (!size) { return NULL; }
  mem = DFL_ck_alloc_nozero(size);

  return memset(mem, 0, size);

}

/* Free memory, checking for double free and corrupted heap. When DEBUG_BUILD
   is set, the old memory will be also clobbered with 0xFF. */

static inline void DFL_ck_free(void *mem) {

  if (!mem) { return; }

  free(mem);

}

/* Re-allocate a buffer, checking for issues and zeroing any newly-added tail.
   With DEBUG_BUILD, the buffer is always reallocated to a new addresses and the
   old memory is clobbered with 0xFF. */

static inline void *DFL_ck_realloc(void *orig, u32 size) {

  void *ret;

  if (!size) {

    DFL_ck_free(orig);
    return NULL;

  }

  ALLOC_CHECK_SIZE(size);

  /* Catch pointer issues sooner: force relocation and make sure that the
     original buffer is wiped. */

  ret = realloc(orig, size);

  ALLOC_CHECK_RESULT(ret, size);

  return (void *)ret;

}

/* Create a buffer with a copy of a string. Returns NULL for NULL inputs. */

static inline u8 *DFL_ck_strdup(u8 *str) {

  u8 *ret;
  u32 size;

  if (!str) { return NULL; }

  size = strlen((char *)str) + 1;

  ALLOC_CHECK_SIZE(size);
  ret = (u8 *)malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return (u8 *)memcpy(ret, str, size);

}

  /* In non-debug mode, we just do straightforward aliasing of the above
     functions to user-visible names such as ck_alloc(). */

  #define ck_alloc DFL_ck_alloc
  #define ck_alloc_nozero DFL_ck_alloc_nozero
  #define ck_realloc DFL_ck_realloc
  #define ck_strdup DFL_ck_strdup
  #define ck_free DFL_ck_free

  #define alloc_report()

#else
  // This is the original alloc-inl of stock afl

  /* User-facing macro to sprintf() to a dynamically allocated buffer. */

  #define alloc_printf(_str...)                        \
    ({                                                 \
                                                       \
      u8 *_tmp;                                        \
      s32 _len = snprintf(NULL, 0, _str);              \
      if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
      _tmp = ck_alloc(_len + 1);                       \
      snprintf((char *)_tmp, _len + 1, _str);          \
      _tmp;                                            \
                                                       \
    })

  /* Macro to enforce allocation limits as a last-resort defense against
     integer overflows. */
  #define ALLOC_CHECK_SIZE(_s)                                          \
    do {                                                                \
                                                                        \
      if ((_s) > MAX_ALLOC) ABORT("Bad alloc request: %u bytes", (_s)); \
                                                                        \
    } while (0)

  /* Macro to check malloc() failures and the like. */

  #define ALLOC_CHECK_RESULT(_r, _s)                                    \
    do {                                                                \
                                                                        \
      if (!(_r)) ABORT("Out of memory: can't allocate %u bytes", (_s)); \
                                                                        \
    } while (0)

  /* Magic tokens used to mark used / freed chunks. */

  #define ALLOC_MAGIC_C1 0xFF00FF00                   /* Used head (dword)  */
  #define ALLOC_MAGIC_F 0xFE00FE00                    /* Freed head (dword) */
  #define ALLOC_MAGIC_C2 0xF0                         /* Used tail (byte)   */

  /* Positions of guard tokens in relation to the user-visible pointer. */

  #define ALLOC_C1(_ptr) (((u32 *)(_ptr))[-2])
  #define ALLOC_S(_ptr) (((u32 *)(_ptr))[-1])
  #define ALLOC_C2(_ptr) (((u8 *)(_ptr))[ALLOC_S(_ptr)])

  #define ALLOC_OFF_HEAD 8
  #define ALLOC_OFF_TOTAL (ALLOC_OFF_HEAD + 1)

  /* Sanity-checking macros for pointers. */

  #define CHECK_PTR(_p)                            \
    do {                                           \
                                                   \
      if (_p) {                                    \
                                                   \
        if (ALLOC_C1(_p) ^ ALLOC_MAGIC_C1) {       \
                                                   \
          if (ALLOC_C1(_p) == ALLOC_MAGIC_F)       \
            ABORT("Use after free.");              \
          else                                     \
            ABORT("Corrupted head alloc canary."); \
                                                   \
        }                                          \
        if (ALLOC_C2(_p) ^ ALLOC_MAGIC_C2)         \
          ABORT("Corrupted tail alloc canary.");   \
                                                   \
      }                                            \
                                                   \
    } while (0)

  #define CHECK_PTR_EXPR(_p)  \
    ({                        \
                              \
      typeof(_p) _tmp = (_p); \
      CHECK_PTR(_tmp);        \
      _tmp;                   \
                              \
    })

/* Allocate a buffer, explicitly not zeroing it. Returns NULL for zero-sized
   requests. */

static inline void *DFL_ck_alloc_nozero(u32 size) {

  void *ret;

  if (!size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);

  ret = (char *)ret + ALLOC_OFF_HEAD;

  ALLOC_C1(ret) = ALLOC_MAGIC_C1;
  ALLOC_S(ret) = size;
  ALLOC_C2(ret) = ALLOC_MAGIC_C2;

  return ret;

}

/* Allocate a buffer, returning zeroed memory. */

static inline void *DFL_ck_alloc(u32 size) {

  void *mem;

  if (!size) return NULL;
  mem = DFL_ck_alloc_nozero(size);

  return memset(mem, 0, size);

}

/* Free memory, checking for double free and corrupted heap. When DEBUG_BUILD
   is set, the old memory will be also clobbered with 0xFF. */

static inline void DFL_ck_free(void *mem) {

  if (!mem) return;

  CHECK_PTR(mem);
  #ifdef DEBUG_BUILD

  /* Catch pointer issues sooner. */
  memset(mem, 0xFF, ALLOC_S(mem));

  #endif                                                     /* DEBUG_BUILD */

  ALLOC_C1(mem) = ALLOC_MAGIC_F;

  free((char *)mem - ALLOC_OFF_HEAD);

}

/* Re-allocate a buffer, checking for issues and zeroing any newly-added tail.
   With DEBUG_BUILD, the buffer is always reallocated to a new addresses and the
   old memory is clobbered with 0xFF. */

static inline void *DFL_ck_realloc(void *orig, u32 size) {

  void *ret;
  u32 old_size = 0;

  if (!size) {

    DFL_ck_free(orig);
    return NULL;

  }

  if (orig) {

    CHECK_PTR(orig);

  #ifndef DEBUG_BUILD
    ALLOC_C1(orig) = ALLOC_MAGIC_F;
  #endif                                                    /* !DEBUG_BUILD */

    old_size = ALLOC_S(orig);
    orig = (char *)orig - ALLOC_OFF_HEAD;

    ALLOC_CHECK_SIZE(old_size);

  }

  ALLOC_CHECK_SIZE(size);

  #ifndef DEBUG_BUILD

  ret = realloc(orig, size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);

  #else

  /* Catch pointer issues sooner: force relocation and make sure that the
     original buffer is wiped. */

  ret = malloc(size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);

  if (orig) {

    memcpy((char *)ret + ALLOC_OFF_HEAD, (char *)orig + ALLOC_OFF_HEAD,
           MIN(size, old_size));
    memset((char *)orig + ALLOC_OFF_HEAD, 0xFF, old_size);

    ALLOC_C1((char *)orig + ALLOC_OFF_HEAD) = ALLOC_MAGIC_F;

    free(orig);

  }

  #endif                                                   /* ^!DEBUG_BUILD */

  ret = (char *)ret + ALLOC_OFF_HEAD;

  ALLOC_C1(ret) = ALLOC_MAGIC_C1;
  ALLOC_S(ret) = size;
  ALLOC_C2(ret) = ALLOC_MAGIC_C2;

  if (size > old_size) memset((char *)ret + old_size, 0, size - old_size);

  return ret;

}

/* Create a buffer with a copy of a string. Returns NULL for NULL inputs. */

static inline u8 *DFL_ck_strdup(u8 *str) {

  void *ret;
  u32 size;

  if (!str) return NULL;

  size = strlen((char *)str) + 1;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);

  ret = (char *)ret + ALLOC_OFF_HEAD;

  ALLOC_C1(ret) = ALLOC_MAGIC_C1;
  ALLOC_S(ret) = size;
  ALLOC_C2(ret) = ALLOC_MAGIC_C2;

  return memcpy(ret, str, size);

}

  #ifndef DEBUG_BUILD

    /* In non-debug mode, we just do straightforward aliasing of the above
       functions to user-visible names such as ck_alloc(). */

    #define ck_alloc DFL_ck_alloc
    #define ck_alloc_nozero DFL_ck_alloc_nozero
    #define ck_realloc DFL_ck_realloc
    #define ck_strdup DFL_ck_strdup
    #define ck_free DFL_ck_free

    #define alloc_report()

  #else

    /* In debugging mode, we also track allocations to detect memory leaks, and
       the flow goes through one more layer of indirection. */

    /* Alloc tracking data structures: */

    #define ALLOC_BUCKETS 4096

struct TRK_obj {

  void *ptr;
  char *file, *func;
  u32 line;

};

    #ifdef AFL_MAIN

struct TRK_obj *TRK[ALLOC_BUCKETS];
u32 TRK_cnt[ALLOC_BUCKETS];

      #define alloc_report() TRK_report()

    #else

extern struct TRK_obj *TRK[ALLOC_BUCKETS];
extern u32             TRK_cnt[ALLOC_BUCKETS];

      #define alloc_report()

    #endif                                                     /* ^AFL_MAIN */

    /* Bucket-assigning function for a given pointer: */

    #define TRKH(_ptr) (((((u32)(_ptr)) >> 16) ^ ((u32)(_ptr))) % ALLOC_BUCKETS)

/* Add a new entry to the list of allocated objects. */

static inline void TRK_alloc_buf(void *ptr, const char *file, const char *func,
                                 u32 line) {

  u32 i, bucket;

  if (!ptr) return;

  bucket = TRKH(ptr);

  /* Find a free slot in the list of entries for that bucket. */

  for (i = 0; i < TRK_cnt[bucket]; i++)

    if (!TRK[bucket][i].ptr) {

      TRK[bucket][i].ptr = ptr;
      TRK[bucket][i].file = (char *)file;
      TRK[bucket][i].func = (char *)func;
      TRK[bucket][i].line = line;
      return;

    }

  /* No space available - allocate more. */

  TRK[bucket] = DFL_ck_realloc(TRK[bucket],
                               (TRK_cnt[bucket] + 1) * sizeof(struct TRK_obj));

  TRK[bucket][i].ptr = ptr;
  TRK[bucket][i].file = (char *)file;
  TRK[bucket][i].func = (char *)func;
  TRK[bucket][i].line = line;

  TRK_cnt[bucket]++;

}

/* Remove entry from the list of allocated objects. */

static inline void TRK_free_buf(void *ptr, const char *file, const char *func,
                                u32 line) {

  u32 i, bucket;

  if (!ptr) return;

  bucket = TRKH(ptr);

  /* Find the element on the list... */

  for (i = 0; i < TRK_cnt[bucket]; i++)

    if (TRK[bucket][i].ptr == ptr) {

      TRK[bucket][i].ptr = 0;
      return;

    }

  WARNF("ALLOC: Attempt to free non-allocated memory in %s (%s:%u)", func, file,
        line);

}

/* Do a final report on all non-deallocated objects. */

static inline void TRK_report(void) {

  u32 i, bucket;

  fflush(0);

  for (bucket = 0; bucket < ALLOC_BUCKETS; bucket++)
    for (i = 0; i < TRK_cnt[bucket]; i++)
      if (TRK[bucket][i].ptr)
        WARNF("ALLOC: Memory never freed, created in %s (%s:%u)",
              TRK[bucket][i].func, TRK[bucket][i].file, TRK[bucket][i].line);

}

/* Simple wrappers for non-debugging functions: */

static inline void *TRK_ck_alloc(u32 size, const char *file, const char *func,
                                 u32 line) {

  void *ret = DFL_ck_alloc(size);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}

static inline void *TRK_ck_realloc(void *orig, u32 size, const char *file,
                                   const char *func, u32 line) {

  void *ret = DFL_ck_realloc(orig, size);
  TRK_free_buf(orig, file, func, line);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}

static inline void *TRK_ck_strdup(u8 *str, const char *file, const char *func,
                                  u32 line) {

  void *ret = DFL_ck_strdup(str);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}

static inline void TRK_ck_free(void *ptr, const char *file, const char *func,
                               u32 line) {

  TRK_free_buf(ptr, file, func, line);
  DFL_ck_free(ptr);

}

    /* Aliasing user-facing names to tracking functions: */

    #define ck_alloc(_p1) TRK_ck_alloc(_p1, __FILE__, __FUNCTION__, __LINE__)

    #define ck_alloc_nozero(_p1) \
      TRK_ck_alloc(_p1, __FILE__, __FUNCTION__, __LINE__)

    #define ck_realloc(_p1, _p2) \
      TRK_ck_realloc(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)

    #define ck_strdup(_p1) TRK_ck_strdup(_p1, __FILE__, __FUNCTION__, __LINE__)

    #define ck_free(_p1) TRK_ck_free(_p1, __FILE__, __FUNCTION__, __LINE__)

  #endif                                                   /* ^!DEBUG_BUILD */

#endif                                          /* _WANT_ORIGINAL_AFL_ALLOC */

/* This function calculates the next power of 2 greater or equal its argument.
 @return The rounded up power of 2 (if no overflow) or 0 on overflow.
*/
static inline size_t next_pow2(size_t in) {

  // Commented this out as this behavior doesn't change, according to unittests
  // if (in == 0 || in > (size_t)-1) {

  //
  //   return 0;                  /* avoid undefined behaviour under-/overflow
  //   */
  //
  // }

  size_t out = in - 1;
  out |= out >> 1;
  out |= out >> 2;
  out |= out >> 4;
  out |= out >> 8;
  out |= out >> 16;
  return out + 1;

}

/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
struct afl_alloc_buf {

  /* The complete allocated size, including the header of len
   * AFL_ALLOC_SIZE_OFFSET */
  size_t complete_size;
  /* ptr to the first element of the actual buffer */
  u8 buf[0];

};

#define AFL_ALLOC_SIZE_OFFSET (offsetof(struct afl_alloc_buf, buf))

/* Returns the container element to this ptr */
static inline struct afl_alloc_buf *afl_alloc_bufptr(void *buf) {

  return (struct afl_alloc_buf *)((u8 *)buf - AFL_ALLOC_SIZE_OFFSET);

}

/* Gets the maximum size of the buf contents (ptr->complete_size -
 * AFL_ALLOC_SIZE_OFFSET) */
static inline size_t afl_alloc_bufsize(void *buf) {

  return afl_alloc_bufptr(buf)->complete_size - AFL_ALLOC_SIZE_OFFSET;

}

/* This function makes sure *size is > size_needed after call.
 It will realloc *buf otherwise.
 *size will grow exponentially as per:
 https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
 Will return NULL and free *buf if size_needed is <1 or realloc failed.
 @return For convenience, this function returns *buf.
 */
static inline void *afl_realloc(void **buf, size_t size_needed) {

  struct afl_alloc_buf *new_buf = NULL;

  size_t current_size = 0;
  size_t next_size = 0;

  if (likely(*buf)) {

    /* the size is always stored at buf - 1*size_t */
    new_buf = (struct afl_alloc_buf *)afl_alloc_bufptr(*buf);
    current_size = new_buf->complete_size;

  }

  size_needed += AFL_ALLOC_SIZE_OFFSET;

  /* No need to realloc */
  if (likely(current_size >= size_needed)) { return *buf; }

  /* No initial size was set */
  if (size_needed < INITIAL_GROWTH_SIZE) {

    next_size = INITIAL_GROWTH_SIZE;

  } else {

    /* grow exponentially */
    next_size = next_pow2(size_needed);

    /* handle overflow: fall back to the original size_needed */
    if (unlikely(!next_size)) { next_size = size_needed; }

  }

  /* alloc */
  struct afl_alloc_buf *newer_buf =
      (struct afl_alloc_buf *)realloc(new_buf, next_size);
  if (unlikely(!newer_buf)) {

    free(new_buf);  // avoid a leak
    *buf = NULL;
    return NULL;

  } else {

    new_buf = newer_buf;

  }

  new_buf->complete_size = next_size;
  *buf = (void *)(new_buf->buf);
  return *buf;

}

/* afl_realloc_exact uses afl alloc buffers but sets it to a specific size */

static inline void *afl_realloc_exact(void **buf, size_t size_needed) {

  struct afl_alloc_buf *new_buf = NULL;

  size_t current_size = 0;

  if (likely(*buf)) {

    /* the size is always stored at buf - 1*size_t */
    new_buf = (struct afl_alloc_buf *)afl_alloc_bufptr(*buf);
    current_size = new_buf->complete_size;

  }

  size_needed += AFL_ALLOC_SIZE_OFFSET;

  /* No need to realloc */
  if (unlikely(current_size == size_needed)) { return *buf; }

  /* alloc */
  struct afl_alloc_buf *newer_buf =
      (struct afl_alloc_buf *)realloc(new_buf, size_needed);
  if (unlikely(!newer_buf)) {

    free(new_buf);  // avoid a leak
    *buf = NULL;
    return NULL;

  } else {

    new_buf = newer_buf;

  }

  new_buf->complete_size = size_needed;
  *buf = (void *)(new_buf->buf);
  return *buf;

}

static inline void afl_free(void *buf) {

  if (buf) { free(afl_alloc_bufptr(buf)); }

}

/* Swaps buf1 ptr and buf2 ptr, as well as their sizes */
static inline void afl_swap_bufs(void **buf1, void **buf2) {

  void *scratch_buf = *buf1;
  *buf1 = *buf2;
  *buf2 = scratch_buf;

}

#undef INITIAL_GROWTH_SIZE

#endif                                               /* ! _HAVE_ALLOC_INL_H */

