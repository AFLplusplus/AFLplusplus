/*
   american fuzzy lop++ - error-checking, memory-zeroing alloc routines
   --------------------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

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

#include "config.h"
#include "types.h"
#include "debug.h"

/* User-facing macro to sprintf() to a dynamically allocated buffer. */

#define alloc_printf(_str...)                        \
  ({                                                 \
                                                     \
    u8* _tmp;                                        \
    s32 _len = snprintf(NULL, 0, _str);              \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1);                       \
    snprintf((char*)_tmp, _len + 1, _str);           \
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

/* Allocator increments for ck_realloc_block(). */

#define ALLOC_BLK_INC 256

/* Allocate a buffer, explicitly not zeroing it. Returns NULL for zero-sized
   requests. */

static inline void* DFL_ck_alloc_nozero(u32 size) {

  u8* ret;

  if (!size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return (void*)ret;

}

/* Allocate a buffer, returning zeroed memory. */

static inline void* DFL_ck_alloc(u32 size) {

  void* mem;

  if (!size) return NULL;
  mem = DFL_ck_alloc_nozero(size);

  return memset(mem, 0, size);

}

/* Free memory  */

static inline void DFL_ck_free(void* mem) {

  free(mem);

}

/* Re-allocate a buffer, checking for issues and zeroing any newly-added tail.
   With DEBUG_BUILD, the buffer is always reallocated to a new addresses and the
   old memory is clobbered with 0xFF. */

static inline void* DFL_ck_realloc(void* orig, u32 size) {

  u8* ret;
  u32 old_size = 0;

  if (!size) {

    DFL_ck_free(orig);
    return NULL;

  }

  ALLOC_CHECK_SIZE(size);

  ret = realloc(orig, size);
  ALLOC_CHECK_RESULT(ret, size);

  if (size > old_size) memset(ret + old_size, 0, size - old_size);

  return (void*)ret;

}

/* Re-allocate a buffer with ALLOC_BLK_INC increments (used to speed up
   repeated small reallocs without complicating the user code). */

static inline void* DFL_ck_realloc_block(void* orig, u32 size) {

  if (orig)
    size += ALLOC_BLK_INC;

  return DFL_ck_realloc(orig, size);

}

/* Create a buffer with a copy of a string. Returns NULL for NULL inputs. */

static inline u8* DFL_ck_strdup(u8* str) {

  u8* ret;
  u32 size;

  if (!str) return NULL;

  size = strlen((char*)str) + 1;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return memcpy(ret, str, size);

}

/* Create a buffer with a copy of a memory block. Returns NULL for zero-sized
   or NULL inputs. */

static inline void* DFL_ck_memdup(void* mem, u32 size) {

  u8* ret;

  if (!mem || !size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return memcpy(ret, mem, size);

}

/* Create a buffer with a block of text, appending a NUL terminator at the end.
   Returns NULL for zero-sized or NULL inputs. */

static inline u8* DFL_ck_memdup_str(u8* mem, u32 size) {

  u8* ret;

  if (!mem || !size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + 1);
  ALLOC_CHECK_RESULT(ret, size);

  memcpy(ret, mem, size);
  ret[size] = 0;

  return ret;

}

/* In non-debug mode, we just do straightforward aliasing of the above functions
   to user-visible names such as ck_alloc(). */

#define ck_alloc DFL_ck_alloc
#define ck_alloc_nozero DFL_ck_alloc_nozero
#define ck_realloc DFL_ck_realloc
#define ck_realloc_block DFL_ck_realloc_block
#define ck_strdup DFL_ck_strdup
#define ck_memdup DFL_ck_memdup
#define ck_memdup_str DFL_ck_memdup_str
#define ck_free DFL_ck_free

#define alloc_report()

#endif                                               /* ! _HAVE_ALLOC_INL_H */

