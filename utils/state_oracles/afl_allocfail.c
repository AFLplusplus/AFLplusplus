/*
   american fuzzy lop++ - allocation failure injection
   ---------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   A preloaded interposer that fails allocation number AFL_ALLOCFAIL_N and
   then disarms itself. One execution therefore exercises exactly one error
   path, which is what makes the resulting crash attributable: the input plus
   the value of N reproduce it, and no second failure muddies the stack.

   Off unless preloaded, and off when AFL_ALLOCFAIL_N is unset or 0.

     AFL_ALLOCFAIL_N=7 LD_PRELOAD=./afl_allocfail.so ./target input          (ELF)
     AFL_ALLOCFAIL_N=7 DYLD_INSERT_LIBRARIES=./afl_allocfail.so ./target input  (macOS)

   The two platforms need different machinery. With ELF, defining malloc()
   here shadows the libc one for the whole process and the real one is
   recovered through dlsym(RTLD_NEXT); dlsym() allocates on glibc, so the
   first calls have to be served from a static arena to avoid recursing back
   into us. dyld does not work that way - libSystem's internal calls are
   already bound and a shadowing definition would not be seen - so macOS uses
   explicit interposition instead: a table in __DATA,__interpose pairing each
   replacement with the original. Calls made from inside this library are not
   themselves interposed, so the replacements can call malloc() directly and
   no bootstrap arena is needed.

 */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __APPLE__

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;

#endif

static unsigned long afl_allocfail_target = 0;
static unsigned long afl_allocfail_count = 0;
static int           afl_allocfail_armed = 0;
static int           afl_allocfail_verbose = 0;
static int           afl_allocfail_ready = 0;

#ifndef __APPLE__

/* dlsym() itself allocates on glibc, so the very first calls have to be
   served from a static arena rather than recursing back into us. */

static unsigned char afl_boot_arena[65536];
static size_t        afl_boot_used = 0;

static void *afl_boot_alloc(size_t size) {

  size = (size + 15u) & ~(size_t)15u;

  if (afl_boot_used + size > sizeof(afl_boot_arena)) { return NULL; }

  void *ret = afl_boot_arena + afl_boot_used;
  afl_boot_used += size;

  return ret;

}

static int afl_is_boot_ptr(const void *ptr) {

  const unsigned char *p = (const unsigned char *)ptr;

  return p >= afl_boot_arena && p < afl_boot_arena + sizeof(afl_boot_arena);

}

#endif                                                       /* !__APPLE__ */

static void afl_allocfail_read_env(void) {

  const char *n = getenv("AFL_ALLOCFAIL_N");

  if (n) {

    afl_allocfail_target = strtoul(n, NULL, 10);
    if (afl_allocfail_target) { afl_allocfail_armed = 1; }

  }

  if (getenv("AFL_ALLOCFAIL_VERBOSE")) { afl_allocfail_verbose = 1; }

}

static void afl_allocfail_init(void) {

  static int in_progress = 0;

  if (afl_allocfail_ready || in_progress) { return; }
  in_progress = 1;

#ifndef __APPLE__

  real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
  real_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
  real_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
  real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");

#endif

  afl_allocfail_read_env();

  in_progress = 0;
  afl_allocfail_ready = 1;

}

#ifdef __APPLE__

/* dyld interposition is live from the process's very first allocation, which
   on macOS means a long run of loader and libSystem work before the program
   exists. Failing one of those kills any program, correct or not, so the
   counter does not start until the inserted library's constructor has run -
   the point where the loader is done and program code is about to begin.
   The ELF path reaches the same place by accident: its counter only starts
   once dlsym() has resolved the real allocator. */

static int afl_allocfail_live = 0;

__attribute__((constructor)) static void afl_allocfail_start(void) {

  afl_allocfail_init();
  afl_allocfail_live = 1;

}

#endif

/* Returns non-zero exactly once, for allocation number AFL_ALLOCFAIL_N. */

static int afl_allocfail_hit(void) {

#ifdef __APPLE__

  if (!afl_allocfail_live) { return 0; }

#endif

  unsigned long n = ++afl_allocfail_count;

  if (!afl_allocfail_armed || n != afl_allocfail_target) { return 0; }

  afl_allocfail_armed = 0;

  if (afl_allocfail_verbose) {

    const char msg[] = "afl_allocfail: failing this allocation\n";
    ssize_t    ignored = write(2, msg, sizeof(msg) - 1);
    (void)ignored;

  }

  return 1;

}

#ifndef __APPLE__

void *malloc(size_t size) {

  if (!afl_allocfail_ready) {

    if (!real_malloc) { afl_allocfail_init(); }
    if (!real_malloc) { return afl_boot_alloc(size); }

  }

  if (afl_allocfail_hit()) {

    errno = ENOMEM;
    return NULL;

  }

  return real_malloc(size);

}

void *calloc(size_t nmemb, size_t size) {

  if (!afl_allocfail_ready) {

    if (!real_calloc) { afl_allocfail_init(); }
    if (!real_calloc) {

      size_t total = nmemb * size;
      void  *ret = afl_boot_alloc(total);
      if (ret) { memset(ret, 0, total); }
      return ret;

    }

  }

  if (afl_allocfail_hit()) {

    errno = ENOMEM;
    return NULL;

  }

  return real_calloc(nmemb, size);

}

void *realloc(void *ptr, size_t size) {

  if (!afl_allocfail_ready) { afl_allocfail_init(); }

  if (afl_is_boot_ptr(ptr)) {

    void *ret = malloc(size);
    if (ret && size) { memcpy(ret, ptr, size); }
    return ret;

  }

  if (afl_allocfail_hit()) {

    errno = ENOMEM;
    return NULL;

  }

  return real_realloc(ptr, size);

}

void free(void *ptr) {

  if (afl_is_boot_ptr(ptr)) { return; }

  if (!real_free) {

    afl_allocfail_init();
    if (!real_free) { return; }

  }

  real_free(ptr);

}

char *strdup(const char *s) {

  size_t len = strlen(s) + 1;
  char  *ret = (char *)malloc(len);

  if (!ret) { return NULL; }

  memcpy(ret, s, len);

  return ret;

}

#else                                                         /* __APPLE__ */

/* Explicit dyld interposition. These are ordinary static functions; the
   table at the bottom is what makes dyld route every other image's calls
   here. Our own calls to malloc() and friends are not interposed, so they
   reach libSystem directly. */

static void *afl_i_malloc(size_t size) {

  if (!afl_allocfail_ready) { afl_allocfail_init(); }

  if (afl_allocfail_hit()) {

    errno = ENOMEM;
    return NULL;

  }

  return malloc(size);

}

static void *afl_i_calloc(size_t nmemb, size_t size) {

  if (!afl_allocfail_ready) { afl_allocfail_init(); }

  if (afl_allocfail_hit()) {

    errno = ENOMEM;
    return NULL;

  }

  return calloc(nmemb, size);

}

static void *afl_i_realloc(void *ptr, size_t size) {

  if (!afl_allocfail_ready) { afl_allocfail_init(); }

  if (afl_allocfail_hit()) {

    errno = ENOMEM;
    return NULL;

  }

  return realloc(ptr, size);

}

static char *afl_i_strdup(const char *s) {

  size_t len = strlen(s) + 1;
  char  *ret = (char *)afl_i_malloc(len);

  if (!ret) { return NULL; }

  memcpy(ret, s, len);

  return ret;

}

#define AFL_INTERPOSE(repl, orig)                                    \
  __attribute__((used)) static struct {                              \
                                                                     \
    const void *replacement;                                         \
    const void *original;                                            \
                                                                     \
  } afl_interpose_##orig __attribute__((section("__DATA,__interpose"))) = { \
                                                                     \
      (const void *)(unsigned long)&repl,                            \
      (const void *)(unsigned long)&orig}

AFL_INTERPOSE(afl_i_malloc, malloc);
AFL_INTERPOSE(afl_i_calloc, calloc);
AFL_INTERPOSE(afl_i_realloc, realloc);
AFL_INTERPOSE(afl_i_strdup, strdup);

#endif                                                        /* __APPLE__ */

