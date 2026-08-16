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

   An LD_PRELOAD interposer that fails allocation number AFL_ALLOCFAIL_N and
   then disarms itself. One execution therefore exercises exactly one error
   path, which is what makes the resulting crash attributable: the input plus
   the value of N reproduce it, and no second failure muddies the stack.

   Off unless preloaded, and off when AFL_ALLOCFAIL_N is unset or 0.

     AFL_ALLOCFAIL_N=7 LD_PRELOAD=./afl_allocfail.so ./target input

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

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;

static unsigned long afl_allocfail_target = 0;
static unsigned long afl_allocfail_count = 0;
static int           afl_allocfail_armed = 0;
static int           afl_allocfail_verbose = 0;
static int           afl_allocfail_ready = 0;

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

static void afl_allocfail_init(void) {

  static int in_progress = 0;

  if (afl_allocfail_ready || in_progress) { return; }
  in_progress = 1;

  real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
  real_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
  real_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
  real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");

  const char *n = getenv("AFL_ALLOCFAIL_N");

  if (n) {

    afl_allocfail_target = strtoul(n, NULL, 10);
    if (afl_allocfail_target) { afl_allocfail_armed = 1; }

  }

  if (getenv("AFL_ALLOCFAIL_VERBOSE")) { afl_allocfail_verbose = 1; }

  in_progress = 0;
  afl_allocfail_ready = 1;

}

/* Returns non-zero exactly once, for allocation number AFL_ALLOCFAIL_N. */

static int afl_allocfail_hit(void) {

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

