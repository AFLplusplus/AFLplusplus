/*

   american fuzzy lop++ - strcmp() / memcmp() CompareCoverage library
   ------------------------------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This Linux-only companion library allows you to instrument strcmp(),
   memcmp(), and related functions to get compare coverage.
   See README.md for more info.

 */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include "types.h"
#include "config.h"

#include "pmparser.h"

#ifndef __linux__
  #error "Sorry, this library is Linux-specific for now!"
#endif                                                        /* !__linux__ */

/* Change this value to tune the compare coverage */

#define MAX_CMP_LENGTH 32

static void *__compcov_code_start, *__compcov_code_end;

static u8 *__compcov_afl_map;

static u32 __compcov_level;

static int (*__libc_strcmp)(const char *, const char *);
static int (*__libc_strncmp)(const char *, const char *, size_t);
static int (*__libc_strcasecmp)(const char *, const char *);
static int (*__libc_strncasecmp)(const char *, const char *, size_t);
static int (*__libc_memcmp)(const void *, const void *, size_t);

static int debug_fd = -1;

#define MAX_MAPPINGS 1024

static struct mapping { void *st, *en; } __compcov_ro[MAX_MAPPINGS];

static u32 __compcov_ro_cnt;

/* Check an address against the list of read-only mappings. */

static u8 __compcov_is_ro(const void *ptr) {

  u32 i;

  for (i = 0; i < __compcov_ro_cnt; i++)
    if (ptr >= __compcov_ro[i].st && ptr <= __compcov_ro[i].en) return 1;

  return 0;

}

static size_t __strlen2(const char *s1, const char *s2, size_t max_length) {

  // from https://github.com/googleprojectzero/CompareCoverage

  size_t len = 0;
  for (; len < max_length && s1[len] != '\0' && s2[len] != '\0'; len++) {}
  return len;

}

/* Identify the binary boundaries in the memory mapping */

static void __compcov_load(void) {

  __libc_strcmp = dlsym(RTLD_NEXT, "strcmp");
  __libc_strncmp = dlsym(RTLD_NEXT, "strncmp");
  __libc_strcasecmp = dlsym(RTLD_NEXT, "strcasecmp");
  __libc_strncasecmp = dlsym(RTLD_NEXT, "strncasecmp");
  __libc_memcmp = dlsym(RTLD_NEXT, "memcmp");

  if (getenv("AFL_QEMU_COMPCOV")) { __compcov_level = 1; }
  if (getenv("AFL_COMPCOV_LEVEL")) {

    __compcov_level = atoi(getenv("AFL_COMPCOV_LEVEL"));

  }

  char *id_str = getenv(SHM_ENV_VAR);
  int   shm_id;

  if (id_str) {

    shm_id = atoi(id_str);
    __compcov_afl_map = shmat(shm_id, NULL, 0);

    if (__compcov_afl_map == (void *)-1) exit(1);

  } else {

    __compcov_afl_map = calloc(1, MAP_SIZE);

  }

  if (getenv("AFL_INST_LIBS")) {

    __compcov_code_start = (void *)0;
    __compcov_code_end = (void *)-1;
    return;

  }

  char *bin_name = getenv("AFL_COMPCOV_BINNAME");

  procmaps_iterator *maps = pmparser_parse(-1);
  procmaps_struct *  maps_tmp = NULL;

  while ((maps_tmp = pmparser_next(maps)) != NULL) {

    /* If AFL_COMPCOV_BINNAME is not set pick the first executable segment */
    if (!bin_name || strstr(maps_tmp->pathname, bin_name) != NULL) {

      if (maps_tmp->is_x) {

        if (!__compcov_code_start) __compcov_code_start = maps_tmp->addr_start;
        if (!__compcov_code_end) __compcov_code_end = maps_tmp->addr_end;

      }

    }

    if ((maps_tmp->is_w && !maps_tmp->is_r) || __compcov_ro_cnt == MAX_MAPPINGS)
      continue;

    __compcov_ro[__compcov_ro_cnt].st = maps_tmp->addr_start;
    __compcov_ro[__compcov_ro_cnt].en = maps_tmp->addr_end;
    ++__compcov_ro_cnt;

  }

  pmparser_free(maps);

}

static void __compcov_trace(uintptr_t cur_loc, const u8 *v0, const u8 *v1,
                            size_t n) {

  size_t i;

  if (debug_fd != 1) {

    char debugbuf[4096];
    snprintf(debugbuf, sizeof(debugbuf), "0x%" PRIxPTR " %s %s %zu\n", cur_loc,
             v0 == NULL ? "(null)" : (char *)v0,
             v1 == NULL ? "(null)" : (char *)v1, n);
    write(debug_fd, debugbuf, strlen(debugbuf));

  }

  for (i = 0; i < n && v0[i] == v1[i]; ++i) {

    __compcov_afl_map[cur_loc + i]++;

  }

}

/* Check an address against the list of read-only mappings. */

static u8 __compcov_is_in_bound(const void *ptr) {

  return ptr >= __compcov_code_start && ptr < __compcov_code_end;

}

/* Replacements for strcmp(), memcmp(), and so on. Note that these will be used
   only if the target is compiled with -fno-builtins and linked dynamically. */

#undef strcmp

int strcmp(const char *str1, const char *str2) {

  void *retaddr = __builtin_return_address(0);

  if (__compcov_is_in_bound(retaddr) &&
      !(__compcov_level < 2 && !__compcov_is_ro(str1) &&
        !__compcov_is_ro(str2))) {

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH + 1);

    if (n <= MAX_CMP_LENGTH) {

      uintptr_t cur_loc = (uintptr_t)retaddr;
      cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;

      __compcov_trace(cur_loc, str1, str2, n);

    }

  }

  return __libc_strcmp(str1, str2);

}

#undef strncmp

int strncmp(const char *str1, const char *str2, size_t len) {

  void *retaddr = __builtin_return_address(0);

  if (__compcov_is_in_bound(retaddr) &&
      !(__compcov_level < 2 && !__compcov_is_ro(str1) &&
        !__compcov_is_ro(str2))) {

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH + 1);
    n = MIN(n, len);

    if (n <= MAX_CMP_LENGTH) {

      uintptr_t cur_loc = (uintptr_t)retaddr;
      cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;

      __compcov_trace(cur_loc, str1, str2, n);

    }

  }

  return __libc_strncmp(str1, str2, len);

}

#undef strcasecmp

int strcasecmp(const char *str1, const char *str2) {

  void *retaddr = __builtin_return_address(0);

  if (__compcov_is_in_bound(retaddr) &&
      !(__compcov_level < 2 && !__compcov_is_ro(str1) &&
        !__compcov_is_ro(str2))) {

    /* Fallback to strcmp, maybe improve in future */

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH + 1);

    if (n <= MAX_CMP_LENGTH) {

      uintptr_t cur_loc = (uintptr_t)retaddr;
      cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;

      __compcov_trace(cur_loc, str1, str2, n);

    }

  }

  return __libc_strcasecmp(str1, str2);

}

#undef strncasecmp

int strncasecmp(const char *str1, const char *str2, size_t len) {

  void *retaddr = __builtin_return_address(0);

  if (__compcov_is_in_bound(retaddr) &&
      !(__compcov_level < 2 && !__compcov_is_ro(str1) &&
        !__compcov_is_ro(str2))) {

    /* Fallback to strncmp, maybe improve in future */

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH + 1);
    n = MIN(n, len);

    if (n <= MAX_CMP_LENGTH) {

      uintptr_t cur_loc = (uintptr_t)retaddr;
      cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;

      __compcov_trace(cur_loc, str1, str2, n);

    }

  }

  return __libc_strncasecmp(str1, str2, len);

}

#undef memcmp

int memcmp(const void *mem1, const void *mem2, size_t len) {

  void *retaddr = __builtin_return_address(0);

  if (__compcov_is_in_bound(retaddr) &&
      !(__compcov_level < 2 && !__compcov_is_ro(mem1) &&
        !__compcov_is_ro(mem2))) {

    size_t n = len;

    if (n <= MAX_CMP_LENGTH) {

      uintptr_t cur_loc = (uintptr_t)retaddr;
      cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;

      __compcov_trace(cur_loc, mem1, mem2, n);

    }

  }

  return __libc_memcmp(mem1, mem2, len);

}

// TODO bcmp

/* Common libraries wrappers (from honggfuzz) */

/*
 * Apache's httpd wrappers
 */
int ap_cstr_casecmp(const char *s1, const char *s2) {

  return strcasecmp(s1, s2);

}

int ap_cstr_casecmpn(const char *s1, const char *s2, size_t n) {

  return strncasecmp(s1, s2, n);

}

int apr_cstr_casecmp(const char *s1, const char *s2) {

  return strcasecmp(s1, s2);

}

int apr_cstr_casecmpn(const char *s1, const char *s2, size_t n) {

  return strncasecmp(s1, s2, n);

}

/*
 * *SSL wrappers
 */
int CRYPTO_memcmp(const void *m1, const void *m2, size_t len) {

  return memcmp(m1, m2, len);

}

int OPENSSL_memcmp(const void *m1, const void *m2, size_t len) {

  return memcmp(m1, m2, len);

}

int OPENSSL_strcasecmp(const char *s1, const char *s2) {

  return strcasecmp(s1, s2);

}

int OPENSSL_strncasecmp(const char *s1, const char *s2, size_t len) {

  return strncasecmp(s1, s2, len);

}

int32_t memcmpct(const void *s1, const void *s2, size_t len) {

  return memcmp(s1, s2, len);

}

/*
 * libXML wrappers
 */
int xmlStrncmp(const char *s1, const char *s2, int len) {

  if (len <= 0) { return 0; }
  if (s1 == s2) { return 0; }
  if (s1 == NULL) { return -1; }
  if (s2 == NULL) { return 1; }
  return strncmp(s1, s2, (size_t)len);

}

int xmlStrcmp(const char *s1, const char *s2) {

  if (s1 == s2) { return 0; }
  if (s1 == NULL) { return -1; }
  if (s2 == NULL) { return 1; }
  return strcmp(s1, s2);

}

int xmlStrEqual(const char *s1, const char *s2) {

  if (s1 == s2) { return 1; }
  if (s1 == NULL) { return 0; }
  if (s2 == NULL) { return 0; }
  if (strcmp(s1, s2) == 0) { return 1; }
  return 0;

}

int xmlStrcasecmp(const char *s1, const char *s2) {

  if (s1 == s2) { return 0; }
  if (s1 == NULL) { return -1; }
  if (s2 == NULL) { return 1; }
  return strcasecmp(s1, s2);

}

int xmlStrncasecmp(const char *s1, const char *s2, int len) {

  if (len <= 0) { return 0; }
  if (s1 == s2) { return 0; }
  if (s1 == NULL) { return -1; }
  if (s2 == NULL) { return 1; }
  return strncasecmp(s1, s2, (size_t)len);

}

const char *xmlStrcasestr(const char *haystack, const char *needle) {

  if (haystack == NULL) { return NULL; }
  if (needle == NULL) { return NULL; }
  return strcasestr(haystack, needle);

}

/*
 * Samba wrappers
 */
int memcmp_const_time(const void *s1, const void *s2, size_t n) {

  return memcmp(s1, s2, n);

}

bool strcsequal(const void *s1, const void *s2) {

  if (s1 == s2) { return true; }
  if (!s1 || !s2) { return false; }
  return (strcmp(s1, s2) == 0);

}

/* Init code to open init the library. */

__attribute__((constructor)) void __compcov_init(void) {

  if (getenv("AFL_QEMU_COMPCOV_DEBUG") != NULL)
    debug_fd =
        open("compcov.debug", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);

  __compcov_load();

}

