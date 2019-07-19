/*

   american fuzzy lop++ - strcmp() / memcmp() CompareCoverage library
   ------------------------------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This Linux-only companion library allows you to instrument strcmp(),
   memcmp(), and related functions to get compare coverage.
   See README.compcov for more info.

 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/shm.h>

#include "../../types.h"
#include "../../config.h"

#include "pmparser.h"

#ifndef __linux__
#  error "Sorry, this library is Linux-specific for now!"
#endif /* !__linux__ */

/* Change this value to tune the compare coverage */

#define MAX_CMP_LENGTH 32

static u8 __compcov_loaded;

static void *__compcov_code_start,
            *__compcov_code_end;

static u8 *__compcov_afl_map;


static size_t __strlen2(const char *s1, const char *s2, size_t max_length) {
  // from https://github.com/googleprojectzero/CompareCoverage
  
  size_t len = 0;
  for (; len < max_length && s1[len] != '\0' && s2[len] != '\0'; len++) { }
  return len;
}

/* Identify the binary boundaries in the memory mapping */

static void __compcov_load(void) {

  __compcov_loaded = 1;
  
  char *id_str = getenv(SHM_ENV_VAR);
  int shm_id;

  if (id_str) {

    shm_id = atoi(id_str);
    __compcov_afl_map = shmat(shm_id, NULL, 0);

    if (__compcov_afl_map == (void*)-1) exit(1);
  } else {
  
    __compcov_afl_map = calloc(1, MAP_SIZE);
  }

  if (getenv("AFL_INST_LIBS")) {
  
    __compcov_code_start = (void*)0;
    __compcov_code_end = (void*)-1;
    return;
  }

  char* bin_name = getenv("AFL_COMPCOV_BINNAME");

  procmaps_iterator* maps = pmparser_parse(-1);
  procmaps_struct* maps_tmp = NULL;

  while ((maps_tmp = pmparser_next(maps)) != NULL) {
  
    /* If AFL_COMPCOV_BINNAME is not set pick the first executable segment */
    if (!bin_name || strstr(maps_tmp->pathname, bin_name) != NULL) {
    
      if (maps_tmp->is_x) {
        if (!__compcov_code_start)
            __compcov_code_start = maps_tmp->addr_start;
        if (!__compcov_code_end)
            __compcov_code_end = maps_tmp->addr_end;
      }
    }
  }

  pmparser_free(maps);
}


static void __compcov_trace(u64 cur_loc, const u8* v0, const u8* v1, size_t n) {

  size_t i;
  
  for (i = 0; i < n && v0[i] == v1[i]; ++i) {
  
    __compcov_afl_map[cur_loc +i]++;
  }
}

/* Check an address against the list of read-only mappings. */

static u8 __compcov_is_in_bound(const void* ptr) {

  return ptr >= __compcov_code_start && ptr < __compcov_code_end;
}


/* Replacements for strcmp(), memcmp(), and so on. Note that these will be used
   only if the target is compiled with -fno-builtins and linked dynamically. */

#undef strcmp

int strcmp(const char* str1, const char* str2) {

  void* retaddr = __builtin_return_address(0);
  
  if (__compcov_is_in_bound(retaddr)) {

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH +1);
    
    if (n <= MAX_CMP_LENGTH) {
    
      u64 cur_loc = (u64)retaddr;
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;
      
      __compcov_trace(cur_loc, str1, str2, n);
    }
  }

  while (1) {

    unsigned char c1 = *str1, c2 = *str2;

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++; str2++;

  }

}


#undef strncmp

int strncmp(const char* str1, const char* str2, size_t len) {

  void* retaddr = __builtin_return_address(0);
  
  if (__compcov_is_in_bound(retaddr)) {

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH +1);
    n = MIN(n, len);
    
    if (n <= MAX_CMP_LENGTH) {
    
      u64 cur_loc = (u64)retaddr;
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;
      
      __compcov_trace(cur_loc, str1, str2, n);
    }
  }
  
  while (len--) {

    unsigned char c1 = *str1, c2 = *str2;

    if (!c1) return 0;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    str1++; str2++;

  }

  return 0;

}


#undef strcasecmp

int strcasecmp(const char* str1, const char* str2) {

  void* retaddr = __builtin_return_address(0);
  
  if (__compcov_is_in_bound(retaddr)) {
    /* Fallback to strcmp, maybe improve in future */

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH +1);
    
    if (n <= MAX_CMP_LENGTH) {
    
      u64 cur_loc = (u64)retaddr;
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;
      
      __compcov_trace(cur_loc, str1, str2, n);
    }
  }

  while (1) {

    unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++; str2++;

  }

}


#undef strncasecmp

int strncasecmp(const char* str1, const char* str2, size_t len) {

  void* retaddr = __builtin_return_address(0);
  
  if (__compcov_is_in_bound(retaddr)) {
    /* Fallback to strncmp, maybe improve in future */

    size_t n = __strlen2(str1, str2, MAX_CMP_LENGTH +1);
    n = MIN(n, len);
    
    if (n <= MAX_CMP_LENGTH) {
    
      u64 cur_loc = (u64)retaddr;
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;
      
      __compcov_trace(cur_loc, str1, str2, n);
    }
  }

  while (len--) {

    unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (!c1) return 0;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    str1++; str2++;

  }

  return 0;

}


#undef memcmp

int memcmp(const void* mem1, const void* mem2, size_t len) {

  void* retaddr = __builtin_return_address(0);
  
  if (__compcov_is_in_bound(retaddr)) {

    size_t n = len;
    
    if (n <= MAX_CMP_LENGTH) {
    
      u64 cur_loc = (u64)retaddr;
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= MAP_SIZE - 1;
      
      __compcov_trace(cur_loc, mem1, mem2, n);
    }
  }

  while (len--) {

    unsigned char c1 = *(const char*)mem1, c2 = *(const char*)mem2;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    mem1++; mem2++;

  }

  return 0;

}

/* Init code to open init the library. */

__attribute__((constructor)) void __compcov_init(void) {

  __compcov_load();
}


