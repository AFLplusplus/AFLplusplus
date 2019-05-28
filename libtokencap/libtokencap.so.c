/*

   american fuzzy lop - extract tokens passed to strcmp / memcmp
   -------------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This Linux-only companion library allows you to instrument strcmp(),
   memcmp(), and related functions to automatically extract tokens.
   See README.tokencap for more info.

 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "../types.h"
#include "../config.h"

#ifndef __linux__
#  error "Sorry, this library is Linux-specific for now!"
#endif /* !__linux__ */


/* Mapping data and such */

#define MAX_MAPPINGS 1024

static struct mapping {
  void *st, *en;
} __tokencap_ro[MAX_MAPPINGS];

static u32   __tokencap_ro_cnt;
static u8    __tokencap_ro_loaded;
static FILE* __tokencap_out_file;


/* Identify read-only regions in memory. Only parameters that fall into these
   ranges are worth dumping when passed to strcmp() and so on. Read-write
   regions are far more likely to contain user input instead. */

static void __tokencap_load_mappings(void) {

  u8 buf[MAX_LINE];
  FILE* f = fopen("/proc/self/maps", "r");

  __tokencap_ro_loaded = 1;

  if (!f) return;

  while (fgets(buf, MAX_LINE, f)) {

    u8 rf, wf;
    void* st, *en;

    if (sscanf(buf, "%p-%p %c%c", &st, &en, &rf, &wf) != 4) continue;
    if (wf == 'w' || rf != 'r') continue;

    __tokencap_ro[__tokencap_ro_cnt].st = (void*)st;
    __tokencap_ro[__tokencap_ro_cnt].en = (void*)en;

    if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;

  }

  fclose(f);

}


/* Check an address against the list of read-only mappings. */

static u8 __tokencap_is_ro(const void* ptr) {

  u32 i;

  if (!__tokencap_ro_loaded) __tokencap_load_mappings();

  for (i = 0; i < __tokencap_ro_cnt; i++) 
    if (ptr >= __tokencap_ro[i].st && ptr <= __tokencap_ro[i].en) return 1;

  return 0;

}


/* Dump an interesting token to output file, quoting and escaping it
   properly. */

static void __tokencap_dump(const u8* ptr, size_t len, u8 is_text) {

  u8 buf[MAX_AUTO_EXTRA * 4 + 1];
  u32 i;
  u32 pos = 0;

  if (len < MIN_AUTO_EXTRA || len > MAX_AUTO_EXTRA || !__tokencap_out_file)
    return;

  for (i = 0; i < len; i++) {

    if (is_text && !ptr[i]) break;

    switch (ptr[i]) {

      case 0 ... 31:
      case 127 ... 255:
      case '\"':
      case '\\':

        sprintf(buf + pos, "\\x%02x", ptr[i]);
        pos += 4;
        break;

      default:

        buf[pos++] = ptr[i];

    }

  }

  buf[pos] = 0;

  fprintf(__tokencap_out_file, "\"%s\"\n", buf);    

}


/* Replacements for strcmp(), memcmp(), and so on. Note that these will be used
   only if the target is compiled with -fno-builtins and linked dynamically. */

#undef strcmp

int strcmp(const char* str1, const char* str2) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, strlen(str1), 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, strlen(str2), 1);

  while (1) {

    unsigned char c1 = *str1, c2 = *str2;

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++; str2++;

  }

}


#undef strncmp

int strncmp(const char* str1, const char* str2, size_t len) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, len, 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, len, 1);

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

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, strlen(str1), 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, strlen(str2), 1);

  while (1) {

    unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++; str2++;

  }

}


#undef strncasecmp

int strncasecmp(const char* str1, const char* str2, size_t len) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, len, 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, len, 1);

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

  if (__tokencap_is_ro(mem1)) __tokencap_dump(mem1, len, 0);
  if (__tokencap_is_ro(mem2)) __tokencap_dump(mem2, len, 0);

  while (len--) {

    unsigned char c1 = *(const char*)mem1, c2 = *(const char*)mem2;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    mem1++; mem2++;

  }

  return 0;

}


#undef strstr

char* strstr(const char* haystack, const char* needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle))
    __tokencap_dump(needle, strlen(needle), 1);

  do {
    const char* n = needle;
    const char* h = haystack;

    while(*n && *h && *n == *h) n++, h++;

    if(!*n) return (char*)haystack;

  } while (*(haystack++));

  return 0;

}


#undef strcasestr

char* strcasestr(const char* haystack, const char* needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle))
    __tokencap_dump(needle, strlen(needle), 1);

  do {

    const char* n = needle;
    const char* h = haystack;

    while(*n && *h && tolower(*n) == tolower(*h)) n++, h++;

    if(!*n) return (char*)haystack;

  } while(*(haystack++));

  return 0;

}


/* Init code to open the output file (or default to stderr). */

__attribute__((constructor)) void __tokencap_init(void) {

  u8* fn = getenv("AFL_TOKEN_FILE");
  if (fn) __tokencap_out_file = fopen(fn, "a");
  if (!__tokencap_out_file) __tokencap_out_file = stderr;

}

