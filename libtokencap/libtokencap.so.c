/*

   american fuzzy lop - extract tokens passed to strcmp / memcmp
   -------------------------------------------------------------

   Written by Michal Zalewski

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
#include <unistd.h>

#include "../types.h"
#include "../config.h"

#if !defined __linux__  && !defined __APPLE__  && !defined __FreeBSD__ && !defined __OpenBSD__
# error "Sorry, this library is unsupported in this platform for now!"
#endif                         /* !__linux__ && !__APPLE__ && ! __FreeBSD__ */

#if defined __APPLE__
# include <mach/vm_map.h>
# include <mach/mach_init.h>
#elif defined __FreeBSD__ || defined __OpenBSD__
# include <sys/types.h>
# include <sys/sysctl.h>
# include <sys/user.h>
# include <sys/mman.h>
#endif

/* Mapping data and such */

#define MAX_MAPPINGS 1024

static struct mapping { void *st, *en; } __tokencap_ro[MAX_MAPPINGS];

static u32   __tokencap_ro_cnt;
static u8    __tokencap_ro_loaded;
static FILE* __tokencap_out_file;

/* Identify read-only regions in memory. Only parameters that fall into these
   ranges are worth dumping when passed to strcmp() and so on. Read-write
   regions are far more likely to contain user input instead. */

static void __tokencap_load_mappings(void) {

#if defined __linux__

  u8    buf[MAX_LINE];
  FILE* f = fopen("/proc/self/maps", "r");

  __tokencap_ro_loaded = 1;

  if (!f) return;

  while (fgets(buf, MAX_LINE, f)) {

    u8    rf, wf;
    void *st, *en;

    if (sscanf(buf, "%p-%p %c%c", &st, &en, &rf, &wf) != 4) continue;
    if (wf == 'w' || rf != 'r') continue;

    __tokencap_ro[__tokencap_ro_cnt].st = (void*)st;
    __tokencap_ro[__tokencap_ro_cnt].en = (void*)en;

    if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;

  }

  fclose(f);

#elif defined __APPLE__

  struct vm_region_submap_info_64 region;
  mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
  vm_address_t base = 0;
  vm_size_t size = 0;
  natural_t depth = 0;

  __tokencap_ro_loaded = 1;

  while (1) {

    if (vm_region_recurse_64(mach_task_self(), &base, &size, &depth,
       (vm_region_info_64_t)&region, &cnt) != KERN_SUCCESS) break;

    if (region.is_submap) {
       depth++;
    } else {
       /* We only care of main map addresses and the read only kinds */
       if ((region.protection & VM_PROT_READ) && !(region.protection & VM_PROT_WRITE)) {
          __tokencap_ro[__tokencap_ro_cnt].st = (void *)base;
          __tokencap_ro[__tokencap_ro_cnt].en = (void *)(base + size);

	  if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;
       }
    }
  }

#elif defined __FreeBSD__ || defined __OpenBSD__

#if defined __FreeBSD__
  int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid()};
#elif defined __OpenBSD__
  int mib[] = {CTL_KERN, KERN_PROC_VMMAP, getpid()};
#endif
  char *buf, *low, *high;
  size_t miblen = sizeof(mib)/sizeof(mib[0]);
  size_t len;

  if (sysctl(mib, miblen, NULL, &len, NULL, 0) == -1) return;

#if defined __FreeBSD__
  len = len * 4 / 3;
#elif defined __OpenBSD__
  len -= len % sizeof(struct kinfo_vmentry);
#endif

  buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (!buf) {
     return;
  }

  if (sysctl(mib, miblen, buf, &len, NULL, 0) == -1) {

     munmap(buf, len);
     return;

  }

  low = buf;
  high = low + len;

  __tokencap_ro_loaded = 1;

  while (low < high) {
     struct kinfo_vmentry *region = (struct kinfo_vmentry *)low;

#if defined __FreeBSD__

     size_t size = region->kve_structsize;

     if (size == 0) break;

     /* We go through the whole mapping of the process and track read-only addresses */
     if ((region->kve_protection & KVME_PROT_READ) &&
	 !(region->kve_protection & KVME_PROT_WRITE)) {

#elif defined __OpenBSD__

     size_t size = sizeof (*region);

     /* We go through the whole mapping of the process and track read-only addresses */
     if ((region->kve_protection & KVE_PROT_READ) &&
	 !(region->kve_protection & KVE_PROT_WRITE)) {
#endif
          __tokencap_ro[__tokencap_ro_cnt].st = (void *)region->kve_start;
          __tokencap_ro[__tokencap_ro_cnt].en = (void *)region->kve_end;

	  if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;
     }

     low += size;
  }

  munmap(buf, len);
#endif
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

  u8  buf[MAX_AUTO_EXTRA * 4 + 1];
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

      default: buf[pos++] = ptr[i];

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
    str1++;
    str2++;

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
    str1++;
    str2++;

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
    str1++;
    str2++;

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
    str1++;
    str2++;

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
    mem1++;
    mem2++;

  }

  return 0;

}

#undef strstr

char* strstr(const char* haystack, const char* needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle)) __tokencap_dump(needle, strlen(needle), 1);

  do {

    const char* n = needle;
    const char* h = haystack;

    while (*n && *h && *n == *h)
      n++, h++;

    if (!*n) return (char*)haystack;

  } while (*(haystack++));

  return 0;

}

#undef strcasestr

char* strcasestr(const char* haystack, const char* needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle)) __tokencap_dump(needle, strlen(needle), 1);

  do {

    const char* n = needle;
    const char* h = haystack;

    while (*n && *h && tolower(*n) == tolower(*h))
      n++, h++;

    if (!*n) return (char*)haystack;

  } while (*(haystack++));

  return 0;

}

/* Init code to open the output file (or default to stderr). */

__attribute__((constructor)) void __tokencap_init(void) {

  u8* fn = getenv("AFL_TOKEN_FILE");
  if (fn) __tokencap_out_file = fopen(fn, "a");
  if (!__tokencap_out_file) __tokencap_out_file = stderr;

}

