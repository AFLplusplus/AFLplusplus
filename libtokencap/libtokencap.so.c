/*

   american fuzzy lop++ - extract tokens passed to strcmp / memcmp
   -------------------------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This Linux-only companion library allows you to instrument strcmp(),
   memcmp(), and related functions to automatically extract tokens.
   See README.tokencap.md for more info.

 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

#include "../types.h"
#include "../config.h"

#if !defined __linux__ && !defined __APPLE__ && !defined __FreeBSD__ && \
    !defined __OpenBSD__ && !defined __NetBSD__ && !defined __DragonFly__
#error "Sorry, this library is unsupported in this platform for now!"
#endif /* !__linux__ && !__APPLE__ && ! __FreeBSD__ && ! __OpenBSD__ && \
          !__NetBSD__*/

#if defined __APPLE__
#include <mach/vm_map.h>
#include <mach/mach_init.h>
#elif defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/mman.h>
#endif

#include <dlfcn.h>

#ifdef RTLD_NEXT
/* The libc functions are a magnitude faster than our replacements.
   Use them when RTLD_NEXT is available. */
int (*__libc_strcmp)(const char *str1, const char *str2);
int (*__libc_strncmp)(const char *str1, const char *str2, size_t len);
int (*__libc_strcasecmp)(const char *str1, const char *str2);
int (*__libc_strncasecmp)(const char *str1, const char *str2, size_t len);
int (*__libc_memcmp)(const void *mem1, const void *mem2, size_t len);
int (*__libc_bcmp)(const void *mem1, const void *mem2, size_t len);
char *(*__libc_strstr)(const char *haystack, const char *needle);
char *(*__libc_strcasestr)(const char *haystack, const char *needle);
void *(*__libc_memmem)(const void *haystack, size_t haystack_len,
                       const void *needle, size_t needle_len);
#endif

/* Mapping data and such */

#define MAX_MAPPINGS 1024

static struct mapping { void *st, *en; } __tokencap_ro[MAX_MAPPINGS];

static u32   __tokencap_ro_cnt;
static u8    __tokencap_ro_loaded;
static int   __tokencap_out_file = -1;
static pid_t __tokencap_pid = -1;

/* Identify read-only regions in memory. Only parameters that fall into these
   ranges are worth dumping when passed to strcmp() and so on. Read-write
   regions are far more likely to contain user input instead. */

static void __tokencap_load_mappings(void) {

#if defined __linux__

  u8    buf[MAX_LINE];
  FILE *f = fopen("/proc/self/maps", "r");

  __tokencap_ro_loaded = 1;

  if (!f) return;

  while (fgets(buf, MAX_LINE, f)) {

    u8    rf, wf;
    void *st, *en;

    if (sscanf(buf, "%p-%p %c%c", &st, &en, &rf, &wf) != 4) continue;
    if (wf == 'w' || rf != 'r') continue;

    __tokencap_ro[__tokencap_ro_cnt].st = (void *)st;
    __tokencap_ro[__tokencap_ro_cnt].en = (void *)en;

    if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;

  }

  fclose(f);

#elif defined __APPLE__

  struct vm_region_submap_info_64 region;
  mach_msg_type_number_t          cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
  vm_address_t                    base = 0;
  vm_size_t                       size = 0;
  natural_t                       depth = 0;

  __tokencap_ro_loaded = 1;

  while (1) {

    if (vm_region_recurse_64(mach_task_self(), &base, &size, &depth,
                             (vm_region_info_64_t)&region,
                             &cnt) != KERN_SUCCESS)
      break;

    if (region.is_submap) {

      depth++;

    } else {

      /* We only care of main map addresses and the read only kinds */
      if ((region.protection & VM_PROT_READ) &&
          !(region.protection & VM_PROT_WRITE)) {

        __tokencap_ro[__tokencap_ro_cnt].st = (void *)base;
        __tokencap_ro[__tokencap_ro_cnt].en = (void *)(base + size);

        if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;

      }

      base += size;
      size = 0;

    }

  }

#elif defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__

#if defined   __FreeBSD__
  int    mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, __tokencap_pid};
#elif defined __OpenBSD__
  int mib[] = {CTL_KERN, KERN_PROC_VMMAP, __tokencap_pid};
#elif defined __NetBSD__
  int mib[] = {CTL_VM, VM_PROC, VM_PROC_MAP, __tokencap_pid,
               sizeof(struct kinfo_vmentry)};
#endif
  char * buf, *low, *high;
  size_t miblen = sizeof(mib) / sizeof(mib[0]);
  size_t len;

  if (sysctl(mib, miblen, NULL, &len, NULL, 0) == -1) return;

#if defined __FreeBSD__ || defined __NetBSD__
  len = len * 4 / 3;
#elif defined                      __OpenBSD__
  len -= len % sizeof(struct kinfo_vmentry);
#endif

  buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (buf == MAP_FAILED) return;

  if (sysctl(mib, miblen, buf, &len, NULL, 0) == -1) {

    munmap(buf, len);
    return;

  }

  low = buf;
  high = low + len;

  __tokencap_ro_loaded = 1;

  while (low < high) {

    struct kinfo_vmentry *region = (struct kinfo_vmentry *)low;

#if defined __FreeBSD__ || defined __NetBSD__

#if defined   __FreeBSD__
    size_t                size = region->kve_structsize;

    if (size == 0) break;
#elif defined __NetBSD__
    size_t size = sizeof(*region);
#endif

    /* We go through the whole mapping of the process and track read-only
     * addresses */
    if ((region->kve_protection & KVME_PROT_READ) &&
        !(region->kve_protection & KVME_PROT_WRITE)) {

#elif defined __OpenBSD__

    size_t size = sizeof(*region);

    /* We go through the whole mapping of the process and track read-only
     * addresses */
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

static u8 __tokencap_is_ro(const void *ptr) {

  u32 i;

  if (!__tokencap_ro_loaded) __tokencap_load_mappings();

  for (i = 0; i < __tokencap_ro_cnt; i++)
    if (ptr >= __tokencap_ro[i].st && ptr <= __tokencap_ro[i].en) return 1;

  return 0;

}

/* Dump an interesting token to output file, quoting and escaping it
   properly. */

static void __tokencap_dump(const u8 *ptr, size_t len, u8 is_text) {

  u8  buf[MAX_AUTO_EXTRA * 4 + 1];
  u32 i;
  u32 pos = 0;

  if (len < MIN_AUTO_EXTRA || len > MAX_AUTO_EXTRA || __tokencap_out_file == -1)
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

  int wrt_ok = (1 == write(__tokencap_out_file, "\"", 1));
  wrt_ok &= (pos == write(__tokencap_out_file, buf, pos));
  wrt_ok &= (2 == write(__tokencap_out_file, "\"\n", 2));

}

/* Replacements for strcmp(), memcmp(), and so on. Note that these will be used
   only if the target is compiled with -fno-builtins and linked dynamically. */

#undef strcmp

int strcmp(const char *str1, const char *str2) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, strlen(str1), 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, strlen(str2), 1);

#ifdef RTLD_NEXT
  if (__libc_strcmp) return __libc_strcmp(str1, str2);
#endif

  while (1) {

    const unsigned char c1 = *str1, c2 = *str2;

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++;
    str2++;

  }

}

#undef strncmp

int strncmp(const char *str1, const char *str2, size_t len) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, len, 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, len, 1);

#ifdef RTLD_NEXT
  if (__libc_strncmp) return __libc_strncmp(str1, str2, len);
#endif

  while (len--) {

    unsigned char c1 = *str1, c2 = *str2;

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++;
    str2++;

  }

  return 0;

}

#undef strcasecmp

int strcasecmp(const char *str1, const char *str2) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, strlen(str1), 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, strlen(str2), 1);

#ifdef RTLD_NEXT
  if (__libc_strcasecmp) return __libc_strcasecmp(str1, str2);
#endif

  while (1) {

    const unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++;
    str2++;

  }

}

#undef strncasecmp

int strncasecmp(const char *str1, const char *str2, size_t len) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, len, 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, len, 1);

#ifdef RTLD_NEXT
  if (__libc_strncasecmp) return __libc_strncasecmp(str1, str2, len);
#endif

  while (len--) {

    const unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++;
    str2++;

  }

  return 0;

}

#undef memcmp

int memcmp(const void *mem1, const void *mem2, size_t len) {

  if (__tokencap_is_ro(mem1)) __tokencap_dump(mem1, len, 0);
  if (__tokencap_is_ro(mem2)) __tokencap_dump(mem2, len, 0);

#ifdef RTLD_NEXT
  if (__libc_memcmp) return __libc_memcmp(mem1, mem2, len);
#endif

  const char *strmem1 = (const char *)mem1;
  const char *strmem2 = (const char *)mem2;

  while (len--) {

    const unsigned char c1 = *strmem1, c2 = *strmem2;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    strmem1++;
    strmem2++;

  }

  return 0;

}

#undef bcmp

int bcmp(const void *mem1, const void *mem2, size_t len) {

  if (__tokencap_is_ro(mem1)) __tokencap_dump(mem1, len, 0);
  if (__tokencap_is_ro(mem2)) __tokencap_dump(mem2, len, 0);

#ifdef RTLD_NEXT
  if (__libc_bcmp) return __libc_bcmp(mem1, mem2, len);
#endif

  const char *strmem1 = (const char *)mem1;
  const char *strmem2 = (const char *)mem2;

  while (len--) {

    int diff = *strmem1 ^ *strmem2;
    if (diff != 0) return 1;
    strmem1++;
    strmem2++;

  }

  return 0;

}

#undef strstr

char *strstr(const char *haystack, const char *needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle)) __tokencap_dump(needle, strlen(needle), 1);

#ifdef RTLD_NEXT
  if (__libc_strstr) return __libc_strstr(haystack, needle);
#endif

  do {

    const char *n = needle;
    const char *h = haystack;

    while (*n && *h && *n == *h)
      n++, h++;

    if (!*n) return (char *)haystack;

  } while (*(haystack++));

  return 0;

}

#undef strcasestr

char *strcasestr(const char *haystack, const char *needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle)) __tokencap_dump(needle, strlen(needle), 1);

#ifdef RTLD_NEXT
  if (__libc_strcasestr) return __libc_strcasestr(haystack, needle);
#endif

  do {

    const char *n = needle;
    const char *h = haystack;

    while (*n && *h && tolower(*n) == tolower(*h))
      n++, h++;

    if (!*n) return (char *)haystack;

  } while (*(haystack++));

  return 0;

}

#undef memmem

void *memmem(const void *haystack, size_t haystack_len, const void *needle,
             size_t needle_len) {

  if (__tokencap_is_ro(haystack)) __tokencap_dump(haystack, haystack_len, 1);

  if (__tokencap_is_ro(needle)) __tokencap_dump(needle, needle_len, 1);

#ifdef RTLD_NEXT
  if (__libc_memmem)
    return __libc_memmem(haystack, haystack_len, needle, needle_len);
#endif

  const char *n = (const char *)needle;
  const char *h = (const char *)haystack;
  if (haystack_len < needle_len) return 0;
  if (needle_len == 0) return (void *)haystack;
  if (needle_len == 1) return memchr(haystack, *n, haystack_len);

  const char *end = h + (haystack_len - needle_len);

  do {

    if (*h == *n) {

      if (memcmp(h, n, needle_len) == 0) return (void *)h;

    }

  } while (h++ <= end);

  return 0;

}

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

const char *ap_strcasestr(const char *s1, const char *s2) {

  return strcasestr(s1, s2);

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

const char *xmlStrstr(const char *haystack, const char *needle) {

  if (haystack == NULL) { return NULL; }
  if (needle == NULL) { return NULL; }
  return strstr(haystack, needle);

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

/* bcmp/memcmp BSD flavors, similar to CRYPTO_memcmp */

int timingsafe_bcmp(const void *mem1, const void *mem2, size_t len) {

  return bcmp(mem1, mem2, len);

}

int timingsafe_memcmp(const void *mem1, const void *mem2, size_t len) {

  return memcmp(mem1, mem2, len);

}

/* Init code to open the output file (or default to stderr). */

__attribute__((constructor)) void __tokencap_init(void) {

  u8 *fn = getenv("AFL_TOKEN_FILE");
  if (fn) __tokencap_out_file = open(fn, O_RDWR | O_CREAT | O_APPEND, 0655);
  if (__tokencap_out_file == -1) __tokencap_out_file = STDERR_FILENO;
  __tokencap_pid = getpid();

#ifdef RTLD_NEXT
  __libc_strcmp = dlsym(RTLD_NEXT, "strcmp");
  __libc_strncmp = dlsym(RTLD_NEXT, "strncmp");
  __libc_strcasecmp = dlsym(RTLD_NEXT, "strcasecmp");
  __libc_strncasecmp = dlsym(RTLD_NEXT, "strncasecmp");
  __libc_memcmp = dlsym(RTLD_NEXT, "memcmp");
  __libc_bcmp = dlsym(RTLD_NEXT, "bcmp");
  __libc_strstr = dlsym(RTLD_NEXT, "strstr");
  __libc_strcasestr = dlsym(RTLD_NEXT, "strcasestr");
  __libc_memmem = dlsym(RTLD_NEXT, "memmem");
#endif

}

/* closing as best as we can the tokens file */
__attribute__((destructor)) void __tokencap_shutdown(void) {

  if (__tokencap_out_file != STDERR_FILENO) close(__tokencap_out_file);

}

