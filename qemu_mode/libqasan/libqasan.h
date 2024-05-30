/*******************************************************************************
Copyright (c) 2019-2024, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef __LIBQASAN_H__
#define __LIBQASAN_H__

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <wchar.h>

#include "qasan.h"

#define QASAN_LOG(msg...)                   \
  do {                                      \
                                            \
    if (__qasan_log) {                      \
                                            \
      fprintf(stderr, "==%d== ", getpid()); \
      fprintf(stderr, msg);                 \
                                            \
    }                                       \
                                            \
  } while (0)

#ifdef DEBUG
  #define QASAN_DEBUG(msg...)                 \
    do {                                      \
                                              \
      if (__qasan_debug) {                    \
                                              \
        fprintf(stderr, "==%d== ", getpid()); \
        fprintf(stderr, msg);                 \
                                              \
      }                                       \
                                              \
    } while (0)

#else
  #define QASAN_DEBUG(msg...) \
    do {                      \
                              \
    } while (0)
#endif

#define ASSERT_DLSYM(name)                                              \
  ({                                                                    \
                                                                        \
    void *a = (void *)dlsym(RTLD_NEXT, #name);                          \
    if (!a) {                                                           \
                                                                        \
      fprintf(stderr,                                                   \
              "FATAL ERROR: failed dlsym of " #name " in libqasan!\n"); \
      abort();                                                          \
                                                                        \
    }                                                                   \
    a;                                                                  \
                                                                        \
  })

extern int __qasan_debug;
extern int __qasan_log;

void __libqasan_init_hooks(void);
void __libqasan_init_malloc(void);

void __libqasan_hotpatch(void);

size_t __libqasan_malloc_usable_size(void *ptr);
void  *__libqasan_malloc(size_t size);
void   __libqasan_free(void *ptr);
void  *__libqasan_calloc(size_t nmemb, size_t size);
void  *__libqasan_realloc(void *ptr, size_t size);
int    __libqasan_posix_memalign(void **ptr, size_t align, size_t len);
void  *__libqasan_memalign(size_t align, size_t len);
void  *__libqasan_aligned_alloc(size_t align, size_t len);

void    *__libqasan_memcpy(void *dest, const void *src, size_t n);
void    *__libqasan_memmove(void *dest, const void *src, size_t n);
void    *__libqasan_memset(void *s, int c, size_t n);
void    *__libqasan_memchr(const void *s, int c, size_t n);
void    *__libqasan_memrchr(const void *s, int c, size_t n);
size_t   __libqasan_strlen(const char *s);
size_t   __libqasan_strnlen(const char *s, size_t len);
int      __libqasan_strcmp(const char *str1, const char *str2);
int      __libqasan_strncmp(const char *str1, const char *str2, size_t len);
int      __libqasan_strcasecmp(const char *str1, const char *str2);
int      __libqasan_strncasecmp(const char *str1, const char *str2, size_t len);
int      __libqasan_memcmp(const void *mem1, const void *mem2, size_t len);
int      __libqasan_bcmp(const void *mem1, const void *mem2, size_t len);
char    *__libqasan_strstr(const char *haystack, const char *needle);
char    *__libqasan_strcasestr(const char *haystack, const char *needle);
void    *__libqasan_memmem(const void *haystack, size_t haystack_len,
                           const void *needle, size_t needle_len);
char    *__libqasan_strchr(const char *s, int c);
char    *__libqasan_strrchr(const char *s, int c);
size_t   __libqasan_wcslen(const wchar_t *s);
wchar_t *__libqasan_wcscpy(wchar_t *d, const wchar_t *s);
int      __libqasan_wcscmp(const wchar_t *s1, const wchar_t *s2);

#endif

