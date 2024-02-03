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

#include "libqasan.h"
#include <features.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <pthread.h>

#define REDZONE_SIZE 128
// 50 mb quarantine
#define QUARANTINE_MAX_BYTES 52428800

#if __STDC_VERSION__ < 201112L || \
    (defined(__FreeBSD__) && __FreeBSD_version < 1200000)
// use this hack if not C11
typedef struct {

  long long   __ll;
  long double __ld;

} max_align_t;

#endif

#define ALLOC_ALIGN_SIZE (_Alignof(max_align_t))

struct chunk_begin {

  size_t              requested_size;
  void               *aligned_orig;  // NULL if not aligned
  struct chunk_begin *next;
  struct chunk_begin *prev;
  char                redzone[REDZONE_SIZE];

};

struct chunk_struct {

  struct chunk_begin begin;
  char               redzone[REDZONE_SIZE];
  size_t             prev_size_padding;

};

#ifdef __GLIBC__

void *(*__lq_libc_malloc)(size_t);
void (*__lq_libc_free)(void *);
  #define backend_malloc __lq_libc_malloc
  #define backend_free __lq_libc_free

  #define TMP_ZONE_SIZE 4096
static int           __tmp_alloc_zone_idx;
static unsigned char __tmp_alloc_zone[TMP_ZONE_SIZE];

#else

// From dlmalloc.c
void *dlmalloc(size_t);
void  dlfree(void *);
  #define backend_malloc dlmalloc
  #define backend_free dlfree

#endif

int __libqasan_malloc_initialized;

static struct chunk_begin *quarantine_top;
static struct chunk_begin *quarantine_end;
static size_t              quarantine_bytes;

#ifdef __BIONIC__
static pthread_mutex_t quarantine_lock;
  #define LOCK_TRY pthread_mutex_trylock
  #define LOCK_INIT pthread_mutex_init
  #define LOCK_UNLOCK pthread_mutex_unlock
#else
static pthread_spinlock_t quarantine_lock;
  #define LOCK_TRY pthread_spin_trylock
  #define LOCK_INIT pthread_spin_init
  #define LOCK_UNLOCK pthread_spin_unlock
#endif

// need qasan disabled
static int quarantine_push(struct chunk_begin *ck) {

  if (ck->requested_size >= QUARANTINE_MAX_BYTES) return 0;

  if (LOCK_TRY(&quarantine_lock)) return 0;

  while (ck->requested_size + quarantine_bytes >= QUARANTINE_MAX_BYTES) {

    struct chunk_begin *tmp = quarantine_end;
    quarantine_end = tmp->prev;

    quarantine_bytes -= tmp->requested_size;

    if (tmp->aligned_orig)
      backend_free(tmp->aligned_orig);
    else
      backend_free(tmp);

  }

  ck->next = quarantine_top;
  if (quarantine_top) quarantine_top->prev = ck;
  quarantine_top = ck;

  LOCK_UNLOCK(&quarantine_lock);

  return 1;

}

void __libqasan_init_malloc(void) {

  if (__libqasan_malloc_initialized) return;

#ifdef __GLIBC__
  __lq_libc_malloc = dlsym(RTLD_NEXT, "malloc");
  __lq_libc_free = dlsym(RTLD_NEXT, "free");
#endif

  LOCK_INIT(&quarantine_lock, PTHREAD_PROCESS_PRIVATE);

  __libqasan_malloc_initialized = 1;
  QASAN_LOG("\n");
  QASAN_LOG("Allocator initialization done.\n");
  QASAN_LOG("\n");

}

size_t __libqasan_malloc_usable_size(void *ptr) {

  char *p = ptr;
  p -= sizeof(struct chunk_begin);

  // Validate that the chunk marker is readable (a crude check
  // to verify that ptr is a valid malloc region before we dereference it)
  QASAN_LOAD(p, sizeof(struct chunk_begin) - REDZONE_SIZE);
  return ((struct chunk_begin *)p)->requested_size;

}

void *__libqasan_malloc(size_t size) {

  if (!__libqasan_malloc_initialized) {

    __libqasan_init_malloc();

#ifdef __GLIBC__
    void *r = &__tmp_alloc_zone[__tmp_alloc_zone_idx];

    if (size & (ALLOC_ALIGN_SIZE - 1))
      __tmp_alloc_zone_idx +=
          (size & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
    else
      __tmp_alloc_zone_idx += size;

    return r;
#endif

  }

  int state = QASAN_SWAP(QASAN_DISABLED);  // disable qasan for this thread

  struct chunk_begin *p = backend_malloc(sizeof(struct chunk_struct) + size);

  QASAN_SWAP(state);

  if (!p) return NULL;

  QASAN_UNPOISON(p, sizeof(struct chunk_struct) + size);

  p->requested_size = size;
  p->aligned_orig = NULL;
  p->next = p->prev = NULL;

  QASAN_ALLOC(&p[1], (char *)&p[1] + size);
  QASAN_POISON(p->redzone, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
  if (size & (ALLOC_ALIGN_SIZE - 1))
    QASAN_POISON((char *)&p[1] + size,
                 (size & ~(ALLOC_ALIGN_SIZE - 1)) + 8 - size + REDZONE_SIZE,
                 ASAN_HEAP_RIGHT_RZ);
  else
    QASAN_POISON((char *)&p[1] + size, REDZONE_SIZE, ASAN_HEAP_RIGHT_RZ);

  __builtin_memset(&p[1], 0xff, size);

  return &p[1];

}

void __libqasan_free(void *ptr) {

  if (!ptr) return;

#ifdef __GLIBC__
  if (ptr >= (void *)__tmp_alloc_zone &&
      ptr < ((void *)__tmp_alloc_zone + TMP_ZONE_SIZE))
    return;
#endif

  struct chunk_begin *p = ptr;
  p -= 1;

  // Validate that the chunk marker is readable (a crude check
  // to verify that ptr is a valid malloc region before we dereference it)
  QASAN_LOAD(p, sizeof(struct chunk_begin) - REDZONE_SIZE);
  size_t n = p->requested_size;

  QASAN_STORE(ptr, n);
  int state = QASAN_SWAP(QASAN_DISABLED);  // disable qasan for this thread

  if (!quarantine_push(p)) {

    if (p->aligned_orig)
      backend_free(p->aligned_orig);
    else
      backend_free(p);

  }

  QASAN_SWAP(state);

  if (n & (ALLOC_ALIGN_SIZE - 1))
    n = (n & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;

  QASAN_POISON(ptr, n, ASAN_HEAP_FREED);
  QASAN_DEALLOC(ptr);

}

void *__libqasan_calloc(size_t nmemb, size_t size) {

  size *= nmemb;

#ifdef __GLIBC__
  if (!__libqasan_malloc_initialized) {

    void *r = &__tmp_alloc_zone[__tmp_alloc_zone_idx];
    __tmp_alloc_zone_idx += size;
    return r;

  }

#endif

  char *p = __libqasan_malloc(size);
  if (!p) return NULL;

  __builtin_memset(p, 0, size);

  return p;

}

void *__libqasan_realloc(void *ptr, size_t size) {

  char *p = __libqasan_malloc(size);
  if (!p) return NULL;

  if (!ptr) return p;

  size_t n = ((struct chunk_begin *)ptr)[-1].requested_size;
  if (size < n) n = size;

  __builtin_memcpy(p, ptr, n);

  __libqasan_free(ptr);
  return p;

}

int __libqasan_posix_memalign(void **ptr, size_t align, size_t len) {

  if ((align % 2) || (align % sizeof(void *))) return EINVAL;
  if (len == 0) {

    *ptr = NULL;
    return 0;

  }

  size_t size = len + align;

  int state = QASAN_SWAP(QASAN_DISABLED);  // disable qasan for this thread

  char *orig = backend_malloc(sizeof(struct chunk_struct) + size);

  QASAN_SWAP(state);

  if (!orig) return ENOMEM;

  QASAN_UNPOISON(orig, sizeof(struct chunk_struct) + size);

  char *data = orig + sizeof(struct chunk_begin);
  data += align - ((uintptr_t)data % align);

  struct chunk_begin *p = (struct chunk_begin *)data - 1;

  p->requested_size = len;
  p->aligned_orig = orig;

  QASAN_ALLOC(data, data + len);
  QASAN_POISON(p->redzone, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
  if (len & (ALLOC_ALIGN_SIZE - 1))
    QASAN_POISON(
        data + len,
        (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE - len + REDZONE_SIZE,
        ASAN_HEAP_RIGHT_RZ);
  else
    QASAN_POISON(data + len, REDZONE_SIZE, ASAN_HEAP_RIGHT_RZ);

  __builtin_memset(data, 0xff, len);

  *ptr = data;

  return 0;

}

void *__libqasan_memalign(size_t align, size_t len) {

  void *ret = NULL;

  __libqasan_posix_memalign(&ret, align, len);

  return ret;

}

void *__libqasan_aligned_alloc(size_t align, size_t len) {

  void *ret = NULL;

  if ((len % align)) return NULL;

  __libqasan_posix_memalign(&ret, align, len);

  return ret;

}

