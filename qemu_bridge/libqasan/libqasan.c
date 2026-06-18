#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>

#include "qasan.h"

#define REDZONE_SIZE 128
#define QUARANTINE_MAX_BYTES 52428800

#define ALLOC_ALIGN_SIZE (sizeof(long double))

struct chunk_begin {
  size_t              requested_size;
  void               *aligned_orig;
  struct chunk_begin *next;
  struct chunk_begin *prev;
  char                redzone[REDZONE_SIZE];
};

struct chunk_struct {
  struct chunk_begin begin;
  char               redzone[REDZONE_SIZE];
  size_t             prev_size_padding;
};

static void *(*__lq_libc_malloc)(size_t);
static void (*__lq_libc_free)(void *);

#define backend_malloc __lq_libc_malloc
#define backend_free __lq_libc_free

static int __libqasan_malloc_initialized;

static struct chunk_begin *quarantine_top;
static struct chunk_begin *quarantine_end;
static size_t              quarantine_bytes;

static pthread_spinlock_t quarantine_lock;

#define TMP_ZONE_SIZE 4096
static int           __tmp_alloc_zone_idx;
static unsigned char __tmp_alloc_zone[TMP_ZONE_SIZE];

static int quarantine_push(struct chunk_begin *ck)
{
    if (ck->requested_size >= QUARANTINE_MAX_BYTES) {
        return 0;
    }
    if (pthread_spin_trylock(&quarantine_lock)) {
        return 0;
    }

    while (ck->requested_size + quarantine_bytes >= QUARANTINE_MAX_BYTES) {
        struct chunk_begin *tmp = quarantine_end;
        if (!tmp) {
            break;
        }
        quarantine_end = tmp->prev;
        quarantine_bytes -= tmp->requested_size;
        if (tmp->aligned_orig) {
            backend_free(tmp->aligned_orig);
        } else {
            backend_free(tmp);
        }
    }

    ck->next = quarantine_top;
    if (quarantine_top) {
        quarantine_top->prev = ck;
    }
    quarantine_top = ck;
    if (!quarantine_end) {
        quarantine_end = ck;
    }
    quarantine_bytes += ck->requested_size;

    pthread_spin_unlock(&quarantine_lock);
    return 1;
}

void __libqasan_init_malloc(void)
{
    if (__libqasan_malloc_initialized) {
        return;
    }
    __lq_libc_malloc = dlsym(RTLD_NEXT, "malloc");
    __lq_libc_free = dlsym(RTLD_NEXT, "free");
    pthread_spin_init(&quarantine_lock, PTHREAD_PROCESS_PRIVATE);
    __libqasan_malloc_initialized = 1;
}

size_t __libqasan_malloc_usable_size(void *ptr)
{
    char *p = ptr;
    p -= sizeof(struct chunk_begin);
    QASAN_LOAD(p, sizeof(struct chunk_begin) - REDZONE_SIZE);
    return ((struct chunk_begin *)p)->requested_size;
}

void *__libqasan_malloc(size_t size)
{
    if (!__libqasan_malloc_initialized) {
        __libqasan_init_malloc();
        void *r = &__tmp_alloc_zone[__tmp_alloc_zone_idx];
        if (size & (ALLOC_ALIGN_SIZE - 1)) {
            __tmp_alloc_zone_idx +=
                (size & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
        } else {
            __tmp_alloc_zone_idx += size;
        }
        return r;
    }

    int state = QASAN_SWAP(QASAN_DISABLED);
    struct chunk_begin *p = backend_malloc(sizeof(struct chunk_struct) + size);
    QASAN_SWAP(state);

    if (!p) {
        return NULL;
    }

    QASAN_UNPOISON(p, sizeof(struct chunk_struct) + size);

    p->requested_size = size;
    p->aligned_orig = NULL;
    p->next = p->prev = NULL;

    QASAN_ALLOC(&p[1], (char *)&p[1] + size);
    QASAN_POISON(p->redzone, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
    if (size & (ALLOC_ALIGN_SIZE - 1)) {
        QASAN_POISON((char *)&p[1] + size,
                     (size & ~(ALLOC_ALIGN_SIZE - 1)) + 8 - size + REDZONE_SIZE,
                     ASAN_HEAP_RIGHT_RZ);
    } else {
        QASAN_POISON((char *)&p[1] + size, REDZONE_SIZE, ASAN_HEAP_RIGHT_RZ);
    }

    __builtin_memset(&p[1], 0xff, size);

    return &p[1];
}

void __libqasan_free(void *ptr)
{
    if (!ptr) {
        return;
    }

    if (ptr >= (void *)__tmp_alloc_zone &&
        ptr < ((void *)__tmp_alloc_zone + TMP_ZONE_SIZE)) {
        return;
    }

    struct chunk_begin *p = ptr;
    p -= 1;

    QASAN_LOAD(p, sizeof(struct chunk_begin) - REDZONE_SIZE);
    size_t n = p->requested_size;

    QASAN_STORE(ptr, n);
    int state = QASAN_SWAP(QASAN_DISABLED);

    if (!quarantine_push(p)) {
        if (p->aligned_orig) {
            backend_free(p->aligned_orig);
        } else {
            backend_free(p);
        }
    }

    QASAN_SWAP(state);

    if (n & (ALLOC_ALIGN_SIZE - 1)) {
        n = (n & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
    }

    QASAN_POISON(ptr, n, ASAN_HEAP_FREED);
    QASAN_DEALLOC(ptr);
}

void *__libqasan_calloc(size_t nmemb, size_t size)
{
    size *= nmemb;

    if (!__libqasan_malloc_initialized) {
        void *r = &__tmp_alloc_zone[__tmp_alloc_zone_idx];
        __tmp_alloc_zone_idx += size;
        return r;
    }

    char *p = __libqasan_malloc(size);
    if (!p) {
        return NULL;
    }
    __builtin_memset(p, 0, size);
    return p;
}

void *__libqasan_realloc(void *ptr, size_t size)
{
    char *p = __libqasan_malloc(size);
    if (!p) {
        return NULL;
    }
    if (!ptr) {
        return p;
    }
    size_t n = ((struct chunk_begin *)ptr)[-1].requested_size;
    if (size < n) {
        n = size;
    }
    __builtin_memcpy(p, ptr, n);
    __libqasan_free(ptr);
    return p;
}

int __libqasan_posix_memalign(void **ptr, size_t align, size_t len)
{
    if ((align % 2) || (align % sizeof(void *))) {
        return EINVAL;
    }
    if (len == 0) {
        *ptr = NULL;
        return 0;
    }

    size_t size = len + align;

    int state = QASAN_SWAP(QASAN_DISABLED);
    char *orig = backend_malloc(sizeof(struct chunk_struct) + size);
    QASAN_SWAP(state);

    if (!orig) {
        return ENOMEM;
    }

    QASAN_UNPOISON(orig, sizeof(struct chunk_struct) + size);

    char *data = orig + sizeof(struct chunk_begin);
    data += align - ((uintptr_t)data % align);

    struct chunk_begin *p = (struct chunk_begin *)data - 1;

    p->requested_size = len;
    p->aligned_orig = orig;

    QASAN_ALLOC(data, data + len);
    QASAN_POISON(p->redzone, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
    if (len & (ALLOC_ALIGN_SIZE - 1)) {
        QASAN_POISON(
            data + len,
            (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE - len +
                REDZONE_SIZE,
            ASAN_HEAP_RIGHT_RZ);
    } else {
        QASAN_POISON(data + len, REDZONE_SIZE, ASAN_HEAP_RIGHT_RZ);
    }

    __builtin_memset(data, 0xff, len);

    *ptr = data;
    return 0;
}

void *__libqasan_memalign(size_t align, size_t len)
{
    void *ret = NULL;
    __libqasan_posix_memalign(&ret, align, len);
    return ret;
}

void *__libqasan_aligned_alloc(size_t align, size_t len)
{
    void *ret = NULL;
    if ((len % align)) {
        return NULL;
    }
    __libqasan_posix_memalign(&ret, align, len);
    return ret;
}

void *malloc(size_t size)
{
    return __libqasan_malloc(size);
}

void free(void *ptr)
{
    __libqasan_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    return __libqasan_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    return __libqasan_realloc(ptr, size);
}

int posix_memalign(void **ptr, size_t align, size_t len)
{
    return __libqasan_posix_memalign(ptr, align, len);
}

void *memalign(size_t align, size_t len)
{
    return __libqasan_memalign(align, len);
}

void *aligned_alloc(size_t align, size_t len)
{
    return __libqasan_aligned_alloc(align, len);
}

void *valloc(size_t len)
{
    return __libqasan_memalign(sysconf(_SC_PAGESIZE), len);
}

size_t malloc_usable_size(void *ptr)
{
    return __libqasan_malloc_usable_size(ptr);
}

ssize_t read(int fd, void *buf, size_t count)
{
    QASAN_STORE(buf, count);
    return syscall(SYS_read, fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    QASAN_LOAD(buf, count);
    return syscall(SYS_write, fd, buf, count);
}

static int __libqasan_is_initialized = 0;

__attribute__((constructor)) void __libqasan_init(void)
{
    if (__libqasan_is_initialized) {
        return;
    }
    __libqasan_is_initialized = 1;
    __libqasan_init_malloc();
    if (getenv("QASAN_LOG")) {
        fprintf(stderr, "QEMU-AddressSanitizer (v%s)\n", QASAN_VERSTR);
    }
}
