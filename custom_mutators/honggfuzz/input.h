#ifndef _HG_INPUT_
#define _HG_INPUT_

#include <stdarg.h>
#ifdef __clang__
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "honggfuzz.h"
#include "afl-fuzz.h"

/*
 * Go-style defer scoped implementation
 *
 * If compiled with clang, use: -fblocks -lBlocksRuntime
 *
 * Example of use:
 *
 * {
 *   int fd = open(fname, O_RDONLY);
 *   if (fd == -1) {
 *     error(....);
 *     return;
 *   }
 *   defer { close(fd); };
 *   ssize_t sz = read(fd, buf, sizeof(buf));
 *   ...
 *   ...
 * }
 *
 */

#define __STRMERGE(a, b) a##b
#define _STRMERGE(a, b)  __STRMERGE(a, b)
#ifdef __clang__
#if __has_extension(blocks)
static void __attribute__((unused)) __clang_cleanup_func(void (^*dfunc)(void)) {
    (*dfunc)();
}

#define defer                                                                                      \
    void (^_STRMERGE(__defer_f_, __COUNTER__))(void)                                               \
        __attribute__((cleanup(__clang_cleanup_func))) __attribute__((unused)) = ^

#else /* __has_extension(blocks) */
#define defer UNIMPLEMENTED - NO - SUPPORT - FOR - BLOCKS - IN - YOUR - CLANG - ENABLED
#endif /*  __has_extension(blocks) */
#else  /* !__clang__, e.g.: gcc */

#define __block
#define _DEFER(a, count)                                                                            \
    auto void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)));               \
    int       _STRMERGE(__defer_var_, count) __attribute__((cleanup(_STRMERGE(__defer_f_, count)))) \
        __attribute__((unused));                                                                    \
    void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)))
#define defer _DEFER(a, __COUNTER__)
#endif /* ifdef __clang__ */

#define HF_MIN(x, y) (x <= y ? x : y)
#define HF_MAX(x, y) (x >= y ? x : y)
#define ATOMIC_GET
#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))
#define HF_ATTR_UNUSED __attribute__((unused))
#define util_Malloc(x) malloc(x)

extern uint8_t *         queue_input;
extern size_t            queue_input_size;
extern afl_state_t *     afl_struct;

inline void wmb() { }
inline void LOG_F(const char *format, ...) { }
static inline uint64_t util_rndGet(uint64_t min, uint64_t max) {
  return min + rand_below(afl_struct, max - min + 1);
}
static inline uint64_t util_rnd64() { return rand_below(afl_struct, 1 << 30); }

static inline const uint8_t* input_getRandomInputAsBuf(run_t* run, size_t* len) {
  *len = queue_input_size;
  run->dynfile->data = queue_input;
  run->dynfile->size = queue_input_size;
  return queue_input;
}
static inline void input_setSize(run_t* run, size_t sz) {
  run->dynfile->size = sz;
}
static inline void util_turnToPrintable(uint8_t* buf, size_t sz) {
  for (size_t i = 0; i < sz; i++)
    buf[i] = buf[i] % 95 + 32;
}
static inline void util_rndBuf(uint8_t* buf, size_t sz) {
  if (sz == 0) return;
  for (size_t i = 0; i < sz; i++)
    buf[i] = (uint8_t)rand_below(afl_struct, 256);
}
static inline uint8_t util_rndPrintable() {
  return 32 + rand_below(afl_struct, 127 - 32);
}
static inline void util_rndBufPrintable(uint8_t* buf, size_t sz) {
  for (size_t i = 0; i < sz; i++)
    buf[i] = util_rndPrintable();
}

#endif
