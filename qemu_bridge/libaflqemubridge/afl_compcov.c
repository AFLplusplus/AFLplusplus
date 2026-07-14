#include "qemu/osdep.h"
#include "libaflqemubridge/afl.h"
#include "libafl/hooks/tcg/cmp.h"

#ifdef CONFIG_AFL

int afl_compcov_level = 0;

static uint64_t afl_compcov_hash(uint64_t v)
{
    v ^= ((v << 49) | (v >> 15)) ^ ((v << 24) | (v >> 40));
    v *= 0x9FB21C651E98DF25ULL;
    v ^= (v >> 35) + 8;
    v *= 0x9FB21C651E98DF25ULL;
    return v ^ (v >> 28);
}

static inline void afl_compcov_inc(uint64_t id)
{
    uint8_t *p = &afl_area_ptr[id % afl_map_size];
    if (unlikely(++(*p) == 0)) {
        *p = 1;
    }
}

static uint64_t afl_compcov_gen(uint64_t data, vaddr pc, size_t size)
{
    (void)data;
    (void)size;
    if (!afl_range_is_instrumented(pc)) {
        return (uint64_t)-1;
    }
    return (uint64_t)(afl_compcov_hash((uint64_t)pc) % afl_map_size);
}

static void afl_compcov_exec2(uint64_t data, uint64_t id, uint16_t v0,
                              uint16_t v1)
{
    (void)data;
    if ((v0 & 0xff00) == (v1 & 0xff00)) {
        afl_compcov_inc(id);
    }
}

static void afl_compcov_exec4(uint64_t data, uint64_t id, uint32_t v0,
                              uint32_t v1)
{
    (void)data;
    if ((v0 & 0xff000000) == (v1 & 0xff000000)) {
        afl_compcov_inc(id + 2);
        if ((v0 & 0xff0000) == (v1 & 0xff0000)) {
            afl_compcov_inc(id + 1);
            if ((v0 & 0xff00) == (v1 & 0xff00)) {
                afl_compcov_inc(id);
            }
        }
    }
}

static void afl_compcov_exec8(uint64_t data, uint64_t id, uint64_t v0,
                              uint64_t v1)
{
    (void)data;
    if ((v0 & 0xff00000000000000ULL) == (v1 & 0xff00000000000000ULL)) {
        afl_compcov_inc(id + 6);
        if ((v0 & 0xff000000000000ULL) == (v1 & 0xff000000000000ULL)) {
            afl_compcov_inc(id + 5);
            if ((v0 & 0xff0000000000ULL) == (v1 & 0xff0000000000ULL)) {
                afl_compcov_inc(id + 4);
                if ((v0 & 0xff00000000ULL) == (v1 & 0xff00000000ULL)) {
                    afl_compcov_inc(id + 3);
                    if ((v0 & 0xff000000) == (v1 & 0xff000000)) {
                        afl_compcov_inc(id + 2);
                        if ((v0 & 0xff0000) == (v1 & 0xff0000)) {
                            afl_compcov_inc(id + 1);
                            if ((v0 & 0xff00) == (v1 & 0xff00)) {
                                afl_compcov_inc(id);
                            }
                        }
                    }
                }
            }
        }
    }
}

void afl_compcov_init(void)
{
    char *e = getenv("AFL_QEMU_COMPCOV");
    char *l = getenv("AFL_COMPCOV_LEVEL");
    if (l) {
        afl_compcov_level = atoi(l);
    } else if (e) {
        afl_compcov_level = 1;
    }
    if (afl_compcov_level < 1) {
        return;
    }
    libafl_add_cmp_hook(afl_compcov_gen, NULL, afl_compcov_exec2,
                        afl_compcov_exec4, afl_compcov_exec8, 0);
}

#endif
