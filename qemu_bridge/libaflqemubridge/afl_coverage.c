#include "qemu/osdep.h"
#include "libaflqemubridge/afl.h"
#include "libafl/hooks/tcg/edge.h"

#ifdef CONFIG_AFL

uint8_t *afl_area_ptr;
uint32_t afl_map_size;

static uint64_t afl_edge_gen(uint64_t data, vaddr src, vaddr dst)
{
    (void)data;
    if (!afl_range_is_instrumented(src) && !afl_range_is_instrumented(dst)) {
        return (uint64_t)-1;
    }
    if (!afl_inst_ratio_keep(src)) {
        return (uint64_t)-1;
    }
    return afl_idtable_lookup((uint64_t)src, (uint64_t)dst);
}

static void afl_edge_exec(uint64_t data, uint64_t id)
{
    (void)data;
    uint8_t *p = &afl_area_ptr[id];
    if (unlikely(++(*p) == 0)) {
        *p = 1;
    }
}

void afl_coverage_register(void)
{
    libafl_add_edge_hook(afl_edge_gen, afl_edge_exec, 0);
}

#endif
