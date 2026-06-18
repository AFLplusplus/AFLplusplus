#include "qemu/osdep.h"
#include "qemu.h"
#include "libafl/cpu.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/ijon.h"
#include "libaflqemubridge/imported/config.h"
#include "libaflqemubridge/imported/types.h"
#include "libafl/hooks/syscall.h"

#ifdef CONFIG_AFL

int afl_ijon_enabled = 0;

static uint64_t *afl_ijon_max_area = NULL;
static uint32_t afl_ijon_state = 0;
static uint32_t afl_ijon_cov_map_size = 0;

uint32_t afl_ijon_extra_size(void)
{
    if (!afl_ijon_enabled) {
        return 0;
    }
    return MAP_SIZE_IJON_MAP + (uint32_t)MAP_SIZE_IJON_BYTES;
}

static uint64_t afl_ijon_simple_hash(uint64_t x)
{
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    x = x ^ (x >> 31);
    return x;
}

static void afl_ijon_ensure_max_area(void)
{
    if (afl_ijon_max_area || !afl_area_ptr) {
        return;
    }
    uint32_t set_map_size = afl_ijon_cov_map_size + MAP_SIZE_IJON_MAP;
    afl_ijon_max_area = (uint64_t *)(afl_area_ptr + set_map_size);
    memset(afl_ijon_max_area, 0, MAP_SIZE_IJON_ENTRIES * sizeof(uint64_t));
}

static void afl_ijon_max(uint32_t addr, uint64_t val)
{
    if (!afl_ijon_enabled) {
        return;
    }
    afl_ijon_ensure_max_area();
    if (!afl_ijon_max_area) {
        return;
    }
    uint32_t var_id =
        (uint32_t)(afl_ijon_simple_hash((uint64_t)addr) % MAP_SIZE_IJON_ENTRIES);
    if (afl_ijon_max_area[var_id] < val) {
        afl_ijon_max_area[var_id] = val;
    }
}

static void afl_ijon_min(uint32_t addr, uint64_t val)
{
    afl_ijon_max(addr, 0xffffffffffffffffULL - val);
}

static void afl_ijon_max_until(uint32_t addr, uint64_t val, uint64_t limit)
{
    uint64_t encoded =
        val >= limit ? UINT64_MAX : UINT64_MAX - limit + val;
    afl_ijon_max(addr, encoded);
}

static void afl_ijon_set(uint32_t loc_addr, uint32_t val)
{
    if (!afl_ijon_enabled || !afl_area_ptr) {
        return;
    }
    uint32_t combined_hash = loc_addr ^ val ^ afl_ijon_state;
    uint32_t coverage_id = combined_hash % MAP_SIZE_IJON_MAP;
    afl_area_ptr[afl_ijon_cov_map_size + coverage_id] = 1;
}

static void afl_ijon_inc(uint32_t loc_addr, uint32_t val)
{
    if (!afl_ijon_enabled || !afl_area_ptr) {
        return;
    }
    uint32_t combined_hash = loc_addr ^ val ^ afl_ijon_state;
    uint32_t coverage_id = combined_hash % MAP_SIZE_IJON_MAP;
    afl_area_ptr[afl_ijon_cov_map_size + coverage_id] += 1;
}

static void afl_ijon_xor_state(uint32_t val)
{
    afl_ijon_state = (afl_ijon_state ^ val) % (uint32_t)MAP_SIZE_IJON_MAP;
}

static void afl_ijon_reset_state(void)
{
    afl_ijon_state = 0;
}

static target_long afl_ijon_dispatch(target_long action, target_long arg1,
                                     target_long arg2, target_long arg3)
{
    switch (action) {
        case IJON_ACTION_MAX:
            afl_ijon_max((uint32_t)arg1, (uint64_t)arg2);
            break;
        case IJON_ACTION_MIN:
            afl_ijon_min((uint32_t)arg1, (uint64_t)arg2);
            break;
        case IJON_ACTION_SET:
            afl_ijon_set((uint32_t)arg1, (uint32_t)arg2);
            break;
        case IJON_ACTION_INC:
            afl_ijon_inc((uint32_t)arg1, (uint32_t)arg2);
            break;
        case IJON_ACTION_XOR_STATE:
            afl_ijon_xor_state((uint32_t)arg1);
            break;
        case IJON_ACTION_RESET_STATE:
            afl_ijon_reset_state();
            break;
        case IJON_ACTION_MAX_UNTIL:
            afl_ijon_max_until((uint32_t)arg1, (uint64_t)arg2, (uint64_t)arg3);
            break;
        case IJON_ACTION_CMP:
            afl_ijon_inc((uint32_t)arg1, (uint32_t)arg2);
            break;
        default:
            break;
    }
    return 0;
}

static struct libafl_syshook_ret afl_ijon_syscall_hook(
    uint64_t data, int *sys_num, target_ulong *arg0, target_ulong *arg1,
    target_ulong *arg2, target_ulong *arg3, target_ulong *arg4,
    target_ulong *arg5, target_ulong *arg6, target_ulong *arg7)
{
    (void)data;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    (void)arg7;

    struct libafl_syshook_ret ret = {.tag = LIBAFL_SYSHOOK_RUN};

    if ((uint32_t)*sys_num != IJON_FAKESYS_NR) {
        return ret;
    }

    target_long r = afl_ijon_dispatch((target_long)*arg0, (target_long)*arg1,
                                      (target_long)*arg2, (target_long)*arg3);

    ret.tag = LIBAFL_SYSHOOK_SKIP;
    ret.syshook_skip_retval = (target_ulong)r;
    return ret;
}

void afl_ijon_init(uint32_t cov_map_size)
{
    if (!getenv("AFL_QEMU_IJON")) {
        return;
    }

    afl_ijon_enabled = 1;
    afl_ijon_cov_map_size = cov_map_size;
    afl_ijon_state = 0;
    afl_ijon_max_area = NULL;

    libafl_add_pre_syscall_hook(afl_ijon_syscall_hook, 0);

    if (getenv("AFL_DEBUG")) {
        fprintf(stderr,
                "[AFL] IJON enabled: cov=%u set/inc=%u max=%u total_extra=%u\n",
                (unsigned)cov_map_size, (unsigned)MAP_SIZE_IJON_MAP,
                (unsigned)MAP_SIZE_IJON_BYTES,
                (unsigned)afl_ijon_extra_size());
    }
}

#endif
