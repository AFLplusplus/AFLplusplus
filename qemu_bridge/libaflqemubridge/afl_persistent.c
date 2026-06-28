#include "qemu/osdep.h"
#include "qemu/selfmap.h"
#include "qemu/interval-tree.h"
#include "user/page-protection.h"
#include "user/mmap.h"
#include "qemu.h"
#include "user/guest-host.h"
#include "libafl/user.h"
#include "libafl/cpu.h"
#include "libafl/hooks/tcg/instruction.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/imported/config.h"
#include "libaflqemubridge/imported/types.h"

#ifdef CONFIG_AFL

#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#if defined(TARGET_X86_64)
#define AFL_SP_REG 7
#define AFL_PC_REG 16
#define AFL_PERSISTENT_SUPPORTED 1
#elif defined(TARGET_I386)
#define AFL_SP_REG 4
#define AFL_PC_REG 8
#define AFL_PERSISTENT_SUPPORTED 1
#else
#define AFL_PERSISTENT_SUPPORTED 0
#endif

uint32_t *afl_child_sync = NULL;
int afl_persistent_use_futex = 0;

static int afl_is_persistent_val = 0;
static uint64_t afl_persistent_addr = 0;
static uint64_t afl_persistent_ret_addr = 0;
static uint64_t afl_persistent_cnt = 0;
static int afl_persistent_save_gpr = 0;
static int afl_persistent_memory = 0;
static int afl_persistent_exits = 0;
static int64_t afl_persistent_retaddr_offset = 0;

static int afl_persistent_first_pass = 1;
static uint32_t afl_cycle_cnt = 0;

static uint64_t afl_saved_sp = 0;
static int afl_saved_sp_valid = 0;
static abi_ulong afl_saved_brk = 0;

#define AFL_MAX_REGS 256
static int afl_num_regs = 0;
static int afl_reg_sizes[AFL_MAX_REGS];
static uint8_t afl_saved_regs[AFL_MAX_REGS][32];

struct afl_mem_region {
    uint64_t start;
    uint64_t end;
    uint8_t *backup;
    struct afl_mem_region *next;
};

static struct afl_mem_region *afl_mem_regions = NULL;

static inline long afl_sys_futex(void *uaddr, int op, int val,
                                 const struct timespec *timeout, void *uaddr2,
                                 int val3)
{
    return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static inline void afl_sync_wake(void *uaddr)
{
    afl_sys_futex(uaddr, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static void afl_child_sync_attach(void)
{
    /* The fuzzer<->child sync word is embedded in the last bytes of the
       trace_bits shared map; AFL_CHILD_SYNC_SHM carries its byte offset. The
       coverage map (afl_area_ptr) is already attached at this point. */
    char *child_sync_off = getenv("AFL_CHILD_SYNC_SHM");
    if (!child_sync_off || !afl_area_ptr) {
        return;
    }
    uint32_t off = (uint32_t)strtoul(child_sync_off, NULL, 10);
    afl_child_sync = (uint32_t *)(void *)(afl_area_ptr + off);
}

static int afl_read_sp(CPUState *cpu, uint64_t *out)
{
#if AFL_PERSISTENT_SUPPORTED
    uint8_t spbuf[32] = {0};
    int n = libafl_qemu_read_reg(cpu, AFL_SP_REG, spbuf);
    if (n <= 0) {
        return 0;
    }
    uint64_t sp = 0;
    memcpy(&sp, spbuf, n > 8 ? 8 : n);
    *out = sp;
    return 1;
#else
    (void)cpu;
    (void)out;
    return 0;
#endif
}

static void afl_write_sp(CPUState *cpu, uint64_t sp)
{
#if AFL_PERSISTENT_SUPPORTED
    uint8_t spbuf[32];
    memset(spbuf, 0, sizeof(spbuf));
    memcpy(spbuf, &sp, sizeof(sp));
    libafl_qemu_write_reg(cpu, AFL_SP_REG, spbuf);
#else
    (void)cpu;
    (void)sp;
#endif
}

static void afl_persistent_save_gprs(CPUState *cpu)
{
    if (!afl_num_regs) {
        afl_num_regs = libafl_qemu_num_regs(cpu);
        if (afl_num_regs > AFL_MAX_REGS) {
            afl_num_regs = AFL_MAX_REGS;
        }
    }
    for (int i = 0; i < afl_num_regs; ++i) {
        afl_reg_sizes[i] = libafl_qemu_read_reg(cpu, i, afl_saved_regs[i]);
    }
}

static void afl_persistent_restore_gprs(CPUState *cpu)
{
    for (int i = 0; i < afl_num_regs; ++i) {
        if (afl_reg_sizes[i] > 0) {
            libafl_qemu_write_reg(cpu, i, afl_saved_regs[i]);
        }
    }
}

static void afl_persistent_collect_memory(CPUState *cpu)
{
    IntervalTreeRoot *proc_maps = read_self_maps();
    IntervalTreeRoot *pageflags = pageflags_get_root();

    IntervalTreeNode *node = libafl_maps_first(pageflags);
    while (node) {
        struct libafl_mapinfo info;
        node = libafl_maps_next(node, proc_maps, &info);
        if (!info.is_valid || !(info.flags & PROT_WRITE)) {
            continue;
        }
        uint64_t start = info.start;
        uint64_t end = info.end;
        if (end <= start) {
            continue;
        }
        uint64_t len = end - start;
        struct afl_mem_region *r = calloc(1, sizeof(struct afl_mem_region));
        if (!r) {
            fprintf(stderr, "[AFL] persistent: calloc failed\n");
            _exit(1);
        }
        r->start = start;
        r->end = end;
        r->backup = malloc(len);
        if (!r->backup) {
            fprintf(stderr, "[AFL] persistent: malloc failed\n");
            _exit(1);
        }
        memcpy(r->backup, g2h(cpu, start), len);
        r->next = afl_mem_regions;
        afl_mem_regions = r;
    }

    free_self_maps(proc_maps);
}

static int afl_region_overlaps_snapshot(uint64_t start, uint64_t end)
{
    for (struct afl_mem_region *r = afl_mem_regions; r; r = r->next) {
        if (start < r->end && r->start < end) {
            return 1;
        }
    }
    return 0;
}

#define AFL_MAX_NEW_REGIONS 4096

static void afl_persistent_restore_memory(CPUState *cpu)
{
    uint64_t new_start[AFL_MAX_NEW_REGIONS];
    uint64_t new_len[AFL_MAX_NEW_REGIONS];
    size_t new_count = 0;

    IntervalTreeRoot *proc_maps = read_self_maps();
    IntervalTreeRoot *pageflags = pageflags_get_root();

    IntervalTreeNode *node = libafl_maps_first(pageflags);
    while (node) {
        struct libafl_mapinfo info;
        node = libafl_maps_next(node, proc_maps, &info);
        if (!info.is_valid || !(info.flags & PROT_WRITE)) {
            continue;
        }
        uint64_t start = info.start;
        uint64_t end = info.end;
        if (end <= start) {
            continue;
        }
        if (!afl_region_overlaps_snapshot(start, end)) {
            if (new_count < AFL_MAX_NEW_REGIONS) {
                new_start[new_count] = start;
                new_len[new_count] = end - start;
                new_count++;
            }
        }
    }

    free_self_maps(proc_maps);

    for (size_t i = 0; i < new_count; ++i) {
        target_munmap(new_start[i], new_len[i]);
    }

    libafl_set_brk(afl_saved_brk);

    for (struct afl_mem_region *r = afl_mem_regions; r; r = r->next) {
        memcpy(g2h(cpu, r->start), r->backup, r->end - r->start);
    }
}

static void afl_persistent_patch_retaddr(CPUState *cpu)
{
#if AFL_PERSISTENT_SUPPORTED
    uint64_t sp = 0;
    if (!afl_read_sp(cpu, &sp)) {
        return;
    }
    uint64_t target = sp + afl_persistent_retaddr_offset;
#if defined(TARGET_X86_64)
    uint64_t val = afl_persistent_addr;
    memcpy(g2h(cpu, target), &val, sizeof(val));
#else
    uint32_t val = (uint32_t)afl_persistent_addr;
    memcpy(g2h(cpu, target), &val, sizeof(val));
#endif
#else
    (void)cpu;
#endif
}

static void afl_persistent_sync(void)
{
    if (afl_child_sync) {
        uint32_t expected = AFL_CHILD_RUN;
        while (!__atomic_compare_exchange_n(afl_child_sync, &expected,
                                            AFL_CHILD_DONE, 0, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
            if (expected == AFL_CHILD_EXITED) {
                _exit(0);
            }
        }

        afl_sync_wake(afl_child_sync);

        uint32_t sync_val;
        while ((sync_val = __atomic_load_n(afl_child_sync, __ATOMIC_ACQUIRE)) ==
               AFL_CHILD_DONE) {
            afl_sys_futex(afl_child_sync, FUTEX_WAIT, AFL_CHILD_DONE, NULL, NULL,
                          0);
        }

        if (sync_val == AFL_CHILD_EXITED) {
            _exit(0);
        }
    } else {
        raise(SIGSTOP);
    }
}

static void afl_persistent_routine(uint64_t data, vaddr pc)
{
    (void)data;
    (void)pc;

    CPUState *cpu = libafl_qemu_current_cpu();

    if (afl_persistent_first_pass) {
        memset(afl_area_ptr, 0, afl_map_size);
        afl_area_ptr[0] = 1;

        afl_saved_sp_valid = afl_read_sp(cpu, &afl_saved_sp);

        if (afl_persistent_memory) {
            afl_saved_brk = libafl_get_brk();
            afl_persistent_collect_memory(cpu);
        }
        if (afl_persistent_save_gpr) {
            afl_persistent_save_gprs(cpu);
        }

        afl_cycle_cnt = afl_persistent_cnt;
        afl_persistent_first_pass = 0;

        if (!afl_persistent_ret_addr && !afl_persistent_exits) {
            afl_persistent_patch_retaddr(cpu);
        }
        return;
    }

    if (afl_persistent_ret_addr) {
        return;
    }

    if (afl_persistent_cnt && --afl_cycle_cnt == 0) {
        _exit(0);
    }

    afl_persistent_sync();

    if (afl_persistent_memory) {
        afl_persistent_restore_memory(cpu);
    }
    if (afl_persistent_save_gpr) {
        afl_persistent_restore_gprs(cpu);
    } else if (afl_saved_sp_valid) {
        afl_write_sp(cpu, afl_saved_sp);
    }

    if (!afl_persistent_ret_addr && !afl_persistent_exits) {
        afl_persistent_patch_retaddr(cpu);
    }

    afl_area_ptr[0] = 1;
}

static void afl_persistent_ret_routine(uint64_t data, vaddr pc)
{
    (void)data;
    (void)pc;

    CPUState *cpu = libafl_qemu_current_cpu();

    if (afl_persistent_first_pass) {
        return;
    }

    if (afl_persistent_cnt && --afl_cycle_cnt == 0) {
        _exit(0);
    }

    afl_persistent_sync();

    if (afl_persistent_memory) {
        afl_persistent_restore_memory(cpu);
    }
    if (afl_persistent_save_gpr) {
        afl_persistent_restore_gprs(cpu);
    } else if (afl_saved_sp_valid) {
        afl_write_sp(cpu, afl_saved_sp);
    }

    afl_area_ptr[0] = 1;

#if AFL_PERSISTENT_SUPPORTED
    uint8_t pcbuf[32];
    memset(pcbuf, 0, sizeof(pcbuf));
    memcpy(pcbuf, &afl_persistent_addr, sizeof(afl_persistent_addr));
    libafl_qemu_write_reg(cpu, AFL_PC_REG, pcbuf);
    libafl_qemu_set_pc(cpu, (vaddr)afl_persistent_addr);
#endif
}

bool afl_is_persistent(void)
{
    return afl_is_persistent_val != 0;
}

void afl_persistent_init(void)
{
    char *e;

    e = getenv("AFL_QEMU_PERSISTENT_ADDR");
    if (e) {
        afl_persistent_addr = strtoull(e, NULL, 0);
        afl_is_persistent_val = 1;
    }

    e = getenv("AFL_QEMU_PERSISTENT_RET");
    if (e) {
        afl_persistent_ret_addr = strtoull(e, NULL, 0);
    }

    if (getenv("AFL_QEMU_PERSISTENT_GPR")) {
        afl_persistent_save_gpr = 1;
    }
    if (getenv("AFL_QEMU_PERSISTENT_MEM")) {
        afl_persistent_memory = 1;
    }
    if (getenv("AFL_QEMU_PERSISTENT_EXITS")) {
        afl_persistent_exits = 1;
    }

    e = getenv("AFL_QEMU_PERSISTENT_RETADDR_OFFSET");
    if (e) {
        afl_persistent_retaddr_offset = strtoll(e, NULL, 0);
    }

    e = getenv("AFL_QEMU_PERSISTENT_CNT");
    if (e) {
        afl_persistent_cnt = strtoull(e, NULL, 0);
    } else {
        afl_persistent_cnt = 0;
    }

    e = getenv("AFL_QEMU_SNAPSHOT");
    if (e) {
        afl_is_persistent_val = 1;
        afl_persistent_save_gpr = 1;
        afl_persistent_memory = 1;
        afl_persistent_exits = 1;
        if (afl_persistent_addr == 0) {
            afl_persistent_addr = strtoull(e, NULL, 0);
        }
    }

    if (!afl_is_persistent_val) {
        return;
    }

#if !AFL_PERSISTENT_SUPPORTED
    fprintf(stderr, "[AFL] persistent mode not supported on this target\n");
    afl_is_persistent_val = 0;
    return;
#endif

    afl_child_sync_attach();
    if (afl_child_sync) {
        afl_persistent_use_futex = 1;
    }

    if (afl_persistent_addr) {
        libafl_qemu_add_instruction_hooks(afl_persistent_addr,
                                          afl_persistent_routine, 0, 1);
    }
    if (afl_persistent_ret_addr) {
        libafl_qemu_add_instruction_hooks(afl_persistent_ret_addr,
                                          afl_persistent_ret_routine, 0, 1);
    }

    if (getenv("AFL_DEBUG")) {
        fprintf(stderr,
                "[AFL] persistent: 0x%lx [0x%lx] cnt=%lu %s%s%s futex=%d\n",
                (unsigned long)afl_persistent_addr,
                (unsigned long)afl_persistent_ret_addr,
                (unsigned long)afl_persistent_cnt,
                (afl_persistent_save_gpr ? "gpr " : ""),
                (afl_persistent_memory ? "mem " : ""),
                (afl_persistent_exits ? "exits " : ""), afl_persistent_use_futex);
    }
}

#endif
