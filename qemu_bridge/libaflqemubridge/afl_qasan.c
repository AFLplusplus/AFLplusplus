#include "qemu/osdep.h"
#include "qemu.h"
#include "cpu.h"
#include "user/guest-host.h"
#include "exec/cpu-common.h"
#include "user-internals.h"
#include "signal-common.h"

#include "libafl/cpu.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/asan-giovese.h"
#include "libafl/hooks/tcg/read_write.h"
#include "libafl/hooks/syscall.h"

#ifdef CONFIG_AFL

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>

#if defined(TARGET_X86_64) || defined(TARGET_I386)
#define QASAN_PC_GET(env) ((env)->eip)
#define QASAN_BP_GET(env) ((env)->regs[R_EBP])
#define QASAN_SP_GET(env) ((env)->regs[R_ESP])
#elif defined(TARGET_AARCH64)
#define QASAN_PC_GET(env) ((env)->pc)
#define QASAN_BP_GET(env) ((env)->xregs[29])
#define QASAN_SP_GET(env) ((env)->xregs[31])
#elif defined(TARGET_ARM)
#define QASAN_PC_GET(env) ((env)->regs[15])
#define QASAN_BP_GET(env) ((env)->regs[11])
#define QASAN_SP_GET(env) ((env)->regs[13])
#elif defined(TARGET_RISCV)
#define QASAN_PC_GET(env) ((env)->pc)
#define QASAN_BP_GET(env) ((env)->gpr[8])
#define QASAN_SP_GET(env) ((env)->gpr[2])
#else
#define QASAN_PC_GET(env) (0)
#define QASAN_BP_GET(env) (0)
#define QASAN_SP_GET(env) (0)
#endif

#define QASAN_G2H(x) ((uintptr_t)g2h_untagged((vaddr)(x)))

static int qasan_disabled = 0;

void* __ag_high_shadow = HIGH_SHADOW_ADDR;
void* __ag_low_shadow = LOW_SHADOW_ADDR;

struct qasan_chunk {
    target_ulong start;
    target_ulong end;
    struct call_context* alloc_ctx;
    struct call_context* free_ctx;
    struct qasan_chunk* next;
};

static struct qasan_chunk* qasan_chunks;

void asan_giovese_init(void)
{
    assert(mmap(__ag_high_shadow, HIGH_SHADOW_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                0) != MAP_FAILED);
    assert(mmap(__ag_low_shadow, LOW_SHADOW_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                0) != MAP_FAILED);
    assert(mmap(GAP_SHADOW_ADDR, GAP_SHADOW_SIZE, PROT_NONE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                0) != MAP_FAILED);
}

struct chunk_info* asan_giovese_alloc_search(target_ulong query)
{
    struct qasan_chunk* c = qasan_chunks;
    while (c) {
        if (query >= c->start && query < c->end) {
            return (struct chunk_info*)c;
        }
        c = c->next;
    }
    return NULL;
}

void asan_giovese_alloc_insert(target_ulong start, target_ulong end,
                               struct call_context* alloc_ctx)
{
    struct qasan_chunk** pp = &qasan_chunks;
    while (*pp) {
        struct qasan_chunk* c = *pp;
        if (!(end <= c->start || start >= c->end)) {
            *pp = c->next;
            free(c->alloc_ctx);
            free(c->free_ctx);
            free(c);
        } else {
            pp = &c->next;
        }
    }

    struct qasan_chunk* node = calloc(sizeof(struct qasan_chunk), 1);
    node->start = start;
    node->end = end;
    node->alloc_ctx = alloc_ctx;
    node->free_ctx = NULL;
    node->next = qasan_chunks;
    qasan_chunks = node;
}

int asan_giovese_guest_loadN(target_ulong addr, size_t n)
{
    if (!n) {
        return 0;
    }

    target_ulong start = addr;
    target_ulong end = start + n;
    target_ulong last_8 = end & ~7;

    if (start & 0x7) {
        target_ulong next_8 = (start & ~7) + 8;
        size_t first_size = next_8 - start;

        if (n <= first_size) {
            uintptr_t h = QASAN_G2H(start);
            int8_t* shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
            int8_t k = *shadow_addr;
            return k != 0 && ((intptr_t)((h & 7) + n) > k);
        }

        uintptr_t h = QASAN_G2H(start);
        int8_t* shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
        int8_t k = *shadow_addr;
        if (k != 0 && ((intptr_t)((h & 7) + first_size) > k)) {
            return 1;
        }
        start = next_8;
    }

    while (start < last_8) {
        uintptr_t h = QASAN_G2H(start);
        int8_t* shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
        if (*shadow_addr) {
            return 1;
        }
        start += 8;
    }

    if (last_8 != end) {
        uintptr_t h = QASAN_G2H(start);
        size_t last_size = end - last_8;
        int8_t* shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
        int8_t k = *shadow_addr;
        return k != 0 && ((intptr_t)((h & 7) + last_size) > k);
    }

    return 0;
}

int asan_giovese_guest_storeN(target_ulong addr, size_t n)
{
    return asan_giovese_guest_loadN(addr, n);
}

int asan_giovese_poison_guest_region(target_ulong addr, size_t n,
                                     uint8_t poison_byte)
{
    if (!n) {
        return 0;
    }

    target_ulong start = addr;
    target_ulong end = start + n;
    target_ulong last_8 = end & ~7;

    if (start & 0x7) {
        target_ulong next_8 = (start & ~7) + 8;
        size_t first_size = next_8 - start;

        if (n < first_size) {
            return 0;
        }

        uintptr_t h = QASAN_G2H(start);
        uint8_t* shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
        *shadow_addr = 8 - first_size;
        start = next_8;
    }

    while (start < last_8) {
        uintptr_t h = QASAN_G2H(start);
        uint8_t* shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
        *shadow_addr = poison_byte;
        start += 8;
    }

    return 1;
}

int asan_giovese_user_poison_guest_region(target_ulong addr, size_t n)
{
    return asan_giovese_poison_guest_region(addr, n, ASAN_USER);
}

int asan_giovese_unpoison_guest_region(target_ulong addr, size_t n)
{
    target_ulong start = addr;
    target_ulong end = start + n;

    while (start < end) {
        uintptr_t h = QASAN_G2H(start);
        uint8_t* shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
        *shadow_addr = 0;
        start += 8;
    }

    return 1;
}

void asan_giovese_populate_context(struct call_context* ctx, target_ulong pc)
{
    ctx->size = 1;
    ctx->addresses = calloc(1, sizeof(*ctx->addresses));
    if (!ctx->addresses) {
        ctx->size = 0;
        return;
    }
#ifdef __NR_gettid
    ctx->tid = (uint32_t)syscall(__NR_gettid);
#else
    ctx->tid = 0;
#endif
    ctx->addresses[0] = pc;
}

char* asan_giovese_printaddr(target_ulong addr)
{
    (void)addr;
    return NULL;
}

static const char* poisoned_strerror(uint8_t poison_byte)
{
    switch (poison_byte) {
        case ASAN_HEAP_RZ:
        case ASAN_HEAP_LEFT_RZ:
        case ASAN_HEAP_RIGHT_RZ:
            return "heap-buffer-overflow";
        case ASAN_HEAP_FREED:
            return "heap-use-after-free";
    }
    return "use-after-poison";
}

static int poisoned_find_error(target_ulong addr, size_t n,
                               target_ulong* fault_addr,
                               const char** err_string)
{
    target_ulong start = addr;
    target_ulong end = start + n;

    while (start < end) {
        uintptr_t rs = QASAN_G2H(start);
        int8_t* shadow_addr = (int8_t*)(rs >> 3) + SHADOW_OFFSET;
        int8_t v = *shadow_addr;
        if (v < 0 || (uint8_t)v >= 0x08) {
            if (*fault_addr == 0) {
                *fault_addr = start;
            }
            *err_string = poisoned_strerror((uint8_t)v);
            return 1;
        }
        if (v != ASAN_VALID) {
            target_ulong a = (start & ~7) + v;
            if (*fault_addr == 0 && a >= start && a < end) {
                *fault_addr = a;
            }
        }
        start += 8;
    }

    if (*fault_addr == 0) {
        *fault_addr = addr;
    }
    *err_string = "use-after-poison";
    return 1;
}

static const char* access_type_str[] = {"READ", "WRITE"};

static void print_alloc_location(target_ulong addr, target_ulong fault_addr)
{
    struct chunk_info* ckinfo = asan_giovese_alloc_search(fault_addr);
    if (!ckinfo && addr != fault_addr) {
        ckinfo = asan_giovese_alloc_search(addr);
    }
    int i = 0;
    while (!ckinfo && i < 128) {
        ckinfo = asan_giovese_alloc_search(fault_addr - (i++));
    }
    i = 0;
    while (!ckinfo && i < 128) {
        ckinfo = asan_giovese_alloc_search(fault_addr + (i++));
    }

    if (!ckinfo) {
        fprintf(stderr, "Address 0x" TARGET_FMT_lx " is a wild pointer.\n",
                fault_addr);
        return;
    }

    if (fault_addr >= ckinfo->start && fault_addr < ckinfo->end) {
        fprintf(stderr,
                "0x" TARGET_FMT_lx " is located " TARGET_FMT_ld
                " bytes inside of " TARGET_FMT_ld "-byte region [0x"
                TARGET_FMT_lx ",0x" TARGET_FMT_lx ")\n",
                fault_addr, fault_addr - ckinfo->start,
                ckinfo->end - ckinfo->start, ckinfo->start, ckinfo->end);
    } else if (ckinfo->start >= fault_addr) {
        fprintf(stderr,
                "0x" TARGET_FMT_lx " is located " TARGET_FMT_ld
                " bytes to the left of " TARGET_FMT_ld "-byte region [0x"
                TARGET_FMT_lx ",0x" TARGET_FMT_lx ")\n",
                fault_addr, ckinfo->start - fault_addr,
                ckinfo->end - ckinfo->start, ckinfo->start, ckinfo->end);
    } else {
        fprintf(stderr,
                "0x" TARGET_FMT_lx " is located " TARGET_FMT_ld
                " bytes to the right of " TARGET_FMT_ld "-byte region [0x"
                TARGET_FMT_lx ",0x" TARGET_FMT_lx ")\n",
                fault_addr, fault_addr - ckinfo->end,
                ckinfo->end - ckinfo->start, ckinfo->start, ckinfo->end);
    }

    if (ckinfo->free_ctx) {
        fprintf(stderr, "freed by thread T%d here:\n", ckinfo->free_ctx->tid);
    } else if (ckinfo->alloc_ctx) {
        fprintf(stderr, "allocated by thread T%d here:\n",
                ckinfo->alloc_ctx->tid);
    }
}

int asan_giovese_report_and_crash(int access_type, target_ulong addr, size_t n,
                                  CPUArchState* env)
{
    target_ulong pc = QASAN_PC_GET(env);
    target_ulong bp = QASAN_BP_GET(env);
    target_ulong sp = QASAN_SP_GET(env);
    struct call_context ctx = {0};
    asan_giovese_populate_context(&ctx, pc);
    target_ulong fault_addr = 0;
    const char* error_type;

    if (!poisoned_find_error(addr, n, &fault_addr, &error_type)) {
        free(ctx.addresses);
        return 0;
    }

    fprintf(stderr,
            "=================================================================\n"
            "==%d==ERROR: " ASAN_NAME_STR ": %s on address 0x" TARGET_FMT_lx
            " at pc 0x" TARGET_FMT_lx " bp 0x" TARGET_FMT_lx " sp 0x"
            TARGET_FMT_lx "\n",
            getpid(), error_type, addr, pc, bp, sp);

    fprintf(stderr, "%s of size %zu at 0x" TARGET_FMT_lx " thread T%d\n",
            access_type_str[access_type], n, addr, ctx.tid);

    print_alloc_location(addr, fault_addr);

    fprintf(stderr, "SUMMARY: " ASAN_NAME_STR ": %s\n", error_type);
    fprintf(stderr, "==%d==ABORTING\n", getpid());

    free(ctx.addresses);

    signal(SIGABRT, SIG_DFL);
    abort();

    return 0;
}

int asan_giovese_badfree(target_ulong addr, target_ulong pc)
{
    fprintf(stderr,
            "=================================================================\n"
            "==%d==ERROR: " ASAN_NAME_STR
            ": attempting free on address which was not malloc()-ed: 0x"
            TARGET_FMT_lx "\n",
            getpid(), addr);
    (void)pc;
    fprintf(stderr, "SUMMARY: " ASAN_NAME_STR ": bad-free\n");
    fprintf(stderr, "==%d==ABORTING\n", getpid());
    signal(SIGABRT, SIG_DFL);
    abort();
    return 0;
}

static target_long qasan_actions_dispatcher(CPUArchState* env,
                                            target_long action,
                                            target_long arg1, target_long arg2,
                                            target_long arg3)
{
    switch (action) {
        case QASAN_ACTION_CHECK_LOAD:
            if (asan_giovese_guest_loadN(arg1, arg2)) {
                asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, arg1, arg2, env);
            }
            break;

        case QASAN_ACTION_CHECK_STORE:
            if (asan_giovese_guest_storeN(arg1, arg2)) {
                asan_giovese_report_and_crash(ACCESS_TYPE_STORE, arg1, arg2,
                                              env);
            }
            break;

        case QASAN_ACTION_POISON:
            asan_giovese_poison_guest_region(arg1, arg2, arg3);
            break;

        case QASAN_ACTION_USER_POISON:
            asan_giovese_user_poison_guest_region(arg1, arg2);
            break;

        case QASAN_ACTION_UNPOISON:
            asan_giovese_unpoison_guest_region(arg1, arg2);
            break;

        case QASAN_ACTION_IS_POISON:
            return asan_giovese_guest_loadN(arg1, arg2);

        case QASAN_ACTION_ALLOC: {
            struct call_context* ctx = calloc(sizeof(struct call_context), 1);
            asan_giovese_populate_context(ctx, QASAN_PC_GET(env));
            asan_giovese_alloc_insert(arg1, arg2, ctx);
            break;
        }

        case QASAN_ACTION_DEALLOC: {
            struct chunk_info* ckinfo = asan_giovese_alloc_search(arg1);
            if (ckinfo) {
                if (ckinfo->start != (target_ulong)arg1) {
                    asan_giovese_badfree(arg1, QASAN_PC_GET(env));
                }
                ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
                asan_giovese_populate_context(ckinfo->free_ctx,
                                              QASAN_PC_GET(env));
            } else {
                asan_giovese_badfree(arg1, QASAN_PC_GET(env));
            }
            break;
        }

        case QASAN_ACTION_ENABLE:
            qasan_disabled = 0;
            break;

        case QASAN_ACTION_DISABLE:
            qasan_disabled = 1;
            break;

        case QASAN_ACTION_SWAP_STATE: {
            int r = qasan_disabled;
            qasan_disabled = arg1;
            return r;
        }

        default:
            fprintf(stderr, "Invalid QASAN action " TARGET_FMT_ld "\n", action);
            abort();
    }

    return 0;
}

static struct libafl_syshook_ret afl_qasan_syscall_hook(
    uint64_t data, int* sys_num, target_ulong* arg0, target_ulong* arg1,
    target_ulong* arg2, target_ulong* arg3, target_ulong* arg4,
    target_ulong* arg5, target_ulong* arg6, target_ulong* arg7)
{
    (void)data;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    (void)arg7;

    struct libafl_syshook_ret ret = {.tag = LIBAFL_SYSHOOK_RUN};

    if ((uint32_t)*sys_num != QASAN_FAKESYS_NR) {
        return ret;
    }

    CPUState* cpu = libafl_qemu_current_cpu();
    if (!cpu) {
        return ret;
    }
    CPUArchState* env = cpu_env(cpu);

    target_long r = qasan_actions_dispatcher(env, (target_long)*arg0,
                                             (target_long)*arg1,
                                             (target_long)*arg2,
                                             (target_long)*arg3);

    ret.tag = LIBAFL_SYSHOOK_SKIP;
    ret.syshook_skip_retval = (target_ulong)r;
    return ret;
}

static void afl_qasan_check_load(uint64_t data, uint64_t id, vaddr pc,
                                 vaddr addr, size_t size)
{
    (void)data;
    (void)id;
    if (qasan_disabled) {
        return;
    }
    if (asan_giovese_guest_loadN((target_ulong)addr, size)) {
        CPUState* cpu = libafl_qemu_current_cpu();
        if (cpu) {
            asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, (target_ulong)addr,
                                          size, cpu_env(cpu));
        }
    }
    (void)pc;
}

static void afl_qasan_check_store(uint64_t data, uint64_t id, vaddr pc,
                                  vaddr addr, size_t size)
{
    (void)data;
    (void)id;
    if (qasan_disabled) {
        return;
    }
    if (asan_giovese_guest_storeN((target_ulong)addr, size)) {
        CPUState* cpu = libafl_qemu_current_cpu();
        if (cpu) {
            asan_giovese_report_and_crash(ACCESS_TYPE_STORE, (target_ulong)addr,
                                          size, cpu_env(cpu));
        }
    }
    (void)pc;
}

static uint64_t afl_qasan_rw_gen(uint64_t data, vaddr pc, TCGTemp* addr,
                                 MemOpIdx oi)
{
    (void)data;
    (void)pc;
    (void)addr;
    (void)oi;
    return 0;
}

void afl_qasan_init(void)
{
    if (!getenv("AFL_USE_QASAN")) {
        return;
    }

    asan_giovese_init();

    libafl_add_pre_syscall_hook(afl_qasan_syscall_hook, 0);

    libafl_add_read_hook(afl_qasan_rw_gen, NULL, NULL, NULL, NULL,
                         afl_qasan_check_load, 0);
    libafl_add_write_hook(afl_qasan_rw_gen, NULL, NULL, NULL, NULL,
                          afl_qasan_check_store, 0);
}

#endif
