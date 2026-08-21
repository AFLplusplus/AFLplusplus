#include "qemu/osdep.h"
#include "qemu.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "exec/page-protection.h"
#include "libafl/cpu.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/imported/config.h"
#include "libaflqemubridge/imported/types.h"
#include "libaflqemubridge/imported/cmplog.h"
#include "libafl/hooks/tcg/cmp.h"
#include "libafl/hooks/tcg/block.h"

#ifdef CONFIG_AFL

#include <sys/shm.h>

struct cmp_map *__afl_cmp_map = NULL;

#if defined(TARGET_X86_64)
#define AFL_RTN_REG_ARG1 5
#define AFL_RTN_REG_ARG2 4
#define AFL_RTN_SUPPORTED 1
#else
#define AFL_RTN_SUPPORTED 0
#endif

static uint64_t afl_cmplog_gen(uint64_t data, vaddr pc, size_t size)
{
    (void)data;
    (void)size;
    if (!afl_range_is_instrumented(pc)) {
        return (uint64_t)-1;
    }
    return (uint64_t)pc;
}

static uint32_t __afl_cmp_cursor[CMP_MAP_W];

static inline void afl_cmplog_ins(uint64_t id, uint8_t shape, uint64_t v0,
                                  uint64_t v1)
{
    uint32_t k = cmp_map_select(__afl_cmp_map, id);
    if (k == CMP_MAP_W) {
        return;
    }

    if (__afl_cmp_map->headers[k].hits &&
        __afl_cmp_map->headers[k].type != CMP_TYPE_INS) {
        return;
    }
    if (__afl_cmp_map->headers[k].type != CMP_TYPE_INS) {
        __afl_cmp_map->headers[k].hits = 0;
    }

    if (__afl_cmp_map->headers[k].hits == 0) {
        __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
        __afl_cmp_map->headers[k].shape = shape;
        cmp_map_set_attribute(__afl_cmp_map, k, CMP_ATTR_NONE);
    }

    uint32_t occurrence;
    uint32_t hits =
        cmp_map_reserve(&__afl_cmp_map->headers[k], &__afl_cmp_cursor[k],
                        CMP_MAP_H, &occurrence);
    __afl_cmp_map->log[k][hits].v0 = v0;
    __afl_cmp_map->log[k][hits].v1 = v1;
    __afl_cmp_map->log[k][hits].occurrence = occurrence;
}

static void afl_cmplog_exec1(uint64_t data, uint64_t id, uint8_t v0,
                             uint8_t v1)
{
    (void)data;
    afl_cmplog_ins(id, 0, v0, v1);
}

static void afl_cmplog_exec2(uint64_t data, uint64_t id, uint16_t v0,
                             uint16_t v1)
{
    (void)data;
    afl_cmplog_ins(id, 1, v0, v1);
}

static void afl_cmplog_exec4(uint64_t data, uint64_t id, uint32_t v0,
                             uint32_t v1)
{
    (void)data;
    afl_cmplog_ins(id, 3, v0, v1);
}

static void afl_cmplog_exec8(uint64_t data, uint64_t id, uint64_t v0,
                             uint64_t v1)
{
    (void)data;
    afl_cmplog_ins(id, 7, v0, v1);
}

#if AFL_RTN_SUPPORTED
static int afl_rtn_read_ptr(CPUState *cpu, int reg, uint64_t *out)
{
    uint8_t buf[32] = {0};
    int n = libafl_qemu_read_reg(cpu, reg, buf);
    if (n <= 0) {
        return 0;
    }
    uint64_t v = 0;
    memcpy(&v, buf, n > 8 ? 8 : n);
    *out = v;
    return 1;
}

static int afl_rtn_ptr_ok(uint64_t addr)
{
    if (!addr) {
        return 0;
    }
    if (!guest_addr_valid_untagged(addr)) {
        return 0;
    }
    if (!guest_range_valid_untagged(addr, 0x20)) {
        return 0;
    }
    if (!page_check_range((vaddr)addr, 0x20, PAGE_READ)) {
        return 0;
    }
    return 1;
}
#endif

#if AFL_RTN_SUPPORTED
static void afl_cmplog_rtn_exec(uint64_t data, uint64_t id)
{
    (void)data;
    CPUState *cpu = libafl_qemu_current_cpu();
    if (!cpu) {
        return;
    }

    uint64_t arg1 = 0;
    uint64_t arg2 = 0;
    if (!afl_rtn_read_ptr(cpu, AFL_RTN_REG_ARG1, &arg1) ||
        !afl_rtn_read_ptr(cpu, AFL_RTN_REG_ARG2, &arg2)) {
        return;
    }

    if (!afl_rtn_ptr_ok(arg1) || !afl_rtn_ptr_ok(arg2)) {
        return;
    }

    void *ptr1 = g2h(cpu, arg1);
    void *ptr2 = g2h(cpu, arg2);

    uint32_t k = cmp_map_select(__afl_cmp_map, id);
    if (k == CMP_MAP_W) {
        return;
    }

    if (__afl_cmp_map->headers[k].hits &&
        __afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {
        return;
    }
    if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) {
        __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;
        __afl_cmp_map->headers[k].hits = 0;
        __afl_cmp_map->headers[k].shape = 30;
        cmp_map_set_attribute(__afl_cmp_map, k, CMP_ATTR_NONE);
    }

    uint32_t occurrence;
    uint32_t hits =
        cmp_map_reserve(&__afl_cmp_map->headers[k], &__afl_cmp_cursor[k],
                        CMP_MAP_RTN_H, &occurrence);
    struct cmpfn_operands *op =
        &((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits];
    memset(op, 0, sizeof(*op));
    op->v0_len = 31;
    op->v1_len = 31;
    op->occurrence = occurrence;
    memcpy(op->v0, ptr1, 31);
    memcpy(op->v1, ptr2, 31);
}

static uint64_t afl_cmplog_rtn_gen(uint64_t data, vaddr pc)
{
    (void)data;
    if (!afl_range_is_instrumented(pc)) {
        return (uint64_t)-1;
    }
    return (uint64_t)pc;
}
#endif

int afl_cmplog_is_active(void)
{
    return __afl_cmp_map != NULL;
}

void afl_cmplog_reset_cursor(void)
{
    if (__afl_cmp_map == NULL) {
        return;
    }
    memset(__afl_cmp_cursor, 0, sizeof(__afl_cmp_cursor));
}

void afl_cmplog_init(void)
{
    if (!getenv("___AFL_EINS_ZWEI_POLIZEI___")) {
        return;
    }

    char *id_str = getenv(CMPLOG_SHM_ENV_VAR);
    if (!id_str) {
        return;
    }

    int shm_id = atoi(id_str);
    __afl_cmp_map = shmat(shm_id, NULL, 0);
    if (__afl_cmp_map == (void *)-1) {
        perror("shmat __AFL_CMPLOG_SHM_ID");
        __afl_cmp_map = NULL;
        _exit(1);
    }

    libafl_add_cmp_hook(afl_cmplog_gen, afl_cmplog_exec1, afl_cmplog_exec2,
                        afl_cmplog_exec4, afl_cmplog_exec8, 0);

#if AFL_RTN_SUPPORTED
    if (!getenv("AFL_QEMU_CMPLOG_NO_RTN")) {
        libafl_add_block_hook(afl_cmplog_rtn_gen, NULL, afl_cmplog_rtn_exec, 0);
    }
#endif
}

#endif
