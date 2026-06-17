#ifndef LIBAFL_AFL_TSL_H
#define LIBAFL_AFL_TSL_H

#ifdef CONFIG_AFL

#include <stdint.h>

#include "accel/tcg/tb-cpu-state.h"
#include "exec/translation-block.h"

struct afl_tsl {
    uint8_t is_chain;
    uint64_t pc;
    uint64_t cs_base;
    uint32_t flags;
    uint32_t cflags;
    uint64_t last_pc;
    uint64_t last_cs_base;
    uint32_t last_flags;
    uint32_t last_cflags;
    int32_t tb_exit;
};

void afl_request_tsl(TCGTBCPUState s);
void afl_request_tsl_chain(TranslationBlock *last_tb, TCGTBCPUState s,
                           int tb_exit);

#endif
#endif
