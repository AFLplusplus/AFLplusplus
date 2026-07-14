#include "qemu/osdep.h"

#include "accel/tcg/tb-cpu-state.h"
#include "exec/translation-block.h"

#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/afl_tsl.h"

#include <unistd.h>

int afl_fork_child;

void afl_request_tsl(TCGTBCPUState s)
{
    struct afl_tsl t;

    t.is_chain = 0;
    t.pc = s.pc;
    t.cs_base = s.cs_base;
    t.flags = s.flags;
    t.cflags = s.cflags;
    if (write(AFL_TSL_FD, &t, sizeof(t)) != sizeof(t)) {
        return;
    }
}

void afl_request_tsl_chain(TranslationBlock *last_tb, TCGTBCPUState s,
                           int tb_exit)
{
    struct afl_tsl t;

    t.is_chain = 1;
    t.pc = s.pc;
    t.cs_base = s.cs_base;
    t.flags = s.flags;
    t.cflags = s.cflags;
    t.last_pc = last_tb->pc;
    t.last_cs_base = last_tb->cs_base;
    t.last_flags = last_tb->flags;
    t.last_cflags = last_tb->cflags;
    t.tb_exit = tb_exit;
    if (write(AFL_TSL_FD, &t, sizeof(t)) != sizeof(t)) {
        return;
    }
}
