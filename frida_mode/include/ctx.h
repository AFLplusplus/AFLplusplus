#ifndef _CTX_H
#define _CTX_H

#include "frida-gumjs.h"

#if defined(__x86_64__)
gsize ctx_read_reg(GumX64CpuContext *ctx, x86_reg reg);
#elif defined(__i386__)
gsize ctx_read_reg(GumIA32CpuContext *ctx, x86_reg reg);
#elif defined(__aarch64__)
gsize  ctx_read_reg(GumArm64CpuContext *ctx, arm64_reg reg);
size_t ctx_get_size(const cs_insn *instr, cs_arm64_op *operand);
#elif defined(__arm__)
gsize ctx_read_reg(GumArmCpuContext *ctx, arm_reg reg);
#endif

#endif

