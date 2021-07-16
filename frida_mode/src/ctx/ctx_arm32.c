#include "frida-gumjs.h"

#include "debug.h"

#include "ctx.h"

#if defined(__arm__)

gsize ctx_read_reg(GumArmCpuContext *ctx, arm_reg reg) {

  FATAL("ctx_read_reg unimplemented for this architecture");

}

#endif

