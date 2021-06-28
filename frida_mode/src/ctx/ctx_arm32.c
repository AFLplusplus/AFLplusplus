#include "frida-gumjs.h"

#include "debug.h"

#include "ctx.h"

#if defined(__arm__)

gsize ctx_read_reg(GumIA32CpuContext *ctx, x86_reg reg) {

  FATAL("ctx_read_reg unimplemented for this architecture");

}

#endif

