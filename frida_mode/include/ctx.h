#ifndef _CTX_H
#define _CTX_H

#include "frida-gum.h"

#if defined(__x86_64__)
guint64 ctx_read_reg(GumX64CpuContext *ctx, x86_reg reg);
#endif

#endif

