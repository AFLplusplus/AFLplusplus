#ifndef _CTX_H
#define _CTX_H

#include "frida-gum.h"

#if defined(__x86_64__) || defined(__i386__)
gsize ctx_read_reg(GumCpuContext *ctx, x86_reg reg);
#endif

#endif

