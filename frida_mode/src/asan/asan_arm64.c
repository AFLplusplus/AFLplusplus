#include <dlfcn.h>
#include "frida-gumjs.h"

#include "asan.h"
#include "ctx.h"
#include "util.h"

#if defined(__aarch64__)

typedef struct {

  size_t      size;
  cs_arm64_op operand;

} asan_ctx_t;

typedef void (*asan_loadN_t)(gsize address, uint8_t size);
typedef void (*asan_storeN_t)(gsize address, uint8_t size);

asan_loadN_t  asan_loadN = NULL;
asan_storeN_t asan_storeN = NULL;

static void asan_callout(GumCpuContext *ctx, gpointer user_data) {

  asan_ctx_t   *asan_ctx = (asan_ctx_t *)user_data;
  cs_arm64_op  *operand = &asan_ctx->operand;
  arm64_op_mem *mem = &operand->mem;
  gsize         base = 0;
  gsize         index = 0;
  gsize         address;

  if (mem->base != ARM64_REG_INVALID) { base = ctx_read_reg(ctx, mem->base); }

  if (mem->index != ARM64_REG_INVALID) {

    index = ctx_read_reg(ctx, mem->index);

  }

  address = base + index + mem->disp;

  if ((operand->access & CS_AC_WRITE) == CS_AC_WRITE) {

    asan_storeN(address, asan_ctx->size);

  }

  if ((operand->access & CS_AC_READ) == CS_AC_READ) {

    asan_loadN(address, asan_ctx->size);

  }

}

void asan_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  UNUSED_PARAMETER(iterator);

  cs_arm64     arm64 = instr->detail->arm64;
  cs_arm64_op *operand;
  asan_ctx_t  *ctx;

  if (!asan_initialized) return;

  for (uint8_t i = 0; i < arm64.op_count; i++) {

    operand = &arm64.operands[i];

    if (operand->type != ARM64_OP_MEM) { continue; }

    ctx = g_malloc0(sizeof(asan_ctx_t));
    ctx->size = ctx_get_size(instr, &arm64.operands[0]);
    memcpy(&ctx->operand, operand, sizeof(cs_arm64_op));
    gum_stalker_iterator_put_callout(iterator, asan_callout, ctx, g_free);

  }

}

void asan_arch_init(void) {

  asan_loadN = (asan_loadN_t)dlsym(RTLD_DEFAULT, "__asan_loadN");
  asan_storeN = (asan_loadN_t)dlsym(RTLD_DEFAULT, "__asan_storeN");
  if (asan_loadN == NULL || asan_storeN == NULL) {

    FFATAL("Frida ASAN failed to find '__asan_loadN' or '__asan_storeN'");

  }

  asan_exclude_module_by_symbol("__asan_loadN");

}

#endif

