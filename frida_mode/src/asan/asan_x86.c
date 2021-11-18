#include <dlfcn.h>
#include "frida-gumjs.h"

#include "asan.h"
#include "ctx.h"
#include "util.h"

#if defined(__i386__)

typedef void (*asan_loadN_t)(gsize address, uint8_t size);
typedef void (*asan_storeN_t)(gsize address, uint8_t size);

asan_loadN_t  asan_loadN = NULL;
asan_storeN_t asan_storeN = NULL;

static void asan_callout(GumCpuContext *ctx, gpointer user_data) {

  UNUSED_PARAMETER(user_data);

  cs_x86_op * operand = (cs_x86_op *)user_data;
  x86_op_mem *mem = &operand->mem;
  gsize       base = 0;
  gsize       index = 0;
  gsize       address;
  uint8_t     size;

  if (mem->base != X86_REG_INVALID) { base = ctx_read_reg(ctx, mem->base); }

  if (mem->index != X86_REG_INVALID) { index = ctx_read_reg(ctx, mem->index); }

  address = base + (mem->scale * index) + mem->disp;
  size = operand->size;

  if (operand->access == CS_AC_READ) {

    asan_loadN(address, size);

  } else if (operand->access == CS_AC_WRITE) {

    asan_storeN(address, size);

  }

}

void asan_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  UNUSED_PARAMETER(iterator);

  cs_x86      x86 = instr->detail->x86;
  cs_x86_op * operand;
  x86_op_mem *mem;
  cs_x86_op * ctx;

  if (!asan_initialized) return;

  if (instr->id == X86_INS_LEA) return;

  if (instr->id == X86_INS_NOP) return;

  for (uint8_t i = 0; i < x86.op_count; i++) {

    operand = &x86.operands[i];

    if (operand->type != X86_OP_MEM) { continue; }

    mem = &operand->mem;
    if (mem->segment != X86_REG_INVALID) { continue; }

    ctx = g_malloc0(sizeof(cs_x86_op));
    memcpy(ctx, operand, sizeof(cs_x86_op));
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

