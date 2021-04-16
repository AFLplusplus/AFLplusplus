#include "frida-gum.h"

#include "debug.h"
#include "cmplog.h"

#include "complog.h"

#if defined(__x86_64__)

typedef struct {

  x86_op_type type;
  uint8_t     size;

  union {

    x86_op_mem mem;
    x86_reg    reg;
    int64_t    imm;

  };

} complog_ctx_t;

typedef struct {

  complog_ctx_t operand1;
  complog_ctx_t operand2;

} complog_pair_ctx_t;

static guint64 complog_read_reg(GumX64CpuContext *ctx, x86_reg reg) {

  switch (reg) {

    case X86_REG_EAX:
      return ctx->rax & GUM_INT32_MASK;

    case X86_REG_ECX:
      return ctx->rcx & GUM_INT32_MASK;

    case X86_REG_EDX:
      return ctx->rdx & GUM_INT32_MASK;

    case X86_REG_EBX:
      return ctx->rbx & GUM_INT32_MASK;

    case X86_REG_ESP:
      return ctx->rsp & GUM_INT32_MASK;

    case X86_REG_EBP:
      return ctx->rbp & GUM_INT32_MASK;

    case X86_REG_ESI:
      return ctx->rsi & GUM_INT32_MASK;

    case X86_REG_EDI:
      return ctx->rdi & GUM_INT32_MASK;

    case X86_REG_R8D:
      return ctx->r8 & GUM_INT32_MASK;

    case X86_REG_R9D:
      return ctx->r9 & GUM_INT32_MASK;

    case X86_REG_R10D:
      return ctx->r10 & GUM_INT32_MASK;

    case X86_REG_R11D:
      return ctx->r11 & GUM_INT32_MASK;

    case X86_REG_R12D:
      return ctx->r12 & GUM_INT32_MASK;

    case X86_REG_R13D:
      return ctx->r13 & GUM_INT32_MASK;

    case X86_REG_R14D:
      return ctx->r14 & GUM_INT32_MASK;

    case X86_REG_R15D:
      return ctx->r15 & GUM_INT32_MASK;

    case X86_REG_EIP:
      return ctx->rip & GUM_INT32_MASK;

    case X86_REG_RAX:
      return ctx->rax;

    case X86_REG_RCX:
      return ctx->rcx;

    case X86_REG_RDX:
      return ctx->rdx;

    case X86_REG_RBX:
      return ctx->rbx;

    case X86_REG_RSP:
      return ctx->rsp;

    case X86_REG_RBP:
      return ctx->rbp;

    case X86_REG_RSI:
      return ctx->rsi;

    case X86_REG_RDI:
      return ctx->rdi;

    case X86_REG_R8:
      return ctx->r8;

    case X86_REG_R9:
      return ctx->r9;

    case X86_REG_R10:
      return ctx->r10;

    case X86_REG_R11:
      return ctx->r11;

    case X86_REG_R12:
      return ctx->r12;

    case X86_REG_R13:
      return ctx->r13;

    case X86_REG_R14:
      return ctx->r14;

    case X86_REG_R15:
      return ctx->r15;

    case X86_REG_RIP:
      return ctx->rip;

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

static guint64 complog_read_mem(GumX64CpuContext *ctx, x86_op_mem *mem) {

  guint64 base = 0;
  guint64 index = 0;
  guint64 address;

  if (mem->base != X86_REG_INVALID) base = complog_read_reg(ctx, mem->base);

  if (mem->index != X86_REG_INVALID) index = complog_read_reg(ctx, mem->index);

  address = base + (index * mem->scale) + mem->disp;
  return address;

}

static void complog_handle_call(GumCpuContext *context, guint64 target) {

  guint64 address = complog_read_reg(context, X86_REG_RIP);
  guint64 rdi = complog_read_reg(context, X86_REG_RDI);
  guint64 rsi = complog_read_reg(context, X86_REG_RSI);

  void *ptr1 = GSIZE_TO_POINTER(rdi);
  void *ptr2 = GSIZE_TO_POINTER(rsi);

  if (!complog_is_readable(ptr1, 32) || !complog_is_readable(ptr2, 32)) return;

  uintptr_t k = address;

  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 31;

  hits &= CMP_MAP_RTN_H - 1;
  gum_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v0, ptr1,
             32);
  gum_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v1, ptr2,
             32);

}

static guint64 cmplog_get_operand_value(GumCpuContext *context,
                                        complog_ctx_t *ctx) {

  switch (ctx->type) {

    case X86_OP_REG:
      return complog_read_reg(context, ctx->reg);
    case X86_OP_IMM:
      return ctx->imm;
    case X86_OP_MEM:
      return complog_read_mem(context, &ctx->mem);
    default:
      FATAL("Invalid operand type: %d\n", ctx->type);

  }

}

static void complog_call_callout(GumCpuContext *context, gpointer user_data) {

  complog_ctx_t *ctx = (complog_ctx_t *)user_data;

  guint64 target = cmplog_get_operand_value(context, ctx);
  complog_handle_call(context, target);

}

static void complog_instrument_put_operand(complog_ctx_t *ctx,
                                           cs_x86_op *    operand) {

  ctx->type = operand->type;
  ctx->size = operand->size;
  switch (operand->type) {

    case X86_OP_REG:
      gum_memcpy(&ctx->reg, &operand->reg, sizeof(x86_reg));
      break;
    case X86_OP_IMM:
      gum_memcpy(&ctx->imm, &operand->imm, sizeof(int64_t));
      break;
    case X86_OP_MEM:
      gum_memcpy(&ctx->mem, &operand->mem, sizeof(x86_op_mem));
      break;
    default:
      FATAL("Invalid operand type: %d\n", operand->type);

  }

}

static void complog_instrument_call_put_callout(GumStalkerIterator *iterator,
                                                cs_x86_op *         operand) {

  complog_ctx_t *ctx = g_malloc(sizeof(complog_ctx_t));
  complog_instrument_put_operand(ctx, operand);

  gum_stalker_iterator_put_callout(iterator, complog_call_callout, ctx, g_free);

}

static void complog_instrument_call(const cs_insn *     instr,
                                    GumStalkerIterator *iterator) {

  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand;

  if (instr->id != X86_INS_CALL) return;

  if (x86.op_count != 1) return;

  operand = &x86.operands[0];

  if (operand->type == X86_OP_INVALID) return;
  if (operand->type == X86_OP_MEM && operand->mem.segment != X86_REG_INVALID)
    return;

  complog_instrument_call_put_callout(iterator, operand);

}

static void complog_handle_cmp_sub(GumCpuContext *context, guint64 operand1,
                                   guint64 operand2, uint8_t size) {

  guint64 address = complog_read_reg(context, X86_REG_RIP);

  register uintptr_t k = (uintptr_t)address;

  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = (size - 1);

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = operand1;
  __afl_cmp_map->log[k][hits].v1 = operand2;

}

static void complog_cmp_sub_callout(GumCpuContext *context,
                                    gpointer       user_data) {

  complog_pair_ctx_t *ctx = (complog_pair_ctx_t *)user_data;

  if (ctx->operand1.size != ctx->operand2.size) FATAL("Operand size mismatch");

  guint64 operand1 = cmplog_get_operand_value(context, &ctx->operand1);
  guint64 operand2 = cmplog_get_operand_value(context, &ctx->operand2);

  complog_handle_cmp_sub(context, operand1, operand2, ctx->operand1.size);

}

static void complog_instrument_cmp_sub_put_callout(GumStalkerIterator *iterator,
                                                   cs_x86_op *         operand1,
                                                   cs_x86_op *operand2) {

  complog_pair_ctx_t *ctx = g_malloc(sizeof(complog_pair_ctx_t));
  complog_instrument_put_operand(&ctx->operand1, operand1);
  complog_instrument_put_operand(&ctx->operand2, operand2);

  gum_stalker_iterator_put_callout(iterator, complog_cmp_sub_callout, ctx,
                                   g_free);

}

static void complog_instrument_cmp_sub(const cs_insn *     instr,
                                       GumStalkerIterator *iterator) {

  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand1;
  cs_x86_op *operand2;

  switch (instr->id) {

    case X86_INS_CMP:
    case X86_INS_SUB:
      break;
    default:
      return;

  }

  if (x86.op_count != 2) return;

  operand1 = &x86.operands[0];
  operand2 = &x86.operands[1];

  if (operand1->type == X86_OP_INVALID) return;
  if (operand2->type == X86_OP_INVALID) return;

  if (operand1->type == X86_OP_MEM && operand1->mem.segment != X86_REG_INVALID)
    return;

  if (operand2->type == X86_OP_MEM && operand2->mem.segment != X86_REG_INVALID)
    return;

  complog_instrument_cmp_sub_put_callout(iterator, operand1, operand2);

}

void complog_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  if (__afl_cmp_map == NULL) return;

  complog_instrument_call(instr, iterator);
  complog_instrument_cmp_sub(instr, iterator);

}

#endif

