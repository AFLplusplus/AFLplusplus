#include "frida-gum.h"

#include "debug.h"
#include "cmplog.h"

#include "frida_cmplog.h"
#include "util.h"

#if defined(__x86_64__)

  #define X86_REG_8L(LABEL, REG)  \
    case LABEL: {                 \
                                  \
      return REG & GUM_INT8_MASK; \
                                  \
    }

  #define X86_REG_8H(LABEL, REG)          \
    case LABEL: {                         \
                                          \
      return (REG & GUM_INT16_MASK) >> 8; \
                                          \
    }

  #define X86_REG_16(LABEL, REG)     \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT16_MASK); \
                                     \
    }

  #define X86_REG_32(LABEL, REG)     \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT32_MASK); \
                                     \
    }

  #define X86_REG_64(LABEL, REG) \
    case LABEL: {                \
                                 \
      return (REG);              \
                                 \
    }

typedef struct {

  x86_op_type type;
  uint8_t     size;

  union {

    x86_op_mem mem;
    x86_reg    reg;
    int64_t    imm;

  };

} cmplog_ctx_t;

typedef struct {

  cmplog_ctx_t operand1;
  cmplog_ctx_t operand2;

} cmplog_pair_ctx_t;

static guint64 cmplog_read_reg(GumX64CpuContext *ctx, x86_reg reg) {

  switch (reg) {

    X86_REG_8L(X86_REG_AL, ctx->rax)
    X86_REG_8L(X86_REG_BL, ctx->rbx)
    X86_REG_8L(X86_REG_CL, ctx->rcx)
    X86_REG_8L(X86_REG_DL, ctx->rdx)
    X86_REG_8L(X86_REG_BPL, ctx->rbp)
    X86_REG_8L(X86_REG_SIL, ctx->rsi)
    X86_REG_8L(X86_REG_DIL, ctx->rdi)

    X86_REG_8H(X86_REG_AH, ctx->rax)
    X86_REG_8H(X86_REG_BH, ctx->rbx)
    X86_REG_8H(X86_REG_CH, ctx->rcx)
    X86_REG_8H(X86_REG_DH, ctx->rdx)

    X86_REG_16(X86_REG_AX, ctx->rax)
    X86_REG_16(X86_REG_BX, ctx->rbx)
    X86_REG_16(X86_REG_CX, ctx->rcx)
    X86_REG_16(X86_REG_DX, ctx->rdx)
    X86_REG_16(X86_REG_DI, ctx->rdi)
    X86_REG_16(X86_REG_SI, ctx->rsi)
    X86_REG_16(X86_REG_BP, ctx->rbp)

    X86_REG_32(X86_REG_EAX, ctx->rax)
    X86_REG_32(X86_REG_ECX, ctx->rcx)
    X86_REG_32(X86_REG_EDX, ctx->rdx)
    X86_REG_32(X86_REG_EBX, ctx->rbx)
    X86_REG_32(X86_REG_ESP, ctx->rsp)
    X86_REG_32(X86_REG_EBP, ctx->rbp)
    X86_REG_32(X86_REG_ESI, ctx->rsi)
    X86_REG_32(X86_REG_EDI, ctx->rdi)
    X86_REG_32(X86_REG_R8D, ctx->r8)
    X86_REG_32(X86_REG_R9D, ctx->r9)
    X86_REG_32(X86_REG_R10D, ctx->r10)
    X86_REG_32(X86_REG_R11D, ctx->r11)
    X86_REG_32(X86_REG_R12D, ctx->r12)
    X86_REG_32(X86_REG_R13D, ctx->r13)
    X86_REG_32(X86_REG_R14D, ctx->r14)
    X86_REG_32(X86_REG_R15D, ctx->r15)
    X86_REG_32(X86_REG_EIP, ctx->rip)

    X86_REG_64(X86_REG_RAX, ctx->rax)
    X86_REG_64(X86_REG_RCX, ctx->rcx)
    X86_REG_64(X86_REG_RDX, ctx->rdx)
    X86_REG_64(X86_REG_RBX, ctx->rbx)
    X86_REG_64(X86_REG_RSP, ctx->rsp)
    X86_REG_64(X86_REG_RBP, ctx->rbp)
    X86_REG_64(X86_REG_RSI, ctx->rsi)
    X86_REG_64(X86_REG_RDI, ctx->rdi)
    X86_REG_64(X86_REG_R8, ctx->r8)
    X86_REG_64(X86_REG_R9, ctx->r9)
    X86_REG_64(X86_REG_R10, ctx->r10)
    X86_REG_64(X86_REG_R11, ctx->r11)
    X86_REG_64(X86_REG_R12, ctx->r12)
    X86_REG_64(X86_REG_R13, ctx->r13)
    X86_REG_64(X86_REG_R14, ctx->r14)
    X86_REG_64(X86_REG_R15, ctx->r15)
    X86_REG_64(X86_REG_RIP, ctx->rip)

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

static gboolean cmplog_read_mem(GumX64CpuContext *ctx, uint8_t size,
                                x86_op_mem *mem, guint64 *val) {

  guint64 base = 0;
  guint64 index = 0;
  guint64 address;

  if (mem->base != X86_REG_INVALID) base = cmplog_read_reg(ctx, mem->base);

  if (mem->index != X86_REG_INVALID) index = cmplog_read_reg(ctx, mem->index);

  address = base + (index * mem->scale) + mem->disp;

  if (!cmplog_is_readable(address, size)) { return FALSE; }

  switch (size) {

    case 1:
      *val = *((guint8 *)address);
      return TRUE;
    case 2:
      *val = *((guint16 *)address);
      return TRUE;
    case 4:
      *val = *((guint32 *)address);
      return TRUE;
    case 8:
      *val = *((guint64 *)address);
      return TRUE;
    default:
      FATAL("Invalid operand size: %d\n", size);

  }

  return FALSE;

}

static gboolean cmplog_get_operand_value(GumCpuContext *context,
                                         cmplog_ctx_t *ctx, guint64 *val) {

  switch (ctx->type) {

    case X86_OP_REG:
      *val = cmplog_read_reg(context, ctx->reg);
      return TRUE;
    case X86_OP_IMM:
      *val = ctx->imm;
      return TRUE;
    case X86_OP_MEM:
      return cmplog_read_mem(context, ctx->size, &ctx->mem, val);
    default:
      FATAL("Invalid operand type: %d\n", ctx->type);

  }

  return FALSE;

}

static void cmplog_call_callout(GumCpuContext *context, gpointer user_data) {

  UNUSED_PARAMETER(user_data);

  guint64 address = cmplog_read_reg(context, X86_REG_RIP);
  guint64 rdi = cmplog_read_reg(context, X86_REG_RDI);
  guint64 rsi = cmplog_read_reg(context, X86_REG_RSI);

  if (((G_MAXULONG - rdi) < 32) || ((G_MAXULONG - rsi) < 32)) return;

  if (!cmplog_is_readable(rdi, 32) || !cmplog_is_readable(rsi, 32)) return;

  void *ptr1 = GSIZE_TO_POINTER(rdi);
  void *ptr2 = GSIZE_TO_POINTER(rsi);

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

static void cmplog_instrument_put_operand(cmplog_ctx_t *ctx,
                                          cs_x86_op *   operand) {

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

static void cmplog_instrument_call(const cs_insn *     instr,
                                   GumStalkerIterator *iterator) {

  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand;

  if (instr->id != X86_INS_CALL) return;

  if (x86.op_count != 1) return;

  operand = &x86.operands[0];

  if (operand->type == X86_OP_INVALID) return;
  if (operand->type == X86_OP_MEM && operand->mem.segment != X86_REG_INVALID)
    return;

  gum_stalker_iterator_put_callout(iterator, cmplog_call_callout, NULL, NULL);

}

static void cmplog_handle_cmp_sub(GumCpuContext *context, guint64 operand1,
                                  guint64 operand2, uint8_t size) {

  guint64 address = cmplog_read_reg(context, X86_REG_RIP);

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

static void cmplog_cmp_sub_callout(GumCpuContext *context, gpointer user_data) {

  cmplog_pair_ctx_t *ctx = (cmplog_pair_ctx_t *)user_data;
  guint64            operand1;
  guint64            operand2;

  if (ctx->operand1.size != ctx->operand2.size) FATAL("Operand size mismatch");

  if (!cmplog_get_operand_value(context, &ctx->operand1, &operand1)) { return; }
  if (!cmplog_get_operand_value(context, &ctx->operand2, &operand2)) { return; }

  cmplog_handle_cmp_sub(context, operand1, operand2, ctx->operand1.size);

}

static void cmplog_instrument_cmp_sub_put_callout(GumStalkerIterator *iterator,
                                                  cs_x86_op *         operand1,
                                                  cs_x86_op *operand2) {

  cmplog_pair_ctx_t *ctx = g_malloc(sizeof(cmplog_pair_ctx_t));
  if (ctx == NULL) return;

  cmplog_instrument_put_operand(&ctx->operand1, operand1);
  cmplog_instrument_put_operand(&ctx->operand2, operand2);

  gum_stalker_iterator_put_callout(iterator, cmplog_cmp_sub_callout, ctx,
                                   g_free);

}

static void cmplog_instrument_cmp_sub(const cs_insn *     instr,
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

  if ((operand1->type == X86_OP_MEM) &&
      (operand1->mem.segment != X86_REG_INVALID))
    return;

  if ((operand2->type == X86_OP_MEM) &&
      (operand2->mem.segment != X86_REG_INVALID))
    return;

  cmplog_instrument_cmp_sub_put_callout(iterator, operand1, operand2);

}

void cmplog_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  if (__afl_cmp_map == NULL) return;

  cmplog_instrument_call(instr, iterator);
  cmplog_instrument_cmp_sub(instr, iterator);

}

#endif

