#include "frida-gumjs.h"

#include "debug.h"
#include "cmplog.h"

#include "ctx.h"
#include "frida_cmplog.h"
#include "util.h"

#if defined(__aarch64__)

typedef struct {

  arm64_op_type type;
  uint8_t       size;

  union {

    arm64_op_mem mem;
    arm64_reg    reg;
    int64_t      imm;

  };

} cmplog_ctx_t;

typedef struct {

  cmplog_ctx_t operand1;
  cmplog_ctx_t operand2;
  size_t       size;

} cmplog_pair_ctx_t;

static gboolean cmplog_read_mem(GumCpuContext *ctx, uint8_t size,
                                arm64_op_mem *mem, gsize *val) {

  gsize base = 0;
  gsize index = 0;
  gsize address;

  if (mem->base != ARM64_REG_INVALID) { base = ctx_read_reg(ctx, mem->base); }

  if (mem->index != ARM64_REG_INVALID) {

    index = ctx_read_reg(ctx, mem->index);

  }

  address = base + index + mem->disp;

  if (!cmplog_is_readable(address, size)) { return FALSE; }

  switch (size) {

    case 1:
      *val = *((guint8 *)GSIZE_TO_POINTER(address));
      return TRUE;
    case 2:
      *val = *((guint16 *)GSIZE_TO_POINTER(address));
      return TRUE;
    case 4:
      *val = *((guint32 *)GSIZE_TO_POINTER(address));
      return TRUE;
    case 8:
      *val = *((guint64 *)GSIZE_TO_POINTER(address));
      return TRUE;
    default:
      FATAL("Invalid operand size: %d\n", size);

  }

  return FALSE;

}

static gboolean cmplog_get_operand_value(GumCpuContext *context,
                                         cmplog_ctx_t *ctx, gsize *val) {

  switch (ctx->type) {

    case ARM64_OP_REG:
      *val = ctx_read_reg(context, ctx->reg);
      return TRUE;
    case ARM64_OP_IMM:
      *val = ctx->imm;
      return TRUE;
    case ARM64_OP_MEM:
      return cmplog_read_mem(context, ctx->size, &ctx->mem, val);
    default:
      FATAL("Invalid operand type: %d\n", ctx->type);

  }

  return FALSE;

}

static void cmplog_call_callout(GumCpuContext *context, gpointer user_data) {

  UNUSED_PARAMETER(user_data);

  gsize address = context->pc;
  gsize x0 = ctx_read_reg(context, ARM64_REG_X0);
  gsize x1 = ctx_read_reg(context, ARM64_REG_X1);

  if (((G_MAXULONG - x0) < 32) || ((G_MAXULONG - x1) < 32)) return;

  if (!cmplog_is_readable(x0, 32) || !cmplog_is_readable(x1, 32)) return;

  void *ptr1 = GSIZE_TO_POINTER(x0);
  void *ptr2 = GSIZE_TO_POINTER(x1);

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
                                          cs_arm64_op * operand) {

  ctx->type = operand->type;
  switch (operand->type) {

    case ARM64_OP_REG:
      gum_memcpy(&ctx->reg, &operand->reg, sizeof(arm64_reg));
      break;
    case ARM64_OP_IMM:
      gum_memcpy(&ctx->imm, &operand->imm, sizeof(int64_t));
      break;
    case ARM64_OP_MEM:
      gum_memcpy(&ctx->mem, &operand->mem, sizeof(arm64_op_mem));
      break;
    default:
      FATAL("Invalid operand type: %d\n", operand->type);

  }

}

static void cmplog_instrument_call(const cs_insn *     instr,
                                   GumStalkerIterator *iterator) {

  cs_arm64     arm64 = instr->detail->arm64;
  cs_arm64_op *operand;

  switch (instr->id) {

    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
      break;
    default:
      return;

  }

  if (arm64.op_count != 1) return;

  operand = &arm64.operands[0];

  if (operand->type == ARM64_OP_INVALID) return;

  gum_stalker_iterator_put_callout(iterator, cmplog_call_callout, NULL, NULL);

}

static void cmplog_handle_cmp_sub(GumCpuContext *context, gsize operand1,
                                  gsize operand2, uint8_t size) {

  gsize address = context->pc;

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
  gsize              operand1;
  gsize              operand2;

  if (!cmplog_get_operand_value(context, &ctx->operand1, &operand1)) { return; }
  if (!cmplog_get_operand_value(context, &ctx->operand2, &operand2)) { return; }

  cmplog_handle_cmp_sub(context, operand1, operand2, ctx->size);

}

static void cmplog_instrument_cmp_sub_put_callout(GumStalkerIterator *iterator,
                                                  cs_arm64_op *       operand1,
                                                  cs_arm64_op *       operand2,
                                                  size_t              size) {

  cmplog_pair_ctx_t *ctx = g_malloc(sizeof(cmplog_pair_ctx_t));
  if (ctx == NULL) return;

  cmplog_instrument_put_operand(&ctx->operand1, operand1);
  cmplog_instrument_put_operand(&ctx->operand2, operand2);
  ctx->size = size;

  gum_stalker_iterator_put_callout(iterator, cmplog_cmp_sub_callout, ctx,
                                   g_free);

}

static void cmplog_instrument_cmp_sub(const cs_insn *     instr,
                                      GumStalkerIterator *iterator) {

  cs_arm64     arm64 = instr->detail->arm64;
  cs_arm64_op *operand1;
  cs_arm64_op *operand2;
  size_t       size;

  switch (instr->id) {

    case ARM64_INS_ADCS:
    case ARM64_INS_ADDS:
    case ARM64_INS_ANDS:
    case ARM64_INS_BICS:
    case ARM64_INS_CMN:
    case ARM64_INS_CMP:
    case ARM64_INS_CMPEQ:
    case ARM64_INS_CMPGE:
    case ARM64_INS_CMPGT:
    case ARM64_INS_CMPHI:
    case ARM64_INS_CMPHS:
    case ARM64_INS_CMPLE:
    case ARM64_INS_CMPLO:
    case ARM64_INS_CMPLS:
    case ARM64_INS_CMPLT:
    case ARM64_INS_CMPNE:
    case ARM64_INS_EORS:
    case ARM64_INS_NANDS:
    case ARM64_INS_NEGS:
    case ARM64_INS_NGCS:
    case ARM64_INS_NORS:
    case ARM64_INS_NOTS:
    case ARM64_INS_ORNS:
    case ARM64_INS_ORRS:
    case ARM64_INS_SBCS:
    case ARM64_INS_SUBS:
      break;

    default:
      return;

  }

  if (arm64.op_count != 2) return;

  operand1 = &arm64.operands[0];
  operand2 = &arm64.operands[1];

  if (operand1->type == ARM64_OP_INVALID) return;
  if (operand2->type == ARM64_OP_INVALID) return;

  size = ctx_get_size(instr, &arm64.operands[0]);

  cmplog_instrument_cmp_sub_put_callout(iterator, operand1, operand2, size);

}

void cmplog_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  if (__afl_cmp_map == NULL) return;

  cmplog_instrument_call(instr, iterator);
  cmplog_instrument_cmp_sub(instr, iterator);

}

#endif

