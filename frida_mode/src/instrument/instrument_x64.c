#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "ranges.h"

#if defined(__x86_64__)

static GumAddress current_log_impl = GUM_ADDRESS(0);

static const guint8 afl_log_code[] = {

    // 0xcc,

    0x9c,                                                         /* pushfq */
    0x51,                                                       /* push rcx */
    0x52,                                                       /* push rdx */

    0x48, 0x8b, 0x0d, 0x28,
    0x00, 0x00, 0x00,                          /* mov rcx, sym.&previous_pc */
    0x48, 0x8b, 0x11,                               /* mov rdx, qword [rcx] */
    0x48, 0x31, 0xfa,                                       /* xor rdx, rdi */

    0x48, 0x03, 0x15, 0x13,
    0x00, 0x00, 0x00, /* add rdx, sym._afl_area_ptr_ptr
                       */

    0x80, 0x02, 0x01,                              /* add byte ptr [rdx], 1 */
    0x80, 0x12, 0x00,                              /* adc byte ptr [rdx], 0 */
    0x48, 0xd1, 0xef,                                         /* shr rdi, 1 */
    0x48, 0x89, 0x39,                               /* mov qword [rcx], rdi */

    0x5a,                                                        /* pop rdx */
    0x59,                                                        /* pop rcx */
    0x9d,                                                          /* popfq */

    0xc3,                                                            /* ret */
    0x90, 0x90, 0x90                                             /* nop pad */

    /* Read-only data goes here: */
    /* uint8_t* __afl_area_ptr */
    /* uint64_t* &previous_pc */

};

static const guint8 afl_log_code_with_suppression[] = {

    // 0xcc,

    0x9c,                                                         /* pushfq */
    0x51,                                                       /* push rcx */
    0x52,                                                       /* push rdx */

    0x8b, 0x8c, 0x24, 0x00, 0xc0, 0xff,
    0xff,                                           /* mov ecx, [rsp-13684] */
    0x81, 0xf9, 0xce, 0xfa, 0xad, 0xde,              /* cmp ecx, 0xdeadface */

    0x74, 0x20,                                                 /* je done: */

    0x48, 0x8b, 0x0d, 0x28, 0x00, 0x00,
    0x00,                                      /* mov rcx, sym.&previous_pc */
    0x48, 0x8b, 0x11,                               /* mov rdx, qword [rcx] */
    0x48, 0x31, 0xfa,                                       /* xor rdx, rdi */

    0x48, 0x03, 0x15, 0x13, 0x00, 0x00,
    0x00, /* add rdx, sym._afl_area_ptr_ptr
           */

    0x80, 0x02, 0x01,                              /* add byte ptr [rdx], 1 */
    0x80, 0x12, 0x00,                              /* adc byte ptr [rdx], 0 */
    0x48, 0xd1, 0xef,                                         /* shr rdi, 1 */
    0x48, 0x89, 0x39,                               /* mov qword [rcx], rdi */

    0x5a,                                                        /* pop rdx */
    0x59,                                                        /* pop rcx */
    0x9d,                                                          /* popfq */

    0xc3,                                                            /* ret */
    0x90, 0x90, 0x90                                             /* nop pad */

    /* Read-only data goes here: */
    /* uint8_t* __afl_area_ptr */
    /* uint64_t* &previous_pc */

};

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  guint64 current_pc = instr->address;
  guint64 area_offset = (current_pc >> 4) ^ (current_pc << 8);
  area_offset &= MAP_SIZE - 1;
  GumX86Writer *cw = output->writer.x86;

  if (current_log_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, current_log_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

    current_log_impl = cw->pc;
    if (instrument_suppression) {

      gum_x86_writer_put_bytes(cw, afl_log_code_with_suppression,
                               sizeof(afl_log_code_with_suppression));

    } else {

      gum_x86_writer_put_bytes(cw, afl_log_code, sizeof(afl_log_code));

    }

    uint64_t *afl_prev_loc_ptr = &previous_pc;
    gum_x86_writer_put_bytes(cw, (const guint8 *)&__afl_area_ptr,
                             sizeof(__afl_area_ptr));
    gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                             sizeof(afl_prev_loc_ptr));

    gum_x86_writer_put_label(cw, after_log_impl);

  }

  // gum_x86_writer_put_breakpoint(cw);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDI, area_offset);
  gum_x86_writer_put_call_address(cw, current_log_impl);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        GUM_RED_ZONE_SIZE);

}

static gboolean instrument_is_end_of_block(const cs_insn *instr) {

  switch (instr->id) {

    case X86_INS_RET:
    case X86_INS_RETF:

    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JMP:

    case X86_INS_JAE:
    case X86_INS_JA:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:

    case X86_INS_CALL:
      return TRUE;
    default:
      return FALSE;

  }

}

static gboolean instrument_is_excluded_call(const cs_insn *instr) {

  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand = &x86.operands[0];

  if (instr->id != X86_INS_CALL) { return FALSE; }
  if (x86.op_count != 1) { FATAL("Unexpected operand count"); }
  if (operand->type != X86_OP_IMM) { return FALSE; }

  if (!range_is_excluded(GSIZE_TO_POINTER(operand->imm))) { return FALSE; }

  return TRUE;

}

static gssize instrument_get_offset_adjust(const cs_insn *instr) {

  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand = &x86.operands[0];

  switch (instr->id) {

    case X86_INS_RET:
      if (x86.op_count == 0) {

        return -8;

      } else {

        if (operand->type == X86_OP_IMM) { return -((operand->imm + 1) * 8); }

        return 0;

      }

    case X86_INS_RETF:
      if (x86.op_count == 0) {

        return -16;

      } else {

        if (operand->type != X86_OP_IMM) { FATAL("Unexpected operand type"); }
        return -((operand->imm + 2) * 8);

      }

    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JMP:

    case X86_INS_JAE:
    case X86_INS_JA:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
      return 0;
    case X86_INS_CALL:
      /* far */
      if (x86.op_count != 1) { FATAL("Unexpected operand count"); }

      if (operand->type == X86_OP_MEM) {

        if (operand->mem.segment != X86_REG_INVALID) { return 16; }

      }

      if (instrument_is_excluded_call(instr)) { return 0; }

      return 8;
    default:
      FATAL("Unexpected instruction");

  }

}

void instrument_coverage_write_cookie(const cs_insn *   instr,
                                      GumStalkerOutput *output,
                                      gssize            stack_offset) {

  GumX86Writer *cw = output->writer.x86;
  cs_x86        x86 = instr->detail->x86;
  cs_x86_op *   operand = &x86.operands[0];
  guint32       suppress_cookie = 0xdeadface;
  guint32       no_suppress_cookie = 0xb00bd00d;

  switch (instr->id) {

    case X86_INS_RET:
      gum_x86_writer_put_mov_reg_offset_ptr_u32(cw, GUM_REG_RSP, -stack_offset,
                                                no_suppress_cookie);
      return;

    case X86_INS_RETF:
      gum_x86_writer_put_mov_reg_offset_ptr_u32(cw, GUM_REG_RSP, -stack_offset,
                                                no_suppress_cookie);
      return;

    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JMP:
    case X86_INS_CALL:
      /* far */
      if (x86.op_count != 1) { FATAL("Unexpected operand count"); }

      if (operand->type == X86_OP_IMM) {

        gum_x86_writer_put_mov_reg_offset_ptr_u32(
            cw, GUM_REG_RSP, -stack_offset, suppress_cookie);

      } else {

        gum_x86_writer_put_mov_reg_offset_ptr_u32(
            cw, GUM_REG_RSP, -stack_offset, no_suppress_cookie);

      }

      return;

    case X86_INS_JAE:
    case X86_INS_JA:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS: {

      gconstpointer match = cw->code + 1;
      gconstpointer done_match = cw->code + 2;
      gum_x86_writer_put_jcc_short_label(cw, instr->id, match, GUM_NO_HINT);
      gum_x86_writer_put_mov_reg_offset_ptr_u32(cw, GUM_REG_RSP, -stack_offset,
                                                no_suppress_cookie);
      gum_x86_writer_put_jmp_short_label(cw, done_match);
      gum_x86_writer_put_label(cw, match);
      gum_x86_writer_put_mov_reg_offset_ptr_u32(cw, GUM_REG_RSP, -stack_offset,
                                                suppress_cookie);
      gum_x86_writer_put_label(cw, done_match);
      return;

    }

    default:
      FATAL("Unexpected instruction");

  }

}

void instrument_coverage_suppress(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  // -------------------------
  // | RDX (callee saved)    |
  // -------------------------
  // | RCX (callee saved)    |
  // -------------------------
  // | RFLAGS (callee saved) |
  // -------------------------
  // | return address        |
  // -------------------------
  // | RDI (caller saved)    |
  // -------------------------
  // | red-zone              |
  // -------------------------
  // | old sp                |
  // -------------------------

  if (!instrument_suppression) { return; }

  if (!instrument_is_end_of_block(instr)) { return; }

  gssize offset = 16384;
  gssize used = (GUM_RED_ZONE_SIZE + (5 * 8));
  gssize adjust = instrument_get_offset_adjust(instr);

  gssize stack_offset = offset + used + adjust;

  instrument_coverage_write_cookie(instr, output, stack_offset);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

