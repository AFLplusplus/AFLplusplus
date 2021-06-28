#include "frida-gumjs.h"

#include "debug.h"

#include "ranges.h"
#include "stats.h"
#include "util.h"

#if defined(__x86_64__)

typedef struct {

  stats_data_header_t header;

  guint64 num_call_imm;
  guint64 num_call_imm_excluded;
  guint64 num_call_reg;
  guint64 num_call_mem;

  guint64 num_jmp_imm;
  guint64 num_jmp_reg;
  guint64 num_jmp_mem;

  guint64 num_jmp_cond_imm;
  guint64 num_jmp_cond_reg;
  guint64 num_jmp_cond_mem;

  guint64 num_jmp_cond_jcxz;

  guint64 num_ret;

  guint64 num_rip_relative;

} stats_data_arch_t;

gboolean stats_is_supported_arch(void) {

  return TRUE;

}

size_t stats_data_size_arch(void) {

  return sizeof(stats_data_arch_t);

}

void stats_write_arch(void) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  guint64 num_instructions = stats_data_arch->header.num_instructions;

  stats_print(
      "Call Immediates:                %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_call_imm,
      ((float)(stats_data_arch->num_call_imm * 100) / num_instructions));
  stats_print("Call Immediates Excluded:       %" G_GINT64_MODIFIER
              "u "
              "(%3.2f%%)\n",
              stats_data_arch->num_call_imm_excluded,
              ((float)(stats_data_arch->num_call_imm_excluded * 100) /
               num_instructions));
  stats_print(
      "Call Register:                  %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_call_reg,
      ((float)(stats_data_arch->num_call_reg * 100) / num_instructions));
  stats_print(
      "Call Memory:                    %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_call_mem,
      ((float)(stats_data_arch->num_call_mem * 100) / num_instructions));

  stats_print("\n");

  stats_print("Jump Immediates:                %" G_GINT64_MODIFIER
              "u "
              "(%3.2f%%)\n",
              stats_data_arch->num_jmp_imm,
              ((float)(stats_data_arch->num_jmp_imm * 100) / num_instructions));
  stats_print("Jump Register:                  %" G_GINT64_MODIFIER
              "u "
              "(%3.2f%%)\n",
              stats_data_arch->num_jmp_reg,
              ((float)(stats_data_arch->num_jmp_reg * 100) / num_instructions));
  stats_print("Jump Memory:                    %" G_GINT64_MODIFIER
              "u "
              "(%3.2f%%)\n",
              stats_data_arch->num_jmp_mem,
              ((float)(stats_data_arch->num_jmp_mem * 100) / num_instructions));

  stats_print("\n");

  stats_print(
      "Conditional Jump Immediates:    %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_jmp_cond_imm,
      ((float)(stats_data_arch->num_jmp_cond_imm * 100) / num_instructions));
  stats_print(
      "Conditional Jump CX Immediate:  %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_jmp_cond_jcxz,
      ((float)(stats_data_arch->num_jmp_cond_jcxz * 100) / num_instructions));
  stats_print(
      "Conditional Jump Register:      %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_jmp_cond_reg,
      ((float)(stats_data_arch->num_jmp_cond_reg * 100) / num_instructions));
  stats_print(
      "Conditional Jump Memory:        %" G_GINT64_MODIFIER
      "u "
      "(%3.2f%%)\n",
      stats_data_arch->num_jmp_cond_mem,
      ((float)(stats_data_arch->num_jmp_cond_mem * 100) / num_instructions));

  stats_print("\n");

  stats_print("Returns:                        %" G_GINT64_MODIFIER
              "u "
              "(%3.2f%%)\n",
              stats_data_arch->num_ret,
              (stats_data_arch->num_ret * 100 / num_instructions));

  stats_print("\n");

  stats_print("Rip Relative:                   %" G_GINT64_MODIFIER
              "u "
              "(%3.2f%%)\n",
              stats_data_arch->num_rip_relative,
              (stats_data_arch->num_rip_relative * 100 / num_instructions));

  stats_print("\n");
  stats_print("\n");

}

static x86_op_type stats_get_operand_type(const cs_insn *instr) {

  cs_x86 *   x86 = &instr->detail->x86;
  cs_x86_op *operand;

  if (x86->op_count != 1) {

    FATAL("Unexpected operand count (%d): %s %s\n", x86->op_count,
          instr->mnemonic, instr->op_str);

  }

  operand = &x86->operands[0];

  return operand->type;

}

static void stats_collect_call_imm_excluded_arch(const cs_insn *instr) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  cs_x86 *           x86 = &instr->detail->x86;
  cs_x86_op *        operand = &x86->operands[0];

  if (range_is_excluded((gpointer)operand->imm)) {

    stats_data_arch->num_call_imm_excluded++;

  }

}

static void stats_collect_call_arch(const cs_insn *instr) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  x86_op_type        type = stats_get_operand_type(instr);
  switch (type) {

    case X86_OP_IMM:
      stats_data_arch->num_call_imm++;
      stats_collect_call_imm_excluded_arch(instr);
      break;
    case X86_OP_REG:
      stats_data_arch->num_call_reg++;
      break;
    case X86_OP_MEM:
      stats_data_arch->num_call_mem++;
      break;
    default:
      FATAL("Invalid operand type: %s %s\n", instr->mnemonic, instr->op_str);

  }

}

static void stats_collect_jump_arch(const cs_insn *instr) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  x86_op_type        type = stats_get_operand_type(instr);
  switch (type) {

    case X86_OP_IMM:
      stats_data_arch->num_jmp_imm++;
      break;
    case X86_OP_REG:
      stats_data_arch->num_jmp_reg++;
      break;
    case X86_OP_MEM:
      stats_data_arch->num_jmp_mem++;
      break;
    default:
      FATAL("Invalid operand type: %s %s\n", instr->mnemonic, instr->op_str);

  }

}

static void stats_collect_jump_cond_arch(const cs_insn *instr) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  x86_op_type        type = stats_get_operand_type(instr);
  switch (type) {

    case X86_OP_IMM:
      stats_data_arch->num_jmp_cond_imm++;
      break;
    case X86_OP_REG:
      stats_data_arch->num_jmp_cond_reg++;
      break;
    case X86_OP_MEM:
      stats_data_arch->num_jmp_cond_mem++;
      break;
    default:
      FATAL("Invalid operand type: %s %s\n", instr->mnemonic, instr->op_str);

  }

}

static void stats_collect_rip_relative_arch(const cs_insn *instr) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  cs_x86 *           x86 = &instr->detail->x86;
  guint              mod;
  guint              rm;

  if (x86->encoding.modrm_offset == 0) { return; }

  mod = (x86->modrm & 0xc0) >> 6;
  if (mod != 0) { return; }

  rm = (x86->modrm & 0x07) >> 0;
  if (rm != 5) { return; }

  stats_data_arch->num_rip_relative++;

}

void stats_collect_arch(const cs_insn *instr) {

  stats_data_arch_t *stats_data_arch = (stats_data_arch_t *)stats_data;
  switch (instr->id) {

    case X86_INS_CALL:
      stats_collect_call_arch(instr);
      break;
    case X86_INS_JMP:
      stats_collect_jump_arch(instr);
      break;
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
      stats_collect_jump_cond_arch(instr);
      break;
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
      stats_data_arch->num_jmp_cond_jcxz++;
      break;
    case X86_INS_RET:
      stats_data_arch->num_ret++;
      break;
    default:
      stats_collect_rip_relative_arch(instr);
      break;

  }

}

#endif

