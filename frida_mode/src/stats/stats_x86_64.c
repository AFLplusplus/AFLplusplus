#include <sys/shm.h>
#include <sys/mman.h>

#include "frida-gumjs.h"

#include "ranges.h"
#include "stats.h"
#include "util.h"

#define MICRO_TO_SEC 1000000

#if defined(__x86_64__) || defined(__i386__)

typedef struct {

  guint64 num_blocks;
  guint64 num_instructions;

  guint64 num_eob;

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

  guint64 num_rip_relative_type[X86_INS_ENDING];
  char    name_rip_relative_type[X86_INS_ENDING][CS_MNEMONIC_SIZE];

} stats_data_arch_t;

static stats_data_arch_t *stats_data_arch = NULL;

void starts_arch_init(void) {

  int shm_id = shmget(IPC_PRIVATE, sizeof(stats_data_arch_t),
                      IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) { FFATAL("shm_id < 0 - errno: %d\n", errno); }

  stats_data_arch = shmat(shm_id, NULL, 0);
  g_assert(stats_data_arch != MAP_FAILED);

  /*
   * Configure the shared memory region to be removed once the process dies.
   */
  if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

    FFATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

  }

  /* Clear it, not sure it's necessary, just seems like good practice */
  memset(stats_data_arch, '\0', sizeof(stats_data_arch_t));

}

static void stats_write_arch_stat(char *label, guint64 value, guint64 total) {

  stats_print("%-30s ", label);
  stats_print("%10" G_GINT64_MODIFIER "u ", value);
  if (total == 0) {

    stats_print("(--.--%%), ");

  } else {

    stats_print("(%5.2f%%) ", ((float)value * 100) / total);

  }

  stats_print("\n");

}

static void stats_write_arch_stat_delta(char *label, guint64 prev_value,
                                        guint64 curr_value, guint elapsed,
                                        guint64 prev_total,
                                        guint64 curr_total) {

  guint64 delta = curr_value - prev_value;
  guint64 delta_total = curr_total - prev_total;
  guint64 per_sec = delta / elapsed;

  stats_print("%-30s ", label);

  stats_print("%10" G_GINT64_MODIFIER "u ", curr_value);
  if (curr_total == 0) {

    stats_print("(--.--%%), ");

  } else {

    stats_print("(%5.2f%%) ", ((float)curr_value * 100) / curr_total);

  }

  stats_print("%10" G_GINT64_MODIFIER "u ", delta);
  if (delta_total == 0) {

    stats_print("(--.--%%), ");

  } else {

    stats_print("(%5.2f%%) ", ((float)delta * 100) / delta_total);

  }

  stats_print("[%10" G_GINT64_MODIFIER "u/s]", per_sec);
  stats_print("\n");

}

void stats_write_arch(stats_data_t *data) {

  guint elapsed =
      (data->curr.stats_time - data->prev.stats_time) / MICRO_TO_SEC;
  stats_print("%-30s %10s %19s\n", "Transitions", "cumulative", "delta");
  stats_print("%-30s %10s %19s\n", "-----------", "----------", "-----");
  stats_print(
      "%-30s %10" G_GINT64_MODIFIER "u %-8s %10" G_GINT64_MODIFIER "u\n",
      "total", data->curr.total, "", data->curr.total - data->prev.total);
  stats_write_arch_stat_delta("call_imm", data->prev.call_imm,
                              data->curr.call_imm, elapsed, data->prev.total,
                              data->curr.total);
  stats_write_arch_stat_delta("call_reg", data->prev.call_reg,
                              data->curr.call_reg, elapsed, data->prev.total,
                              data->curr.total);
  stats_write_arch_stat_delta("call_mem", data->prev.call_mem,
                              data->curr.call_mem, elapsed, data->prev.total,
                              data->curr.total);
  stats_write_arch_stat_delta("ret_slow_path", data->prev.ret_slow_path,
                              data->curr.ret_slow_path, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("post_call_invoke", data->prev.post_call_invoke,
                              data->curr.post_call_invoke, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("excluded_call_imm", data->prev.excluded_call_imm,
                              data->curr.excluded_call_imm, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_imm", data->prev.jmp_imm, data->curr.jmp_imm,
                              elapsed, data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_reg", data->prev.jmp_reg, data->curr.jmp_reg,
                              elapsed, data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_mem", data->prev.jmp_mem, data->curr.jmp_mem,
                              elapsed, data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_imm", data->prev.jmp_cond_imm,
                              data->curr.jmp_cond_imm, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_mem", data->prev.jmp_cond_mem,
                              data->curr.jmp_cond_mem, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_reg", data->prev.jmp_cond_reg,
                              data->curr.jmp_cond_reg, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_jcxz", data->prev.jmp_cond_jcxz,
                              data->curr.jmp_cond_jcxz, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_continuation", data->prev.jmp_continuation,
                              data->curr.jmp_continuation, elapsed,
                              data->prev.total, data->curr.total);
  stats_print("\n");
  stats_print("\n");

  stats_print("Instrumentation\n");
  stats_print("---------------\n");
  stats_print("%-30s %10" G_GINT64_MODIFIER "u\n", "Instructions",
              stats_data_arch->num_instructions);
  stats_print("%-30s %10" G_GINT64_MODIFIER "u\n", "Blocks",
              stats_data_arch->num_blocks);

  if (stats_data_arch->num_blocks != 0) {

    stats_print(
        "%-30s %10" G_GINT64_MODIFIER "u\n", "Avg Instructions / Block ",
        stats_data_arch->num_instructions / stats_data_arch->num_blocks);

  }

  stats_print("\n");
  stats_print("\n");

  guint64 num_instructions = stats_data_arch->num_instructions;

  stats_print("EOB Instructions\n");
  stats_print("----------------\n");
  stats_write_arch_stat("Total", stats_data_arch->num_eob, num_instructions);
  stats_write_arch_stat("Call Immediates", stats_data_arch->num_call_imm,
                        num_instructions);
  stats_write_arch_stat("Call Immediates Excluded",
                        stats_data_arch->num_call_imm_excluded,
                        num_instructions);
  stats_write_arch_stat("Call Register", stats_data_arch->num_call_reg,
                        num_instructions);
  stats_write_arch_stat("Call Memory", stats_data_arch->num_call_mem,
                        num_instructions);
  stats_write_arch_stat("Jump Immediates", stats_data_arch->num_jmp_imm,
                        num_instructions);
  stats_write_arch_stat("Jump Register", stats_data_arch->num_jmp_reg,
                        num_instructions);
  stats_write_arch_stat("Jump Memory", stats_data_arch->num_jmp_mem,
                        num_instructions);
  stats_write_arch_stat("Conditional Jump Immediates",
                        stats_data_arch->num_jmp_cond_imm, num_instructions);
  stats_write_arch_stat("Conditional Jump CX Immediate",
                        stats_data_arch->num_jmp_cond_jcxz, num_instructions);
  stats_write_arch_stat("Conditional Jump Register",
                        stats_data_arch->num_jmp_cond_reg, num_instructions);
  stats_write_arch_stat("Conditional Jump Memory",
                        stats_data_arch->num_jmp_cond_mem, num_instructions);
  stats_write_arch_stat("Returns", stats_data_arch->num_ret, num_instructions);
  stats_print("\n");
  stats_print("\n");

  stats_print("Relocated Instructions\n");
  stats_print("----------------------\n");
  stats_write_arch_stat("Total", stats_data_arch->num_rip_relative,
                        num_instructions);

  for (size_t i = 0; i < X86_INS_ENDING; i++) {

    if (stats_data_arch->num_rip_relative_type[i] != 0) {

      stats_write_arch_stat(stats_data_arch->name_rip_relative_type[i],
                            stats_data_arch->num_rip_relative_type[i],
                            stats_data_arch->num_rip_relative);

    }

  }

  stats_print("\n");
  stats_print("\n");

}

static x86_op_type stats_get_operand_type(const cs_insn *instr) {

  cs_x86    *x86 = &instr->detail->x86;
  cs_x86_op *operand;

  if (x86->op_count != 1) {

    FFATAL("Unexpected operand count (%d): %s %s\n", x86->op_count,
           instr->mnemonic, instr->op_str);

  }

  operand = &x86->operands[0];

  return operand->type;

}

static void stats_collect_call_imm_excluded_arch(const cs_insn *instr) {

  cs_x86    *x86 = &instr->detail->x86;
  cs_x86_op *operand = &x86->operands[0];

  if (range_is_excluded(GUM_ADDRESS(operand->imm))) {

    stats_data_arch->num_call_imm_excluded++;

  }

}

static void stats_collect_call_arch(const cs_insn *instr) {

  x86_op_type type = stats_get_operand_type(instr);
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
      FFATAL("Invalid operand type: %s %s\n", instr->mnemonic, instr->op_str);

  }

}

static void stats_collect_jump_arch(const cs_insn *instr) {

  x86_op_type type = stats_get_operand_type(instr);
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
      FFATAL("Invalid operand type: %s %s\n", instr->mnemonic, instr->op_str);

  }

}

static void stats_collect_jump_cond_arch(const cs_insn *instr) {

  x86_op_type type = stats_get_operand_type(instr);
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
      FFATAL("Invalid operand type: %s %s\n", instr->mnemonic, instr->op_str);

  }

}

static void stats_collect_rip_relative_arch(const cs_insn *instr) {

  cs_x86 *x86 = &instr->detail->x86;
  guint   mod;
  guint   rm;

  if (x86->encoding.modrm_offset == 0) { return; }

  mod = (x86->modrm & 0xc0) >> 6;
  if (mod != 0) { return; }

  rm = (x86->modrm & 0x07) >> 0;
  if (rm != 5) { return; }

  stats_data_arch->num_rip_relative++;
  stats_data_arch->num_rip_relative_type[instr->id]++;
  memcpy(stats_data_arch->name_rip_relative_type[instr->id], instr->mnemonic,
         CS_MNEMONIC_SIZE);

}

void stats_collect_arch(const cs_insn *instr, gboolean begin) {

  if (stats_data_arch == NULL) { return; }
  if (begin) { stats_data_arch->num_blocks++; }
  stats_data_arch->num_instructions++;

  switch (instr->id) {

    case X86_INS_CALL:
      stats_collect_call_arch(instr);
      stats_data_arch->num_eob++;
      break;
    case X86_INS_JMP:
      stats_collect_jump_arch(instr);
      stats_data_arch->num_eob++;
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
      stats_data_arch->num_eob++;
      break;
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
      stats_data_arch->num_jmp_cond_jcxz++;
      stats_data_arch->num_eob++;
      break;
    case X86_INS_RET:
      stats_data_arch->num_ret++;
      stats_data_arch->num_eob++;
      break;
    default:
      stats_collect_rip_relative_arch(instr);
      break;

  }

}

#endif

