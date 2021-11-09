#include <sys/shm.h>
#include <sys/mman.h>

#include "frida-gumjs.h"

#include "ranges.h"
#include "stats.h"
#include "util.h"

#define MICRO_TO_SEC 1000000

#if defined(__aarch64__)

typedef struct {

  guint64 num_blocks;
  guint64 num_instructions;

  guint64 num_eob;
  guint64 num_reloc;

  guint64 num_adr;
  guint64 num_adrp;

  guint64 num_b;
  guint64 num_bcc;
  guint64 num_bl;
  guint64 num_br;

  guint64 num_cbz;
  guint64 num_cbnz;

  guint64 num_ldr;
  guint64 num_ldrsw;

  guint64 num_ret;

  guint64 num_tbz;
  guint64 num_tbnz;

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
  stats_write_arch_stat_delta("excluded_call_reg", data->prev.excluded_call_reg,
                              data->curr.excluded_call_reg, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("ret", data->prev.ret, data->curr.ret, elapsed,
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
  stats_write_arch_stat_delta("jmp_cond_cc", data->prev.jmp_cond_cc,
                              data->curr.jmp_cond_cc, elapsed, data->prev.total,
                              data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_cbz", data->prev.jmp_cond_cbz,
                              data->curr.jmp_cond_cbz, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_cbnz", data->prev.jmp_cond_cbnz,
                              data->curr.jmp_cond_cbnz, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_tbz", data->prev.jmp_cond_tbz,
                              data->curr.jmp_cond_tbz, elapsed,
                              data->prev.total, data->curr.total);
  stats_write_arch_stat_delta("jmp_cond_tbnz", data->prev.jmp_cond_tbnz,
                              data->curr.jmp_cond_tbnz, elapsed,
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
  stats_write_arch_stat("B", stats_data_arch->num_b, num_instructions);
  stats_write_arch_stat("Bcc", stats_data_arch->num_bcc, num_instructions);
  stats_write_arch_stat("BL", stats_data_arch->num_bl, num_instructions);
  stats_write_arch_stat("BR", stats_data_arch->num_br, num_instructions);
  stats_write_arch_stat("CBZ", stats_data_arch->num_cbz, num_instructions);
  stats_write_arch_stat("CBNZ", stats_data_arch->num_cbnz, num_instructions);
  stats_write_arch_stat("RET", stats_data_arch->num_ret, num_instructions);
  stats_write_arch_stat("TBZ", stats_data_arch->num_tbz, num_instructions);
  stats_write_arch_stat("TBNZ", stats_data_arch->num_tbnz, num_instructions);
  stats_print("\n");
  stats_print("\n");

  stats_print("Relocated Instructions\n");
  stats_print("----------------------\n");
  stats_write_arch_stat("Total", stats_data_arch->num_reloc, num_instructions);

  stats_write_arch_stat("ADR", stats_data_arch->num_adr, num_instructions);
  stats_write_arch_stat("ADRP", stats_data_arch->num_adrp, num_instructions);
  stats_write_arch_stat("LDR", stats_data_arch->num_ldr, num_instructions);
  stats_write_arch_stat("LDRSW", stats_data_arch->num_ldrsw, num_instructions);

  stats_print("\n");
  stats_print("\n");

}

void stats_collect_arch(const cs_insn *instr, gboolean begin) {

  if (stats_data_arch == NULL) { return; }
  if (begin) { stats_data_arch->num_blocks++; }
  stats_data_arch->num_instructions++;

  switch (instr->id) {

    case ARM64_INS_ADR:
      stats_data_arch->num_adr++;
      stats_data_arch->num_reloc++;
      break;

    case ARM64_INS_ADRP:
      stats_data_arch->num_adrp++;
      stats_data_arch->num_reloc++;
      break;

    case ARM64_INS_B:
      switch (instr->detail->arm64.cc) {

        case ARM64_CC_INVALID:
        case ARM64_CC_AL:
        case ARM64_CC_NV:
          stats_data_arch->num_b++;
          break;
        default:
          stats_data_arch->num_bcc++;
          break;

      }

      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
      stats_data_arch->num_br++;
      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
      stats_data_arch->num_bl++;
      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_CBZ:
      stats_data_arch->num_cbz++;
      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_CBNZ:
      stats_data_arch->num_cbnz++;
      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_LDR:
      stats_data_arch->num_ldr++;
      stats_data_arch->num_reloc++;
      break;

    case ARM64_INS_LDRSW:
      stats_data_arch->num_ldrsw++;
      stats_data_arch->num_reloc++;
      break;

    case ARM64_INS_RET:
    case ARM64_INS_RETAA:
    case ARM64_INS_RETAB:
      stats_data_arch->num_ret++;
      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_TBZ:
      stats_data_arch->num_tbz++;
      stats_data_arch->num_eob++;
      break;

    case ARM64_INS_TBNZ:
      stats_data_arch->num_tbnz++;
      stats_data_arch->num_eob++;
      break;

    default:
      break;

  }

}

#endif

