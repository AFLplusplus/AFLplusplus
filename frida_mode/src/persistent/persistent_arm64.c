#include <unistd.h>
#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "persistent.h"
#include "util.h"

#if defined(__aarch64__)

struct arm64_regs {

  uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10;

  union {

    uint64_t x11;
    uint32_t fp_32;

  };

  union {

    uint64_t x12;
    uint32_t ip_32;

  };

  union {

    uint64_t x13;
    uint32_t sp_32;

  };

  union {

    uint64_t x14;
    uint32_t lr_32;

  };

  union {

    uint64_t x15;
    uint32_t pc_32;

  };

  union {

    uint64_t x16;
    uint64_t ip0;

  };

  union {

    uint64_t x17;
    uint64_t ip1;

  };

  uint64_t x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28;

  union {

    uint64_t x29;
    uint64_t fp;

  };

  union {

    uint64_t x30;
    uint64_t lr;

  };

  union {

    uint64_t x31;
    uint64_t sp;

  };

  // the zero register is not saved here ofc

  uint64_t pc;

  uint32_t cpsr;

  uint8_t  vfp_zregs[32][16 * 16];
  uint8_t  vfp_pregs[17][32];
  uint32_t vfp_xregs[16];

};

typedef struct arm64_regs arch_api_regs;

static arch_api_regs saved_regs = {0};
static gpointer      saved_lr = NULL;

gboolean persistent_is_supported(void) {

  return true;

}

static void instrument_persitent_save_regs(GumArm64Writer *   cw,
                                           struct arm64_regs *regs) {

  GumAddress    regs_address = GUM_ADDRESS(regs);
  const guint32 mrs_x1_nzcv = 0xd53b4201;

  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X3,
                                              ARM64_REG_SP, -(16),
                                              GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_instruction(cw, mrs_x1_nzcv);

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X0,
                                       GUM_ADDRESS(regs_address));

  /* Skip x0 & x1 we'll do that later */

  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X3,
                                              ARM64_REG_X0, (16 * 1),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X4, ARM64_REG_X5,
                                              ARM64_REG_X0, (16 * 2),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X6, ARM64_REG_X7,
                                              ARM64_REG_X0, (16 * 3),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X8, ARM64_REG_X9,
                                              ARM64_REG_X0, (16 * 4),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X10, ARM64_REG_X11,
                                              ARM64_REG_X0, (16 * 5),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X12, ARM64_REG_X13,
                                              ARM64_REG_X0, (16 * 6),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X14, ARM64_REG_X15,
                                              ARM64_REG_X0, (16 * 7),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X16, ARM64_REG_X17,
                                              ARM64_REG_X0, (16 * 8),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X18, ARM64_REG_X19,
                                              ARM64_REG_X0, (16 * 9),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X20, ARM64_REG_X21,
                                              ARM64_REG_X0, (16 * 10),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X22, ARM64_REG_X23,
                                              ARM64_REG_X0, (16 * 11),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X24, ARM64_REG_X25,
                                              ARM64_REG_X0, (16 * 12),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X26, ARM64_REG_X27,
                                              ARM64_REG_X0, (16 * 13),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X28, ARM64_REG_X29,
                                              ARM64_REG_X0, (16 * 14),
                                              GUM_INDEX_SIGNED_OFFSET);

  /* LR & Adjusted SP */
  gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_X2, ARM64_REG_SP,
                                       (GUM_RED_ZONE_SIZE + 32));
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X30, ARM64_REG_X2,
                                              ARM64_REG_X0, (16 * 15),
                                              GUM_INDEX_SIGNED_OFFSET);

  /* PC & CPSR */
  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X2,
                                       GUM_ADDRESS(persistent_start));
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X1,
                                              ARM64_REG_X0, (16 * 16),
                                              GUM_INDEX_SIGNED_OFFSET);

  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_Q0, ARM64_REG_Q1,
                                              ARM64_REG_X0, (16 * 17),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_Q2, ARM64_REG_Q3,
                                              ARM64_REG_X0, (16 * 18),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_Q4, ARM64_REG_Q5,
                                              ARM64_REG_X0, (16 * 19),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_Q6, ARM64_REG_Q7,
                                              ARM64_REG_X0, (16 * 20),
                                              GUM_INDEX_SIGNED_OFFSET);

  /* x0 & x1 */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X3,
                                              ARM64_REG_SP, 16,
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X3,
                                              ARM64_REG_X0, (16 * 0),
                                              GUM_INDEX_SIGNED_OFFSET);

  /* Pop the saved values */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_SP, 16, GUM_INDEX_POST_ADJUST);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

}

static void instrument_persitent_restore_regs(GumArm64Writer *   cw,
                                              struct arm64_regs *regs) {

  GumAddress    regs_address = GUM_ADDRESS(regs);
  const guint32 msr_nzcv_x1 = 0xd51b4201;

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X0,
                                       GUM_ADDRESS(regs_address));

  /* Skip x0 - x3 we'll do that last */

  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X4, ARM64_REG_X5,
                                              ARM64_REG_X0, (16 * 2),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X6, ARM64_REG_X7,
                                              ARM64_REG_X0, (16 * 3),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X8, ARM64_REG_X9,
                                              ARM64_REG_X0, (16 * 4),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X10, ARM64_REG_X11,
                                              ARM64_REG_X0, (16 * 5),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X12, ARM64_REG_X13,
                                              ARM64_REG_X0, (16 * 6),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X14, ARM64_REG_X15,
                                              ARM64_REG_X0, (16 * 7),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X16, ARM64_REG_X17,
                                              ARM64_REG_X0, (16 * 8),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X18, ARM64_REG_X19,
                                              ARM64_REG_X0, (16 * 9),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X20, ARM64_REG_X21,
                                              ARM64_REG_X0, (16 * 10),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X22, ARM64_REG_X23,
                                              ARM64_REG_X0, (16 * 11),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X24, ARM64_REG_X25,
                                              ARM64_REG_X0, (16 * 12),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X26, ARM64_REG_X27,
                                              ARM64_REG_X0, (16 * 13),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X28, ARM64_REG_X29,
                                              ARM64_REG_X0, (16 * 14),
                                              GUM_INDEX_SIGNED_OFFSET);

  /* LR & Adjusted SP (use x1 as clobber) */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X30, ARM64_REG_X1,
                                              ARM64_REG_X0, (16 * 15),
                                              GUM_INDEX_SIGNED_OFFSET);

  gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_SP, ARM64_REG_X1);

  /* Don't restore RIP use x1-x3 as clobber */

  /* PC (x2) & CPSR (x1) */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X1,
                                              ARM64_REG_X0, (16 * 16),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_instruction(cw, msr_nzcv_x1);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_Q0, ARM64_REG_Q1,
                                              ARM64_REG_X0, (16 * 17),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_Q2, ARM64_REG_Q3,
                                              ARM64_REG_X0, (16 * 18),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_Q4, ARM64_REG_Q5,
                                              ARM64_REG_X0, (16 * 19),
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_Q6, ARM64_REG_Q7,
                                              ARM64_REG_X0, (16 * 20),
                                              GUM_INDEX_SIGNED_OFFSET);

  /* x2 & x3 */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X3,
                                              ARM64_REG_X0, (16 * 1),
                                              GUM_INDEX_SIGNED_OFFSET);
  /* x0 & x1 */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X0, ARM64_REG_X1,
                                              ARM64_REG_X0, (16 * 0),
                                              GUM_INDEX_SIGNED_OFFSET);

}

static void instrument_exit(GumArm64Writer *cw) {

  gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_call_address_with_arguments(
      cw, GUM_ADDRESS(_exit), 1, GUM_ARG_REGISTER, ARM64_REG_X0);

}

static int instrument_afl_persistent_loop_func(void) {

  int ret = __afl_persistent_loop(persistent_count);
  previous_pc = 0;
  return ret;

}

static void instrument_afl_persistent_loop(GumArm64Writer *cw) {

  gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_SP, ARM64_REG_SP,
                                       GUM_RED_ZONE_SIZE);
  gum_arm64_writer_put_call_address_with_arguments(
      cw, GUM_ADDRESS(instrument_afl_persistent_loop_func), 0);
  gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_SP, ARM64_REG_SP,
                                       GUM_RED_ZONE_SIZE);

}

static void persistent_prologue_hook(GumArm64Writer *   cw,
                                     struct arm64_regs *regs) {

  if (hook == NULL) return;

  gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_SP, ARM64_REG_SP,
                                       GUM_RED_ZONE_SIZE);
  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X3,
                                       GUM_ADDRESS(&__afl_fuzz_len));
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X3, ARM64_REG_X3, 0);
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X3, ARM64_REG_X3, 0);

  gum_arm64_writer_put_and_reg_reg_imm(cw, ARM64_REG_X3, ARM64_REG_X3,
                                       G_MAXULONG);

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X2,
                                       GUM_ADDRESS(&__afl_fuzz_ptr));
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X2, 0);

  gum_arm64_writer_put_call_address_with_arguments(
      cw, GUM_ADDRESS(hook), 4, GUM_ARG_ADDRESS, GUM_ADDRESS(regs),
      GUM_ARG_ADDRESS, GUM_ADDRESS(0), GUM_ARG_REGISTER, ARM64_REG_X2,
      GUM_ARG_REGISTER, ARM64_REG_X3);

  gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_SP, ARM64_REG_SP,
                                       GUM_RED_ZONE_SIZE);

}

static void instrument_persitent_save_lr(GumArm64Writer *cw) {

  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X0,
                                       GUM_ADDRESS(&saved_lr));

  gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG_LR, ARM64_REG_X0, 0);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

}

void persistent_prologue(GumStalkerOutput *output) {

  /*
   *  SAVE REGS
   *  SAVE RET
   *  POP RET
   * loop:
   *  CALL instrument_afl_persistent_loop
   *  TEST EAX, EAX
   *  JZ end:
   *  call hook (optionally)
   *  RESTORE REGS
   *  call original
   *  jmp loop:
   *
   * end:
   *  JMP SAVED RET
   *
   * original:
   *  INSTRUMENTED PERSISTENT FUNC
   */

  GumArm64Writer *cw = output->writer.arm64;

  gconstpointer loop = cw->code + 1;

  instrument_persitent_save_regs(cw, &saved_regs);

  /* loop: */
  gum_arm64_writer_put_label(cw, loop);

  /* call instrument_prologue_func */
  instrument_afl_persistent_loop(cw);

  /* jz done */
  gconstpointer done = cw->code + 1;
  gum_arm64_writer_put_cmp_reg_reg(cw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_b_cond_label(cw, ARM64_CC_EQ, done);

  /* Optionally call the persistent hook */
  persistent_prologue_hook(cw, &saved_regs);

  instrument_persitent_restore_regs(cw, &saved_regs);
  gconstpointer original = cw->code + 1;
  /* call original */

  gum_arm64_writer_put_bl_label(cw, original);

  /* jmp loop */
  gum_arm64_writer_put_b_label(cw, loop);

  /* done: */
  gum_arm64_writer_put_label(cw, done);

  instrument_exit(cw);

  /* original: */
  gum_arm64_writer_put_label(cw, original);

  instrument_persitent_save_lr(cw);

  if (persistent_debug) { gum_arm64_writer_put_brk_imm(cw, 0); }

}

void persistent_epilogue(GumStalkerOutput *output) {

  GumArm64Writer *cw = output->writer.arm64;

  if (persistent_debug) { gum_arm64_writer_put_brk_imm(cw, 0); }

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X0,
                                       GUM_ADDRESS(&saved_lr));

  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X0, ARM64_REG_X0, 0);

  gum_arm64_writer_put_br_reg(cw, ARM64_REG_X0);

}

#endif

