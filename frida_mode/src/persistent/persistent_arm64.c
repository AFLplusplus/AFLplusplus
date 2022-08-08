#include <unistd.h>
#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"
#include "persistent.h"
#include "util.h"

#if defined(__aarch64__)
typedef struct {

  GumCpuContext ctx;
  uint64_t      rflags;

} persistent_ctx_t;

static persistent_ctx_t saved_regs = {0};
static gpointer         saved_lr = NULL;

gboolean persistent_is_supported(void) {

  return true;

}

static void instrument_persitent_save_regs(GumArm64Writer   *cw,
                                           persistent_ctx_t *regs) {

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

  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_X0,
      offsetof(GumCpuContext, x[2]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X0,
      offsetof(GumCpuContext, x[4]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X6, ARM64_REG_X7, ARM64_REG_X0,
      offsetof(GumCpuContext, x[6]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X0,
      offsetof(GumCpuContext, x[8]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X10, ARM64_REG_X11, ARM64_REG_X0,
      offsetof(GumCpuContext, x[10]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X0,
      offsetof(GumCpuContext, x[12]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X14, ARM64_REG_X15, ARM64_REG_X0,
      offsetof(GumCpuContext, x[14]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X0,
      offsetof(GumCpuContext, x[16]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X18, ARM64_REG_X19, ARM64_REG_X0,
      offsetof(GumCpuContext, x[18]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X0,
      offsetof(GumCpuContext, x[20]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X22, ARM64_REG_X23, ARM64_REG_X0,
      offsetof(GumCpuContext, x[22]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X0,
      offsetof(GumCpuContext, x[24]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X26, ARM64_REG_X27, ARM64_REG_X0,
      offsetof(GumCpuContext, x[26]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X28, ARM64_REG_X29, ARM64_REG_X0,
      offsetof(GumCpuContext, x[28]), GUM_INDEX_SIGNED_OFFSET);

  /* LR (x30) */
  gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG_X30, ARM64_REG_X0,
                                          offsetof(GumCpuContext, lr));

  /* PC & Adjusted SP (31) */
  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X2,
                                       GUM_ADDRESS(persistent_start));
  gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_X3, ARM64_REG_SP,
                                       (GUM_RED_ZONE_SIZE + 32));
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_X0, offsetof(GumCpuContext, pc),
      GUM_INDEX_SIGNED_OFFSET);

  /* CPSR */
  gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG_X1, ARM64_REG_X0,
                                          offsetof(persistent_ctx_t, rflags));

  /* Q */
  for (int i = 0; i < 16; i++) {

    gum_arm64_writer_put_stp_reg_reg_reg_offset(
        cw, ARM64_REG_Q0 + (i * 2), ARM64_REG_Q0 + (i * 2) + 1, ARM64_REG_X0,
        offsetof(GumCpuContext, v[i]), GUM_INDEX_SIGNED_OFFSET);

  }

  /* x0 & x1 */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X3,
                                              ARM64_REG_SP, 16,
                                              GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_X0,
      offsetof(GumCpuContext, x[0]), GUM_INDEX_SIGNED_OFFSET);

  /* Pop the saved values */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_SP, 16, GUM_INDEX_POST_ADJUST);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

}

static void instrument_persitent_restore_regs(GumArm64Writer   *cw,
                                              persistent_ctx_t *regs) {

  GumAddress    regs_address = GUM_ADDRESS(regs);
  const guint32 msr_nzcv_x1 = 0xd51b4201;

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X0,
                                       GUM_ADDRESS(regs_address));

  /* Skip x0 - x3 we'll do that last */

  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X0,
      offsetof(GumCpuContext, x[4]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X6, ARM64_REG_X7, ARM64_REG_X0,
      offsetof(GumCpuContext, x[6]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X0,
      offsetof(GumCpuContext, x[8]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X10, ARM64_REG_X11, ARM64_REG_X0,
      offsetof(GumCpuContext, x[10]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X0,
      offsetof(GumCpuContext, x[12]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X14, ARM64_REG_X15, ARM64_REG_X0,
      offsetof(GumCpuContext, x[14]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X0,
      offsetof(GumCpuContext, x[16]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X18, ARM64_REG_X19, ARM64_REG_X0,
      offsetof(GumCpuContext, x[18]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X0,
      offsetof(GumCpuContext, x[20]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X22, ARM64_REG_X23, ARM64_REG_X0,
      offsetof(GumCpuContext, x[22]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X0,
      offsetof(GumCpuContext, x[24]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X26, ARM64_REG_X27, ARM64_REG_X0,
      offsetof(GumCpuContext, x[26]), GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X28, ARM64_REG_X29, ARM64_REG_X0,
      offsetof(GumCpuContext, x[28]), GUM_INDEX_SIGNED_OFFSET);

  /* LR (x30) */
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X30, ARM64_REG_X0,
                                          offsetof(GumCpuContext, lr));

  /* Adjusted SP (31) (use x1 as clobber)*/
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X1, ARM64_REG_X0,
                                          offsetof(GumCpuContext, sp));
  gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_SP, ARM64_REG_X1);

  /* CPSR */
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X1, ARM64_REG_X0,
                                          offsetof(persistent_ctx_t, rflags));
  gum_arm64_writer_put_instruction(cw, msr_nzcv_x1);

  /* Q */
  for (int i = 0; i < 16; i++) {

    gum_arm64_writer_put_ldp_reg_reg_reg_offset(
        cw, ARM64_REG_Q0 + (i * 2), ARM64_REG_Q0 + (i * 2) + 1, ARM64_REG_X0,
        offsetof(GumCpuContext, v[i]), GUM_INDEX_SIGNED_OFFSET);

  }

  /* x2 & x3 */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X2, ARM64_REG_X3, ARM64_REG_X0,
      offsetof(GumCpuContext, x[2]), GUM_INDEX_SIGNED_OFFSET);
  /* x0 & x1 */
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X0,
      offsetof(GumCpuContext, x[0]), GUM_INDEX_SIGNED_OFFSET);

}

static void instrument_exit(GumArm64Writer *cw) {

  gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_call_address_with_arguments(
      cw, GUM_ADDRESS(_exit), 1, GUM_ARG_REGISTER, ARM64_REG_X0);

}

static int instrument_afl_persistent_loop_func(void) {

  int ret = __afl_persistent_loop(persistent_count);
  if (instrument_previous_pc_addr == NULL) {

    FATAL("instrument_previous_pc_addr uninitialized");

  }

  *instrument_previous_pc_addr = instrument_hash_zero;
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

static void persistent_prologue_hook(GumArm64Writer   *cw,
                                     persistent_ctx_t *regs) {

  if (persistent_hook == NULL) return;

  gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_SP, ARM64_REG_SP,
                                       GUM_RED_ZONE_SIZE);
  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X2,
                                       GUM_ADDRESS(&__afl_fuzz_len));
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X2, 0);
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X2, ARM64_REG_X2, 0);

  gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_W2, ARM64_REG_W2);

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X1,
                                       GUM_ADDRESS(&__afl_fuzz_ptr));
  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X1, ARM64_REG_X1, 0);

  gum_arm64_writer_put_call_address_with_arguments(
      cw, GUM_ADDRESS(persistent_hook), 3, GUM_ARG_ADDRESS,
      GUM_ADDRESS(&regs->ctx), GUM_ARG_REGISTER, ARM64_REG_X1, GUM_ARG_REGISTER,
      ARM64_REG_X2);

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

void persistent_prologue_arch(GumStalkerOutput *output) {

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

  FVERBOSE("Persistent loop reached");

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

void persistent_epilogue_arch(GumStalkerOutput *output) {

  GumArm64Writer *cw = output->writer.arm64;

  if (persistent_debug) { gum_arm64_writer_put_brk_imm(cw, 0); }

  gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X0,
                                       GUM_ADDRESS(&saved_lr));

  gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X0, ARM64_REG_X0, 0);

  gum_arm64_writer_put_br_reg(cw, ARM64_REG_X0);

}

#endif

