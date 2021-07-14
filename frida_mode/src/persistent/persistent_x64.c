#include <unistd.h>
#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "persistent.h"
#include "util.h"

#if defined(__x86_64__)

typedef struct {

  GumCpuContext ctx;
  uint64_t      rflags;

} persistent_ctx_t;

static persistent_ctx_t saved_regs = {0};
static gpointer         saved_ret = NULL;

gboolean persistent_is_supported(void) {

  return true;

}

static void instrument_persitent_save_regs(GumX86Writer *    cw,
                                           persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  /* Should be pushing FPU here, but meh */
  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RAX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RAX, regs_address);

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rbx), GUM_REG_RBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rcx), GUM_REG_RCX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rdx), GUM_REG_RDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rdi), GUM_REG_RDI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rsi), GUM_REG_RSI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rbp), GUM_REG_RBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r8), GUM_REG_R8);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r9), GUM_REG_R9);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r10), GUM_REG_R10);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r11), GUM_REG_R11);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r12), GUM_REG_R12);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r13), GUM_REG_R13);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r14), GUM_REG_R14);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, r15), GUM_REG_R15);

  /* Store RIP */
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RBX,
                                     GUM_ADDRESS(persistent_start));

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rip), GUM_REG_RBX);

  /* Store adjusted RSP */
  gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_RBX, GUM_REG_RSP);

  /* RED_ZONE + Saved flags, RAX, alignment */
  gum_x86_writer_put_add_reg_imm(cw, GUM_REG_RBX,
                                 GUM_RED_ZONE_SIZE + (0x8 * 2));
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rsp), GUM_REG_RBX);

  /* Save the flags */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSP, 0x8);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(persistent_ctx_t, rflags), GUM_REG_RBX);

  /* Save the RAX */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSP, 0x0);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_RAX, offsetof(GumCpuContext, rax), GUM_REG_RBX);

  /* Pop the saved values */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP, 0x10);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void instrument_persitent_restore_regs(GumX86Writer *    cw,
                                              persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RAX, regs_address);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RCX, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rcx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RDX, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rdx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RDI, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rdi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RSI, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rsi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBP, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rbp));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R8, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r8));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R9, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r9));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R10, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r10));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R11, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r11));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R12, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r12));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R13, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r13));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R14, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r14));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_R15, GUM_REG_RAX,
                                            offsetof(GumCpuContext, r15));

  /* Don't restore RIP */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RSP, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rsp));

  /* Restore RBX, RAX & Flags */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rbx));
  gum_x86_writer_put_push_reg(cw, GUM_REG_RBX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RAX,
                                            offsetof(GumCpuContext, rax));
  gum_x86_writer_put_push_reg(cw, GUM_REG_RBX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RAX,
                                            offsetof(persistent_ctx_t, rflags));
  gum_x86_writer_put_push_reg(cw, GUM_REG_RBX);

  gum_x86_writer_put_popfx(cw);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RBX);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void instrument_exit(GumX86Writer *cw) {

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RAX, GUM_ADDRESS(_exit));
  gum_x86_writer_put_mov_reg_u32(cw, GUM_REG_RDI, 0);
  gum_x86_writer_put_call_reg(cw, GUM_REG_RAX);

}

static int instrument_afl_persistent_loop_func(void) {

  int ret = __afl_persistent_loop(persistent_count);
  instrument_previous_pc = instrument_hash_zero;
  return ret;

}

static void instrument_afl_persistent_loop(GumX86Writer *cw) {

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));
  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(instrument_afl_persistent_loop_func), 0);
  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_RAX, GUM_REG_RAX);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void persistent_prologue_hook(GumX86Writer *cw, persistent_ctx_t *regs) {

  if (persistent_hook == NULL) return;
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX,
                                     GUM_ADDRESS(&__afl_fuzz_len));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RDX, GUM_REG_RDX, 0);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RDX, GUM_REG_RDX, 0);
  gum_x86_writer_put_mov_reg_u64(cw, GUM_REG_RDI, 0xffffffff);
  gum_x86_writer_put_and_reg_reg(cw, GUM_REG_RDX, GUM_REG_RDI);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RSI,
                                     GUM_ADDRESS(&__afl_fuzz_ptr));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RSI, GUM_REG_RSI, 0);

  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(persistent_hook), 3, GUM_ARG_ADDRESS,
      GUM_ADDRESS(&regs->ctx), GUM_ARG_REGISTER, GUM_REG_RSI, GUM_ARG_REGISTER,
      GUM_REG_RDX);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void instrument_persitent_save_ret(GumX86Writer *cw) {

  /* Stack usage by this function */
  gssize offset = GUM_RED_ZONE_SIZE + (3 * 8);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RBX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RAX, GUM_ADDRESS(&saved_ret));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSP,
                                            offset);
  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_REG_RAX, GUM_REG_RBX);

  gum_x86_writer_put_pop_reg(cw, GUM_REG_RBX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_popfx(cw);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

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

  GumX86Writer *cw = output->writer.x86;

  gconstpointer loop = cw->code + 1;

  OKF("Persistent loop reached");

  /* Pop the return value */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP, 8);

  instrument_persitent_save_regs(cw, &saved_regs);

  /* loop: */
  gum_x86_writer_put_label(cw, loop);

  /* call instrument_prologue_func */
  instrument_afl_persistent_loop(cw);

  /* jz done */
  gconstpointer done = cw->code + 1;
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, done, GUM_UNLIKELY);

  /* Optionally call the persistent hook */
  persistent_prologue_hook(cw, &saved_regs);

  instrument_persitent_restore_regs(cw, &saved_regs);
  gconstpointer original = cw->code + 1;
  /* call original */

  gum_x86_writer_put_call_near_label(cw, original);

  /* jmp loop */
  gum_x86_writer_put_jmp_near_label(cw, loop);

  /* done: */
  gum_x86_writer_put_label(cw, done);

  instrument_exit(cw);

  /* original: */
  gum_x86_writer_put_label(cw, original);

  instrument_persitent_save_ret(cw);

  if (persistent_debug) { gum_x86_writer_put_breakpoint(cw); }

}

void persistent_epilogue_arch(GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;

  if (persistent_debug) { gum_x86_writer_put_breakpoint(cw); }

  /* The stack should be aligned when we re-enter our loop */
  gconstpointer zero = cw->code + 1;
  gum_x86_writer_put_test_reg_u32(cw, GUM_REG_RSP, 0xF);
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, zero, GUM_NO_HINT);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP, -8);
  gum_x86_writer_put_label(cw, zero);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RAX, GUM_ADDRESS(&saved_ret));
  gum_x86_writer_put_jmp_reg_ptr(cw, GUM_REG_RAX);

}

#endif

