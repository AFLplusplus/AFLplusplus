#include <unistd.h>
#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"
#include "persistent.h"
#include "util.h"

#if defined(__x86_64__)

typedef struct {

  GumCpuContext ctx;
  uint64_t      rflags;

} persistent_ctx_t;

static persistent_ctx_t saved_regs = {0};
static gpointer         persistent_loop = NULL;

gboolean persistent_is_supported(void) {

  return true;

}

static void instrument_persitent_save_regs(GumX86Writer     *cw,
                                           persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  /* Should be pushing FPU here, but meh */
  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_X86_RAX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RAX, regs_address);

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rbx), GUM_X86_RBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rcx), GUM_X86_RCX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rdx), GUM_X86_RDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rdi), GUM_X86_RDI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rsi), GUM_X86_RSI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rbp), GUM_X86_RBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r8), GUM_X86_R8);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r9), GUM_X86_R9);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r10), GUM_X86_R10);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r11), GUM_X86_R11);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r12), GUM_X86_R12);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r13), GUM_X86_R13);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r14), GUM_X86_R14);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, r15), GUM_X86_R15);

  /* Store RIP */
  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RBX,
                                     GUM_ADDRESS(persistent_start));

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rip), GUM_X86_RBX);

  /* Store adjusted RSP */
  gum_x86_writer_put_mov_reg_reg(cw, GUM_X86_RBX, GUM_X86_RSP);

  /* RED_ZONE + Saved flags, RAX, alignment */
  gum_x86_writer_put_add_reg_imm(cw, GUM_X86_RBX,
                                 GUM_RED_ZONE_SIZE + (0x8 * 2));
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rsp), GUM_X86_RBX);

  /* Save the flags */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBX, GUM_X86_RSP, 0x8);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(persistent_ctx_t, rflags), GUM_X86_RBX);

  /* Save the RAX */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBX, GUM_X86_RSP, 0x0);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_RAX, offsetof(GumCpuContext, rax), GUM_X86_RBX);

  /* Pop the saved values */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP, 0x10);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void instrument_persitent_restore_regs(GumX86Writer     *cw,
                                              persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);
  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RAX, regs_address);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RCX, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rcx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RDX, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rdx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RDI, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rdi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RSI, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rsi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBP, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rbp));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R8, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r8));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R9, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r9));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R10, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r10));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R11, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r11));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R12, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r12));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R13, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r13));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R14, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r14));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_R15, GUM_X86_RAX,
                                            offsetof(GumCpuContext, r15));

  /* Don't restore RIP */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RSP, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rsp));

  /* Restore RBX, RAX & Flags */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBX, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rbx));
  gum_x86_writer_put_push_reg(cw, GUM_X86_RBX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBX, GUM_X86_RAX,
                                            offsetof(GumCpuContext, rax));
  gum_x86_writer_put_push_reg(cw, GUM_X86_RBX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBX, GUM_X86_RAX,
                                            offsetof(persistent_ctx_t, rflags));
  gum_x86_writer_put_push_reg(cw, GUM_X86_RBX);

  gum_x86_writer_put_popfx(cw);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_RAX);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_RBX);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void instrument_afl_persistent_loop_func(void) {

  if (__afl_persistent_loop(persistent_count) == 0) { _exit(0); }

  if (instrument_previous_pc_addr == NULL) {

    FATAL("instrument_previous_pc_addr uninitialized");

  }

  *instrument_previous_pc_addr = instrument_hash_zero;

}

static void instrument_afl_persistent_loop(GumX86Writer *cw) {

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        -(GUM_RED_ZONE_SIZE));
  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(instrument_afl_persistent_loop_func), 0);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void persistent_prologue_hook(GumX86Writer *cw, persistent_ctx_t *regs) {

  if (persistent_hook == NULL) return;
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RDX,
                                     GUM_ADDRESS(&__afl_fuzz_len));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RDX, GUM_X86_RDX, 0);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RDX, GUM_X86_RDX, 0);
  gum_x86_writer_put_mov_reg_u64(cw, GUM_X86_RDI, 0xffffffff);
  gum_x86_writer_put_and_reg_reg(cw, GUM_X86_RDX, GUM_X86_RDI);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RSI,
                                     GUM_ADDRESS(&__afl_fuzz_ptr));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RSI, GUM_X86_RSI, 0);

  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(persistent_hook), 3, GUM_ARG_ADDRESS,
      GUM_ADDRESS(&regs->ctx), GUM_ARG_REGISTER, GUM_X86_RSI, GUM_ARG_REGISTER,
      GUM_X86_RDX);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void instrument_persitent_save_ret(GumX86Writer *cw) {

  /* Stack usage by this function */
  gssize offset = GUM_RED_ZONE_SIZE + (3 * 8);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_X86_RAX);
  gum_x86_writer_put_push_reg(cw, GUM_X86_RBX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RAX,
                                     GUM_ADDRESS(&persistent_ret));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_RBX, GUM_X86_RSP,
                                            offset);
  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_X86_RAX, GUM_X86_RBX);

  gum_x86_writer_put_pop_reg(cw, GUM_X86_RBX);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_RAX);
  gum_x86_writer_put_popfx(cw);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

void persistent_prologue_arch(GumStalkerOutput *output) {

  /*
   *  SAVE RET (Used to write the epilogue if persistent_ret is not set)
   *  SAVE REGS
   * loop: (Save address of where the eiplogue should jump back to)
   *  CALL instrument_afl_persistent_loop
   *  CALL hook (optionally)
   *  RESTORE REGS
   *  INSTRUMENTED PERSISTENT FUNC
   */

  GumX86Writer *cw = output->writer.x86;

  FVERBOSE("Persistent loop reached");

  /*
   * If we haven't set persistent_ret, then assume that we are dealing with a
   * function and we should loop when that function returns.
   */
  if (persistent_ret == 0) { instrument_persitent_save_ret(cw); }

  /* Save the current context */
  instrument_persitent_save_regs(cw, &saved_regs);

  /* Store a pointer to where we should return for our next iteration */
  persistent_loop = gum_x86_writer_cur(cw);

  /* call __afl_persistent_loop and _exit if zero. Also reset our previous_pc */
  instrument_afl_persistent_loop(cw);

  /* Optionally call the persistent hook */
  persistent_prologue_hook(cw, &saved_regs);

  /* Restore our CPU context before we continue execution */
  instrument_persitent_restore_regs(cw, &saved_regs);

  if (persistent_debug) { gum_x86_writer_put_breakpoint(cw); }

  /* The original instrumented code is emitted here. */

}

void persistent_epilogue_arch(GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;

  if (persistent_debug) { gum_x86_writer_put_breakpoint(cw); }

  /* The stack should be aligned when we re-enter our loop */
  gconstpointer zero = cw->code + 1;
  gum_x86_writer_put_test_reg_u32(cw, GUM_X86_RSP, 0xF);
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, zero, GUM_NO_HINT);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_RSP, GUM_X86_RSP, -8);
  gum_x86_writer_put_label(cw, zero);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RAX,
                                     GUM_ADDRESS(&persistent_loop));
  gum_x86_writer_put_jmp_reg_ptr(cw, GUM_X86_RAX);

}

#endif

