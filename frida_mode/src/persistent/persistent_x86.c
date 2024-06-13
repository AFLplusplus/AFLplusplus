#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"
#include "persistent.h"
#include "util.h"

#if defined(__i386__)

typedef struct {

  GumCpuContext ctx;
  uint32_t      eflags;

} persistent_ctx_t;

static persistent_ctx_t saved_regs = {0};
static gpointer         persistent_loop = NULL;

gboolean persistent_is_supported(void) {

  return true;

}

static void instrument_persitent_save_regs(GumX86Writer     *cw,
                                           persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);

  /* Should be pushing FPU here, but meh */
  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_X86_EAX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_EAX, regs_address);

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, ebx), GUM_X86_EBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, ecx), GUM_X86_ECX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, edx), GUM_X86_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, edi), GUM_X86_EDI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, esi), GUM_X86_ESI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, ebp), GUM_X86_EBP);

  /* Store RIP */
  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_EBX,
                                     GUM_ADDRESS(persistent_start));

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, eip), GUM_X86_EBX);

  /* Store adjusted RSP */
  gum_x86_writer_put_mov_reg_reg(cw, GUM_X86_EBX, GUM_X86_ESP);

  /* RED_ZONE + Saved flags, RAX */
  gum_x86_writer_put_add_reg_imm(cw, GUM_X86_EBX, (0x4 * 2));
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, esp), GUM_X86_EBX);

  /* Save the flags */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBX, GUM_X86_ESP, 0x4);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(persistent_ctx_t, eflags), GUM_X86_EBX);

  /* Save the RAX */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBX, GUM_X86_ESP, 0x0);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_EAX, offsetof(GumCpuContext, eax), GUM_X86_EBX);

  /* Pop the saved values */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_ESP, GUM_X86_ESP, 0x8);

}

static void instrument_persitent_restore_regs(GumX86Writer     *cw,
                                              persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);
  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_EAX, regs_address);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_ECX, GUM_X86_EAX,
                                            offsetof(GumCpuContext, ecx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EDX, GUM_X86_EAX,
                                            offsetof(GumCpuContext, edx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EDI, GUM_X86_EAX,
                                            offsetof(GumCpuContext, edi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_ESI, GUM_X86_EAX,
                                            offsetof(GumCpuContext, esi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBP, GUM_X86_EAX,
                                            offsetof(GumCpuContext, ebp));

  /* Don't restore RIP */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_ESP, GUM_X86_EAX,
                                            offsetof(GumCpuContext, esp));

  /* Restore RBX, RAX & Flags */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBX, GUM_X86_EAX,
                                            offsetof(GumCpuContext, ebx));
  gum_x86_writer_put_push_reg(cw, GUM_X86_EBX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBX, GUM_X86_EAX,
                                            offsetof(GumCpuContext, eax));
  gum_x86_writer_put_push_reg(cw, GUM_X86_EBX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBX, GUM_X86_EAX,
                                            offsetof(persistent_ctx_t, eflags));
  gum_x86_writer_put_push_reg(cw, GUM_X86_EBX);

  gum_x86_writer_put_popfx(cw);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_EAX);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_EBX);

}

static void instrument_afl_persistent_loop_func(void) {

  if (__afl_persistent_loop(persistent_count) == 0) { _exit(0); };

  if (instrument_previous_pc_addr == NULL) {

    FATAL("instrument_previous_pc_addr uninitialized");

  }

  *instrument_previous_pc_addr = instrument_hash_zero;

}

static void instrument_afl_persistent_loop(GumX86Writer *cw) {

  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(instrument_afl_persistent_loop_func), 0);

}

static void persistent_prologue_hook(GumX86Writer *cw, persistent_ctx_t *regs) {

  if (persistent_hook == NULL) return;

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_ECX,
                                     GUM_ADDRESS(&__afl_fuzz_len));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_ECX, GUM_X86_ECX, 0);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_ECX, GUM_X86_ECX, 0);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_EDX,
                                     GUM_ADDRESS(&__afl_fuzz_ptr));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EDX, GUM_X86_EDX, 0);

  /* Base address is 64-bits (hence two zero arguments) */
  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(persistent_hook), 3, GUM_ARG_ADDRESS,
      GUM_ADDRESS(&regs->ctx), GUM_ARG_REGISTER, GUM_X86_EDX, GUM_ARG_REGISTER,
      GUM_X86_ECX);

}

static void instrument_persitent_save_ret(GumX86Writer *cw) {

  /* Stack usage by this function */
  gssize offset = (3 * 4);

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_X86_EAX);
  gum_x86_writer_put_push_reg(cw, GUM_X86_EBX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_EAX,
                                     GUM_ADDRESS(&persistent_ret));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_EBX, GUM_X86_ESP,
                                            offset);
  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_X86_EAX, GUM_X86_EBX);

  gum_x86_writer_put_pop_reg(cw, GUM_X86_EBX);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_EAX);
  gum_x86_writer_put_popfx(cw);

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
  gum_x86_writer_put_and_reg_u32(cw, GUM_X86_ESP, 0xfffffff0);
  gum_x86_writer_put_sub_reg_imm(cw, GUM_X86_ESP, 0x4);

  gum_x86_writer_put_mov_reg_address(cw, GUM_X86_EAX,
                                     GUM_ADDRESS(&persistent_loop));
  gum_x86_writer_put_jmp_reg_ptr(cw, GUM_X86_EAX);

}

#endif

