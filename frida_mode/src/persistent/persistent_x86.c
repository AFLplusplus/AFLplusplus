#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "persistent.h"

#if defined(__i386__)

typedef struct {

  GumCpuContext ctx;
  uint32_t      eflags;

} persistent_ctx_t;

static persistent_ctx_t saved_regs = {0};

static gpointer saved_ret = NULL;

gboolean persistent_is_supported(void) {

  return true;

}

static void instrument_persitent_save_regs(GumX86Writer *    cw,
                                           persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);

  /* Should be pushing FPU here, but meh */
  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_EAX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EAX, regs_address);

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, ebx), GUM_REG_EBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, ecx), GUM_REG_ECX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, edx), GUM_REG_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, edi), GUM_REG_EDI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, esi), GUM_REG_ESI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, ebp), GUM_REG_EBP);

  /* Store RIP */
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EBX,
                                     GUM_ADDRESS(persistent_start));

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, eip), GUM_REG_EBX);

  /* Store adjusted RSP */
  gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_EBX, GUM_REG_ESP);

  /* RED_ZONE + Saved flags, RAX */
  gum_x86_writer_put_add_reg_imm(cw, GUM_REG_EBX, (0x4 * 2));
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, esp), GUM_REG_EBX);

  /* Save the flags */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBX, GUM_REG_ESP, 0x4);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(persistent_ctx_t, eflags), GUM_REG_EBX);

  /* Save the RAX */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBX, GUM_REG_ESP, 0x0);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_REG_EAX, offsetof(GumCpuContext, eax), GUM_REG_EBX);

  /* Pop the saved values */
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_ESP, GUM_REG_ESP, 0x8);

}

static void instrument_persitent_restore_regs(GumX86Writer *    cw,
                                              persistent_ctx_t *regs) {

  GumAddress regs_address = GUM_ADDRESS(regs);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EAX, regs_address);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_ECX, GUM_REG_EAX,
                                            offsetof(GumCpuContext, ecx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EDX, GUM_REG_EAX,
                                            offsetof(GumCpuContext, edx));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EDI, GUM_REG_EAX,
                                            offsetof(GumCpuContext, edi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_ESI, GUM_REG_EAX,
                                            offsetof(GumCpuContext, esi));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBP, GUM_REG_EAX,
                                            offsetof(GumCpuContext, ebp));

  /* Don't restore RIP */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_ESP, GUM_REG_EAX,
                                            offsetof(GumCpuContext, esp));

  /* Restore RBX, RAX & Flags */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBX, GUM_REG_EAX,
                                            offsetof(GumCpuContext, ebx));
  gum_x86_writer_put_push_reg(cw, GUM_REG_EBX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBX, GUM_REG_EAX,
                                            offsetof(GumCpuContext, eax));
  gum_x86_writer_put_push_reg(cw, GUM_REG_EBX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBX, GUM_REG_EAX,
                                            offsetof(persistent_ctx_t, eflags));
  gum_x86_writer_put_push_reg(cw, GUM_REG_EBX);

  gum_x86_writer_put_popfx(cw);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_EAX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_EBX);

}

static void instrument_exit(GumX86Writer *cw) {

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EAX, GUM_ADDRESS(_exit));
  gum_x86_writer_put_mov_reg_u32(cw, GUM_REG_EDI, 0);
  gum_x86_writer_put_push_reg(cw, GUM_REG_EDI);
  gum_x86_writer_put_call_reg(cw, GUM_REG_EAX);

}

static int instrument_afl_persistent_loop_func(void) {

  int ret = __afl_persistent_loop(persistent_count);
  instrument_previous_pc = instrument_hash_zero;
  return ret;

}

static void instrument_afl_persistent_loop(GumX86Writer *cw) {

  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(instrument_afl_persistent_loop_func), 0);
  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_EAX, GUM_REG_EAX);

}

static void persistent_prologue_hook(GumX86Writer *cw, persistent_ctx_t *regs) {

  if (persistent_hook == NULL) return;

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_ECX,
                                     GUM_ADDRESS(&__afl_fuzz_len));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_ECX, GUM_REG_ECX, 0);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_ECX, GUM_REG_ECX, 0);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EDX,
                                     GUM_ADDRESS(&__afl_fuzz_ptr));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EDX, GUM_REG_EDX, 0);

  /* Base address is 64-bits (hence two zero arguments) */
  gum_x86_writer_put_call_address_with_arguments(
      cw, GUM_CALL_CAPI, GUM_ADDRESS(persistent_hook), 3, GUM_ARG_ADDRESS,
      GUM_ADDRESS(&regs->ctx), GUM_ARG_REGISTER, GUM_REG_EDX, GUM_ARG_REGISTER,
      GUM_REG_ECX);

}

static void instrument_persitent_save_ret(GumX86Writer *cw) {

  /* Stack usage by this function */
  gssize offset = (3 * 4);

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_EAX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_EBX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EAX, GUM_ADDRESS(&saved_ret));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_EBX, GUM_REG_ESP,
                                            offset);
  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_REG_EAX, GUM_REG_EBX);

  gum_x86_writer_put_pop_reg(cw, GUM_REG_EBX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_EAX);
  gum_x86_writer_put_popfx(cw);

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
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_ESP, GUM_REG_ESP, 4);

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

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EAX, GUM_ADDRESS(&saved_ret));
  gum_x86_writer_put_jmp_reg_ptr(cw, GUM_REG_EAX);

}

#endif

