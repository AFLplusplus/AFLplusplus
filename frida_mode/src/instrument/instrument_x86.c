#include "frida-gumjs.h"

#include "debug.h"

#include "instrument.h"
#include "util.h"

#if defined(__i386__)

static GumAddress current_log_impl = GUM_ADDRESS(0);

static void instrument_coverage_function(GumX86Writer *cw) {

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_ECX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_EDX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_ECX,
                                     GUM_ADDRESS(&instrument_previous_pc));
  gum_x86_writer_put_mov_reg_reg_ptr(cw, GUM_REG_EDX, GUM_REG_ECX);
  gum_x86_writer_put_xor_reg_reg(cw, GUM_REG_EDX, GUM_REG_EDI);

  gum_x86_writer_put_add_reg_imm(cw, GUM_REG_EDX, GUM_ADDRESS(__afl_area_ptr));

  /* add byte ptr [edx], 1 */
  uint8_t add_byte_ptr_edx_1[] = {0x80, 0x02, 0x01};
  gum_x86_writer_put_bytes(cw, add_byte_ptr_edx_1, sizeof(add_byte_ptr_edx_1));

  /* adc byte ptr [edx], 0 */
  uint8_t adc_byte_ptr_edx_0[] = {0x80, 0x12, 0x00};
  gum_x86_writer_put_bytes(cw, adc_byte_ptr_edx_0, sizeof(adc_byte_ptr_edx_0));

  uint8_t ror_di_1[] = {0x66, 0xd1, 0xcf};
  gum_x86_writer_put_bytes(cw, ror_di_1, sizeof(ror_di_1));
  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_REG_ECX, GUM_REG_EDI);

  gum_x86_writer_put_pop_reg(cw, GUM_REG_EDX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_ECX);
  gum_x86_writer_put_popfx(cw);
  gum_x86_writer_put_ret(cw);

}

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static void instrument_coverate_write_function(GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;

  if (current_log_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, current_log_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

    current_log_impl = cw->pc;
    instrument_coverage_function(cw);

    gum_x86_writer_put_label(cw, after_log_impl);

  }

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  instrument_coverate_write_function(output);

  gum_x86_writer_put_push_reg(cw, GUM_REG_EDI);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_EDI, area_offset);
  gum_x86_writer_put_call_address(cw, current_log_impl);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_EDI);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

