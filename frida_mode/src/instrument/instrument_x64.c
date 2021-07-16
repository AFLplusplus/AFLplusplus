#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"

#if defined(__x86_64__)

static GumAddress current_log_impl = GUM_ADDRESS(0);

static const guint8 afl_log_code[] = {

    0x9c,                                                         /* pushfq */
    0x51,                                                       /* push rcx */
    0x52,                                                       /* push rdx */

    0x48, 0x8b, 0x0d, 0x26,
    0x00, 0x00, 0x00,                          /* mov rcx, sym.&previous_pc */
    0x48, 0x8b, 0x11,                               /* mov rdx, qword [rcx] */
    0x48, 0x31, 0xfa,                                       /* xor rdx, rdi */

    0x48, 0x03, 0x15, 0x11,
    0x00, 0x00, 0x00,                     /* add rdx, sym._afl_area_ptr_ptr */

    0x80, 0x02, 0x01,                              /* add byte ptr [rdx], 1 */
    0x80, 0x12, 0x00,                              /* adc byte ptr [rdx], 0 */
    0x66, 0xd1, 0xcf,                                          /* ror di, 1 */
    0x48, 0x89, 0x39,                               /* mov qword [rcx], rdi */

    0x5a,                                                        /* pop rdx */
    0x59,                                                        /* pop rcx */
    0x9d,                                                          /* popfq */

    0xc3,                                                            /* ret */

    0x90

    /* Read-only data goes here: */
    /* uint8_t* __afl_area_ptr */
    /* uint64_t* &previous_pc */

};

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static guint8 align_pad[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

static void instrument_coverate_write_function(GumStalkerOutput *output) {

  guint64       misalign = 0;
  GumX86Writer *cw = output->writer.x86;

  if (current_log_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, current_log_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

    misalign = (cw->pc & 0x7);
    if (misalign != 0) {

      gum_x86_writer_put_bytes(cw, align_pad, 8 - misalign);

    }

    current_log_impl = cw->pc;
    gum_x86_writer_put_bytes(cw, afl_log_code, sizeof(afl_log_code));

    uint64_t *afl_prev_loc_ptr = &instrument_previous_pc;
    gum_x86_writer_put_bytes(cw, (const guint8 *)&__afl_area_ptr,
                             sizeof(__afl_area_ptr));
    gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                             sizeof(afl_prev_loc_ptr));

    gum_x86_writer_put_label(cw, after_log_impl);

  }

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  instrument_coverate_write_function(output);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDI, area_offset);
  gum_x86_writer_put_call_address(cw, current_log_impl);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        GUM_RED_ZONE_SIZE);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

