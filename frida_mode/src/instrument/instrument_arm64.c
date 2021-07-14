#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"

#if defined(__aarch64__)

static GumAddress current_log_impl = GUM_ADDRESS(0);

static const guint8 afl_log_code[] = {

    // __afl_area_ptr[current_pc ^ previous_pc]++;
    // previous_pc = current_pc ROR 1;
    0xE1, 0x0B, 0xBF, 0xA9,  // stp x1, x2, [sp, -0x10]!
    0xE3, 0x13, 0xBF, 0xA9,  // stp x3, x4, [sp, -0x10]!

    // x0 = current_pc
    0x21, 0x02, 0x00, 0x58,  // ldr x1, #0x44, =&__afl_area_ptr
    0x21, 0x00, 0x40, 0xf9,  // ldr x1, [x1] (=__afl_area_ptr)

    0x22, 0x02, 0x00, 0x58,  // ldr x2, #0x44, =&previous_pc
    0x42, 0x00, 0x40, 0xf9,  // ldr x2, [x2] (=previous_pc)

    // __afl_area_ptr[current_pc ^ previous_pc]++;
    0x42, 0x00, 0x00, 0xca,  // eor x2, x2, x0
    0x23, 0x68, 0x62, 0xf8,  // ldr x3, [x1, x2]
    0x63, 0x04, 0x00, 0x91,  // add x3, x3, #1
    0x63, 0x00, 0x1f, 0x9a,  // adc x3, x3, xzr
    0x23, 0x68, 0x22, 0xf8,  // str x3, [x1, x2]

    // previous_pc = current_pc ROR 1;
    0xe4, 0x07, 0x40, 0x8b,  // add x4, xzr, x0, LSR #1
    0xe0, 0xff, 0x00, 0x8b,  // add x0, xzr, x0, LSL #63
    0x80, 0xc0, 0x40, 0x8b,  // add x0, x4, x0, LSR #48

    0xe2, 0x00, 0x00, 0x58,  // ldr x2, #0x1c, =&previous_pc
    0x40, 0x00, 0x00, 0xf9,  // str x0, [x2]

    0xE3, 0x13, 0xc1, 0xA8,  // ldp x3, x4, [sp], #0x10
    0xE1, 0x0B, 0xc1, 0xA8,  // ldp x1, x2, [sp], #0x10
    0xC0, 0x03, 0x5F, 0xD6,  // ret

    // &afl_area_ptr_ptr
    // &afl_prev_loc_ptr

};

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  guint64 current_pc = instr->address;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  GumArm64Writer *cw = output->writer.arm64;

  if (current_log_impl == 0 ||
      !gum_arm64_writer_can_branch_directly_between(cw, cw->pc,
                                                    current_log_impl) ||
      !gum_arm64_writer_can_branch_directly_between(cw, cw->pc + 128,
                                                    current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_arm64_writer_put_b_label(cw, after_log_impl);

    current_log_impl = cw->pc;
    gum_arm64_writer_put_bytes(cw, afl_log_code, sizeof(afl_log_code));

    uint8_t **afl_area_ptr_ptr = &__afl_area_ptr;
    uint64_t *afl_prev_loc_ptr = &instrument_previous_pc;
    gum_arm64_writer_put_bytes(cw, (const guint8 *)&afl_area_ptr_ptr,
                               sizeof(afl_area_ptr_ptr));
    gum_arm64_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                               sizeof(afl_prev_loc_ptr));

    gum_arm64_writer_put_label(cw, after_log_impl);

  }

  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_LR, ARM64_REG_X0, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X0, area_offset);
  gum_arm64_writer_put_bl_imm(cw, current_log_impl);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_LR, ARM64_REG_X0, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_arm64_writer_flush(output->writer.arm64);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_arm64_writer_cur(output->writer.arm64);

}

#endif

