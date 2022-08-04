#include "frida-gumjs.h"

#include "instrument.h"
#include "util.h"

#if defined(__arm__)

gboolean instrument_cache_enabled = FALSE;
gsize    instrument_cache_size = 0;

gboolean instrument_is_coverage_optimize_supported(void) {

  return false;

}

void instrument_coverage_optimize(const cs_insn    *instr,
                                  GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);
  FFATAL("Optimized coverage not supported on this architecture");

}

void instrument_coverage_optimize_insn(const cs_insn    *instr,
                                       GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);
  FFATAL("Optimized coverage not supported on this architecture");

}

void instrument_coverage_optimize_init(void) {

  FWARNF("Optimized coverage not supported on this architecture");

}

void instrument_flush(GumStalkerOutput *output) {

  if (output->encoding == GUM_INSTRUCTION_SPECIAL) {

    gum_thumb_writer_flush(output->writer.thumb);

  } else {

    gum_arm_writer_flush(output->writer.arm);

  }

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_arm_writer_cur(output->writer.arm);

}

void instrument_cache_config(void) {

}

void instrument_cache_init(void) {

}

void instrument_cache_insert(gpointer real_address, gpointer code_address) {

  UNUSED_PARAMETER(real_address);
  UNUSED_PARAMETER(code_address);

}

void instrument_cache(const cs_insn *instr, GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);

}

void instrument_write_regs(GumCpuContext *cpu_context, gpointer user_data) {

  int fd = (int)user_data;
  instrument_regs_format(fd,
                         "r0 : 0x%08x, r1 : 0x%08x, r2 : 0x%08x, r3 : 0x%08x\n",
                         cpu_context->r[0], cpu_context->r[2],
                         cpu_context->r[1], cpu_context->r[3]);
  instrument_regs_format(fd,
                         "r4 : 0x%08x, r5 : 0x%08x, r6 : 0x%08x, r7 : 0x%08x\n",
                         cpu_context->r[4], cpu_context->r[5],
                         cpu_context->r[6], cpu_context->r[7]);
  instrument_regs_format(
      fd, "r8 : 0x%08x, r9 : 0x%08x, r10: 0x%08x, r11: 0x%08x\n",
      cpu_context->r8, cpu_context->r9, cpu_context->r10, cpu_context->r11);
  instrument_regs_format(
      fd, "r12: 0x%08x, sp : 0x%08x, lr : 0x%08x, pc : 0x%08x\n",
      cpu_context->r12, cpu_context->sp, cpu_context->lr, cpu_context->pc);
  instrument_regs_format(fd, "cpsr: 0x%08x\n\n", cpu_context->cpsr);

}

#endif

