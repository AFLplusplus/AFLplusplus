#include "frida-gumjs.h"

#include "instrument.h"
#include "util.h"

#if defined(__arm__)

gboolean instrument_cache_enabled = FALSE;
gsize    instrument_cache_size = 0;

gboolean instrument_is_coverage_optimize_supported(void) {

  return false;

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);
  FFATAL("Optimized coverage not supported on this architecture");

}

void instrument_coverage_optimize_insn(const cs_insn *   instr,
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

#endif

