#include "frida-gum.h"

#include "debug.h"

#include "instrument.h"
#include "util.h"

#if defined(__arm__)

gboolean instrument_is_coverage_optimize_supported(void) {

  return false;

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);
  FATAL("Optimized coverage not supported on this architecture");

}

#endif

