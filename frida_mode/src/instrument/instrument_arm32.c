#include "frida-gum.h"

#include "debug.h"

#include "instrument.h"

#if defined(__arm__)

gboolean instrument_is_coverage_optimize_supported() {

  return false;

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  FATAL("Optimized coverage not supported on this architecture");

}

#endif

