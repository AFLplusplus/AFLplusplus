#include "frida-gum.h"

#include "debug.h"

#include "complog.h"
#include "util.h"

#if defined(__aarch64__)
void complog_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(iterator);
  if (__afl_cmp_map == NULL) { return; }
  FATAL("Complog mode not supported on this architecture");

}

#endif

