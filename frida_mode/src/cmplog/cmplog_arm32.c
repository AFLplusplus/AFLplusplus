#include "frida-gumjs.h"

#include "debug.h"

#include "frida_cmplog.h"
#include "util.h"

#if defined(__arm__)
void cmplog_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(iterator);
  if (__afl_cmp_map == NULL) { return; }
  FATAL("CMPLOG mode not supported on this architecture");

}

#endif

