#include "frida-gumjs.h"

#include "asan.h"
#include "util.h"

#if defined(__arm__)
void asan_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(iterator);
  if (asan_initialized) {

    FFATAL("ASAN mode not supported on this architecture");

  }

}

void asan_arch_init(void) {

  FFATAL("ASAN mode not supported on this architecture");

}

#endif

