#include "frida-gum.h"

#include "debug.h"

#include "asan.h"
#include "util.h"

#if defined(__aarch64__)
void asan_instrument(const cs_insn *instr, GumStalkerIterator *iterator) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(iterator);
  if (asan_initialized) {

    FATAL("ASAN mode not supported on this architecture");

  }

}

#endif

