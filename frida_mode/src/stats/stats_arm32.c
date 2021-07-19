#include "frida-gumjs.h"

#include "debug.h"

#include "stats.h"
#include "util.h"

#if defined(__arm__)

gboolean stats_is_supported_arch(void) {

  return FALSE;

}

size_t stats_data_size_arch(void) {

  FATAL("Stats not supported on this architecture");

}

void stats_write_arch(void) {

  FATAL("Stats not supported on this architecture");

}

void stats_collect_arch(const cs_insn *instr) {

  UNUSED_PARAMETER(instr);
  FATAL("Stats not supported on this architecture");

}

#endif

