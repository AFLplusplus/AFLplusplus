#include "frida-gumjs.h"

#include "debug.h"

#include "stats.h"
#include "util.h"

#if defined(__arm__)

void starts_arch_init(void) {

  FATAL("Stats not supported on this architecture");

}

void stats_write_arch(stats_data_t *data) {

  FATAL("Stats not supported on this architecture");

}

void stats_collect_arch(const cs_insn *instr, gboolean begin) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(begin);
  FATAL("Stats not supported on this architecture");

}

#endif

