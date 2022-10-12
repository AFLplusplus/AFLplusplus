#include "frida-gumjs.h"

#include "stats.h"
#include "util.h"

#if defined(__arm__)

void starts_arch_init(void) {

  FFATAL("Stats not supported on this architecture");

}

void stats_write_arch(stats_data_t *data) {

  UNUSED_PARAMETER(data);
  FFATAL("Stats not supported on this architecture");

}

void stats_collect_arch(const cs_insn *instr, gboolean begin) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(begin);
  FFATAL("Stats not supported on this architecture");

}

#endif

