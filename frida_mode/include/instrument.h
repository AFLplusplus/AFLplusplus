#include "frida-gum.h"

#include "config.h"

extern uint64_t __thread previous_pc;
extern uint8_t *__afl_area_ptr;
extern uint32_t __afl_map_size;

void instrument_init();

GumStalkerTransformer *instrument_get_transformer();

/* Functions to be implemented by the different architectures */
gboolean instrument_is_coverage_optimize_supported();

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output);

