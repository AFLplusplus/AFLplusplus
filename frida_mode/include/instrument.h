#ifndef _INSTRUMENT_H
#define _INSTRUMENT_H

#include "frida-gum.h"

#include "config.h"

extern __thread uint64_t previous_pc;
extern uint8_t *         __afl_area_ptr;
extern uint32_t          __afl_map_size;

void instrument_init(void);

GumStalkerTransformer *instrument_get_transformer(void);

/* Functions to be implemented by the different architectures */
gboolean instrument_is_coverage_optimize_supported(void);

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output);

#endif

