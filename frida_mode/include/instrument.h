#ifndef _INSTRUMENT_H
#define _INSTRUMENT_H

#include "frida-gumjs.h"

#include "config.h"

extern char *   instrument_debug_filename;
extern char *   instrument_coverage_filename;
extern gboolean instrument_tracing;
extern gboolean instrument_optimize;
extern gboolean instrument_unique;
extern guint64  instrument_hash_zero;
extern char *   instrument_coverage_unstable_filename;
extern gboolean instrument_coverage_insn;

extern gboolean instrument_use_fixed_seed;
extern guint64  instrument_fixed_seed;

extern uint8_t *__afl_area_ptr;
extern uint32_t __afl_map_size;

extern __thread guint64 *instrument_previous_pc_addr;

extern gboolean instrument_cache_enabled;
extern gsize    instrument_cache_size;

void instrument_config(void);

void instrument_init(void);

GumStalkerTransformer *instrument_get_transformer(void);

/* Functions to be implemented by the different architectures */
gboolean instrument_is_coverage_optimize_supported(void);

void instrument_coverage_optimize_init(void);
void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output);
void instrument_coverage_optimize_insn(const cs_insn *   instr,
                                       GumStalkerOutput *output);

void     instrument_debug_config(void);
void     instrument_debug_init(void);
void     instrument_debug_start(uint64_t address, GumStalkerOutput *output);
void     instrument_debug_instruction(uint64_t address, uint16_t size,
                                      GumStalkerOutput *output);
void     instrument_debug_end(GumStalkerOutput *output);
void     instrument_flush(GumStalkerOutput *output);
gpointer instrument_cur(GumStalkerOutput *output);

void instrument_coverage_config(void);
void instrument_coverage_init(void);
void instrument_coverage_start(uint64_t address);
void instrument_coverage_end(uint64_t address);

void instrument_coverage_unstable(guint64 edge, guint64 previous_rip,
                                  guint64 previous_end, guint64 current_rip,
                                  guint64 current_end);

void instrument_on_fork(void);

guint64 instrument_get_offset_hash(GumAddress current_rip);

void instrument_cache_config(void);
void instrument_cache_init(void);
void instrument_cache_insert(gpointer real_address, gpointer code_address);
void instrument_cache(const cs_insn *instr, GumStalkerOutput *output);

#endif

