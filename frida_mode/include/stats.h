#ifndef _STATS_H
#define _STATS_H

#include "frida-gumjs.h"

typedef struct {

  guint64 num_blocks;
  guint64 num_instructions;
  guint64 stats_last_time;
  guint64 stats_idx;
  guint64 transitions_idx;

} stats_data_header_t;

extern stats_data_header_t *stats_data;

extern char *   stats_filename;
extern guint64  stats_interval;
extern gboolean stats_transitions;

void stats_config(void);
void stats_init(void);
void stats_collect(const cs_insn *instr, gboolean begin);
void stats_print(char *format, ...);

gboolean stats_is_supported_arch(void);
size_t   stats_data_size_arch(void);
void     stats_collect_arch(const cs_insn *instr);
void     stats_write_arch(void);

#endif

