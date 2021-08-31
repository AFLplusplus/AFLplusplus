#ifndef _STATS_H
#define _STATS_H

#include "frida-gumjs.h"

typedef struct {

  guint64 stats_time;
  guint64 total;
  guint64 call_imm;
  guint64 call_reg;
  guint64 call_mem;
  guint64 excluded_call_reg;
  guint64 ret_slow_path;
  guint64 ret;
  guint64 post_call_invoke;
  guint64 excluded_call_imm;
  guint64 jmp_imm;
  guint64 jmp_reg;
  guint64 jmp_mem;
  guint64 jmp_cond_imm;
  guint64 jmp_cond_mem;
  guint64 jmp_cond_reg;
  guint64 jmp_cond_jcxz;
  guint64 jmp_cond_cc;
  guint64 jmp_cond_cbz;
  guint64 jmp_cond_cbnz;
  guint64 jmp_cond_tbz;
  guint64 jmp_cond_tbnz;
  guint64 jmp_continuation;

} stats_t;

typedef struct {

  /* transitions */
  stats_t curr;
  stats_t prev;

} stats_data_t;

#define GUM_TYPE_AFL_STALKER_STATS (gum_afl_stalker_stats_get_type())
G_DECLARE_FINAL_TYPE(GumAflStalkerStats, gum_afl_stalker_stats, GUM,
                     AFL_STALKER_STATS, GObject)

extern char *  stats_filename;
extern guint64 stats_interval;

void stats_config(void);
void stats_init(void);
void stats_collect(const cs_insn *instr, gboolean begin);
void stats_print(char *format, ...);

void starts_arch_init(void);
void stats_collect_arch(const cs_insn *instr, gboolean begin);
void stats_write_arch(stats_data_t *data);
void stats_on_fork(void);

#endif

