#ifndef _CMPLOG_H
#define _CMPLOG_H

extern struct cmp_map *__afl_cmp_map;

void cmplog_config(void);
void cmplog_init(void);

/* Functions to be implemented by the different architectures */
void cmplog_instrument(const cs_insn *instr, GumStalkerIterator *iterator);

gboolean cmplog_is_readable(guint64 addr, size_t size);

#endif

