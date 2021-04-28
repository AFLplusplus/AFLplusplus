#ifndef _COMPLOG_H
#define _COMPLOG_H

extern struct cmp_map *__afl_cmp_map;

void complog_init(void);

/* Functions to be implemented by the different architectures */
void complog_instrument(const cs_insn *instr, GumStalkerIterator *iterator);

gboolean complog_is_readable(void *addr, size_t size);

#endif

