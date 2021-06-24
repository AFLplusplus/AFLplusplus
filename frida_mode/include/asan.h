#ifndef _ASAN_H
#define _ASAN_H

#include "frida-gumjs.h"

extern gboolean asan_initialized;

void asan_config(void);
void asan_init(void);
void asan_arch_init(void);
void asan_instrument(const cs_insn *instr, GumStalkerIterator *iterator);

#endif

