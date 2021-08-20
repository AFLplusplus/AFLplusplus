#ifndef _PREFETCH_H
#define _PREFETCH_H

#include "frida-gumjs.h"

extern gboolean prefetch_enable;
extern gboolean prefetch_backpatch;

void prefetch_config(void);
void prefetch_init(void);
void prefetch_write(void *addr);
void prefetch_read(void);

#endif

