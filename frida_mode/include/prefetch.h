#ifndef _PREFETCH_H
#define _PREFETCH_H

#include "frida-gum.h"

void prefetch_init(void);
void prefetch_write(void *addr);
void prefetch_read(void);

#endif

