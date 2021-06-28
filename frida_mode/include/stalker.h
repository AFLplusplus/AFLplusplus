#ifndef _STALKER_H
#define _STALKER_H

#include "frida-gumjs.h"

void        stalker_config(void);
void        stalker_init(void);
GumStalker *stalker_get(void);
void        stalker_start(void);

#endif

