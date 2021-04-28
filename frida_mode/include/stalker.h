#ifndef _STALKER_H
#define _STALKER_H

#include "frida-gum.h"

void        stalker_init(void);
GumStalker *stalker_get(void);
void        stalker_start(void);
void        stalker_pause(void);
void        stalker_resume(void);

#endif

