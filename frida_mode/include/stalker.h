#ifndef _STALKER_H
#define _STALKER_H

#include "frida-gumjs.h"

extern guint stalker_ic_entries;

void        stalker_config(void);
void        stalker_init(void);
GumStalker *stalker_get(void);
void        stalker_start(void);
void        stalker_trust(void);

GumStalkerObserver *stalker_get_observer(void);

#endif

