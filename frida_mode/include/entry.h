#ifndef _ENTRY_H
#define _ENTRY_H

#include "frida-gum.h"

extern guint64 entry_start;

void entry_init(void);

void entry_run(void);

void entry_prologue(GumStalkerIterator *iterator, GumStalkerOutput *output);

#endif

