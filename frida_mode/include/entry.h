#ifndef _ENTRY_H
#define _ENTRY_H

#include "frida-gumjs.h"

extern guint64  entry_point;
extern gboolean traceable;
extern gboolean entry_compiled;
extern gboolean entry_run;

void entry_config(void);

void entry_init(void);

void entry_start(void);

void entry_on_fork(void);

#endif

