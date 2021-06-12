#ifndef _RANGES_H
#define _RANGES_H

#include "frida-gum.h"

void ranges_init(void);

gboolean range_is_excluded(gpointer address);

void ranges_exclude();

#endif

