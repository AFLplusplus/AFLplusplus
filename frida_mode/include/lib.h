#ifndef _LIB_H
#define _LIB_H

#include "frida-gum.h"

void lib_init(void);

guint64 lib_get_text_base(void);

guint64 lib_get_text_limit(void);

#endif

