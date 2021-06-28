#ifndef _INTERCEPTOR_H
#define _INTERCEPTOR_H

#include "frida-gumjs.h"

void intercept_hook(void *address, gpointer replacement, gpointer user_data);
void intercept_unhook(void *address);
void intercept_unhook_self(void);

#endif

