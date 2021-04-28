#ifndef _INTERCEPTOR_H
#define _INTERCEPTOR_H

#include "frida-gum.h"

void intercept(void *address, gpointer replacement, gpointer user_data);
void unintercept(void *address);
void unintercept_self(void);

#endif

