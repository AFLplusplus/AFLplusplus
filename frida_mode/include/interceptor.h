#include "frida-gum.h"

void intercept(void *address, gpointer replacement, gpointer user_data);
void unintercept(void *address);
void unintercept_self();

