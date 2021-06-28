#ifndef _UTIL_H
#define _UTIL_H

#include "frida-gumjs.h"

#define UNUSED_PARAMETER(x) (void)(x)
#define IGNORED_RETURN(x) (void)!(x)

guint64 util_read_address(char *key);

guint64 util_read_num(char *key);

#endif

