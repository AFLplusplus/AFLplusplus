#ifndef _UTIL_H
#define _UTIL_H

#include "frida-gumjs.h"

#include "debug.h"

#define UNUSED_PARAMETER(x) (void)(x)
#define IGNORED_RETURN(x) (void)!(x)

guint64 util_read_address(char *key);

guint64  util_read_num(char *key);
gboolean util_output_enabled(void);

#define FOKF(x...)                         \
  do {                                     \
                                           \
    if (!util_output_enabled()) { break; } \
                                           \
    OKF(x);                                \
                                           \
  } while (0)

#define FWARNF(x...) \
  do {               \
                     \
    WARNF(x);        \
                     \
  } while (0)

#define FFATAL(x...) \
  do {               \
                     \
    FATAL(x);        \
                     \
  } while (0)

#endif

