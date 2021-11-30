#ifndef _UTIL_H
#define _UTIL_H

#include "frida-gumjs.h"

#include "debug.h"

#define UNUSED_PARAMETER(x) (void)(x)
#define IGNORED_RETURN(x) (void)!(x)

guint64  util_read_address(char *key, guint64 default_value);
guint64  util_read_num(char *key, guint64 default_value);
gboolean util_output_enabled(void);
gsize    util_rotate(gsize val, gsize shift, gsize size);
gsize    util_log2(gsize val);

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

