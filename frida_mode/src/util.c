#include "util.h"

gboolean util_verbose = FALSE;

guint64 util_read_address(char *key, guint64 default_value) {

  char *value_str = getenv(key);
  char *end_ptr;

  if (value_str == NULL) { return default_value; }

  if (!g_str_has_prefix(value_str, "0x")) {

    FATAL("Invalid address should have 0x prefix: %s=%s\n", key, value_str);

  }

  char *value_str2 = &value_str[2];

  for (char *c = value_str2; *c != '\0'; c++) {

    if (!g_ascii_isxdigit(*c)) {

      FATAL("Invalid address not formed of hex digits: %s=%s ('%c')\n", key,
            value_str, *c);

    }

  }

  errno = 0;

  guint64 value = g_ascii_strtoull(value_str2, &end_ptr, 16);

  if (errno != 0) {

    FATAL("Error (%d) during conversion: %s", errno, value_str);

  }

  if (value == 0 && end_ptr == value_str2) {

    FATAL("Invalid address failed hex conversion: %s=%s\n", key, value_str2);

  }

  return value;

}

guint64 util_read_num(char *key, guint64 default_value) {

  char *value_str = getenv(key);
  char *end_ptr;

  if (value_str == NULL) { return default_value; }

  for (char *c = value_str; *c != '\0'; c++) {

    if (!g_ascii_isdigit(*c)) {

      FATAL("Invalid address not formed of decimal digits: %s=%s\n", key,
            value_str);

    }

  }

  errno = 0;

  guint64 value = g_ascii_strtoull(value_str, &end_ptr, 10);

  if (errno != 0) {

    FATAL("Error (%d) during conversion: %s", errno, value_str);

  }

  if (value == 0 && end_ptr == value_str) {

    FATAL("Invalid address failed numeric conversion: %s=%s\n", key, value_str);

  }

  return value;

}

gboolean util_output_enabled(void) {

  static gboolean initialized = FALSE;
  static gboolean enabled = FALSE;

  if (!initialized) {

    initialized = TRUE;
    if (getenv("AFL_DEBUG_CHILD") != NULL) { enabled = TRUE; }
    if (util_verbose_enabled()) { enabled = TRUE; }

  }

  return enabled;

}

gboolean util_verbose_enabled(void) {

  static gboolean initialized = FALSE;

  if (!initialized) {

    initialized = TRUE;
    if (getenv("AFL_FRIDA_VERBOSE") || getenv("AFL_DEBUG")) {

      util_verbose = TRUE;

    }

  }

  return util_verbose;

}

gsize util_rotate(gsize val, gsize shift, gsize size) {

  if (shift == 0) { return val; }
  gsize result = ((val >> shift) | (val << (size - shift)));
  result = result & ((1 << size) - 1);
  return result;

}

gsize util_log2(gsize val) {

  for (gsize i = 0; i < 64; i++) {

    if (((gsize)1 << i) == val) { return i; }

  }

  FFATAL("Not a power of two");

}

