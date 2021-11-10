#include "util.h"

guint64 util_read_address(char *key) {

  char *value_str = getenv(key);

  if (value_str == NULL) { return 0; }

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

  guint64 value = g_ascii_strtoull(value_str2, NULL, 16);
  if (value == 0) {

    FATAL("Invalid address failed hex conversion: %s=%s\n", key, value_str2);

  }

  return value;

}

guint64 util_read_num(char *key) {

  char *value_str = getenv(key);

  if (value_str == NULL) { return 0; }

  for (char *c = value_str; *c != '\0'; c++) {

    if (!g_ascii_isdigit(*c)) {

      FATAL("Invalid address not formed of decimal digits: %s=%s\n", key,
            value_str);

    }

  }

  guint64 value = g_ascii_strtoull(value_str, NULL, 10);
  if (value == 0) {

    FATAL("Invalid address failed numeric conversion: %s=%s\n", key, value_str);

  }

  return value;

}

gboolean util_output_enabled(void) {

  static gboolean initialized = FALSE;
  static gboolean enabled = TRUE;

  if (!initialized) {

    initialized = TRUE;
    if (getenv("AFL_DEBUG_CHILD") == NULL) { enabled = FALSE; }

  }

  return enabled;

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

