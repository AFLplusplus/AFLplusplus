#include "util.h"

#include "debug.h"

guint64 util_read_address(char *key) {

  char *value_str = getenv(key);

  if (value_str == NULL) { return 0; }

  if (!g_str_has_prefix(value_str, "0x")) {

    FATAL("Invalid address should have 0x prefix: %s\n", value_str);

  }

  value_str = &value_str[2];

  for (char *c = value_str; *c != '\0'; c++) {

    if (!g_ascii_isxdigit(*c)) {

      FATAL("Invalid address not formed of hex digits: %s\n", value_str);

    }

  }

  guint64 value = g_ascii_strtoull(value_str, NULL, 16);
  if (value == 0) {

    FATAL("Invalid address failed hex conversion: %s\n", value_str);

  }

  return value;

}

guint64 util_read_num(char *key) {

  char *value_str = getenv(key);

  if (value_str == NULL) { return 0; }

  for (char *c = value_str; *c != '\0'; c++) {

    if (!g_ascii_isdigit(*c)) {

      FATAL("Invalid address not formed of decimal digits: %s\n", value_str);

    }

  }

  guint64 value = g_ascii_strtoull(value_str, NULL, 10);
  if (value == 0) {

    FATAL("Invalid address failed numeric conversion: %s\n", value_str);

  }

  return value;

}

