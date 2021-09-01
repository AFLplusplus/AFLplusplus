#include <stdarg.h>

#include "seccomp.h"
#include "util.h"

#ifndef __APPLE__

static void seccomp_print_v(int fd, char *format, va_list ap) {

  char buffer[4096] = {0};
  int  len;

  if (vsnprintf(buffer, sizeof(buffer) - 1, format, ap) < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));
  IGNORED_RETURN(write(fd, buffer, len));

}

void seccomp_print(char *format, ...) {

  va_list ap;
  va_start(ap, format);
  seccomp_print_v(SECCOMP_OUTPUT_FILE_FD, format, ap);
  va_end(ap);

}

#endif

