#include "frida-gumjs.h"

#include "seccomp.h"
#include "util.h"

char *seccomp_filename = NULL;

void seccomp_on_fork(void) {

  if (seccomp_filename == NULL) { return; }

#ifdef __APPLE__
  FFATAL("Seccomp not supported on OSX");
#else
  seccomp_callback_parent();
#endif

}

void seccomp_config(void) {

  seccomp_filename = getenv("AFL_FRIDA_SECCOMP_FILE");

}

void seccomp_init(void) {

  FOKF(cBLU "Seccomp" cRST " - " cGRN "file:" cYEL " [%s]",
       seccomp_filename == NULL ? " " : seccomp_filename);

  if (seccomp_filename == NULL) { return; }

#ifdef __APPLE__
  FFATAL("Seccomp not supported on OSX");
#else
  seccomp_callback_initialize();
#endif

}

