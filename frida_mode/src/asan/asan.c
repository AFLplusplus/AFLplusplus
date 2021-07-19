#include "frida-gum.h"

#include "debug.h"

#include "asan.h"

gboolean asan_initialized = FALSE;

void asan_init(void) {

  if (getenv("AFL_USE_FASAN") != NULL) {

    OKF("Frida ASAN mode enabled");
    asan_arch_init();
    asan_initialized = TRUE;

  } else {

    OKF("Frida ASAN mode disabled");

  }

}

