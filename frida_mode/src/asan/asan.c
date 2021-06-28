#include "frida-gumjs.h"

#include "debug.h"

#include "asan.h"

static gboolean asan_enabled = FALSE;
gboolean        asan_initialized = FALSE;

void asan_config(void) {

  if (getenv("AFL_USE_FASAN") != NULL) {

    OKF("Frida ASAN mode enabled");
    asan_enabled = TRUE;

  } else {

    OKF("Frida ASAN mode disabled");

  }

}

void asan_init(void) {

  if (asan_enabled) {

    asan_arch_init();
    asan_initialized = TRUE;

  }

}

