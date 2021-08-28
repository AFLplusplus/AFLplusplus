#include <dlfcn.h>

#include "frida-gumjs.h"

#include "debug.h"

#include "entry.h"
#include "instrument.h"
#include "persistent.h"
#include "ranges.h"
#include "seccomp.h"
#include "stalker.h"
#include "stats.h"
#include "util.h"

extern void __afl_manual_init();

guint64  entry_point = 0;
gboolean entry_compiled = FALSE;
gboolean entry_run = FALSE;

static void entry_launch(void) {

  OKF("Entry point reached");
  __afl_manual_init();

  /* Child here */
  entry_run = TRUE;
  instrument_on_fork();
  seccomp_on_fork();
  stats_on_fork();

}

void entry_config(void) {

  entry_point = util_read_address("AFL_ENTRYPOINT");

}

void entry_init(void) {

  OKF("entry_point: 0x%016" G_GINT64_MODIFIER "X", entry_point);

  if (dlopen(NULL, RTLD_NOW) == NULL) { FATAL("Failed to dlopen: %d", errno); }

}

void entry_start(void) {

  if (entry_point == 0) { entry_launch(); }

}

static void entry_callout(GumCpuContext *cpu_context, gpointer user_data) {

  UNUSED_PARAMETER(cpu_context);
  UNUSED_PARAMETER(user_data);
  entry_compiled = TRUE;
  entry_launch();

}

void entry_prologue(GumStalkerIterator *iterator, GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);
  OKF("AFL_ENTRYPOINT reached");

  if (persistent_start == 0) {

    ranges_exclude();
    stalker_trust();

  }

  gum_stalker_iterator_put_callout(iterator, entry_callout, NULL, NULL);

}

