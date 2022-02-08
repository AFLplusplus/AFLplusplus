#include <dlfcn.h>

#if defined(__linux__) && !defined(__ANDROID__)
  #include <sys/prctl.h>
#endif

#include "frida-gumjs.h"

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
gboolean traceable = FALSE;
gboolean entry_compiled = FALSE;
gboolean entry_run = FALSE;

static void entry_launch(void) {

  FVERBOSE("Entry point reached");
  __afl_manual_init();

  /* Child here */
  entry_run = TRUE;
  entry_on_fork();
  instrument_on_fork();
  seccomp_on_fork();
  stats_on_fork();

}

#if defined(__linux__) && defined(PR_SET_PTRACER) && !defined(__ANDROID__)
void entry_on_fork(void) {

  if (traceable) {

    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) < 0) {

      FFATAL("Failed to PR_SET_PTRACER");

    }

  }

}

#else
void entry_on_fork(void) {

  if (traceable) { FWARNF("AFL_FRIDA_TRACEABLE unsupported"); }

}

#endif

void entry_config(void) {

  entry_point = util_read_address("AFL_ENTRYPOINT", 0);
  if (getenv("AFL_FRIDA_TRACEABLE") != NULL) { traceable = TRUE; }

}

void entry_init(void) {

  FVERBOSE("Entry Point: 0x%016" G_GINT64_MODIFIER "X", entry_point);
  FVERBOSE("Dumpable: [%c]", traceable ? 'X' : ' ');

  if (dlopen(NULL, RTLD_NOW) == NULL) { FFATAL("Failed to dlopen: %d", errno); }

}

void entry_start(void) {

  if (persistent_start == 0) {

    ranges_exclude();
    stalker_trust();

  }

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
  FVERBOSE("AFL_ENTRYPOINT reached");

  if (persistent_start == 0) {

    ranges_exclude();
    stalker_trust();

  }

  gum_stalker_iterator_put_callout(iterator, entry_callout, NULL, NULL);

}

