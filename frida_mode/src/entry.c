#include "frida-gum.h"

#include "debug.h"

#include "entry.h"
#include "instrument.h"
#include "stalker.h"
#include "util.h"

extern void __afl_manual_init();

guint64 entry_start = 0;

static void entry_launch(void) {

  __afl_manual_init();

  /* Child here */
  previous_pc = 0;

}

void entry_init(void) {

  entry_start = util_read_address("AFL_ENTRYPOINT");
  OKF("entry_point: 0x%016" G_GINT64_MODIFIER "X", entry_start);

}

void entry_run(void) {

  if (entry_start == 0) { entry_launch(); }

}

static void entry_callout(GumCpuContext *cpu_context, gpointer user_data) {

  UNUSED_PARAMETER(cpu_context);
  UNUSED_PARAMETER(user_data);
  entry_launch();

}

void entry_prologue(GumStalkerIterator *iterator, GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);
  gum_stalker_iterator_put_callout(iterator, entry_callout, NULL, NULL);

}

