#include "debug.h"

#include "instrument.h"
#include "stalker.h"
#include "util.h"

static GumStalker *stalker = NULL;

void stalker_config(void) {

  if (!gum_stalker_is_supported()) { FATAL("Failed to initialize embedded"); }

}

static gboolean stalker_exclude_self(const GumRangeDetails *details,
                                     gpointer               user_data) {

  UNUSED_PARAMETER(user_data);
  gchar *     name;
  gboolean    found;
  GumStalker *stalker;
  if (details->file == NULL) { return TRUE; }
  name = g_path_get_basename(details->file->path);

  found = (g_strcmp0(name, "afl-frida-trace.so") == 0);
  g_free(name);
  if (!found) { return TRUE; }

  stalker = stalker_get();
  gum_stalker_exclude(stalker, details->range);

  return FALSE;

}

void stalker_init(void) {

  stalker = gum_stalker_new();
  if (stalker == NULL) { FATAL("Failed to initialize stalker"); }

  gum_stalker_set_trust_threshold(stalker, 0);

  /* *NEVER* stalk the stalker, only bad things will ever come of this! */
  gum_process_enumerate_ranges(GUM_PAGE_EXECUTE, stalker_exclude_self, NULL);

}

GumStalker *stalker_get(void) {

  if (stalker == NULL) { FATAL("Stalker uninitialized"); }
  return stalker;

}

void stalker_start(void) {

  GumStalkerTransformer *transformer = instrument_get_transformer();
  gum_stalker_follow_me(stalker, transformer, NULL);

}

