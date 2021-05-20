#include "debug.h"

#include "instrument.h"
#include "stalker.h"

static GumStalker *stalker = NULL;

void stalker_init(void) {

  if (!gum_stalker_is_supported()) { FATAL("Failed to initialize embedded"); }

  stalker = gum_stalker_new();
  if (stalker == NULL) { FATAL("Failed to initialize stalker"); }

  gum_stalker_set_trust_threshold(stalker, 0);

}

GumStalker *stalker_get(void) {

  if (stalker == NULL) { FATAL("Stalker uninitialized"); }
  return stalker;

}

void stalker_start(void) {

  GumStalkerTransformer *transformer = instrument_get_transformer();
  gum_stalker_follow_me(stalker, transformer, NULL);

}

