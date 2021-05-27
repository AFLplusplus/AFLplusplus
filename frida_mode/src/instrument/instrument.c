#include <unistd.h>

#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "asan.h"
#include "entry.h"
#include "frida_cmplog.h"
#include "instrument.h"
#include "persistent.h"
#include "prefetch.h"
#include "ranges.h"
#include "stalker.h"
#include "util.h"

static gboolean               tracing = false;
static gboolean               optimize = false;
static GumStalkerTransformer *transformer = NULL;

__thread uint64_t previous_pc = 0;

__attribute__((hot)) static void on_basic_block(GumCpuContext *context,
                                                gpointer       user_data) {

  UNUSED_PARAMETER(context);
  /*
   * This function is performance critical as it is called to instrument every
   * basic block. By moving our print buffer to a global, we avoid it affecting
   * the critical path with additional stack adjustments if tracing is not
   * enabled. If tracing is enabled, then we're printing a load of diagnostic
   * information so this overhead is unlikely to be noticeable.
   */
  static char buffer[200];
  int         len;
  GumAddress  current_pc = GUM_ADDRESS(user_data);
  uint8_t *   cursor;
  uint64_t    value;
  if (unlikely(tracing)) {

    /* Avoid any functions which may cause an allocation since the target app
     * may already be running inside malloc and it isn't designed to be
     * re-entrant on a single thread */
    len = snprintf(buffer, sizeof(buffer),
                   "current_pc: 0x%016" G_GINT64_MODIFIER
                   "x, previous_pc: 0x%016" G_GINT64_MODIFIER "x\n",
                   current_pc, previous_pc);

    IGNORED_RETURN(write(STDOUT_FILENO, buffer, len + 1));

  }

  current_pc = (current_pc >> 4) ^ (current_pc << 8);
  current_pc &= MAP_SIZE - 1;

  cursor = &__afl_area_ptr[current_pc ^ previous_pc];
  value = *cursor;

  if (value == 0xff) {

    value = 1;

  } else {

    value++;

  }

  *cursor = value;
  previous_pc = current_pc >> 1;

}

static void instr_basic_block(GumStalkerIterator *iterator,
                              GumStalkerOutput *output, gpointer user_data) {

  UNUSED_PARAMETER(user_data);

  const cs_insn *instr;
  gboolean       begin = TRUE;
  gboolean       excluded;

  while (gum_stalker_iterator_next(iterator, &instr)) {

    if (instr->address == entry_start) { entry_prologue(iterator, output); }
    if (instr->address == persistent_start) { persistent_prologue(output); }
    if (instr->address == persistent_ret) { persistent_epilogue(output); }

    /*
     * Until we reach AFL_ENTRYPOINT (assumed to be main if not specified) or
     * AFL_FRIDA_PERSISTENT_ADDR (if specified), we don't mark our ranges
     * excluded as we wish to remain inside stalker at all times so that we can
     * instrument our entry point and persistent loop (if present). This allows
     * the user to exclude ranges which would be traversed between main and the
     * AFL_ENTRYPOINT, but which they don't want included in their coverage
     * information when fuzzing.
     *
     * Since we have no means to discard the instrumented copies of blocks
     * (setting the trust threshold simply causes a new copy to be made on each
     * execution), we instead ensure that we honour the additional
     * instrumentation requested (e.g. coverage, asan and complog) when a block
     * is compiled no matter where we are during initialization. We will end up
     * re-using these blocks if the code under test calls a block which is also
     * used during initialization.
     *
     * Coverage data generated during initialization isn't a problem since the
     * map is zeroed each time the target is forked or each time the persistent
     * loop is run.
     *
     * Lastly, we don't enable pre-fetching back to the parent until we reach
     * our AFL_ENTRYPOINT, since it is not until then that we start the
     * fork-server and thus start executing in the child.
     */
    excluded = range_is_excluded(GSIZE_TO_POINTER(instr->address));
    if (unlikely(begin)) {

      instrument_debug_start(instr->address, output);

      prefetch_write(GSIZE_TO_POINTER(instr->address));

      if (likely(!excluded)) {

        if (likely(optimize)) {

          instrument_coverage_optimize(instr, output);

        } else {

          gum_stalker_iterator_put_callout(
              iterator, on_basic_block, GSIZE_TO_POINTER(instr->address), NULL);

        }

      }

      begin = FALSE;

    }

    instrument_debug_instruction(instr->address, instr->size);

    if (likely(!excluded)) {

      asan_instrument(instr, iterator);
      cmplog_instrument(instr, iterator);

    }

    gum_stalker_iterator_keep(iterator);

  }

  instrument_debug_end(output);

}

void instrument_init(void) {

  optimize = (getenv("AFL_FRIDA_INST_NO_OPTIMIZE") == NULL);
  tracing = (getenv("AFL_FRIDA_INST_TRACE") != NULL);

  if (!instrument_is_coverage_optimize_supported()) optimize = false;

  OKF("Instrumentation - optimize [%c]", optimize ? 'X' : ' ');
  OKF("Instrumentation - tracing [%c]", tracing ? 'X' : ' ');

  if (tracing && optimize) {

    FATAL("AFL_FRIDA_INST_OPTIMIZE and AFL_FRIDA_INST_TRACE are incompatible");

  }

  if (__afl_map_size != 0x10000) {

    FATAL("Bad map size: 0x%08x", __afl_map_size);

  }

  transformer =
      gum_stalker_transformer_make_from_callback(instr_basic_block, NULL, NULL);

  asan_init();
  cmplog_init();

}

GumStalkerTransformer *instrument_get_transformer(void) {

  if (transformer == NULL) { FATAL("Instrumentation not initialized"); }
  return transformer;

}

