#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"

#include "asan.h"
#include "entry.h"
#include "frida_cmplog.h"
#include "instrument.h"
#include "js.h"
#include "persistent.h"
#include "prefetch.h"
#include "ranges.h"
#include "stalker.h"
#include "stats.h"
#include "util.h"

gboolean instrument_tracing = false;
gboolean instrument_optimize = false;
gboolean instrument_unique = false;

static GumStalkerTransformer *transformer = NULL;

__thread uint64_t instrument_previous_pc = 0;

static GumAddress previous_rip = 0;
static u8 *       edges_notified = NULL;

static void trace_debug(char *format, ...) {

  va_list ap;
  char    buffer[4096] = {0};
  int     ret;
  int     len;

  va_start(ap, format);
  ret = vsnprintf(buffer, sizeof(buffer) - 1, format, ap);
  va_end(ap);

  if (ret < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));

  IGNORED_RETURN(write(STDOUT_FILENO, buffer, len));

}

__attribute__((hot)) static void on_basic_block(GumCpuContext *context,
                                                gpointer       user_data) {

  UNUSED_PARAMETER(context);

  GumAddress current_rip = GUM_ADDRESS(user_data);
  GumAddress current_pc;
  GumAddress edge;
  uint8_t *  cursor;
  uint64_t   value;

  current_pc = (current_rip >> 4) ^ (current_rip << 8);
  current_pc &= MAP_SIZE - 1;

  edge = current_pc ^ instrument_previous_pc;

  cursor = &__afl_area_ptr[edge];
  value = *cursor;

  if (value == 0xff) {

    value = 1;

  } else {

    value++;

  }

  *cursor = value;
  instrument_previous_pc = current_pc >> 1;

  if (unlikely(instrument_tracing)) {

    if (!instrument_unique || edges_notified[edge] == 0) {

      trace_debug("TRACE: edge: %10" G_GINT64_MODIFIER
                  "d, current_rip: 0x%016" G_GINT64_MODIFIER
                  "x, previous_rip: 0x%016" G_GINT64_MODIFIER "x\n",
                  edge, current_rip, previous_rip);

    }

    if (instrument_unique) { edges_notified[edge] = 1; }

    previous_rip = current_rip;

  }

}

static void instrument_basic_block(GumStalkerIterator *iterator,
                                   GumStalkerOutput *  output,
                                   gpointer            user_data) {

  UNUSED_PARAMETER(user_data);

  const cs_insn *instr;
  gboolean       begin = TRUE;
  gboolean       excluded;

  while (gum_stalker_iterator_next(iterator, &instr)) {

    if (unlikely(begin)) { instrument_debug_start(instr->address, output); }

    if (instr->address == entry_point) { entry_prologue(iterator, output); }
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

    stats_collect(instr, begin);

    if (unlikely(begin)) {

      prefetch_write(GSIZE_TO_POINTER(instr->address));

      if (likely(!excluded)) {

        if (likely(instrument_optimize)) {

          instrument_coverage_optimize(instr, output);

        } else {

          gum_stalker_iterator_put_callout(
              iterator, on_basic_block, GSIZE_TO_POINTER(instr->address), NULL);

        }

      }

    }

    instrument_debug_instruction(instr->address, instr->size);

    if (likely(!excluded)) {

      asan_instrument(instr, iterator);
      cmplog_instrument(instr, iterator);

    }

    if (js_stalker_callback(instr, begin, excluded, output)) {

      gum_stalker_iterator_keep(iterator);

    }

    begin = FALSE;

  }

  instrument_flush(output);
  instrument_debug_end(output);

}

void instrument_config(void) {

  instrument_optimize = (getenv("AFL_FRIDA_INST_NO_OPTIMIZE") == NULL);
  instrument_tracing = (getenv("AFL_FRIDA_INST_TRACE") != NULL);
  instrument_unique = (getenv("AFL_FRIDA_INST_TRACE_UNIQUE") != NULL);

  instrument_debug_config();
  asan_config();
  cmplog_config();

}

void instrument_init(void) {

  if (!instrument_is_coverage_optimize_supported()) instrument_optimize = false;

  OKF("Instrumentation - optimize [%c]", instrument_optimize ? 'X' : ' ');
  OKF("Instrumentation - tracing [%c]", instrument_tracing ? 'X' : ' ');
  OKF("Instrumentation - unique [%c]", instrument_unique ? 'X' : ' ');

  if (instrument_tracing && instrument_optimize) {

    WARNF("AFL_FRIDA_INST_TRACE implies AFL_FRIDA_INST_NO_OPTIMIZE");
    instrument_optimize = FALSE;

  }

  if (instrument_unique && instrument_optimize) {

    WARNF("AFL_FRIDA_INST_TRACE_UNIQUE implies AFL_FRIDA_INST_NO_OPTIMIZE");
    instrument_optimize = FALSE;

  }

  if (instrument_unique) { instrument_tracing = TRUE; }

  if (__afl_map_size != 0x10000) {

    FATAL("Bad map size: 0x%08x", __afl_map_size);

  }

  transformer = gum_stalker_transformer_make_from_callback(
      instrument_basic_block, NULL, NULL);

  if (instrument_unique) {

    int shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) { FATAL("shm_id < 0 - errno: %d\n", errno); }

    edges_notified = shmat(shm_id, NULL, 0);
    g_assert(edges_notified != MAP_FAILED);

    /*
     * Configure the shared memory region to be removed once the process dies.
     */
    if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

      FATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

    }

    /* Clear it, not sure it's necessary, just seems like good practice */
    memset(edges_notified, '\0', MAP_SIZE);

  }

  instrument_debug_init();
  asan_init();
  cmplog_init();

}

GumStalkerTransformer *instrument_get_transformer(void) {

  if (transformer == NULL) { FATAL("Instrumentation not initialized"); }
  return transformer;

}

