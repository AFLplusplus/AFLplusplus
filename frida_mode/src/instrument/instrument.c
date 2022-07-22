#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "frida-gumjs.h"

#include "config.h"
#include "hash.h"

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
guint64  instrument_hash_zero = 0;
guint64  instrument_hash_seed = 0;

gboolean instrument_use_fixed_seed = FALSE;
guint64  instrument_fixed_seed = 0;
char    *instrument_coverage_unstable_filename = NULL;
gboolean instrument_coverage_insn = FALSE;

static GumStalkerTransformer *transformer = NULL;

static GumAddress previous_rip = 0;
static GumAddress previous_end = 0;
static u8        *edges_notified = NULL;

__thread guint64  instrument_previous_pc;
__thread guint64 *instrument_previous_pc_addr = NULL;

typedef struct {

  GumAddress address;
  GumAddress end;

} block_ctx_t;

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

guint64 instrument_get_offset_hash(GumAddress current_rip) {

  guint64 area_offset = hash64((unsigned char *)&current_rip,
                               sizeof(GumAddress), instrument_hash_seed);
  gsize   map_size_pow2 = util_log2(__afl_map_size);
  return area_offset &= ((1 << map_size_pow2) - 1);

}

__attribute__((hot)) static void instrument_increment_map(GumAddress edge) {

  uint8_t *cursor;
  uint64_t value;

  cursor = &__afl_area_ptr[edge];
  value = *cursor;

  if (value == 0xff) {

    value = 1;

  } else {

    value++;

  }

  *cursor = value;

}

__attribute__((hot)) static void on_basic_block(GumCpuContext *context,
                                                gpointer       user_data) {

  UNUSED_PARAMETER(context);

  block_ctx_t *ctx = (block_ctx_t *)user_data;
  GumAddress   current_rip = ctx->address;
  guint16      current_end = ctx->end;
  guint64      current_pc = instrument_get_offset_hash(current_rip);
  guint64      edge;
  if (instrument_previous_pc_addr == NULL) {

    instrument_previous_pc_addr = &instrument_previous_pc;
    *instrument_previous_pc_addr = instrument_hash_zero;

  }

  edge = current_pc ^ *instrument_previous_pc_addr;

  instrument_increment_map(edge);

  if (unlikely(instrument_tracing)) {

    if (!instrument_unique || edges_notified[edge] == 0) {

      trace_debug("TRACE: edge: %10" G_GINT64_MODIFIER
                  "d, current_rip: 0x%016" G_GINT64_MODIFIER
                  "x, previous_rip: 0x%016" G_GINT64_MODIFIER "x\n",
                  edge, current_rip, previous_rip);

    }

    if (instrument_unique) { edges_notified[edge] = 1; }

  }

  if (unlikely(instrument_coverage_unstable_filename != NULL)) {

    instrument_coverage_unstable(edge, previous_rip, previous_end, current_rip,
                                 current_end);

  }

  previous_rip = current_rip;
  previous_end = current_end;

  gsize map_size_pow2 = util_log2(__afl_map_size);
  *instrument_previous_pc_addr = util_rotate(current_pc, 1, map_size_pow2);

}

static void instrument_basic_block(GumStalkerIterator *iterator,
                                   GumStalkerOutput   *output,
                                   gpointer            user_data) {

  UNUSED_PARAMETER(user_data);

  const cs_insn *instr;
  gboolean       begin = TRUE;
  gboolean       excluded;
  block_ctx_t   *ctx = NULL;

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
    excluded = range_is_excluded(GUM_ADDRESS(instr->address));

    stats_collect(instr, begin);

    if (unlikely(begin)) {

      instrument_debug_start(instr->address, output);
      instrument_coverage_start(instr->address);

#if defined(__arm__)
      if (output->encoding == GUM_INSTRUCTION_SPECIAL) {

        prefetch_write(GSIZE_TO_POINTER(instr->address + 1));

      } else {

        prefetch_write(GSIZE_TO_POINTER(instr->address));

      }

#else
      prefetch_write(GSIZE_TO_POINTER(instr->address));
#endif

      if (likely(!excluded)) {

        if (likely(instrument_optimize)) {

          instrument_coverage_optimize(instr, output);

        } else {

          ctx = gum_malloc0(sizeof(block_ctx_t));
          ctx->address = GUM_ADDRESS(instr->address);
          gum_stalker_iterator_put_callout(iterator, on_basic_block, ctx, NULL);

        }

      }

    }

    if (instrument_coverage_insn) {

      instrument_coverage_optimize_insn(instr, output);

    }

    instrument_debug_instruction(instr->address, instr->size, output);

    if (likely(!excluded)) {

      asan_instrument(instr, iterator);
      cmplog_instrument(instr, iterator);

    }

    instrument_cache(instr, output);

    if (js_stalker_callback(instr, begin, excluded, output)) {

      gum_stalker_iterator_keep(iterator);

    }

    begin = FALSE;

  }

  if (ctx != NULL) { ctx->end = (instr->address + instr->size); }

  instrument_flush(output);
  instrument_debug_end(output);
  instrument_coverage_end(instr->address + instr->size);

}

void instrument_config(void) {

  instrument_optimize = (getenv("AFL_FRIDA_INST_NO_OPTIMIZE") == NULL);
  instrument_tracing = (getenv("AFL_FRIDA_INST_TRACE") != NULL);
  instrument_unique = (getenv("AFL_FRIDA_INST_TRACE_UNIQUE") != NULL);
  instrument_use_fixed_seed = (getenv("AFL_FRIDA_INST_SEED") != NULL);
  instrument_fixed_seed = util_read_num("AFL_FRIDA_INST_SEED", 0);
  instrument_coverage_unstable_filename =
      (getenv("AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE"));
  instrument_coverage_insn = (getenv("AFL_FRIDA_INST_INSN") != NULL);

  instrument_debug_config();
  instrument_coverage_config();
  asan_config();
  cmplog_config();
  instrument_cache_config();

}

void instrument_init(void) {

  if (!instrument_is_coverage_optimize_supported()) instrument_optimize = false;

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "optimize:" cYEL " [%c]",
       instrument_optimize ? 'X' : ' ');
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "tracing:" cYEL " [%c]",
       instrument_tracing ? 'X' : ' ');
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "unique:" cYEL " [%c]",
       instrument_unique ? 'X' : ' ');
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "fixed seed:" cYEL
            " [%c] [0x%016" G_GINT64_MODIFIER "x]",
       instrument_use_fixed_seed ? 'X' : ' ', instrument_fixed_seed);
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "unstable coverage:" cYEL " [%s]",
       instrument_coverage_unstable_filename == NULL
           ? " "
           : instrument_coverage_unstable_filename);
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "instructions:" cYEL " [%c]",
       instrument_coverage_insn ? 'X' : ' ');

  if (instrument_tracing && instrument_optimize) {

    WARNF("AFL_FRIDA_INST_TRACE implies AFL_FRIDA_INST_NO_OPTIMIZE");
    instrument_optimize = FALSE;

  }

  if (instrument_coverage_unstable_filename && instrument_optimize) {

    WARNF("AFL_FRIDA_INST_COVERAGE_FILE implies AFL_FRIDA_INST_NO_OPTIMIZE");
    instrument_optimize = FALSE;

  }

  if (instrument_unique && instrument_optimize) {

    WARNF("AFL_FRIDA_INST_TRACE_UNIQUE implies AFL_FRIDA_INST_NO_OPTIMIZE");
    instrument_optimize = FALSE;

  }

  if (instrument_unique) { instrument_tracing = TRUE; }

  transformer = gum_stalker_transformer_make_from_callback(
      instrument_basic_block, NULL, NULL);

  if (instrument_unique) {

    int shm_id =
        shmget(IPC_PRIVATE, __afl_map_size, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) { FATAL("shm_id < 0 - errno: %d\n", errno); }

    edges_notified = shmat(shm_id, NULL, 0);
    g_assert(edges_notified != MAP_FAILED);

    /*
     * Configure the shared memory region to be removed once the process
     * dies.
     */
    if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

      FATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

    }

    /* Clear it, not sure it's necessary, just seems like good practice */
    memset(edges_notified, '\0', __afl_map_size);

  }

  if (instrument_use_fixed_seed) {

    /*
     * This configuration option may be useful for diagnostics or
     * debugging.
     */
    instrument_hash_seed = instrument_fixed_seed;

  } else {

    /*
     * By using a different seed value for the hash, we can make different
     * instances have edge collisions in different places when carrying out
     * parallel fuzzing. The seed itself, doesn't have to be random, it
     * just needs to be different for each instance.
     */
    guint64 tid;
#if defined(__APPLE__)
    pthread_threadid_np(NULL, &tid);
#else
    tid = syscall(SYS_gettid);
#endif
    instrument_hash_seed =
        g_get_monotonic_time() ^ (((guint64)getpid()) << 32) ^ tid;

  }

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "seed:" cYEL
            " [0x%016" G_GINT64_MODIFIER "x]",
       instrument_hash_seed);
  instrument_hash_zero = instrument_get_offset_hash(0);

  asan_init();
  cmplog_init();
  instrument_coverage_init();
  instrument_coverage_optimize_init();
  instrument_debug_init();
  instrument_cache_init();

}

GumStalkerTransformer *instrument_get_transformer(void) {

  if (transformer == NULL) { FATAL("Instrumentation not initialized"); }
  return transformer;

}

void instrument_on_fork() {

  if (instrument_previous_pc_addr != NULL) {

    *instrument_previous_pc_addr = instrument_hash_zero;

  }

}

