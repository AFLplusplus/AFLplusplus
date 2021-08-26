#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "debug.h"

#include "instrument.h"
#include "util.h"

char *instrument_coverage_filename = NULL;

static int         coverage_fd = -1;
static int         coverage_pipes[2] = {-1, -1};
static uint64_t    coverage_last_start = 0;
static GHashTable *coverage_hash = NULL;
static GArray *    coverage_modules = NULL;
static GArray *    coverage_ranges = NULL;
static guint       coverage_marked_modules = 0;
static guint       coverage_marked_entries = 0;

typedef struct {

  GumAddress base_address;
  GumAddress limit;
  gsize      size;
  char       path[PATH_MAX + 1];
  guint64    offset;
  gboolean   is_executable;
  guint      count;
  guint16    id;

} coverage_range_t;

typedef struct {

  uint64_t          start;
  uint64_t          end;
  coverage_range_t *module;

} coverage_data_t;

typedef struct {

  guint32 offset;
  guint16 length;
  guint16 module;

} coverage_event_t;

static gboolean coverage_range(const GumRangeDetails *details,
                               gpointer               user_data) {

  UNUSED_PARAMETER(user_data);
  coverage_range_t coverage = {0};

  if (details->file == NULL) { return TRUE; }
  if (details->protection == GUM_PAGE_NO_ACCESS) { return TRUE; }

  coverage.base_address = details->range->base_address;
  coverage.size = details->range->size;
  coverage.limit = coverage.base_address + coverage.size;

  strncpy(coverage.path, details->file->path, PATH_MAX);
  coverage.offset = details->file->offset;

  if ((details->protection & GUM_PAGE_EXECUTE) == 0) {

    coverage.is_executable = false;

  } else {

    coverage.is_executable = true;

  }

  coverage.count = 0;
  coverage.id = 0;

  g_array_append_val(coverage_ranges, coverage);
  return TRUE;

}

static gint coverage_sort(gconstpointer a, gconstpointer b) {

  coverage_range_t *ma = (coverage_range_t *)a;
  coverage_range_t *mb = (coverage_range_t *)b;

  if (ma->base_address < mb->base_address) return -1;

  if (ma->base_address > mb->base_address) return 1;

  return 0;

}

void instrument_coverage_print(char *format, ...) {

  char buffer[4096] = {0};
  int  len;

  va_list ap;
  va_start(ap, format);

  if (vsnprintf(buffer, sizeof(buffer) - 1, format, ap) < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));
  IGNORED_RETURN(write(STDOUT_FILENO, buffer, len));
  va_end(ap);

}

static void coverage_get_modules(void) {

  instrument_coverage_print("Coverage - Collecting modules\n");

  coverage_modules =
      g_array_sized_new(false, false, sizeof(coverage_range_t), 100);

  coverage_range_t current = {0};

  for (guint i = 0; i < coverage_ranges->len; i++) {

    coverage_range_t *range =
        &g_array_index(coverage_ranges, coverage_range_t, i);

    if (range->offset == 0 ||
        (strncmp(range->path, current.path, PATH_MAX) != 0)) {

      if (current.is_executable) {

        g_array_append_val(coverage_modules, current);
        memset(&current, '\0', sizeof(coverage_range_t));

      }

      memcpy(&current, range, sizeof(coverage_range_t));

    } else {

      current.limit = range->limit;
      current.size = current.limit - current.base_address;
      if (range->is_executable) { current.is_executable = true; }

    }

  }

  if (current.is_executable) { g_array_append_val(coverage_modules, current); }

  for (guint i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);
    instrument_coverage_print("Coverage Module - %3u: 0x%016" G_GINT64_MODIFIER
                              "X - 0x%016" G_GINT64_MODIFIER "X (%s)\n",
                              i, module->base_address, module->limit,
                              module->path);

  }

}

static void coverage_get_ranges(void) {

  instrument_coverage_print("Coverage - Collecting ranges\n");

  coverage_ranges =
      g_array_sized_new(false, false, sizeof(coverage_range_t), 100);
  gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, coverage_range, NULL);
  g_array_sort(coverage_ranges, coverage_sort);

  for (guint i = 0; i < coverage_ranges->len; i++) {

    coverage_range_t *range =
        &g_array_index(coverage_ranges, coverage_range_t, i);
    instrument_coverage_print("Coverage Range - %3u: 0x%016" G_GINT64_MODIFIER
                              "X - 0x%016" G_GINT64_MODIFIER "X (%s)\n",
                              i, range->base_address, range->limit,
                              range->path);

  }

}

static void instrument_coverage_mark(void *key, void *value, void *user_data) {

  UNUSED_PARAMETER(key);
  UNUSED_PARAMETER(user_data);
  coverage_data_t *val = (coverage_data_t *)value;
  guint            i;

  for (i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);
    if (val->start > module->limit) continue;

    if (val->end >= module->limit) break;

    val->module = module;
    coverage_marked_entries++;
    module->count++;
    return;

  }

  instrument_coverage_print(
      "Coverage cannot find module for: 0x%016" G_GINT64_MODIFIER
      "X - 0x%016" G_GINT64_MODIFIER "X\n",
      val->start, val->end);

}

static void coverage_write(void *data, size_t size) {

  ssize_t written;
  size_t  remain = size;

  for (char *cursor = (char *)data; remain > 0;
       remain -= written, cursor += written) {

    written = write(coverage_fd, cursor, remain);

    if (written < 0) {

      FATAL("Coverage - Failed to write: %s (%d)\n", (char *)data, errno);

    }

  }

}

static void coverage_format(char *format, ...) {

  va_list ap;
  char    buffer[4096] = {0};
  int     ret;
  int     len;

  va_start(ap, format);
  ret = vsnprintf(buffer, sizeof(buffer) - 1, format, ap);
  va_end(ap);

  if (ret < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));

  coverage_write(buffer, len);

}

static void coverage_write_modules() {

  guint emitted = 0;
  for (guint i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);
    if (module->count == 0) continue;

    coverage_format("%3u, ", emitted);
    coverage_format("%016" G_GINT64_MODIFIER "X, ", module->base_address);
    coverage_format("%016" G_GINT64_MODIFIER "X, ", module->limit);
    /* entry */
    coverage_format("%016" G_GINT64_MODIFIER "X, ", 0);
    /* checksum */
    coverage_format("%016" G_GINT64_MODIFIER "X, ", 0);
    /* timestamp */
    coverage_format("%08" G_GINT32_MODIFIER "X, ", 0);
    coverage_format("%s\n", module->path);
    emitted++;

  }

}

static void coverage_write_events(void *key, void *value, void *user_data) {

  UNUSED_PARAMETER(key);
  UNUSED_PARAMETER(user_data);
  coverage_data_t *val = (coverage_data_t *)value;

  if (val->module == NULL) { return; }

  coverage_event_t evt = {

      .offset = val->start - val->module->base_address,
      .length = val->end - val->start,
      .module = val->module->id,

  };

  coverage_write(&evt, sizeof(coverage_event_t));

}

static void coverage_write_header() {

  char version[] = "DRCOV VERSION: 2\n";
  char flavour[] = "DRCOV FLAVOR: frida\n";
  char columns[] = "Columns: id, base, end, entry, checksum, timestamp, path\n";
  coverage_write(version, sizeof(version) - 1);
  coverage_write(flavour, sizeof(flavour) - 1);
  coverage_format("Module Table: version 2, count %u\n",
                  coverage_marked_modules);
  coverage_write(columns, sizeof(columns) - 1);
  coverage_write_modules();
  coverage_format("BB Table: %u bbs\n", coverage_marked_entries);
  g_hash_table_foreach(coverage_hash, coverage_write_events, NULL);

}

static void coverage_mark_modules() {

  guint i;
  for (i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);

    instrument_coverage_print(
        "Coverage Module - %3u: [%c] 0x%016" G_GINT64_MODIFIER
        "X - 0x%016" G_GINT64_MODIFIER "X [%u] (%u:%s)\n",
        i, module->count == 0 ? ' ' : 'X', module->base_address, module->limit,
        module->count, module->id, module->path);

    if (module->count == 0) { continue; }

    module->id = coverage_marked_modules;
    coverage_marked_modules++;

  }

}

static void instrument_coverage_run() {

  int              bytes;
  coverage_data_t  data;
  coverage_data_t *value;
  instrument_coverage_print("Coverage - Running\n");

  if (close(coverage_pipes[STDOUT_FILENO]) != 0) {

    FATAL("Failed to close parent read pipe");

  }

  for (bytes =
           read(coverage_pipes[STDIN_FILENO], &data, sizeof(coverage_data_t));
       bytes == sizeof(coverage_data_t);
       bytes =
           read(coverage_pipes[STDIN_FILENO], &data, sizeof(coverage_data_t))) {

    value = (coverage_data_t *)gum_malloc0(sizeof(coverage_data_t));
    memcpy(value, &data, sizeof(coverage_data_t));
    g_hash_table_insert(coverage_hash, GSIZE_TO_POINTER(data.start), value);

  }

  if (bytes != 0) { FATAL("Coverage data truncated"); }

  instrument_coverage_print("Coverage - Preparing\n");

  coverage_get_ranges();
  coverage_get_modules();

  guint size = g_hash_table_size(coverage_hash);
  instrument_coverage_print("Coverage - Total Entries: %u\n", size);

  g_hash_table_foreach(coverage_hash, instrument_coverage_mark, NULL);
  instrument_coverage_print("Coverage - Marked Entries: %u\n",
                            coverage_marked_entries);

  coverage_mark_modules();
  instrument_coverage_print("Coverage - Marked Modules: %u\n",
                            coverage_marked_modules);

  coverage_write_header();

  instrument_coverage_print("Coverage - Completed\n");

}

void instrument_coverage_config(void) {

  instrument_coverage_filename = getenv("AFL_FRIDA_INST_COVERAGE_FILE");

}

void instrument_coverage_init(void) {

  OKF("Coverage - enabled [%c]",
      instrument_coverage_filename == NULL ? ' ' : 'X');

  if (instrument_coverage_filename == NULL) { return; }

  OKF("Coverage - file [%s]", instrument_coverage_filename);

  char *path = g_canonicalize_filename(instrument_coverage_filename,
                                       g_get_current_dir());

  OKF("Coverage - path [%s]", path);

  coverage_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (coverage_fd < 0) { FATAL("Failed to open coverage file '%s'", path); }

  g_free(path);

  if (pipe(coverage_pipes) != 0) { FATAL("Failed to create pipes"); }

  coverage_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (coverage_hash == NULL) {

    FATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

  pid_t pid = fork();
  if (pid == -1) { FATAL("Failed to start coverage process"); }

  if (pid == 0) {

    instrument_coverage_run();
    kill(getpid(), SIGKILL);
    _exit(0);

  }

  if (close(coverage_fd) < 0) { FATAL("Failed to close coverage output file"); }

  if (close(coverage_pipes[STDIN_FILENO]) != 0) {

    FATAL("Failed to close parent read pipe");

  }

}

void instrument_coverage_start(uint64_t address) {

  if (instrument_coverage_filename == NULL) { return; }

  coverage_last_start = address;

}

void instrument_coverage_end(uint64_t address) {

  if (instrument_coverage_filename == NULL) { return; }

  coverage_data_t data = {

      .start = coverage_last_start, .end = address, .module = NULL};

  if (write(coverage_pipes[STDOUT_FILENO], &data, sizeof(coverage_data_t)) !=
      sizeof(coverage_data_t)) {

    FATAL("Coverage I/O error");

  }

}

