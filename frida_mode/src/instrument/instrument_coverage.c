#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "instrument.h"
#include "util.h"

char *instrument_coverage_filename = NULL;

static int normal_coverage_fd = -1;
static int normal_coverage_pipes[2] = {-1, -1};

static int unstable_coverage_fd = -1;
static int unstable_coverage_pipes[2] = {-1, -1};

static uint64_t normal_coverage_last_start = 0;
static gchar *  unstable_coverage_fuzzer_stats = NULL;

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

} normal_coverage_data_t;

typedef struct {

  guint64 edge;
  guint64 from;
  guint64 from_end;
  guint64 to;
  guint64 to_end;

} unstable_coverage_data_t;

typedef struct {

  GArray *modules;
  guint   count;

} coverage_mark_ctx_t;

typedef struct {

  guint32 offset;
  guint16 length;
  guint16 module;

} coverage_event_t;

static gboolean coverage_range(const GumRangeDetails *details,
                               gpointer               user_data) {

  GArray *         coverage_ranges = (GArray *)user_data;
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

static GArray *coverage_get_ranges(void) {

  instrument_coverage_print("Coverage - Collecting ranges\n");

  GArray *coverage_ranges =
      g_array_sized_new(false, false, sizeof(coverage_range_t), 100);
  gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, coverage_range,
                               coverage_ranges);
  g_array_sort(coverage_ranges, coverage_sort);

  for (guint i = 0; i < coverage_ranges->len; i++) {

    coverage_range_t *range =
        &g_array_index(coverage_ranges, coverage_range_t, i);
    instrument_coverage_print("Coverage Range - %3u: 0x%016" G_GINT64_MODIFIER
                              "X - 0x%016" G_GINT64_MODIFIER "X (%s)\n",
                              i, range->base_address, range->limit,
                              range->path);

  }

  return coverage_ranges;

}

static GArray *coverage_get_modules(void) {

  instrument_coverage_print("Coverage - Collecting modules\n");
  GArray *coverage_ranges = coverage_get_ranges();
  GArray *coverage_modules =
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
  g_array_free(coverage_ranges, TRUE);

  for (guint i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);
    instrument_coverage_print("Coverage Module - %3u: 0x%016" G_GINT64_MODIFIER
                              "X - 0x%016" G_GINT64_MODIFIER "X (%s)\n",
                              i, module->base_address, module->limit,
                              module->path);

  }

  return coverage_modules;

}

static void instrument_coverage_mark(void *key, void *value, void *user_data) {

  UNUSED_PARAMETER(key);
  coverage_mark_ctx_t *   ctx = (coverage_mark_ctx_t *)user_data;
  GArray *                coverage_modules = ctx->modules;
  normal_coverage_data_t *val = (normal_coverage_data_t *)value;
  guint                   i;

  for (i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);
    if (val->start > module->limit) continue;

    if (val->end >= module->limit) break;

    val->module = module;
    ctx->count = ctx->count + 1;
    module->count++;
    return;

  }

  instrument_coverage_print(
      "Coverage cannot find module for: 0x%016" G_GINT64_MODIFIER
      "X - 0x%016" G_GINT64_MODIFIER "X\n",
      val->start, val->end);

}

static void coverage_write(int fd, void *data, size_t size) {

  ssize_t written;
  size_t  remain = size;

  for (char *cursor = (char *)data; remain > 0;
       remain -= written, cursor += written) {

    written = write(fd, cursor, remain);

    if (written < 0) {

      FFATAL("Coverage - Failed to write: %s (%d)\n", (char *)data, errno);

    }

  }

}

static void coverage_format(int fd, char *format, ...) {

  va_list ap;
  char    buffer[4096] = {0};
  int     ret;
  int     len;

  va_start(ap, format);
  ret = vsnprintf(buffer, sizeof(buffer) - 1, format, ap);
  va_end(ap);

  if (ret < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));

  coverage_write(fd, buffer, len);

}

static void coverage_write_modules(int fd, GArray *coverage_modules) {

  guint emitted = 0;
  for (guint i = 0; i < coverage_modules->len; i++) {

    coverage_range_t *module =
        &g_array_index(coverage_modules, coverage_range_t, i);
    if (module->count == 0) continue;

    coverage_format(fd, "%3u, ", emitted);
    coverage_format(fd, "%016" G_GINT64_MODIFIER "X, ", module->base_address);
    coverage_format(fd, "%016" G_GINT64_MODIFIER "X, ", module->limit);
    /* entry */
    coverage_format(fd, "%016" G_GINT64_MODIFIER "X, ", 0);
    /* checksum */
    coverage_format(fd, "%016" G_GINT64_MODIFIER "X, ", 0);
    /* timestamp */
    coverage_format(fd, "%08" G_GINT32_MODIFIER "X, ", 0);
    coverage_format(fd, "%s\n", module->path);
    emitted++;

  }

}

static void coverage_write_events(void *key, void *value, void *user_data) {

  UNUSED_PARAMETER(key);
  int                     fd = *((int *)user_data);
  normal_coverage_data_t *val = (normal_coverage_data_t *)value;

  if (val->module == NULL) { return; }

  coverage_event_t evt = {

      .offset = val->start - val->module->base_address,
      .length = val->end - val->start,
      .module = val->module->id,

  };

  coverage_write(fd, &evt, sizeof(coverage_event_t));

}

static void coverage_write_header(int fd, guint coverage_marked_modules) {

  char version[] = "DRCOV VERSION: 2\n";
  char flavour[] = "DRCOV FLAVOR: frida\n";
  char columns[] = "Columns: id, base, end, entry, checksum, timestamp, path\n";
  coverage_write(fd, version, sizeof(version) - 1);
  coverage_write(fd, flavour, sizeof(flavour) - 1);
  coverage_format(fd, "Module Table: version 2, count %u\n",
                  coverage_marked_modules);
  coverage_write(fd, columns, sizeof(columns) - 1);

}

static guint coverage_mark_modules(GArray *coverage_modules) {

  guint coverage_marked_modules = 0;
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

  return coverage_marked_modules;

}

static void instrument_coverage_normal_run() {

  int                     bytes;
  normal_coverage_data_t  data;
  normal_coverage_data_t *value;
  instrument_coverage_print("Coverage - Running\n");

  if (close(normal_coverage_pipes[STDOUT_FILENO]) != 0) {

    FFATAL("Failed to close parent read pipe");

  }

  GHashTable *coverage_hash =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
  if (coverage_hash == NULL) {

    FFATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

  for (bytes = read(normal_coverage_pipes[STDIN_FILENO], &data,
                    sizeof(normal_coverage_data_t));
       bytes == sizeof(normal_coverage_data_t);
       bytes = read(normal_coverage_pipes[STDIN_FILENO], &data,
                    sizeof(normal_coverage_data_t))) {

    value =
        (normal_coverage_data_t *)gum_malloc0(sizeof(normal_coverage_data_t));
    memcpy(value, &data, sizeof(normal_coverage_data_t));
    g_hash_table_insert(coverage_hash, GSIZE_TO_POINTER(data.start), value);

  }

  if (bytes != 0) { FFATAL("Coverage data truncated"); }

  instrument_coverage_print("Coverage - Preparing\n");

  GArray *coverage_modules = coverage_get_modules();

  guint size = g_hash_table_size(coverage_hash);
  instrument_coverage_print("Coverage - Total Entries: %u\n", size);

  coverage_mark_ctx_t ctx = {.modules = coverage_modules, .count = 0};

  g_hash_table_foreach(coverage_hash, instrument_coverage_mark, &ctx);
  instrument_coverage_print("Coverage - Marked Entries: %u\n", ctx.count);

  guint coverage_marked_modules = coverage_mark_modules(coverage_modules);
  instrument_coverage_print("Coverage - Marked Modules: %u\n",
                            coverage_marked_modules);

  coverage_write_header(normal_coverage_fd, coverage_marked_modules);
  coverage_write_modules(normal_coverage_fd, coverage_modules);
  coverage_format(normal_coverage_fd, "BB Table: %u bbs\n", ctx.count);
  g_hash_table_foreach(coverage_hash, coverage_write_events,
                       &normal_coverage_fd);

  g_hash_table_unref(coverage_hash);

  instrument_coverage_print("Coverage - Completed\n");

}

static GArray *instrument_coverage_unstable_read_unstable_ids(void) {

  gchar * contents = NULL;
  gsize   length = 0;
  GArray *unstable_edge_ids =
      g_array_sized_new(false, false, sizeof(gpointer), 100);

  if (!g_file_get_contents(unstable_coverage_fuzzer_stats, &contents, &length,
                           NULL)) {

    FFATAL("Failed to read fuzzer_stats");

  }

  instrument_coverage_print("\n");
  instrument_coverage_print("Unstable coverage stats:\n");
  instrument_coverage_print("========================\n");
  instrument_coverage_print("%s\n", contents);
  instrument_coverage_print("\n");

  gchar **lines = g_strsplit(contents, "\n", -1);
  gchar **values = NULL;

  for (guint i = 0; lines[i] != NULL; i++) {

    gchar **fields = g_strsplit(lines[i], ":", 2);
    if (fields[0] == NULL) {

      g_strfreev(fields);
      continue;

    }

    g_strstrip(fields[0]);
    if (g_strcmp0(fields[0], "var_bytes") != 0) {

      g_strfreev(fields);
      continue;

    }

    if (fields[1] == NULL) {

      g_strfreev(fields);
      continue;

    }

    g_strstrip(fields[1]);
    values = g_strsplit(fields[1], " ", -1);
    g_strfreev(fields);

    break;

  }

  if (values == NULL) {

    instrument_coverage_print(
        "Failed to find var_bytes, did you set AFL_DEBUG?\n");

  }

  for (guint i = 0; values[i] != NULL; i++) {

    g_strstrip(values[i]);
    gpointer val = GSIZE_TO_POINTER(g_ascii_strtoull(values[i], NULL, 10));
    g_array_append_val(unstable_edge_ids, val);

  }

  g_strfreev(values);
  g_strfreev(lines);
  g_free(contents);

  for (guint i = 0; i < unstable_edge_ids->len; i++) {

    gpointer *id = &g_array_index(unstable_edge_ids, gpointer, i);

    instrument_coverage_print("Unstable edge (%10u): %" G_GINT64_MODIFIER "u\n",
                              i, GPOINTER_TO_SIZE(*id));

  }

  return unstable_edge_ids;

}

static GHashTable *instrument_collect_unstable_blocks(
    GHashTable *unstable_coverage_hash, GArray *unstable_edge_ids) {

  GHashTable *unstable_blocks =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

  for (guint i = 0; i < unstable_edge_ids->len; i++) {

    gpointer *id = &g_array_index(unstable_edge_ids, gpointer, i);

    GHashTable *child =
        (GHashTable *)g_hash_table_lookup(unstable_coverage_hash, *id);

    if (child == NULL) { FFATAL("Failed to find edge ID"); }

    GHashTableIter iter = {0};
    gpointer       value;
    g_hash_table_iter_init(&iter, child);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {

      unstable_coverage_data_t *unstable = (unstable_coverage_data_t *)value;
      normal_coverage_data_t *  from =
          gum_malloc0(sizeof(normal_coverage_data_t));
      normal_coverage_data_t *to = gum_malloc0(sizeof(normal_coverage_data_t));
      from->start = unstable->from;
      from->end = unstable->from_end;
      from->module = NULL;

      to->start = unstable->to;
      to->end = unstable->to_end;
      to->module = NULL;

      g_hash_table_insert(unstable_blocks, GSIZE_TO_POINTER(from->start), from);
      g_hash_table_insert(unstable_blocks, GSIZE_TO_POINTER(to->start), to);

    }

  }

  return unstable_blocks;

}

static void instrument_coverage_unstable_run(void) {

  int                       bytes;
  unstable_coverage_data_t  data;
  unstable_coverage_data_t *value;
  instrument_coverage_print("Unstable coverage - Running\n");

  if (close(unstable_coverage_pipes[STDOUT_FILENO]) != 0) {

    FFATAL("Failed to close parent read pipe");

  }

  GHashTable *unstable_coverage_hash = g_hash_table_new_full(
      g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)g_hash_table_unref);
  if (unstable_coverage_hash == NULL) {

    FFATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

  guint edges = 0;

  for (bytes = read(unstable_coverage_pipes[STDIN_FILENO], &data,
                    sizeof(unstable_coverage_data_t));
       bytes == sizeof(unstable_coverage_data_t);
       bytes = read(unstable_coverage_pipes[STDIN_FILENO], &data,
                    sizeof(unstable_coverage_data_t))) {

    value = (unstable_coverage_data_t *)gum_malloc0(
        sizeof(unstable_coverage_data_t));
    memcpy(value, &data, sizeof(unstable_coverage_data_t));

    gpointer hash_value = g_hash_table_lookup(unstable_coverage_hash,
                                              GSIZE_TO_POINTER(value->edge));
    if (hash_value == NULL) {

      hash_value =
          g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

      if (!g_hash_table_insert(unstable_coverage_hash,
                               GSIZE_TO_POINTER(value->edge), hash_value)) {

        FFATAL("Entry already in hashtable");

      }

    }

    if (g_hash_table_insert(hash_value, GSIZE_TO_POINTER(value->from), value)) {

      edges++;

    }

  }

  if (bytes != 0) { FFATAL("Unstable coverage data truncated"); }

  instrument_coverage_print("Coverage - Preparing\n");

  GArray *coverage_modules = coverage_get_modules();

  instrument_coverage_print("Found edges: %u\n", edges);

  GArray *unstable_edge_ids = instrument_coverage_unstable_read_unstable_ids();

  GHashTable *unstable_blocks = instrument_collect_unstable_blocks(
      unstable_coverage_hash, unstable_edge_ids);

  guint size = g_hash_table_size(unstable_blocks);
  instrument_coverage_print("Unstable blocks: %u\n", size);

  coverage_mark_ctx_t ctx = {.modules = coverage_modules, .count = 0};

  g_hash_table_foreach(unstable_blocks, instrument_coverage_mark, &ctx);
  instrument_coverage_print("Coverage - Marked Entries: %u\n", ctx.count);

  guint coverage_marked_modules = coverage_mark_modules(coverage_modules);
  instrument_coverage_print("Coverage - Marked Modules: %u\n",
                            coverage_marked_modules);

  coverage_write_header(unstable_coverage_fd, coverage_marked_modules);
  coverage_write_modules(unstable_coverage_fd, coverage_modules);
  coverage_format(unstable_coverage_fd, "BB Table: %u bbs\n", ctx.count);
  g_hash_table_foreach(unstable_blocks, coverage_write_events,
                       &unstable_coverage_fd);

  g_hash_table_unref(unstable_blocks);
  g_array_free(unstable_edge_ids, TRUE);
  g_hash_table_unref(unstable_coverage_hash);

  instrument_coverage_print("Coverage - Completed\n");

}

void instrument_coverage_config(void) {

  instrument_coverage_filename = getenv("AFL_FRIDA_INST_COVERAGE_FILE");

}

void instrument_coverage_normal_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "coverage:" cYEL " [%s]",
       instrument_coverage_filename == NULL ? " "
                                            : instrument_coverage_filename);

  if (instrument_coverage_filename == NULL) { return; }

  char *path = g_canonicalize_filename(instrument_coverage_filename,
                                       g_get_current_dir());

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "coverage path:" cYEL " [%s]",
       path);

  normal_coverage_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (normal_coverage_fd < 0) {

    FFATAL("Failed to open coverage file '%s'", path);

  }

  g_free(path);

  if (pipe(normal_coverage_pipes) != 0) { FFATAL("Failed to create pipes"); }

  pid_t pid = fork();
  if (pid == -1) { FFATAL("Failed to start coverage process"); }

  if (pid == 0) {

    instrument_coverage_normal_run();
    kill(getpid(), SIGKILL);
    _exit(0);

  }

  if (close(normal_coverage_fd) < 0) {

    FFATAL("Failed to close coverage output file");

  }

  if (close(normal_coverage_pipes[STDIN_FILENO]) != 0) {

    FFATAL("Failed to close parent read pipe");

  }

}

void instrument_coverage_unstable_find_output(void) {

  gchar *fds_name = g_strdup_printf("/proc/%d/fd/", getppid());

  gchar *root = g_file_read_link("/proc/self/root", NULL);
  if (root == NULL) { FFATAL("Failed to read link"); }

  GDir *dir = g_dir_open(fds_name, 0, NULL);

  FVERBOSE("Coverage Unstable - fds: %s", fds_name);

  for (const gchar *filename = g_dir_read_name(dir); filename != NULL;
       filename = g_dir_read_name(dir)) {

    gchar *fullname = g_build_path("/", fds_name, filename, NULL);

    gchar *link = g_file_read_link(fullname, NULL);
    if (link == NULL) { FFATAL("Failed to read link: %s", fullname); }

    gchar *basename = g_path_get_basename(link);
    if (g_strcmp0(basename, "default") != 0) {

      g_free(basename);
      g_free(link);
      g_free(fullname);
      continue;

    }

    gchar *relative = NULL;
    size_t root_len = strnlen(root, PATH_MAX);
    if (g_str_has_suffix(link, root)) {

      relative = g_build_path("/", &link[root_len], NULL);

    } else {

      relative = g_build_path("/", link, NULL);

    }

    gchar *cmdline = g_build_path("/", relative, "cmdline", NULL);
    if (!g_file_test(cmdline, G_FILE_TEST_EXISTS)) {

      g_free(cmdline);
      g_free(basename);
      g_free(relative);
      g_free(link);
      g_free(fullname);
      continue;

    }

    unstable_coverage_fuzzer_stats =
        g_build_path("/", relative, "fuzzer_stats", NULL);
    g_free(cmdline);
    g_free(basename);
    g_free(relative);
    g_free(link);
    g_free(fullname);
    break;

  }

  g_dir_close(dir);
  g_free(fds_name);

  if (unstable_coverage_fuzzer_stats == NULL) {

    FFATAL("Failed to find fuzzer stats");

  }

  FVERBOSE("Fuzzer stats: %s", unstable_coverage_fuzzer_stats);

}

void instrument_coverage_unstable_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "unstable coverage:" cYEL " [%s]",
       instrument_coverage_unstable_filename == NULL
           ? " "
           : instrument_coverage_unstable_filename);
  if (instrument_coverage_unstable_filename == NULL) { return; }

  char *path = g_canonicalize_filename(instrument_coverage_unstable_filename,
                                       g_get_current_dir());

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "unstable coverage path:" cYEL
            " [%s]",
       path == NULL ? " " : path);

  unstable_coverage_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (unstable_coverage_fd < 0) {

    FFATAL("Failed to open unstable coverage file '%s'", path);

  }

  g_free(path);

  instrument_coverage_unstable_find_output();

  if (pipe(unstable_coverage_pipes) != 0) {

    FFATAL("Failed to create unstable pipes");

  }

  pid_t pid = fork();
  if (pid == -1) { FFATAL("Failed to start coverage process"); }

  if (pid == 0) {

    instrument_coverage_unstable_run();
    kill(getpid(), SIGKILL);
    _exit(0);

  }

  if (close(unstable_coverage_fd) < 0) {

    FFATAL("Failed to close unstable coverage output file");

  }

  if (close(unstable_coverage_pipes[STDIN_FILENO]) != 0) {

    FFATAL("Failed to close parent read pipe");

  }

}

void instrument_coverage_init(void) {

  instrument_coverage_normal_init();
  instrument_coverage_unstable_init();

}

void instrument_coverage_start(uint64_t address) {

  if (instrument_coverage_filename == NULL) { return; }

  normal_coverage_last_start = address;

}

void instrument_coverage_end(uint64_t address) {

  if (instrument_coverage_filename == NULL) { return; }

  normal_coverage_data_t data = {

      .start = normal_coverage_last_start, .end = address, .module = NULL};

  if (write(normal_coverage_pipes[STDOUT_FILENO], &data,
            sizeof(normal_coverage_data_t)) != sizeof(normal_coverage_data_t)) {

    FFATAL("Coverage I/O error");

  }

}

void instrument_coverage_unstable(guint64 edge, guint64 previous_rip,
                                  guint64 previous_end, guint64 current_rip,
                                  guint64 current_end) {

  if (instrument_coverage_unstable_filename == NULL) { return; }
  unstable_coverage_data_t data = {

      .edge = edge,
      .from = previous_rip,
      .from_end = previous_end,
      .to = current_rip,
      .to_end = current_end};

  if (write(unstable_coverage_pipes[STDOUT_FILENO], &data,
            sizeof(unstable_coverage_data_t)) !=
      sizeof(unstable_coverage_data_t)) {

    FFATAL("Unstable coverage I/O error");

  }

}

