#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"
#include "util.h"

#include "stats.h"

#define MICRO_TO_SEC 1000000

stats_data_header_t *stats_data = NULL;

static int stats_parent_pid = -1;
static int stats_fd = -1;

char *   stats_filename = NULL;
guint64  stats_interval = 0;
gboolean stats_transitions = FALSE;

void stats_config(void) {

  stats_filename = getenv("AFL_FRIDA_STATS_FILE");
  stats_interval = util_read_num("AFL_FRIDA_STATS_INTERVAL");
  if (getenv("AFL_FRIDA_STATS_TRANSITIONS") != NULL) {

    stats_transitions = TRUE;

  }

}

void stats_init(void) {

  stats_parent_pid = getpid();

  OKF("Stats - file [%s]", stats_filename);
  OKF("Stats - interval [%" G_GINT64_MODIFIER "u]", stats_interval);

  if (stats_interval != 0 && stats_filename == NULL) {

    FATAL(
        "AFL_FRIDA_STATS_FILE must be specified if "
        "AFL_FRIDA_STATS_INTERVAL is");

  }

  if (stats_interval == 0) { stats_interval = 10; }

  if (stats_filename == NULL) { return; }

  if (!stats_is_supported_arch()) {

    FATAL("Stats is not supported on this architecture");

  }

  char *path = NULL;

  if (stats_filename == NULL) { return; }

  if (stats_transitions) { gum_stalker_set_counters_enabled(TRUE); }

  path = g_canonicalize_filename(stats_filename, g_get_current_dir());

  OKF("Stats - path [%s]", path);

  stats_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (stats_fd < 0) { FATAL("Failed to open stats file '%s'", path); }

  g_free(path);

  size_t data_size = stats_data_size_arch();

  int shm_id = shmget(IPC_PRIVATE, data_size, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) { FATAL("shm_id < 0 - errno: %d\n", errno); }

  stats_data = shmat(shm_id, NULL, 0);
  g_assert(stats_data != MAP_FAILED);

  /*
   * Configure the shared memory region to be removed once the process dies.
   */
  if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

    FATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

  }

  /* Clear it, not sure it's necessary, just seems like good practice */
  memset(stats_data, '\0', data_size);

}

void stats_vprint(int fd, char *format, va_list ap) {

  char buffer[4096] = {0};
  int  len;

  if (vsnprintf(buffer, sizeof(buffer) - 1, format, ap) < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));
  IGNORED_RETURN(write(fd, buffer, len));

}

void stats_print_fd(int fd, char *format, ...) {

  va_list ap;
  va_start(ap, format);
  stats_vprint(fd, format, ap);
  va_end(ap);

}

void stats_print(char *format, ...) {

  va_list ap;
  va_start(ap, format);
  stats_vprint(stats_fd, format, ap);
  va_end(ap);

}

void stats_write(void) {

  if (stats_parent_pid == getpid()) { return; }

  GDateTime *date_time = g_date_time_new_now_local();
  char *date_time_string = g_date_time_format(date_time, "%Y-%m-%e %H:%M:%S");

  stats_print("stats\n");
  stats_print("-----\n");

  stats_print("Index:                          %" G_GINT64_MODIFIER "u\n",
              stats_data->stats_idx++);
  stats_print("Pid:                            %d\n", getpid());
  stats_print("Time:                           %s\n", date_time_string);
  stats_print("Blocks:                         %" G_GINT64_MODIFIER "u\n",
              stats_data->num_blocks);
  stats_print("Instructions:                   %" G_GINT64_MODIFIER "u\n",
              stats_data->num_instructions);
  stats_print("Avg Instructions / Block:       %" G_GINT64_MODIFIER "u\n",
              stats_data->num_instructions / stats_data->num_blocks);

  stats_print("\n");

  g_free(date_time_string);
  g_date_time_unref(date_time);

  stats_write_arch();

  if (stats_transitions) {

    GDateTime *date_time = g_date_time_new_now_local();
    char *date_time_string = g_date_time_format(date_time, "%Y-%m-%e %H:%M:%S");

    stats_print_fd(STDERR_FILENO, "stats\n");
    stats_print_fd(STDERR_FILENO, "-----\n");
    stats_print_fd(STDERR_FILENO, "Index: %" G_GINT64_MODIFIER "u\n",
                   stats_data->transitions_idx++);
    stats_print_fd(STDERR_FILENO, "Pid:   %d\n", getpid());
    stats_print_fd(STDERR_FILENO, "Time:  %s\n", date_time_string);

    g_free(date_time_string);
    g_date_time_unref(date_time);
    gum_stalker_dump_counters();

  }

}

static void stats_maybe_write(void) {

  guint64 current_time;

  if (stats_interval == 0) { return; }

  current_time = g_get_monotonic_time();

  if ((current_time - stats_data->stats_last_time) >
      (stats_interval * MICRO_TO_SEC)) {

    stats_write();
    stats_data->stats_last_time = current_time;

  }

}

void stats_collect(const cs_insn *instr, gboolean begin) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(begin);

  if (stats_fd < 0) { return; }

  if (begin) { stats_data->num_blocks++; }
  stats_data->num_instructions++;

  stats_collect_arch(instr);

  stats_maybe_write();

}

