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

#include "entry.h"
#include "stalker.h"
#include "stats.h"

#define MICRO_TO_SEC 1000000

char *               stats_filename = NULL;
guint64              stats_interval = 0;
static guint64       stats_interval_us = 0;
static int           stats_fd = -1;
static stats_data_t *stats_data = MAP_FAILED;

void stats_write(void) {

  if (stats_filename == NULL) { return; }

  if (stats_interval == 0) { return; }

  guint64 current_time = g_get_monotonic_time();
  if ((current_time - stats_data->prev.stats_time) < stats_interval_us) {

    return;

  }

  IGNORED_RETURN(ftruncate(stats_fd, 0));
  IGNORED_RETURN(lseek(stats_fd, 0, SEEK_SET));

  stats_data->curr.stats_time = current_time;

  GDateTime *date_time = g_date_time_new_now_local();
  char *     date_string = g_date_time_format(date_time, "%Y-%m-%d");
  char *     time_string = g_date_time_format(date_time, "%H:%M:%S");
  guint elapsed = (stats_data->curr.stats_time - stats_data->prev.stats_time) /
                  MICRO_TO_SEC;

  stats_print("stats\n");
  stats_print("-----\n");

  stats_print("%-21s %s %s\n", "Time", date_string, time_string);
  stats_print("%-30s %10u seconds \n", "Elapsed", elapsed);

  stats_print("\n");
  stats_print("\n");

  g_free(time_string);
  g_free(date_string);
  g_date_time_unref(date_time);

  stats_write_arch(stats_data);

  memcpy(&stats_data->prev, &stats_data->curr, sizeof(stats_t));

}

static void gum_afl_stalker_stats_increment_total(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.total++;

}

static void gum_afl_stalker_stats_increment_call_imm(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.call_imm++;

}

static void gum_afl_stalker_stats_increment_call_reg(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.call_reg++;

}

static void gum_afl_stalker_stats_increment_call_mem(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.call_mem++;

}

static void gum_afl_stalker_stats_increment_excluded_call_reg(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.excluded_call_reg++;

}

static void gum_afl_stalker_stats_increment_ret_slow_path(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.ret_slow_path++;

}

static void gum_afl_stalker_stats_increment_ret(GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.ret++;

}

static void gum_afl_stalker_stats_increment_post_call_invoke(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.post_call_invoke++;

}

static void gum_afl_stalker_stats_increment_excluded_call_imm(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.excluded_call_imm++;

}

static void gum_afl_stalker_stats_increment_jmp_imm(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_imm++;

}

static void gum_afl_stalker_stats_increment_jmp_reg(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_reg++;

}

static void gum_afl_stalker_stats_increment_jmp_mem(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_mem++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_imm(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_imm++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_mem(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_mem++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_reg(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_reg++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_jcxz(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_jcxz++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_cc(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_cc++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_cbz(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_cbz++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_cbnz(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_cbnz++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_tbz(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_tbz++;

}

static void gum_afl_stalker_stats_increment_jmp_cond_tbnz(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_cond_tbnz++;

}

static void gum_afl_stalker_stats_increment_jmp_continuation(
    GumStalkerObserver *observer) {

  UNUSED_PARAMETER(observer);

  if (!entry_compiled) { return; }
  stats_data->curr.jmp_continuation++;

}

static void stats_observer_init(GumStalkerObserver *observer) {

  GumStalkerObserverInterface *iface = GUM_STALKER_OBSERVER_GET_IFACE(observer);
  iface->increment_total = gum_afl_stalker_stats_increment_total;
  iface->increment_call_imm = gum_afl_stalker_stats_increment_call_imm;
  iface->increment_call_reg = gum_afl_stalker_stats_increment_call_reg;
  iface->increment_call_mem = gum_afl_stalker_stats_increment_call_mem;
  iface->increment_excluded_call_reg =
      gum_afl_stalker_stats_increment_excluded_call_reg;
  iface->increment_ret_slow_path =
      gum_afl_stalker_stats_increment_ret_slow_path;
  iface->increment_ret = gum_afl_stalker_stats_increment_ret;
  iface->increment_post_call_invoke =
      gum_afl_stalker_stats_increment_post_call_invoke;
  iface->increment_excluded_call_imm =
      gum_afl_stalker_stats_increment_excluded_call_imm;
  iface->increment_jmp_imm = gum_afl_stalker_stats_increment_jmp_imm;
  iface->increment_jmp_reg = gum_afl_stalker_stats_increment_jmp_reg;
  iface->increment_jmp_mem = gum_afl_stalker_stats_increment_jmp_mem;
  iface->increment_jmp_cond_imm = gum_afl_stalker_stats_increment_jmp_cond_imm;
  iface->increment_jmp_cond_mem = gum_afl_stalker_stats_increment_jmp_cond_mem;
  iface->increment_jmp_cond_reg = gum_afl_stalker_stats_increment_jmp_cond_reg;
  iface->increment_jmp_cond_jcxz =
      gum_afl_stalker_stats_increment_jmp_cond_jcxz;
  iface->increment_jmp_cond_cc = gum_afl_stalker_stats_increment_jmp_cond_cc;
  iface->increment_jmp_cond_cbz = gum_afl_stalker_stats_increment_jmp_cond_cbz;
  iface->increment_jmp_cond_cbnz =
      gum_afl_stalker_stats_increment_jmp_cond_cbnz;
  iface->increment_jmp_cond_tbz = gum_afl_stalker_stats_increment_jmp_cond_tbz;
  iface->increment_jmp_cond_tbnz =
      gum_afl_stalker_stats_increment_jmp_cond_tbnz;
  iface->increment_jmp_continuation =
      gum_afl_stalker_stats_increment_jmp_continuation;

}

void stats_config(void) {

  stats_filename = getenv("AFL_FRIDA_STATS_FILE");
  stats_interval = util_read_num("AFL_FRIDA_STATS_INTERVAL");

}

void stats_init(void) {

  OKF("Stats - file [%s]", stats_filename);
  OKF("Stats - interval [%" G_GINT64_MODIFIER "u]", stats_interval);

  if (stats_interval != 0 && stats_filename == NULL) {

    FATAL(
        "AFL_FRIDA_STATS_FILE must be specified if "
        "AFL_FRIDA_STATS_INTERVAL is");

  }

  if (stats_interval == 0) { stats_interval = 10; }
  stats_interval_us = stats_interval * MICRO_TO_SEC;

  if (stats_filename == NULL) { return; }

  char *path = g_canonicalize_filename(stats_filename, g_get_current_dir());

  OKF("Stats - path [%s]", path);

  stats_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (stats_fd < 0) { FATAL("Failed to open stats file '%s'", path); }

  g_free(path);

  int shm_id =
      shmget(IPC_PRIVATE, sizeof(stats_data_t), IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) { FATAL("shm_id < 0 - errno: %d\n", errno); }

  stats_data = shmat(shm_id, NULL, 0);
  g_assert(stats_data != MAP_FAILED);

  GumStalkerObserver *observer = stalker_get_observer();
  stats_observer_init(observer);

  /*
   * Configure the shared memory region to be removed once the process dies.
   */
  if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

    FATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

  }

  /* Clear it, not sure it's necessary, just seems like good practice */
  memset(stats_data, '\0', sizeof(stats_data_t));

  starts_arch_init();

}

void stats_print(char *format, ...) {

  char buffer[4096] = {0};
  int  len;

  va_list ap;
  va_start(ap, format);

  if (vsnprintf(buffer, sizeof(buffer) - 1, format, ap) < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));
  IGNORED_RETURN(write(stats_fd, buffer, len));
  va_end(ap);

}

void stats_on_fork(void) {

  stats_write();

}

void stats_collect(const cs_insn *instr, gboolean begin) {

  if (!entry_compiled) { return; }
  if (stats_filename == NULL) { return; }
  stats_collect_arch(instr, begin);

}

