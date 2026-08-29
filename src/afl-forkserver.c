/*
   american fuzzy lop++ - forkserver code
   --------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>


   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#include "config.h"
#ifdef AFL_PERSISTENT_RECORD
  #include "afl-fuzz.h"
#endif
#include "types.h"
#include "debug.h"
#include "common.h"
#include "list.h"
#include "forkserver.h"
#include "sharedmem.h"
#include "hash.h"

#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <grp.h>

#ifdef __linux__
  #include <dlfcn.h>
  #include <sys/prctl.h>

  #include <linux/futex.h>
  #include <sys/syscall.h>
  #ifdef USEMMAP
    #include <sys/mman.h>
  #else
    #include <sys/shm.h>
  #endif

static inline long sys_futex(void *uaddr, int op, int val,
                             const struct timespec *timeout, void *uaddr2,
                             int val3) {

  return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);

}

static inline void afl_sync_wake(void *uaddr) {

  sys_futex(uaddr, FUTEX_WAKE, 1, NULL, NULL, 0);

}

/* function to load nyx_helper function from libnyx.so */

nyx_plugin_handler_t *afl_load_libnyx_plugin(u8 *libnyx_binary) {

  void                 *handle;
  nyx_plugin_handler_t *plugin = calloc(1, sizeof(nyx_plugin_handler_t));

  ACTF("Trying to load libnyx.so plugin...");
  handle = dlopen((char *)libnyx_binary, RTLD_NOW);
  if (!handle) { goto fail; }

  plugin->nyx_config_load = dlsym(handle, "nyx_config_load");
  if (plugin->nyx_config_load == NULL) { goto fail; }

  plugin->nyx_config_set_workdir_path =
      dlsym(handle, "nyx_config_set_workdir_path");
  if (plugin->nyx_config_set_workdir_path == NULL) { goto fail; }

  plugin->nyx_config_set_input_buffer_size =
      dlsym(handle, "nyx_config_set_input_buffer_size");
  if (plugin->nyx_config_set_input_buffer_size == NULL) { goto fail; }

  plugin->nyx_config_set_input_buffer_write_protection =
      dlsym(handle, "nyx_config_set_input_buffer_write_protection");
  if (plugin->nyx_config_set_input_buffer_write_protection == NULL) {

    goto fail;

  }

  plugin->nyx_config_set_hprintf_fd =
      dlsym(handle, "nyx_config_set_hprintf_fd");
  if (plugin->nyx_config_set_hprintf_fd == NULL) { goto fail; }

  plugin->nyx_config_set_process_role =
      dlsym(handle, "nyx_config_set_process_role");
  if (plugin->nyx_config_set_process_role == NULL) { goto fail; }

  plugin->nyx_config_set_reuse_snapshot_path =
      dlsym(handle, "nyx_config_set_reuse_snapshot_path");
  if (plugin->nyx_config_set_reuse_snapshot_path == NULL) { goto fail; }

  plugin->nyx_new = dlsym(handle, "nyx_new");
  if (plugin->nyx_new == NULL) { goto fail; }

  plugin->nyx_shutdown = dlsym(handle, "nyx_shutdown");
  if (plugin->nyx_shutdown == NULL) { goto fail; }

  plugin->nyx_option_set_reload_mode =
      dlsym(handle, "nyx_option_set_reload_mode");
  if (plugin->nyx_option_set_reload_mode == NULL) { goto fail; }

  plugin->nyx_option_set_timeout = dlsym(handle, "nyx_option_set_timeout");
  if (plugin->nyx_option_set_timeout == NULL) { goto fail; }

  plugin->nyx_option_apply = dlsym(handle, "nyx_option_apply");
  if (plugin->nyx_option_apply == NULL) { goto fail; }

  plugin->nyx_set_afl_input = dlsym(handle, "nyx_set_afl_input");
  if (plugin->nyx_set_afl_input == NULL) { goto fail; }

  plugin->nyx_exec = dlsym(handle, "nyx_exec");
  if (plugin->nyx_exec == NULL) { goto fail; }

  plugin->nyx_get_bitmap_buffer = dlsym(handle, "nyx_get_bitmap_buffer");
  if (plugin->nyx_get_bitmap_buffer == NULL) { goto fail; }

  plugin->nyx_get_bitmap_buffer_size =
      dlsym(handle, "nyx_get_bitmap_buffer_size");
  if (plugin->nyx_get_bitmap_buffer_size == NULL) { goto fail; }

  plugin->nyx_get_aux_string = dlsym(handle, "nyx_get_aux_string");
  if (plugin->nyx_get_aux_string == NULL) { goto fail; }

  plugin->nyx_remove_work_dir = dlsym(handle, "nyx_remove_work_dir");
  if (plugin->nyx_remove_work_dir == NULL) { goto fail; }

  plugin->nyx_config_set_aux_buffer_size =
      dlsym(handle, "nyx_config_set_aux_buffer_size");
  if (plugin->nyx_config_set_aux_buffer_size == NULL) { goto fail; }

  plugin->nyx_get_target_hash64 = dlsym(handle, "nyx_get_target_hash64");
  if (plugin->nyx_get_target_hash64 == NULL) { goto fail; }

  plugin->nyx_config_free = dlsym(handle, "nyx_config_free");
  if (plugin->nyx_config_free == NULL) { goto fail; }

  OKF("libnyx plugin is ready!");
  return plugin;

fail:

  FATAL("failed to load libnyx: %s\n", dlerror());
  ck_free(plugin);
  return NULL;

}

void afl_nyx_runner_kill(afl_forkserver_t *fsrv) {

  if (fsrv->nyx_mode) {

    if (fsrv->nyx_aux_string) { ck_free(fsrv->nyx_aux_string); }

    /* check if we actually got a valid nyx runner */
    if (fsrv->nyx_runner) {

      fsrv->nyx_handlers->nyx_shutdown(fsrv->nyx_runner);
      /* clear the runner so a subsequent afl_fsrv_start() respawns QEMU-Nyx */
      fsrv->nyx_runner = NULL;

    }

    /* if we have use a tmp work dir we need to remove it */
    if (fsrv->nyx_use_tmp_workdir && fsrv->nyx_tmp_workdir_path) {

      remove_nyx_tmp_workdir(fsrv, fsrv->nyx_tmp_workdir_path);

    }

    if (fsrv->nyx_log_fd >= 0) { close(fsrv->nyx_log_fd); }

  }

}

  /* Wrapper for FATAL() that kills the nyx runner (and removes all created tmp
   * files) before exiting. Used before "afl_fsrv_killall()" is registered as
   * an atexit() handler. */
  #define NYX_PRE_FATAL(fsrv, x...) \
    do {                            \
                                    \
      afl_nyx_runner_kill(fsrv);    \
      FATAL(x);                     \
                                    \
    } while (0)

#elif defined(__APPLE__)

  #include <os/os_sync_wait_on_address.h>
  #include <mach/mach_time.h>
  #include <sys/shm.h>
  #include <sys/mman.h>

static inline void afl_sync_wake(void *uaddr) {

  os_sync_wake_by_address_any(uaddr, sizeof(u32),
                              OS_SYNC_WAKE_BY_ADDRESS_SHARED);

}

#endif

/**
 * The correct fds for reading and writing pipes
 */

/* Describe integer as memory size. */

static list_t fsrv_list = {.element_prealloc_count = 0};

static void fsrv_exec_child(afl_forkserver_t *fsrv, char **argv) {

  if (fsrv->qemu_mode || fsrv->cs_mode) {

    setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0);

  }

  if (fsrv->gid_set) {

    if (setregid(fsrv->gid, fsrv->gid) == -1) {

      FATAL("setgid failed: %s\n", strerror(errno));

    }

    if (setgroups(fsrv->nb_supl_gids, fsrv->supl_gids) == -1) {

      FATAL("setgroups failed: %s\n", strerror(errno));

    }

  }

  if (fsrv->uid_set) {

    if (setreuid(fsrv->uid, fsrv->uid) == -1) {

      FATAL("setuid failed: %s\n", strerror(errno));

    }

  }

  if (fsrv->chown_needed && fsrv->out_file != NULL) {

    if (access(fsrv->out_file, R_OK) == -1) {

      if (errno == EACCES) {

        FATAL(
            "Access to the file to fuzz denied. Most likely the requested\n"
            "    UID and/or GID is denied search permission ('x') for one of "
            "the directories\n    in the path prefix of \"%s\".",
            fsrv->out_file);

      }

    }

  }

  execv(fsrv->target_path, argv);

  WARNF("Execv failed in forkserver: %s.", strerror(errno));

}

#if defined(__linux__) || defined(__APPLE__)

/* Point fsrv->child_sync at the sync word embedded in the last bytes of the
   trace_bits shared map (offset recorded by afl_shm_init) and reset it to
   AFL_CHILD_IDLE. The word lives inside trace_bits, so it needs no separate
   shared segment and is freed together with trace_bits. If no embedded word is
   available (no offset wired, or a non-shared trace_bits map such as the
   sanitizer forkserver's), fall back to file-descriptor based sync. */
static void afl_child_sync_setup(afl_forkserver_t *fsrv) {

  if (!fsrv->use_futex) {

    fsrv->child_sync = NULL;
    return;

  }

  if (fsrv->child_sync_offset && fsrv->trace_bits) {

    fsrv->child_sync = (u32 *)(fsrv->trace_bits + fsrv->child_sync_offset);
    __atomic_store_n(fsrv->child_sync, AFL_CHILD_IDLE, __ATOMIC_RELEASE);

  } else {

    fsrv->child_sync = NULL;
    fsrv->use_futex = false;

  }

}

/* Wait for child to complete via futex with timeout tracking.
   Handles spurious wakeups by rechecking remaining time.
   Returns futex state: 2 = DONE, 3 = EXITED (or timeout/stop). */
static inline u32 afl_futex_wait(afl_forkserver_t *fsrv, u32 timeout_ms,
                                 volatile u8 *stop_soon_p) {

  #ifdef __linux__
  // Absolute deadline on CLOCK_MONOTONIC. Not affected by NTP changes.
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);

  deadline.tv_sec += (time_t)(timeout_ms / 1000);
  deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
  if (deadline.tv_nsec >= 1000000000L) {

    deadline.tv_sec += 1;
    deadline.tv_nsec -= 1000000000L;

  }

  #else
  // Absolute deadline in mach-absolute-time units.
  static mach_timebase_info_data_t tb = {0, 0};
  if (tb.denom == 0) { mach_timebase_info(&tb); }
  uint64_t deadline =
      mach_absolute_time() +
      (((uint64_t)timeout_ms * 1000000ULL) * tb.denom) / tb.numer;
  #endif

  for (;;) {

    u32 fval = __atomic_load_n(fsrv->child_sync, __ATOMIC_ACQUIRE);
    if (fval == AFL_CHILD_DONE || fval == AFL_CHILD_EXITED) { return fval; }

    // Fast path: check timeout & stop before sleeping
    if (fsrv->last_run_timed_out || unlikely(*stop_soon_p)) {

      if (fsrv->child_pid > 0) {

        /* Write EXITED before sending the OS signal.  A child using a
           non-fatal child_kill_signal (e.g. SIGTERM) will see AFL_CHILD_EXITED
           in its futex wait loop and call _exit() cleanly instead of starting
           another test case. */
        __atomic_store_n(fsrv->child_sync, AFL_CHILD_EXITED, __ATOMIC_RELEASE);
        afl_sync_wake(fsrv->child_sync);
        kill(fsrv->child_pid, fsrv->child_kill_signal);

      }

      return AFL_CHILD_EXITED;

    }

    // Wait until the absolute deadline
  #ifdef __linux__
    int r = sys_futex(fsrv->child_sync, FUTEX_WAIT_BITSET, fval, &deadline,
                      NULL, FUTEX_BITSET_MATCH_ANY);
  #else
    int r = os_sync_wait_on_address_with_deadline(
        fsrv->child_sync, (uint64_t)fval, sizeof(u32),
        OS_SYNC_WAIT_ON_ADDRESS_SHARED, OS_CLOCK_MACH_ABSOLUTE_TIME, deadline);
  #endif

    // If we timed out, mark it and loop once to take the kill/return path
    if (r == -1 && errno == ETIMEDOUT) { fsrv->last_run_timed_out = 1; }

    /* Otherwise: value changed, spurious wake, or EINTR => loop and re-check.
       Note: stop_soon_p is only re-checked at the top of the loop.  AFL++
       delivers SIGALRM to the fuzzer process, which causes FUTEX_WAIT to
       return EINTR and the loop to pick up the flag promptly.  Without such a
       signal, a stop_soon_p write from another thread would only be noticed
       on the next ETIMEDOUT or child-signal wakeup. */

  }

}

#endif                                           /* ^__linux__ || __APPLE__ */

static inline void afl_fsrv_report_persistent_sync_mode(
    afl_forkserver_t *fsrv) {

  if (fsrv->persistent_mode && !be_quiet) {

#if defined(__linux__) || defined(__APPLE__)
    if (fsrv->use_futex) {

      ACTF("Using futex persistent-mode synchronization.");

    } else

#endif
      ACTF("Using file descriptor persistent-mode synchronization.");

  }

}

/* Initializes the struct */

void afl_fsrv_init(afl_forkserver_t *fsrv) {

#ifdef __linux__

  fsrv->nyx_handlers = NULL;
  fsrv->out_dir_path = NULL;
  fsrv->nyx_mode = 0;
  fsrv->nyx_parent = false;
  fsrv->nyx_standalone = false;
  fsrv->nyx_runner = NULL;
  fsrv->nyx_id = 0xFFFFFFFF;
  fsrv->nyx_bind_cpu_id = 0xFFFFFFFF;
  fsrv->nyx_use_tmp_workdir = false;
  fsrv->nyx_tmp_workdir_path = NULL;
  fsrv->nyx_log_fd = -1;
  fsrv->nyx_target_hash64 = 0;

  fsrv->gui_mode = 0;
  fsrv->gui_python_dir = NULL;
  fsrv->gui_python_pid = -1;

#endif

  // this structure needs default so we initialize it if this was not done
  // already
  fsrv->out_fd = -1;
  fsrv->out_dir_fd = -1;
  fsrv->dev_null_fd = -1;
  fsrv->crash_trace_fd = -1;
  fsrv->dev_urandom_fd = -1;
  fsrv->fsrv_ctl_fd = -1;
  fsrv->fsrv_st_fd = -1;

  // Settings
  fsrv->use_stdin = true;
  fsrv->no_unlink = false;
  fsrv->exec_tmout = EXEC_TIMEOUT;
  fsrv->init_tmout = EXEC_TIMEOUT * FORK_WAIT_MULT;
  fsrv->mem_limit = MEM_LIMIT;
  fsrv->out_file = NULL;
  fsrv->child_kill_signal = SIGKILL;
  fsrv->max_length = MAX_FILE;

  u8 *crash_traces_env = (u8 *)getenv("AFL_CRASH_TRACES");
  fsrv->allow_cores =
      (getenv("AFL_ALLOW_CORES") != NULL ||
       (crash_traces_env != NULL && atoi((char *)crash_traces_env) > 0))
          ? true
          : false;

  if (getenv("AFL_PRELOAD_DISCRIMINATE_FORKSERVER_PARENT") != NULL) {

    fsrv->setenv = 1;

  } else {

    fsrv->setenv = 0;

  }

  // exec related stuff
  fsrv->child_pid = -1;
  fsrv->last_child_pid = -1;
  fsrv->map_size = get_map_size();

  /* IJON space allocation is handled by normal resize logic based on target's
   * reported size */
  fsrv->real_map_size = fsrv->map_size;
  fsrv->use_fauxsrv = false;
  fsrv->use_value_profile = false;
  fsrv->last_run_timed_out = false;
  fsrv->debug = false;
  fsrv->uses_crash_exitcode = false;
  fsrv->uses_asan = 0;
  fsrv->cmplog_size_derive_requested = false;
  fsrv->supports_allocsize_derive = false;

#ifdef __AFL_CODE_COVERAGE
  fsrv->persistent_trace_bits = NULL;
#endif

  fsrv->uid_set = 0;
  fsrv->gid_set = 0;

  fsrv->perm = DEFAULT_PERMISSION;

  fsrv->qemu_bridge = 0;
  {

    char *be = getenv("AFL_QEMU_BACKEND");
    if (be && !strcmp(be, "legacy")) {

      fsrv->qemu_bridge = 0;

    } else {

      fsrv->qemu_bridge = 1;

    }

  }

#if defined(__linux__) || defined(__APPLE__)
  fsrv->use_futex = false;
  fsrv->child_sync = NULL;
  fsrv->child_sync_offset = 0;
  /* The sync word is embedded in trace_bits; it is wired up in afl_fsrv_start
     once the offset is known (set by afl_shm_init via child_sync_offset). */
  if (!getenv("AFL_OLD_CHILD_SYNC")) { fsrv->use_futex = true; }

#endif

  fsrv->init_child_func = fsrv_exec_child;
  list_append(&fsrv_list, fsrv);

}

/* Initialize a new forkserver instance, duplicating "global" settings */
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from) {

  fsrv_to->use_stdin = from->use_stdin;
  fsrv_to->dev_null_fd = from->dev_null_fd;
  fsrv_to->crash_trace_fd = -1;  // only the main forkserver captures traces
  fsrv_to->exec_tmout = from->exec_tmout;
  fsrv_to->init_tmout = from->init_tmout;
  fsrv_to->mem_limit = from->mem_limit;
  fsrv_to->map_size = from->map_size;
  fsrv_to->real_map_size = from->real_map_size;
  fsrv_to->support_shmem_fuzz = from->support_shmem_fuzz;
  fsrv_to->shmem_fuzz = from->shmem_fuzz;
  fsrv_to->shmem_fuzz_len = from->shmem_fuzz_len;
  fsrv_to->out_file = from->out_file;
  fsrv_to->dev_urandom_fd = from->dev_urandom_fd;
  fsrv_to->out_fd = from->out_fd;  // not sure this is a good idea
  fsrv_to->no_unlink = from->no_unlink;
  fsrv_to->allow_cores = from->allow_cores;
  fsrv_to->uses_crash_exitcode = from->uses_crash_exitcode;
  fsrv_to->crash_exitcode = from->crash_exitcode;
  fsrv_to->child_kill_signal = from->child_kill_signal;
  fsrv_to->fsrv_kill_signal = from->fsrv_kill_signal;
  fsrv_to->debug = from->debug;
  fsrv_to->qemu_bridge = from->qemu_bridge;
  fsrv_to->cmplog_size_derive_requested = from->cmplog_size_derive_requested;
  fsrv_to->supports_allocsize_derive = false;

#ifdef __AFL_CODE_COVERAGE
  fsrv_to->persistent_trace_bits = from->persistent_trace_bits;
#endif

  // These are forkserver specific.
  fsrv_to->out_dir_fd = -1;
  fsrv_to->child_pid = -1;
  fsrv_to->use_fauxsrv = 0;
  fsrv_to->last_run_timed_out = 0;

  fsrv_to->late_send = from->late_send;
  fsrv_to->custom_data_ptr = from->custom_data_ptr;

#if defined(__linux__) || defined(__APPLE__)
  fsrv_to->use_futex = from->use_futex;
  fsrv_to->child_sync = NULL;
  /* The offset is wired by the caller after it assigns fsrv_to->trace_bits
     (it differs per shared map); child_sync itself is derived in
     afl_fsrv_start. */
  fsrv_to->child_sync_offset = 0;
#endif

  fsrv_to->init_child_func = from->init_child_func;
  // Note: do not copy ->add_extra_func or ->persistent_record*

  list_append(&fsrv_list, fsrv_to);

}

void afl_fsrv_setup_preload(afl_forkserver_t *fsrv, char *argv0) {

  // afl-qemu-trace takes care of converting AFL_PRELOAD
  if (fsrv->qemu_mode) return;

  u8 *afl_preload = getenv("AFL_PRELOAD");
  u8 *preload_path = NULL;
  u8 *frida_binary = NULL;
  if (fsrv->frida_mode)
    frida_binary = find_afl_binary(argv0, "afl-frida-trace.so");

  if (afl_preload && frida_binary)
    preload_path = alloc_printf("%s:%s", afl_preload, frida_binary);
  else if (afl_preload)
    preload_path = ck_strdup(afl_preload);
  else if (frida_binary)
    preload_path = ck_strdup(frida_binary);

  ck_free(frida_binary);

  if (preload_path) {

    setenv("LD_PRELOAD", preload_path, 1);
#ifdef __APPLE__
    setenv("DYLD_INSERT_LIBRARIES", preload_path, 1);
#endif
    ck_free(preload_path);

  }

}

/* Wrapper for poll() and read(), reading a 32 bit var.
  Returns the time passed to read.
  If the wait times out, returns timeout_ms + 1;
  Returns 0 if an error occurred (fd closed, signal, ...); */
static u32 __attribute__((hot)) read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms,
                                               volatile u8 *stop_soon_p) {

  int           pret;
  ssize_t       len_read;
  struct pollfd fds[1];
  int           nfds = 1;

  u32 read_start = get_cur_time_us();

  memset(&fds, 0, sizeof(fds));
  fds[0].fd = fd;
  fds[0].events = POLLIN;

  // set exceptfds as well to return when a child exited/closed the pipe
restart_poll:
  pret = poll(fds, nfds, timeout_ms);
  if (likely(pret > 0)) {

  restart_read:
    if (*stop_soon_p) {

      // Early return - the user wants to quit.
      return 0;

    }

    len_read = read(fd, (u8 *)buf, 4);

    if (likely(len_read == 4)) {  // for speed we put this first

      u32 exec_ms = MIN(timeout_ms, (get_cur_time_us() - read_start) / 1000);

      // ensure to report 1 ms has passed (0 is an error)
      return exec_ms > 0 ? exec_ms : 1;

    } else if (unlikely(len_read == -1 && errno == EINTR)) {

      goto restart_read;

    } else if (unlikely(len_read < 4)) {

      return 0;

    }

  } else if (unlikely(!pret)) {

    *buf = -1;
    return timeout_ms + 1;

  } else if (unlikely(pret < 0)) {

    if (likely(errno == EINTR)) goto restart_poll;

    *buf = -1;
    return 0;

  }

  return 0;  // not reached

}

/* Read child_status from the forkserver pipe after a timeout, escalating
   to SIGKILL if the configured child_kill_signal failed to terminate the
   child within FORKSRV_KILL_GRACE_MS. child_kill_signal defaults to
   SIGTERM in persistent mode; targets that catch or defer it (e.g.,
   CPython delivers signals only between bytecodes, so a target stuck in
   a long-running C function such as bignum multiplication never sees the
   signal) would otherwise leave the forkserver wedged in waitpid() and
   the fuzzer wedged in this read forever. SIGKILL is delivered by the
   kernel regardless of target state, so it always unsticks waitpid().

   Returns 1 on success, 0 if *stop_soon_p was raised.
   Hard pipe errors abort via RPFATAL. */
#define FORKSRV_KILL_GRACE_MS 1000U
#if defined(__linux__) || defined(__APPLE__)
static inline u8 read_status_or_escalate(afl_forkserver_t *fsrv,
                                         volatile u8      *stop_soon_p) {

  s32 res = -1;
  u32 read_ms = read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status,
                               FORKSRV_KILL_GRACE_MS, stop_soon_p);

  if (likely(read_ms > 0 && read_ms <= FORKSRV_KILL_GRACE_MS)) { return 1; }

  if (read_ms > FORKSRV_KILL_GRACE_MS) {

    if (fsrv->child_pid > 0) { kill(fsrv->child_pid, SIGKILL); }
    if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_status, 4)) == 4) {

      return 1;

    }

  }

  if (*stop_soon_p) { return 0; }
  RPFATAL(res, "Unable to communicate with fork server");

}

#endif

/* Internal forkserver for non_instrumented_mode=1 and non-forkserver mode runs.
  It execvs for each fork, forwarding exit codes and child pids to afl. */

static void afl_fauxsrv_execv(afl_forkserver_t *fsrv, char **argv) {

  unsigned char tmp[4] = {0, 0, 0, 0};
  pid_t         child_pid;

  if (!be_quiet) { ACTF("Using Fauxserver:"); }

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {

    abort();  // TODO: Abort?

  }

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  while (1) {

    uint32_t was_killed;
    u32      status;

    // Wait for parent by reading from the pipe. Exit if read fails

    if (read(FORKSRV_FD, &was_killed, 4) != 4) { _exit(0); }

    // Create a clone of our process

    child_pid = fork();

    if (child_pid < 0) { PCFATAL("Fork failed"); }

    // In child process: close fds, resume execution

    if (!child_pid) {  // New child

#ifdef __linux__
      prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif

      if (fsrv->out_dir_fd >= 0) close(fsrv->out_dir_fd);
      if (fsrv->dev_null_fd >= 0) close(fsrv->dev_null_fd);
      if (fsrv->dev_urandom_fd >= 0) close(fsrv->dev_urandom_fd);

      if (fsrv->plot_file != NULL) {

        fclose(fsrv->plot_file);
        fsrv->plot_file = NULL;

      }

      // enable terminating on sigpipe in the children
      struct sigaction sa;
      memset((char *)&sa, 0, sizeof(sa));
      sa.sa_handler = SIG_DFL;
      sigaction(SIGPIPE, &sa, NULL);

      signal(SIGCHLD, old_sigchld_handler);

      // FORKSRV_FD is for communication with AFL, we don't need it in the
      // child
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      if (fsrv->gid_set) {

        if (setgid(fsrv->gid) == -1) {

          CFATAL("setgid failed: %s\n", strerror(errno));

        }

      }

      if (fsrv->uid_set) {

        if (setuid(fsrv->uid) == -1) {

          CFATAL("setuid failed: %s\n", strerror(errno));

        }

      }

      // finally: exec...
      execv(fsrv->target_path, argv);

      /* Use a distinctive bitmap signature to tell the parent about execv()
        falling through. */

      *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;

      WARNF("Execv failed in fauxserver.");
      break;

    }

    // In parent process: write PID to AFL

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) { _exit(0); }

    // after child exited, get and relay exit status to parent through waitpid

    if (waitpid(child_pid, &status, 0) < 0) {

      // Zombie Child could not be collected. Scary!
      WARNF("Fauxserver could not determine child's exit code. ");

    }

    // Relay wait status to AFL pipe, then loop back

    if (write(FORKSRV_FD + 1, &status, 4) != 4) { _exit(1); }

  }

}

/* Report on the error received via the forkserver controller and exit */
static void report_error_and_exit(int error) {

  switch (error) {

    case FS_ERROR_MAP_SIZE:
      FATAL(
          "AFL_MAP_SIZE is not set and fuzzing target reports that the "
          "required size is very large. Solution: Run the fuzzing target "
          "stand-alone with the environment variable AFL_DUMP_MAP_SIZE=1 set "
          "the displayed value in the AFL_MAP_SIZE environment variable for "
          "afl-fuzz.");
      break;
    case FS_ERROR_MAP_ADDR:
      FATAL(
          "the fuzzing target reports that hardcoded map address might be the "
          "reason the mmap of the shared memory failed. Solution: recompile "
          "the target with either afl-clang-lto and do not set "
          "AFL_LLVM_MAP_ADDR or recompile with afl-clang-fast.");
      break;
    case FS_ERROR_SHM_OPEN:
      FATAL(
          "the fuzzing target reports that the shm_open() call failed. The "
          "shared maps are handed to the target as inherited file descriptors "
          "and their name is unlinked right away, so this most likely means "
          "the target was built with an afl-cc that predates that (recompile "
          "it, or set AFL_SHM_KEEP_NAME=1 to keep the name around) or that it "
          "closes all file descriptors on startup.");
      break;
    case FS_ERROR_SHMAT:
      FATAL("the fuzzing target reports that the shmat() call failed.");
      break;
    case FS_ERROR_MMAP:
      FATAL(
          "the fuzzing target reports that the mmap() call to the shared "
          "memory failed.");
      break;
    case FS_ERROR_OLD_CMPLOG:
      FATAL(
          "the -c cmplog target was instrumented with an too old AFL++ "
          "version, you need to recompile it.");
      break;
    case FS_ERROR_OLD_CMPLOG_QEMU:
      FATAL(
          "The AFL++ QEMU/FRIDA loaders are from an older version, for -c you "
          "need to recompile it.\n");
      break;
    default:
      FATAL("unknown error code %d from fuzzing target!", error);

  }

}

#ifdef __linux__
void nyx_load_target_hash(afl_forkserver_t *fsrv) {

  void *nyx_config = fsrv->nyx_handlers->nyx_config_load(fsrv->target_path);
  fsrv->nyx_target_hash64 =
      fsrv->nyx_handlers->nyx_get_target_hash64(nyx_config);
  fsrv->nyx_handlers->nyx_config_free(nyx_config);

}

#endif

/* Spins up fork server. The idea is explained here:

   https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-compilter-rt.o */

void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output) {

  int   st_pipe[2], ctl_pipe[2];
  u32   status;
  s32   rlen;
  char *ignore_autodict = getenv("AFL_NO_AUTODICT");

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    if (fsrv->nyx_runner != NULL) { return; }

    if (!be_quiet) { ACTF("Spinning up the NYX backend..."); }

    if (fsrv->nyx_use_tmp_workdir) {

      fsrv->nyx_tmp_workdir_path = create_nyx_tmp_workdir();
      fsrv->out_dir_path = fsrv->nyx_tmp_workdir_path;

    } else {

      if (fsrv->out_dir_path == NULL) {

        NYX_PRE_FATAL(fsrv, "Nyx workdir path not found...");

      }

    }

    // libnyx expects an absolute path
    char *outdir_path_absolute = realpath(fsrv->out_dir_path, NULL);
    if (outdir_path_absolute == NULL) {

      NYX_PRE_FATAL(fsrv, "Nyx workdir path cannot be resolved ...");

    }

    char *workdir_path = alloc_printf("%s/workdir", outdir_path_absolute);

    if (fsrv->nyx_id == 0xFFFFFFFF) {

      NYX_PRE_FATAL(fsrv, "Nyx ID is not set...");

    }

    if (fsrv->nyx_bind_cpu_id == 0xFFFFFFFF) {

      NYX_PRE_FATAL(fsrv, "Nyx CPU ID is not set...");

    }

    void *nyx_config = fsrv->nyx_handlers->nyx_config_load(fsrv->target_path);

    fsrv->nyx_handlers->nyx_config_set_workdir_path(nyx_config, workdir_path);
    fsrv->nyx_handlers->nyx_config_set_input_buffer_size(nyx_config,
                                                         fsrv->max_length);
    fsrv->nyx_handlers->nyx_config_set_input_buffer_write_protection(nyx_config,
                                                                     true);

    char *nyx_log_path = getenv("AFL_NYX_LOG");
    if (nyx_log_path) {

      fsrv->nyx_log_fd =
          open(nyx_log_path, O_CREAT | O_TRUNC | O_WRONLY, DEFAULT_PERMISSION);
      if (fsrv->nyx_log_fd < 0) {

        NYX_PRE_FATAL(fsrv, "AFL_NYX_LOG path could not be written");

      }

      fsrv->nyx_handlers->nyx_config_set_hprintf_fd(nyx_config,
                                                    fsrv->nyx_log_fd);

    }

    if (fsrv->nyx_standalone) {

      fsrv->nyx_handlers->nyx_config_set_process_role(nyx_config, StandAlone);

    } else {

      if (fsrv->nyx_parent) {

        fsrv->nyx_handlers->nyx_config_set_process_role(nyx_config, Parent);

      } else {

        fsrv->nyx_handlers->nyx_config_set_process_role(nyx_config, Child);

      }

    }

    if (getenv("AFL_NYX_AUX_SIZE") != NULL) {

      fsrv->nyx_aux_string_len = atoi(getenv("AFL_NYX_AUX_SIZE"));

      if (fsrv->nyx_handlers->nyx_config_set_aux_buffer_size(
              nyx_config, fsrv->nyx_aux_string_len) != 1) {

        NYX_PRE_FATAL(fsrv,
                      "Invalid AFL_NYX_AUX_SIZE value set (must be a multiple "
                      "of 4096) ...");

      }

    } else {

      fsrv->nyx_aux_string_len = 0x1000;

    }

    if (getenv("AFL_NYX_REUSE_SNAPSHOT") != NULL) {

      if (access(getenv("AFL_NYX_REUSE_SNAPSHOT"), F_OK) == -1) {

        NYX_PRE_FATAL(fsrv, "AFL_NYX_REUSE_SNAPSHOT path does not exist");

      }

      /* stupid sanity check to avoid passing an empty or invalid snapshot
       * directory */
      char *snapshot_file_path =
          alloc_printf("%s/global.state", getenv("AFL_NYX_REUSE_SNAPSHOT"));
      if (access(snapshot_file_path, R_OK) == -1) {

        NYX_PRE_FATAL(fsrv,
                      "AFL_NYX_REUSE_SNAPSHOT path does not contain a valid "
                      "Nyx snapshot");

      }

      ck_free(snapshot_file_path);

      /* another sanity check to avoid passing a snapshot directory that is
       * located in the current workdir (the workdir will be wiped by libnyx on
       * startup) */
      char *workdir_snapshot_path =
          alloc_printf("%s/workdir/snapshot", outdir_path_absolute);
      char *reuse_snapshot_path_real =
          realpath(getenv("AFL_NYX_REUSE_SNAPSHOT"), NULL);

      if (strcmp(workdir_snapshot_path, reuse_snapshot_path_real) == 0) {

        NYX_PRE_FATAL(
            fsrv,
            "AFL_NYX_REUSE_SNAPSHOT path is located in current workdir "
            "(use another output directory)");

      }

      ck_free(reuse_snapshot_path_real);
      ck_free(workdir_snapshot_path);

      fsrv->nyx_handlers->nyx_config_set_reuse_snapshot_path(
          nyx_config, getenv("AFL_NYX_REUSE_SNAPSHOT"));

    }

    fsrv->nyx_runner = fsrv->nyx_handlers->nyx_new(nyx_config, fsrv->nyx_id);
    fsrv->nyx_handlers->nyx_config_free(nyx_config);

    ck_free(workdir_path);
    ck_free(outdir_path_absolute);

    if (fsrv->nyx_runner == NULL) { FATAL("Something went wrong ..."); }

    u32 tmp_map_size =
        fsrv->nyx_handlers->nyx_get_bitmap_buffer_size(fsrv->nyx_runner);
    fsrv->real_map_size = tmp_map_size;
    fsrv->map_size = (((tmp_map_size + 63) >> 6) << 6);
    if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }

    fsrv->trace_bits =
        fsrv->nyx_handlers->nyx_get_bitmap_buffer(fsrv->nyx_runner);

    fsrv->nyx_handlers->nyx_option_set_reload_mode(
        fsrv->nyx_runner, getenv("AFL_NYX_DISABLE_SNAPSHOT_MODE") == NULL);
    fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);

    fsrv->nyx_handlers->nyx_option_set_timeout(fsrv->nyx_runner, 2, 0);
    fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);

    fsrv->nyx_aux_string = malloc(fsrv->nyx_aux_string_len);
    memset(fsrv->nyx_aux_string, 0, fsrv->nyx_aux_string_len);

    // dry run
    fsrv->nyx_handlers->nyx_set_afl_input(fsrv->nyx_runner, "INIT", 4);
    switch (fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner)) {

      case Abort:
        NYX_PRE_FATAL(fsrv, "Error: Nyx abort occurred...");
        break;
      case IoError:
        NYX_PRE_FATAL(fsrv, "Error: QEMU-Nyx has died...");
        break;
      case Error:
        NYX_PRE_FATAL(fsrv, "Error: Nyx runtime error has occurred...");
        break;
      default:
        break;

    }

    // autodict in Nyx mode
    if (!ignore_autodict && fsrv->add_extra_func) {

      char *x =
          alloc_printf("%s/workdir/dump/afl_autodict.txt", fsrv->out_dir_path);
      int nyx_autodict_fd = open(x, O_RDONLY);
      ck_free(x);

      if (nyx_autodict_fd >= 0) {

        struct stat st;
        if (fstat(nyx_autodict_fd, &st) >= 0) {

          u32 f_len = st.st_size;
          u8 *dict = ck_alloc(f_len);
          if (dict == NULL) {

            NYX_PRE_FATAL(
                fsrv, "Could not allocate %u bytes of autodictionary memory",
                f_len);

          }

          u32 offset = 0, count = 0;
          u32 len = f_len;

          while (len != 0) {

            rlen = read(nyx_autodict_fd, dict + offset, len);
            if (rlen > 0) {

              len -= rlen;
              offset += rlen;

            } else {

              NYX_PRE_FATAL(
                  fsrv,
                  "Reading autodictionary fail at position %u with %u bytes "
                  "left.",
                  offset, len);

            }

          }

          offset = 0;
          while (offset < (u32)f_len &&
                 (u8)dict[offset] + offset < (u32)f_len) {

            fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                 (u8)dict[offset]);
            offset += (1 + dict[offset]);
            count++;

          }

          if (!be_quiet) { ACTF("Loaded %u autodictionary entries", count); }
          ck_free(dict);

        }

        close(nyx_autodict_fd);

      }

    }

    return;

  }

#endif

  if (!be_quiet) { ACTF("Spinning up the fork server..."); }

#ifdef AFL_PERSISTENT_RECORD
  if (unlikely(fsrv->persistent_record)) {

    fsrv->persistent_record_data =
        (u8 **)ck_alloc(fsrv->persistent_record * sizeof(u8 *));
    fsrv->persistent_record_len =
        (u32 *)ck_alloc(fsrv->persistent_record * sizeof(u32));

    if (!fsrv->persistent_record_data || !fsrv->persistent_record_len) {

      FATAL("Unable to allocate memory for persistent replay.");

    }

  }

#endif

  if (fsrv->use_fauxsrv) {

    // TODO: Come up with some nice way to initialize this all

    if (fsrv->init_child_func == afl_fauxsrv_execv) {

      if (!be_quiet) { ACTF("Faux forkserver already initialized"); }

    } else if (fsrv->init_child_func != fsrv_exec_child) {

      FATAL("Different forkserver not compatible with fauxserver");

    } else {

      fsrv->init_child_func = afl_fauxsrv_execv;

    }

    if (!be_quiet) { ACTF("Using AFL++ faux forkserver..."); }

  }

  if (pipe(st_pipe) || pipe(ctl_pipe)) { PFATAL("pipe() failed"); }

#if defined(__linux__) || defined(__APPLE__)
  /* Point child_sync at the word embedded in trace_bits (re-derived here
     because trace_bits may have been reallocated by a map resize or fast
     resume restart). This must happen BEFORE fork() so the parent has a
     valid child_sync pointer for the wait loop in afl_fsrv_run_target. */
  afl_child_sync_setup(fsrv);

#endif

  fsrv->last_run_timed_out = 0;
  fsrv->fsrv_pid = fork();

  if (fsrv->fsrv_pid < 0) { PFATAL("fork() failed"); }

  if (!fsrv->fsrv_pid) {

    // CHILD PROCESS

#ifdef __linux__
    prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif

    if (unlikely(fsrv->setenv)) { setenv("AFL_FORKSERVER_PARENT", "1", 0); }

    // enable terminating on sigpipe in the children
    struct sigaction sa;
    memset((char *)&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(SIGPIPE, &sa, NULL);

    struct rlimit r;

    if (!fsrv->cmplog_binary) {

      // we do not want that in non-cmplog fsrv - neither the variables nor
      // the inherited descriptor the cmplog map is handed over on. Only
      // descriptors inside the reserved range can be ours, so anything else
      // is left alone rather than risking a close() of an unrelated one.
      char *cmplog_fd = getenv(CMPLOG_SHM_FD_ENV_VAR);
      int   cmplog_fd_num = cmplog_fd && *cmplog_fd ? atoi(cmplog_fd) : -1;

      if (cmplog_fd_num >= SHM_FD_MIN) { close(cmplog_fd_num); }
      unsetenv(CMPLOG_SHM_ENV_VAR);
      unsetenv(CMPLOG_SHM_FD_ENV_VAR);

    }

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... The floor covers the forkserver
       pipes on FORKSRV_FD / FORKSRV_FD + 1 as well as the SHM_FD_MIN range
       the shared maps are handed over on (see SHM_FD_ENV_VAR). */
    if (!getrlimit(RLIMIT_NOFILE, &r) &&
        r.rlim_cur < (rlim_t)(SHM_FD_MIN + SHM_FD_COUNT)) {

      r.rlim_cur = (rlim_t)(SHM_FD_MIN + SHM_FD_COUNT);
      // asking for more than the hard limit would fail outright and leave the
      // soft limit where it was, below even the forkserver pipes
      if (r.rlim_max != RLIM_INFINITY && r.rlim_cur > r.rlim_max) {

        r.rlim_cur = r.rlim_max;

      }

      setrlimit(RLIMIT_NOFILE, &r);  // Ignore errors

    }

    if (fsrv->mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)fsrv->mem_limit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r);  // Ignore errors
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r);  // Ignore errors
#endif                                                        /* ^RLIMIT_AS */

    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    if (!fsrv->debug && !fsrv->allow_cores) {

      r.rlim_max = r.rlim_cur = 0;
      setrlimit(RLIMIT_CORE, &r);  // Ignore errors

    }

    if (fsrv->allow_cores) {

      r.rlim_max = r.rlim_cur = INT_MAX;
      setrlimit(RLIMIT_CORE, &r);  // Ignore errors

    }

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    if (!(debug_child_output)) {

      if (fsrv->crash_trace_fd >= 0) {

        /* AFL_CRASH_TRACES: capture the target's stdout/stderr so a crashing
           run's sanitizer report / stack trace can be saved beside the crash.
         */
        dup2(fsrv->crash_trace_fd, 1);
        dup2(fsrv->crash_trace_fd, 2);

      } else {

        dup2(fsrv->dev_null_fd, 1);
        dup2(fsrv->dev_null_fd, 2);

      }

    }

    if (!fsrv->use_stdin) {

      dup2(fsrv->dev_null_fd, 0);

    } else {

      dup2(fsrv->out_fd, 0);
      if (fsrv->out_fd >= 0) close(fsrv->out_fd);

    }

    // Set up control and status pipes, close the unneeded original fds

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) { PCFATAL("dup2() failed"); }
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) { PCFATAL("dup2() failed"); }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    if (fsrv->out_dir_fd >= 0) close(fsrv->out_dir_fd);
    if (fsrv->dev_null_fd >= 0) close(fsrv->dev_null_fd);
    if (fsrv->crash_trace_fd >= 0) close(fsrv->crash_trace_fd);
    if (fsrv->dev_urandom_fd >= 0) close(fsrv->dev_urandom_fd);

    if (fsrv->plot_file != NULL) {

      fclose(fsrv->plot_file);
      fsrv->plot_file = NULL;

    }

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) { setenv("LD_BIND_NOW", "1", 1); }

#if defined(__linux__) || defined(__APPLE__)
    /* Tell the target the byte offset of the sync word inside the trace_bits
       shared map. It reaches the map via SHM_ENV_VAR and finds the word at
       (map base + offset); no separate shared segment is needed. */
    if (fsrv->use_futex && fsrv->child_sync && fsrv->persistent_mode) {

      char val[16];
      snprintf(val, sizeof(val), "%u", fsrv->child_sync_offset);
      setenv("AFL_CHILD_SYNC_SHM", val, 1);

    }

#endif

    // Set sane defaults for sanitizers
    set_sanitizer_defaults();

    fsrv->init_child_func(fsrv, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
    CFATAL("Error: execv to target failed\n");

  }

  // PARENT PROCESS

  char pid_buf[16];
  sprintf(pid_buf, "%d", fsrv->fsrv_pid);
  if (fsrv->cmplog_binary)
    setenv("__AFL_TARGET_PID2", pid_buf, 1);
  else
    setenv("__AFL_TARGET_PID1", pid_buf, 1);

  // Close the unneeded endpoints

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv->fsrv_ctl_fd = ctl_pipe[1];
  fsrv->fsrv_st_fd = st_pipe[0];

  // Wait for the fork server to come up, but don't wait too long

  rlen = 0;
  if (fsrv->init_tmout) {

    u32 time_ms = read_s32_timed(fsrv->fsrv_st_fd, &status, fsrv->init_tmout,
                                 stop_soon_p);

    if (!time_ms) {

      s32 tmp_pid = fsrv->fsrv_pid;
      if (tmp_pid > 0) {

        kill(tmp_pid, fsrv->child_kill_signal);
        fsrv->fsrv_pid = -1;

      }

    } else if (time_ms > fsrv->init_tmout) {

      fsrv->last_run_timed_out = 1;
      s32 tmp_pid = fsrv->fsrv_pid;
      if (tmp_pid > 0) {

        kill(tmp_pid, fsrv->child_kill_signal);
        fsrv->fsrv_pid = -1;

      }

    } else {

      rlen = 4;

    }

  } else {

    rlen = read(fsrv->fsrv_st_fd, &status, 4);

  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {

    /*
     *  The new fork server model works like this:
     *    Client: sends "AFLx" in little endian, with x being the forkserver
     *            protocol version.
     *    Server: replies with XOR of the message or exits with an error if it
     *            is not a supported version.
     *    Client: sends 32 bit of options and then sends all parameters of
     *            the options, one after another, increasing by option number.
     *            Ends with "AFLx".
     *  After the initial protocol version confirmation the server does not
     *  send any data anymore - except a future option requires this.
     */

    if ((status & FS_NEW_ERROR) == FS_NEW_ERROR) {

      report_error_and_exit(status & 0x0000ffff);

    }

    if (status >= 0x41464c00 && status <= 0x41464cff) {

      u32 version = status - 0x41464c00;

      if (!version) {

        FATAL(
            "Fork server version is not assigned, this should not happen. "
            "Recompile target.");

      } else if (version < FS_NEW_VERSION_MIN || version > FS_NEW_VERSION_MAX) {

        FATAL(
            "Fork server version is not not supported.  Recompile the target.");

      }

      u32 keep = status;
      status ^= 0xffffffff;
      if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

        FATAL("Writing to forkserver failed.");

      }

      if (!be_quiet) {

        OKF("All right - new fork server model v%u is up.", version);

      }

      rlen = read(fsrv->fsrv_st_fd, &status, 4);

      if (getenv("AFL_DEBUG")) {

        ACTF("Forkserver options received: (0x%08x)", status);

      }

      if ((status & FS_NEW_OPT_MAPSIZE)) {

        u32 tmp_map_size;
        rlen = read(fsrv->fsrv_st_fd, &tmp_map_size, 4);

        if (!fsrv->map_size) { fsrv->map_size = MAP_SIZE; }

        fsrv->real_map_size = tmp_map_size;

        if (tmp_map_size % 64) {

          tmp_map_size = (((tmp_map_size + 63) >> 6) << 6);

        }

        if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }
        if (tmp_map_size > fsrv->map_size) {

          FATAL(
              "Target's coverage map size of %u is larger than the one this "
              "AFL++ is set with (%u). Either set AFL_MAP_SIZE=%u and "
              "restart "
              " afl-fuzz, or change MAP_SIZE_POW2 in config.h and recompile "
              "afl-fuzz",
              tmp_map_size, fsrv->map_size, tmp_map_size);

        }

        fsrv->map_size = tmp_map_size;

      } else {

        fsrv->real_map_size = fsrv->map_size = MAP_SIZE;

      }

      if (status & FS_NEW_OPT_SHDMEM_FUZZ) {

        if (fsrv->support_shmem_fuzz) {

          fsrv->use_shmem_fuzz = 1;
          if (!be_quiet) { ACTF("Using SHARED MEMORY FUZZING feature."); }

        } else {

          FATAL(
              "Target requested sharedmem fuzzing, but we failed to enable "
              "it.");

        }

      }

      fsrv->supports_allocsize_derive =
          !!(status & FS_NEW_OPT_ALLOCSIZE_DERIVE);
      if (fsrv->cmplog_size_derive_requested &&
          !fsrv->supports_allocsize_derive) {

        FATAL(
            "-l z (size-derive) requested but target does not announce "
            "ALLOCSIZE_DERIVE support. Rebuild the target with "
            "AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1 (note: AFL_USE_ASAN disables "
            "ALLOCSIZE/DERIVE).");

      }

#if defined(__linux__) || defined(__APPLE__)
      if (fsrv->use_futex && !(status & FS_NEW_OPT_FUTEX)) {

        if (fsrv->persistent_mode) {

          WARNF(
              "Fast persistent sync is enabled by default, but target does "
              "not support futex synchronization. Falling back to file "
              "descriptor sync. Set AFL_OLD_CHILD_SYNC=1 to request file "
              "descriptor sync explicitly.");

        }

        fsrv->use_futex = false;
        fsrv->child_sync = NULL;

      }

#endif

      if (status & FS_OPT_IJON) {

        fsrv->use_ijon = 1;
        if (!be_quiet) { ACTF("Using IJON feature."); }

      }

      if (status & FS_OPT_C11) {

        fsrv->c11 = 1;
        if (!be_quiet) { ACTF("Using C11 feature."); }

      }

      /* Target reports an appended bug-pass map; configure_bug_runtime
         in afl-fuzz.c subtracts MAP_SIZE_BUG_BYTES from fsrv->map_size
         before the coverage code touches that region. */
      if (status & FS_NEW_OPT_BUG_MAP) {

        fsrv->use_bug_map = 1;
        if (!be_quiet) { ACTF("Bug-pass map detected in target."); }

      }

      if (status & FS_NEW_OPT_VALUE_PROFILE) {

        fsrv->use_value_profile = 1;
        if (!be_quiet) { ACTF("Using VALUE PROFILE feature."); }

      }

      if (status & FS_NEW_OPT_AUTODICT) {

        // even if we do not need the dictionary we have to read it

        u32 dict_size;
        if (read(fsrv->fsrv_st_fd, &dict_size, 4) != 4) {

          FATAL("Reading from forkserver failed.");

        }

        if (dict_size < 2 || dict_size > 0xffffff) {

          FATAL("Dictionary has an illegal size: %d", dict_size);

        }

        u32 offset = 0, count = 0;
        u8 *dict = ck_alloc(dict_size);
        if (dict == NULL) {

          FATAL("Could not allocate %u bytes of autodictionary memory",
                dict_size);

        }

        while (offset < dict_size) {

          rlen = read(fsrv->fsrv_st_fd, dict + offset, dict_size - offset);
          if (rlen > 0) {

            offset += rlen;

          } else {

            FATAL(
                "Reading autodictionary fail at position %u with %u bytes "
                "left.",
                offset, dict_size - offset);

          }

        }

        offset = 0;
        while (offset < dict_size && (u8)dict[offset] + offset < dict_size) {

          if (!ignore_autodict && fsrv->add_extra_func) {

            fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                 (u8)dict[offset]);
            count++;

          }

          offset += (1 + dict[offset]);

        }

        if (!be_quiet && count) {

          ACTF("Loaded %u autodictionary entries", count);

        }

        ck_free(dict);

      }

      u32 status2;
      rlen = read(fsrv->fsrv_st_fd, &status2, 4);

      // Mask out expected capability flags when comparing handshake status
      u32 expected_flags = 0;
      if (fsrv->use_ijon) { expected_flags |= FS_OPT_IJON; }
      if (fsrv->use_value_profile) {

        expected_flags |= FS_NEW_OPT_VALUE_PROFILE;

      }

      if ((status2 & ~expected_flags) != keep) {

        FATAL("Error in forkserver communication (%08x=>%08x)", keep, status2);

      }

    } else {

#if defined(__linux__) || defined(__APPLE__)

      if (fsrv->use_futex) {

        if (fsrv->persistent_mode) {

          WARNF(
              "Fast persistent sync is enabled by default, but old forkserver "
              "protocol is in use. Falling back to file descriptor sync. Set "
              "AFL_OLD_CHILD_SYNC=1 to request file descriptor sync "
              "explicitly.");

        }

        fsrv->use_futex = false;
        fsrv->child_sync = NULL;

      }

#endif
      if (!fsrv->qemu_mode && !fsrv->cs_mode && !fsrv->use_fauxsrv
#ifdef __linux__
          && !fsrv->nyx_mode
#endif
      ) {

        if (fsrv->cmplog_size_derive_requested) {

          WARNF(
              "-l z (size-derive) requested but target uses the old forkserver "
              "protocol — ignored");
          fsrv->cmplog_size_derive_requested = false;

        }

        WARNF(
            "Old fork server model is used by the target, this still works "
            "though.");

      }

      if (!be_quiet) { OKF("All right - old fork server is up."); }

      if (getenv("AFL_DEBUG")) {

        ACTF("Extended forkserver functions received (%08x).", status);

      }

      if ((status & FS_OPT_ERROR) == FS_OPT_ERROR)
        report_error_and_exit(FS_OPT_GET_ERROR(status));

      if (fsrv->cmplog_binary && !fsrv->qemu_mode) {

        FATAL("Target was compiled with outdated CMPLOG, recompile it!\n");

      }

      if ((status & FS_OPT_ENABLED) == FS_OPT_ENABLED) {

        // workaround for recent AFL++ versions
        if ((status & FS_OPT_OLD_AFLPP_WORKAROUND) ==
            FS_OPT_OLD_AFLPP_WORKAROUND)
          status = (status & 0xf0ffffff);

        if ((status & FS_OPT_NEWCMPLOG) == 0 && fsrv->cmplog_binary) {

          if (fsrv->qemu_mode || fsrv->frida_mode) {

            report_error_and_exit(FS_ERROR_OLD_CMPLOG_QEMU);

          } else {

            report_error_and_exit(FS_ERROR_OLD_CMPLOG);

          }

        }

        if ((status & FS_OPT_C11) == FS_OPT_C11) {

          fsrv->c11 = 1;
          if (!be_quiet) { ACTF("Using C11 feature."); }

        }

        if ((status & FS_OPT_SHDMEM_FUZZ) == FS_OPT_SHDMEM_FUZZ) {

          if (fsrv->support_shmem_fuzz) {

            fsrv->use_shmem_fuzz = 1;
            if (!be_quiet) { ACTF("Using SHARED MEMORY FUZZING feature."); }

            if ((status & FS_OPT_AUTODICT) == 0 || ignore_autodict) {

              u32 send_status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);
              if (write(fsrv->fsrv_ctl_fd, &send_status, 4) != 4) {

                FATAL("Writing to forkserver failed.");

              }

            }

          } else {

            FATAL(
                "Target requested sharedmem fuzzing, but we failed to enable "
                "it.");

          }

        }

        if ((status & FS_OPT_MAPSIZE) == FS_OPT_MAPSIZE) {

          u32 tmp_map_size = FS_OPT_GET_MAPSIZE(status);

          if (!fsrv->map_size) { fsrv->map_size = MAP_SIZE; }

          fsrv->real_map_size = tmp_map_size;

          if (tmp_map_size % 64) {

            tmp_map_size = (((tmp_map_size + 63) >> 6) << 6);

          }

          if (!be_quiet) { ACTF("Target map size: %u", fsrv->real_map_size); }
          if (tmp_map_size > fsrv->map_size) {

            FATAL(
                "Target's coverage map size of %u is larger than the one this "
                "AFL++ is set with (%u). Either set AFL_MAP_SIZE=%u and "
                "restart "
                " afl-fuzz, or change MAP_SIZE_POW2 in config.h and recompile "
                "afl-fuzz",
                tmp_map_size, fsrv->map_size, tmp_map_size);

          }

          fsrv->map_size = tmp_map_size;

        } else {

          fsrv->real_map_size = fsrv->map_size = MAP_SIZE;

        }

        if ((status & FS_OPT_AUTODICT) == FS_OPT_AUTODICT) {

          if (!ignore_autodict) {

            if (fsrv->add_extra_func == NULL || fsrv->afl_ptr == NULL) {

              // this is not afl-fuzz - or it is cmplog - we deny and return
              if (fsrv->use_shmem_fuzz) {

                status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);

              } else {

                status = (FS_OPT_ENABLED);

              }

              if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

                FATAL("Writing to forkserver failed.");

              }

              afl_fsrv_report_persistent_sync_mode(fsrv);
              return;

            }

            if (!be_quiet) { ACTF("Using AUTODICT feature."); }

            if (fsrv->use_shmem_fuzz) {

              status = (FS_OPT_ENABLED | FS_OPT_AUTODICT | FS_OPT_SHDMEM_FUZZ);

            } else {

              status = (FS_OPT_ENABLED | FS_OPT_AUTODICT);

            }

            if (write(fsrv->fsrv_ctl_fd, &status, 4) != 4) {

              FATAL("Writing to forkserver failed.");

            }

            if (read(fsrv->fsrv_st_fd, &status, 4) != 4) {

              FATAL("Reading from forkserver failed.");

            }

            if (status < 2 || (u32)status > 0xffffff) {

              FATAL("Dictionary has an illegal size: %d", status);

            }

            u32 offset = 0, count = 0;
            u32 len = status;
            u8 *dict = ck_alloc(len);
            if (dict == NULL) {

              FATAL("Could not allocate %u bytes of autodictionary memory",
                    len);

            }

            while (len != 0) {

              rlen = read(fsrv->fsrv_st_fd, dict + offset, len);
              if (rlen > 0) {

                len -= rlen;
                offset += rlen;

              } else {

                FATAL(
                    "Reading autodictionary fail at position %u with %u bytes "
                    "left.",
                    offset, len);

              }

            }

            offset = 0;
            while (offset < (u32)status &&
                   (u8)dict[offset] + offset < (u32)status) {

              fsrv->add_extra_func(fsrv->afl_ptr, dict + offset + 1,
                                   (u8)dict[offset]);
              offset += (1 + dict[offset]);
              count++;

            }

            if (!be_quiet) { ACTF("Loaded %u autodictionary entries", count); }
            ck_free(dict);

          }

        }

      } else {

        // if AFL_MAP_SIZE is set, use this map size
        if (getenv("AFL_MAP_SIZE") || getenv("AFL_MAPSIZE")) {

          fsrv->real_map_size = fsrv->map_size = get_map_size();

        } else {

          // Otherwise the binary is most likely instrumented using AFL's tool,
          // and we will set map_size to MAP_SIZE.
          fsrv->real_map_size = fsrv->map_size = MAP_SIZE;

        }

      }

    }

    afl_fsrv_report_persistent_sync_mode(fsrv);
    return;

  }

  if (fsrv->last_run_timed_out) {

    FATAL(
        "Timeout while initializing fork server (setting "
        "AFL_FORKSRV_INIT_TMOUT may help)");

  }

  if (waitpid(fsrv->fsrv_pid, &status, 0) <= 0) { PFATAL("waitpid() failed"); }

  char *which = fsrv->asanfuzz_binary ? "SAND"
                : fsrv->cmplog_binary ? "CMPLOG"
                                      : "fuzzing";

  if (WIFSIGNALED(status)) {

    if (fsrv->mem_limit && fsrv->mem_limit < 500 && fsrv->uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the %s target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "run with '-m 0'.\n",
           which);

    } else if (!fsrv->mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the %s target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! You can try the following:\n\n"

           "    - The target binary crashes because necessary runtime "
           "conditions it needs\n"
           "      are not met. Try to:\n"
           "      1. Run again with AFL_DEBUG=1 set and check the output of "
           "the target\n"
           "         binary for clues.\n"
           "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
           "analyze the\n"
           "         generated core dump.\n\n"

           "    - Possibly the target requires a huge coverage map and has "
           "CTORS.\n"
           "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

           MSG_FORK_ON_APPLE

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke the Fuzzing Zulip server for troubleshooting "
           "tips.\n",
           which);

    } else {

      u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the %s target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! You can try the following:\n\n"

           "    - The target binary crashes because necessary runtime "
           "conditions it needs\n"
           "      are not met. Try to:\n"
           "      1. Run again with AFL_DEBUG=1 set and check the output of "
           "the target\n"
           "         binary for clues.\n"
           "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
           "analyze the\n"
           "         generated core dump.\n\n"

           "    - The current memory limit (%s) is too restrictive, causing "
           "the\n"
           "      target to hit an OOM condition in the dynamic linker. Try "
           "bumping up\n"
           "      the limit with the -m setting in the command line. A simple "
           "way confirm\n"
           "      this diagnosis would be:\n\n"

           MSG_ULIMIT_USAGE
           " /path/to/fuzzed_app )\n\n"

           "      Tip: you can use https://jwilk.net/software/recidivm to\n"
           "      estimate the required amount of virtual memory for the "
           "binary.\n\n"

           MSG_FORK_ON_APPLE

           "    - Possibly the target requires a huge coverage map and has "
           "CTORS.\n"
           "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke the Fuzzing Zulip server for troubleshooting "
           "tips.\n",
           which,
           stringify_mem_size(val_buf, sizeof(val_buf), fsrv->mem_limit << 20),
           fsrv->mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG) {

    FATAL("Unable to execute target application ('%s')", argv[0]);

  }

  if (fsrv->mem_limit && fsrv->mem_limit < 500 && fsrv->uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the %s target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    run with '-m 0'.\n",
         which);

  } else if (!fsrv->mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the %s target binary terminated before we could "
         "complete"
         " a\n"
         "handshake with the injected code. You can try the following:\n\n"

         "    - The target binary crashes because necessary runtime conditions "
         "it needs\n"
         "      are not met. Try to:\n"
         "      1. Run again with AFL_DEBUG=1 set and check the output of the "
         "target\n"
         "         binary for clues.\n"
         "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
         "analyze the\n"
         "         generated core dump.\n\n"

         "    - Possibly the target requires a huge coverage map and has "
         "CTORS.\n"
         "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

         "Otherwise there is a horrible bug in the fuzzer.\n"
         "Poke the Fuzzing Zulip server for troubleshooting tips.\n",
         which);

  } else {

    u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, looks like the %s target binary terminated "
        "before we could complete a\n"
        "    handshake with the injected code. You can try the following:\n\n"

        "%s"

        "    - The target binary crashes because necessary runtime conditions "
        "it needs\n"
        "      are not met. Try to:\n"
        "      1. Run again with AFL_DEBUG=1 set and check the output of the "
        "target\n"
        "         binary for clues.\n"
        "      2. Run again with AFL_DEBUG=1 and 'ulimit -c unlimited' and "
        "analyze the\n"
        "         generated core dump.\n\n"

        "    - Possibly the target requires a huge coverage map and has "
        "CTORS.\n"
        "      Retry with setting AFL_MAP_SIZE=10000000.\n\n"

        "    - The current memory limit (%s) is too restrictive, causing an "
        "OOM\n"
        "      fault in the dynamic linker. This can be fixed with the -m "
        "option. A\n"
        "      simple way to confirm the diagnosis may be:\n\n"

        MSG_ULIMIT_USAGE
        " /path/to/fuzzed_app )\n\n"

        "      Tip: you can use https://jwilk.net/software/recidivm to\n"
        "      estimate the required amount of virtual memory for the "
        "binary.\n\n"

        "    - The target was compiled with afl-clang-lto and a constructor "
        "was\n"
        "      instrumented, recompiling without AFL_LLVM_MAP_ADDR might solve "
        "your \n"
        "      problem\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other "
        "options\n"
        "      fail, poke the Fuzzing Zulip server for troubleshooting "
        "tips.\n",
        getenv(DEFER_ENV_VAR)
            ? "    - You are using deferred forkserver, but __AFL_INIT() is "
              "never\n"
              "      reached before the program terminates.\n\n"
            : "",
        which, stringify_int(val_buf, sizeof(val_buf), fsrv->mem_limit << 20),
        fsrv->mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}

/* Stop the forkserver and child */

void afl_fsrv_kill(afl_forkserver_t *fsrv) {

  if (fsrv->child_pid > 0) { kill(fsrv->child_pid, fsrv->child_kill_signal); }
  if (fsrv->fsrv_pid > 0) {

    kill(fsrv->fsrv_pid, fsrv->fsrv_kill_signal);
    usleep(25);
    waitpid(fsrv->fsrv_pid, NULL, WNOHANG);

  }

  if (fsrv->fsrv_ctl_fd >= 0) {

    close(fsrv->fsrv_ctl_fd);
    fsrv->fsrv_ctl_fd = -1;

  }

  if (fsrv->fsrv_st_fd >= 0) {

    close(fsrv->fsrv_st_fd);
    fsrv->fsrv_st_fd = -1;

  }

  fsrv->fsrv_pid = -1;
  fsrv->child_pid = -1;
#ifdef AFL_PERSISTENT_RECORD
  if (fsrv->persistent_record_data) {

    for (u32 i = 0; i < fsrv->persistent_record; ++i) {

      afl_free(fsrv->persistent_record_data[i]);

    }

    ck_free(fsrv->persistent_record_data);
    fsrv->persistent_record_data = NULL;

  }

  if (fsrv->persistent_record_len) {

    ck_free(fsrv->persistent_record_len);
    fsrv->persistent_record_len = NULL;

  }

#endif

#ifdef __linux__
  /* child_sync lives inside trace_bits (freed by afl_shm_deinit), so there is
     nothing to release here; just drop the pointer. It is re-derived by the
     next afl_fsrv_start. */
  fsrv->child_sync = NULL;

  afl_nyx_runner_kill(fsrv);

  if (fsrv->gui_mode) {

    if (fsrv->gui_python_pid > 0) {

      kill(fsrv->gui_python_pid, fsrv->child_kill_signal);

    }

    fsrv->gui_python_pid = -1;

  }

#endif

}

/* Get the map size from the target forkserver */

u32 afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                         volatile u8 *stop_soon_p, u8 debug_child_output) {

  afl_fsrv_start(fsrv, argv, stop_soon_p, debug_child_output);
  return fsrv->map_size;

}

/* An IJON build and a bug-pass build append areas to trace_bits that are not
   coverage, the whole region being [cov | IJON_MAP | IJON_BYTES | BUG].
   afl-fuzz consumes those channels and takes the tails off its own view (see
   configure_ijon_runtime and configure_bug_runtime); every other tool has no
   use for them and would otherwise count them as edges, minimise against them
   or write them out as coverage. The IJON set/inc area stays inside the map on
   purpose, because afl-fuzz counts it as coverage - dropping it here would make
   afl-cmin disagree with the fuzzer about what a new tuple is. The shared
   segment keeps its full size, only the coverage view shrinks. Call this after
   the handshake that set the size, and only once per handshake. */

void afl_fsrv_trim_extra_maps(afl_forkserver_t *fsrv) {

  u32 tail = 0;

  if (fsrv->use_bug_map) { tail += MAP_SIZE_BUG_BYTES; }
  if (fsrv->use_ijon) { tail += MAP_SIZE_IJON_BYTES; }

  if (!tail) { return; }

  if (fsrv->map_size <= tail + 4 || fsrv->real_map_size <= tail + 4) {

    FATAL(
        "target reports a map of %u bytes, too small to hold the IJON and "
        "bug-pass areas it announced - BUG!",
        fsrv->map_size);

  }

  fsrv->map_size -= tail;
  fsrv->real_map_size -= tail;

  if (!be_quiet) {

    ACTF("Coverage map is %u bytes, %u bytes of IJON/bug-pass areas excluded.",
         fsrv->map_size, tail);

  }

}

/* Get mapsize from fsrv and resize if larger than DEFAULT_SHMEM_SIZE */

void afl_fsrv_resize_mapsize(afl_forkserver_t *fsrv, void *shm_p,
                             char **use_argv, u32 map_size,
                             volatile u8 *stop_soon, bool unicorn_mode) {

  if (!fsrv->cs_mode && (!fsrv->qemu_mode || fsrv->qemu_bridge) &&
      !unicorn_mode) {

    if (map_size <= DEFAULT_SHMEM_SIZE) {

      fsrv->map_size = DEFAULT_SHMEM_SIZE;  // dummy temporary value

    } else {

      validate_map_size(map_size);
      fsrv->map_size = map_size;

    }

    char vbuf[16];
    snprintf(vbuf, sizeof(vbuf), "%u", fsrv->map_size);
    setenv("AFL_MAP_SIZE", vbuf, 1);

    u32 new_map_size =
        afl_fsrv_get_mapsize(fsrv, use_argv, stop_soon,
                             (get_afl_env("AFL_DEBUG_CHILD") ||
                              get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                                 ? 1
                                 : 0);

    if (new_map_size) {

      // only reinitialize when it makes sense
      if (map_size < new_map_size) {

        if (!be_quiet)
          ACTF("Acquired new map size for target: %u bytes\n", new_map_size);

#ifdef __linux__
        // no need to terminate the nyx runner
        if (!fsrv->nyx_mode) {

#endif
          sharedmem_t *shm = (sharedmem_t *)shm_p;
          afl_shm_deinit(shm);
          afl_fsrv_kill(fsrv);
          fsrv->map_size = new_map_size;
          fsrv->trace_bits =
              afl_shm_init(shm, new_map_size, 0, DEFAULT_PERMISSION, -1);
          fsrv->child_sync_offset = shm->child_sync_offset;
          afl_fsrv_start(fsrv, use_argv, stop_soon,
                         (get_afl_env("AFL_DEBUG_CHILD") ||
                          get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                             ? 1
                             : 0);
#ifdef __linux__

        }

#endif

      }

      map_size = new_map_size;

    }

    fsrv->map_size = map_size;

  } else {

    afl_fsrv_start(fsrv, use_argv, stop_soon,
                   (get_afl_env("AFL_DEBUG_CHILD") ||
                    get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                       ? 1
                       : 0);

  }

  afl_fsrv_trim_extra_maps(fsrv);

}

/* Delete the current testcase and write the buf to the testcase file */

void __attribute__((hot)) afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv,
                                                     u8 *buf, size_t len) {

#ifdef __linux__
  if (unlikely(fsrv->nyx_mode)) {

    fsrv->nyx_handlers->nyx_set_afl_input(fsrv->nyx_runner, buf, len);
    return;

  }

#endif

#ifdef AFL_PERSISTENT_RECORD
  if (unlikely(fsrv->persistent_record)) {

    fsrv->persistent_record_len[fsrv->persistent_record_idx] = len;
    fsrv->persistent_record_data[fsrv->persistent_record_idx] = afl_realloc(
        (void **)&fsrv->persistent_record_data[fsrv->persistent_record_idx],
        len);

    if (unlikely(!fsrv->persistent_record_data[fsrv->persistent_record_idx])) {

      FATAL("allocating replay memory failed.");

    }

    memcpy(fsrv->persistent_record_data[fsrv->persistent_record_idx], buf, len);

    if (unlikely(++fsrv->persistent_record_idx >= fsrv->persistent_record)) {

      fsrv->persistent_record_idx = 0;

    }

  }

#endif

  if (likely(fsrv->use_shmem_fuzz)) {

    if (unlikely(len > MAX_FILE)) len = MAX_FILE;

    *fsrv->shmem_fuzz_len = len;
    memcpy(fsrv->shmem_fuzz, buf, len);
#ifdef _DEBUG
    if (getenv("AFL_DEBUG")) {

      fprintf(stderr, "FS crc: %016llx len: %u\n",
              hash64(fsrv->shmem_fuzz, *fsrv->shmem_fuzz_len, HASH_CONST),
              *fsrv->shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *fsrv->shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", fsrv->shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *fsrv->shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", buf[i]);
      fprintf(stderr, "\n");

    }

#endif

  } else {

    s32 fd = fsrv->out_fd;

    if (!fsrv->use_stdin && fsrv->out_file) {

      if (unlikely(fsrv->no_unlink)) {

        fd = open(fsrv->out_file, O_WRONLY | O_CREAT | O_TRUNC, fsrv->perm);

      } else {

        unlink(fsrv->out_file);  // Ignore errors
        fd = open(fsrv->out_file, O_WRONLY | O_CREAT | O_EXCL, fsrv->perm);

      }

      if (fd < 0) { PFATAL("Unable to create '%s'", fsrv->out_file); }

      if (fsrv->chown_needed) {

        if (fchown(fd, -1, fsrv->gid) == -1) { PFATAL("fchown() failed"); }

      }

    } else if (unlikely(fd <= 0)) {

      // We should have a (non-stdin) fd at this point, else we got a problem.
      FATAL(
          "Nowhere to write output to (neither out_fd nor out_file set (fd is "
          "%d))",
          fd);

    } else {

      lseek(fd, 0, SEEK_SET);

    }

    // fprintf(stderr, "WRITE %d %u\n", fd, len);
    ck_write(fd, buf, len, fsrv->out_file);

    if (fsrv->use_stdin) {

      if (ftruncate(fd, len)) { PFATAL("ftruncate() failed"); }
      lseek(fd, 0, SEEK_SET);

    } else {

      close(fd);

    }

  }

}

/* Validate the child PID received from the forkserver.
   Returns false if stop_soon is set (caller should return 0).
   Calls FATAL on invalid child PIDs. */

static inline bool afl_fsrv_check_child_pid(afl_forkserver_t *fsrv,
                                            volatile u8      *stop_soon_p) {

  if (likely(fsrv->child_pid > 0)) { return true; }

  if (*stop_soon_p) { return false; }

  if ((fsrv->child_pid & FS_OPT_ERROR) &&
      FS_OPT_GET_ERROR(fsrv->child_pid) == FS_ERROR_SHM_OPEN)
    FATAL(
        "Target reported shared memory access failed (perhaps increase "
        "shared memory available).");

  FATAL("Fork server is misbehaving (OOM?)");

}

#ifdef AFL_PERSISTENT_RECORD
/* Reset persistent record tracking when a new child process is spawned. */

static inline void afl_fsrv_persistent_record_reset(afl_forkserver_t *fsrv) {

  if (unlikely(fsrv->persistent_record &&
               fsrv->persistent_record_pid != fsrv->child_pid)) {

    fsrv->persistent_record_pid = fsrv->child_pid;
    u32 idx, val;
    if (unlikely(!fsrv->persistent_record_idx))
      idx = fsrv->persistent_record - 1;
    else
      idx = fsrv->persistent_record_idx - 1;
    val = fsrv->persistent_record_len[idx];
    memset((void *)fsrv->persistent_record_len, 0,
           fsrv->persistent_record * sizeof(u32));
    fsrv->persistent_record_len[idx] = val;

  }

}

#endif

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot)) afl_fsrv_run_target(
    afl_forkserver_t *fsrv, u32 timeout, volatile u8 *stop_soon_p) {

  s32 res;
  u32 exec_ms;
  u32 write_value = fsrv->last_run_timed_out;

  /* AFL_CRASH_TRACES: clear the capture buffer before each run so a crash's
     trace file holds only the crashing run's own stdout/stderr, not output
     accumulated from previous runs. Only the main forkserver sets
     crash_trace_fd (>= 0), and only when the feature is enabled, so this is a
     single no-op branch otherwise. */

  if (unlikely(fsrv->crash_trace_fd >= 0)) {

    if (ftruncate(fsrv->crash_trace_fd, 0) != 0) {             /* non-fatal */

    }

  }

#ifdef AFL_PERSISTENT_RECORD
  fsrv_run_result_t retval = FSRV_RUN_OK;
  char             *persistent_out_fmt;
#endif

#ifdef __linux__
  if (fsrv->nyx_mode) {

    static uint32_t last_timeout_value = 0;

    if (last_timeout_value != timeout) {

      fsrv->nyx_handlers->nyx_option_set_timeout(
          fsrv->nyx_runner, timeout / 1000, (timeout % 1000) * 1000);
      fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);
      last_timeout_value = timeout;

    }

    enum NyxReturnValue ret_val =
        fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner);

    fsrv->total_execs++;

    switch (ret_val) {

      case Normal:
        return FSRV_RUN_OK;
      case Crash:
      case Asan:
        return FSRV_RUN_CRASH;
      case Timeout:
        return FSRV_RUN_TMOUT;
      case InvalidWriteToPayload:
        if (!!getenv("AFL_NYX_HANDLE_INVALID_WRITE")) { return FSRV_RUN_CRASH; }

        // ???
        FATAL("FixMe: Nyx InvalidWriteToPayload handler is missing");
        break;
      case Abort:
        FATAL("Error: Nyx abort occurred...");
      case IoError:
        if (*stop_soon_p) {

          return 0;

        } else {

          FATAL("Error: QEMU-Nyx has died...");

        }

        break;
      case Error:
        FATAL("Error: Nyx runtime error has occurred...");
        break;

    }

    return FSRV_RUN_OK;

  }

#endif
  /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  /* If the binary is not instrumented, we don't care about the coverage.
   * Make it a bit faster */
  if (!fsrv->san_but_not_instrumented) {

#ifdef __linux__
    if (likely(!fsrv->nyx_mode)) {

      memset(fsrv->trace_bits, 0, fsrv->map_size);
      MEM_BARRIER();

    }

#else
    // Clear shared memory for clean execution
    memset(fsrv->trace_bits, 0, fsrv->map_size);
    MEM_BARRIER();
#endif

  }

  /* we have the fork server (or faux server) up and running
  First, tell it if the previous run timed out. */

#if defined(__linux__) || defined(__APPLE__)
  if (likely(fsrv->use_futex && fsrv->child_pid > 0)) {

    // Futex protocol: see afl_child_state_t in types.h

    /* Check if the forkserver already signaled that the child exited
       (e.g. crash/exit between iterations while we were processing the
       previous DONE result).  The pipe status is already written at this
       point (forkserver writes pipe before futex), so jump straight to
       reading it. */
    u32 cur = __atomic_load_n(fsrv->child_sync, __ATOMIC_ACQUIRE);
    if (unlikely(cur == AFL_CHILD_EXITED)) { goto futex_read_status; }

    // HOT PATH: persistent child is alive, signal it to run
    __atomic_store_n(fsrv->child_sync, AFL_CHILD_RUN, __ATOMIC_RELEASE);
    afl_sync_wake(fsrv->child_sync);

    if (unlikely(fsrv->late_send)) {

      fsrv->late_send(fsrv->custom_data_ptr, fsrv->custom_input,
                      fsrv->custom_input_len);

    }

    u32 fres = afl_futex_wait(fsrv, timeout, stop_soon_p);

    if (fres == AFL_CHILD_DONE) {

      // DONE: child completed this iteration successfully
      fsrv->total_execs++;
      MEM_BARRIER();

      if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {

        return FSRV_RUN_ERROR;

      }

      return FSRV_RUN_OK;

    }

    // EXITED or timeout/stop: read child status from forkserver pipe
  futex_read_status:
    if (!read_status_or_escalate(fsrv, stop_soon_p)) { return 0; }

    fsrv->child_pid = -1;
    __atomic_store_n(fsrv->child_sync, AFL_CHILD_IDLE, __ATOMIC_RELEASE);
    goto classify_result;

  }

#endif
  if ((res = write(fsrv->fsrv_ctl_fd, &write_value, 4)) != 4) {

    if (*stop_soon_p) { return 0; }
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  fsrv->last_run_timed_out = 0;

  if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_pid, 4)) != 4) {

    if (*stop_soon_p) { return 0; }
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if (likely(fsrv->child_pid > 0)) { fsrv->last_child_pid = fsrv->child_pid; }

  // GUI Mode
#ifdef __linux__
  if (unlikely(fsrv->gui_mode)) {

    pid_t python_pid;
    python_pid = fork();

    if (python_pid < 0) { PFATAL("GUI mode fork failed."); }
    fsrv->gui_python_pid = python_pid;
    if (python_pid == 0) {  // child that will perform GUI interactions

  #ifdef __linux__
      prctl(PR_SET_PDEATHSIG, SIGKILL);
  #endif

      ACTF("Non-forkserver exec'ing, with PID = %ld\n", (long)getpid());
      char gui_pid_str[16];
      sprintf(gui_pid_str, "%d",
              (int)fsrv->child_pid);  // Convert pid_t to a string

      execl(fsrv->gui_python_dir, fsrv->gui_python_dir, fsrv->out_file,
            gui_pid_str, NULL);

      PFATAL("execl failed for %s", fsrv->gui_python_dir);
      exit(1);

    }

  }

#endif

#ifdef AFL_PERSISTENT_RECORD
  afl_fsrv_persistent_record_reset(fsrv);
#endif

  if (!afl_fsrv_check_child_pid(fsrv, stop_soon_p)) { return 0; }

  if (unlikely(fsrv->late_send)) {

    fsrv->late_send(fsrv->custom_data_ptr, fsrv->custom_input,
                    fsrv->custom_input_len);

  }

#if defined(__linux__) || defined(__APPLE__)
  if (likely(fsrv->use_futex && fsrv->persistent_mode)) {

    u32 fres = afl_futex_wait(fsrv, timeout, stop_soon_p);

    if (fres == AFL_CHILD_DONE) {

      // DONE: child completed this iteration successfully
      fsrv->total_execs++;
      MEM_BARRIER();

      if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {

        return FSRV_RUN_ERROR;

      }

      return FSRV_RUN_OK;

    }

    // EXITED or timeout/stop: read child status from forkserver pipe
    if (!read_status_or_escalate(fsrv, stop_soon_p)) { return 0; }

    fsrv->child_pid = -1;
    __atomic_store_n(fsrv->child_sync, AFL_CHILD_IDLE, __ATOMIC_RELEASE);
    goto classify_result;

  }

#endif

  exec_ms = read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status, timeout,
                           stop_soon_p);

  if (exec_ms > timeout) {

    /* If there was no response from forkserver after timeout milliseconds,
    we kill the child. The forkserver should inform us afterwards */

    s32 tmp_pid = fsrv->child_pid;
    if (tmp_pid > 0) {

      kill(tmp_pid, fsrv->child_kill_signal);
      fsrv->child_pid = -1;

    }

    fsrv->last_run_timed_out = 1;
    if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }

  }

  if (!exec_ms) {

    if (*stop_soon_p) { return 0; }
    SAYF("\n" cLRD "[-] " cRST
         "Unable to communicate with fork server. Some possible reasons:\n\n"
         "    - You've run out of memory. Use -m to increase the the memory "
         "limit\n"
         "      to something higher than %llu.\n"
         "    - The binary or one of the libraries it uses manages to "
         "create\n"
         "      threads before the forkserver initializes.\n"
         "    - The binary, at least in some circumstances, exits in a way "
         "that\n"
         "      also kills the parent process - raise() could be the "
         "culprit.\n"
         "    - If using persistent mode with QEMU, "
         "AFL_QEMU_PERSISTENT_ADDR "
         "is\n"
         "      probably not valid (hint: add the base address in case of "
         "PIE)"
         "\n\n"
         "If all else fails you can disable the fork server via "
         "AFL_NO_FORKSRV=1.\n",
         fsrv->mem_limit);
    RPFATAL(res, "Unable to communicate with fork server");

  }

  if (!WIFSTOPPED(fsrv->child_status)) { fsrv->child_pid = -1; }

#if defined(__linux__) || defined(__APPLE__)
classify_result:
#endif
  fsrv->total_execs++;

  /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  // Report outcome to caller

  // Was the run unsuccessful?
  if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {

    return FSRV_RUN_ERROR;

  }

  // Did we timeout?
  if (unlikely(fsrv->last_run_timed_out)) {

    fsrv->last_kill_signal = fsrv->child_kill_signal;

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(fsrv->persistent_record)) {

      retval = FSRV_RUN_TMOUT;
      persistent_out_fmt = "%s/hangs/RECORD:%06u,cnt:%06u%s%s";
      goto store_persistent_record;

    }

#endif

    return FSRV_RUN_TMOUT;

  }

  /* Did we crash?
  In a normal case, (abort) WIFSIGNALED(child_status) will be set.
  MSAN & LSAN in uses_asan mode use special exit codes as they doesn't support
  abort_on_error. On top, a user may specify a custom AFL_CRASH_EXITCODE.
  Handle all four cases here. */

  if (unlikely(
          // A normal crash/abort
          (WIFSIGNALED(fsrv->child_status)
  /* Explicitly ignore SIGINT/SIGTERM as a crash, since we use them to terminate
   * the GUI's*/
#ifdef __linux__
           && (!fsrv->gui_mode || (WTERMSIG(fsrv->child_status) != SIGINT &&
                                   WTERMSIG(fsrv->child_status) != SIGTERM))
#endif
               ) ||
          // special handling for msan
          ((fsrv->uses_asan & 4) &&
           WEXITSTATUS(fsrv->child_status) == MSAN_ERROR) ||
          // special handling for lsan
          ((fsrv->uses_asan & 2) &&
           WEXITSTATUS(fsrv->child_status) == LSAN_ERROR) ||
          // the custom crash_exitcode was returned by the target
          (fsrv->uses_crash_exitcode &&
           WEXITSTATUS(fsrv->child_status) == fsrv->crash_exitcode))) {

    // For a proper crash, set last_kill_signal to WTERMSIG, else set it to 0
    fsrv->last_kill_signal =
        WIFSIGNALED(fsrv->child_status) ? WTERMSIG(fsrv->child_status) : 0;

    // For a special exit code, set last_exit_code to non-zero
    fsrv->last_exit_code =
        WIFSIGNALED(fsrv->child_status) ? 0 : WEXITSTATUS(fsrv->child_status);

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(fsrv->persistent_record)) {

      retval = FSRV_RUN_CRASH;
      persistent_out_fmt = "%s/crashes/RECORD:%06u,cnt:%06u%s%s";
      goto store_persistent_record;

    }

#endif

    return FSRV_RUN_CRASH;

  }

  // success :)
  return FSRV_RUN_OK;

#ifdef AFL_PERSISTENT_RECORD
store_persistent_record: {

  char fn[PATH_MAX];
  u32  i, writecnt = 0;
  for (i = 0; i < fsrv->persistent_record; ++i) {

    u32 entry = (i + fsrv->persistent_record_idx) % fsrv->persistent_record;
    u8 *data = fsrv->persistent_record_data[entry];
    u32 len = fsrv->persistent_record_len[entry];
    if (likely(len && data)) {

      snprintf(
          fn, sizeof(fn), persistent_out_fmt, fsrv->persistent_record_dir,
          fsrv->persistent_record_cnt, writecnt++,
          ((afl_state_t *)(fsrv->afl_ptr))->file_extension ? "." : "",
          ((afl_state_t *)(fsrv->afl_ptr))->file_extension
              ? (const char *)((afl_state_t *)(fsrv->afl_ptr))->file_extension
              : "");
      int fd = open(fn, O_CREAT | O_TRUNC | O_WRONLY, 0644);
      if (fd >= 0) {

        ck_write(fd, data, len, fn);
        close(fd);

      }

    }

  }

  ++fsrv->persistent_record_cnt;

  return retval;

}

#endif

}

void afl_fsrv_killall() {

  LIST_FOREACH(&fsrv_list, afl_forkserver_t, { afl_fsrv_kill(el); });

}

void afl_fsrv_deinit(afl_forkserver_t *fsrv) {

  afl_fsrv_kill(fsrv);
  list_remove(&fsrv_list, fsrv);

#ifdef AFL_PERSISTENT_RECORD
  if (fsrv->persistent_record_dir) {

    ck_free(fsrv->persistent_record_dir);
    fsrv->persistent_record_dir = NULL;

  }

#endif

}

