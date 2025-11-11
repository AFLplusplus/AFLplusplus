/*
   american fuzzy lop++ - IJON input management and scheduling
   ----------------------------------------------------------

*/

#define _GNU_SOURCE
#define AFL_LLVM_IJON

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "afl-ijon-min.h"
#include "afl-fuzz.h"

/* Global IJON history limit - initialized from environment or AFL state */
static int  afl_ijon_history_limit_global = 0;
static bool afl_ijon_history_limit_initialized = false;

/* Global comprehensive IJON state for fastresume save/load */
static ijon_fastresume_state_t afl_ijon_fastresume_state = {0};
static u8                      afl_ijon_fastresume_loaded = 0;

/* Functions to save/load comprehensive IJON state for fastresume */
void save_ijon_state_for_fastresume(u32 offset, u32 map_size, u32 real_map_size,
                                    u32 target_map_size) {

  afl_ijon_fastresume_state.ijon_offset = offset;
  afl_ijon_fastresume_state.map_size = map_size;
  afl_ijon_fastresume_state.real_map_size = real_map_size;
  afl_ijon_fastresume_state.target_map_size = target_map_size;
  afl_ijon_fastresume_state.is_initialized = 1;
  afl_ijon_fastresume_loaded = 1;

}

ijon_fastresume_state_t *get_saved_ijon_state(void) {

  return afl_ijon_fastresume_loaded ? &afl_ijon_fastresume_state : NULL;

}

u8 has_saved_ijon_state(void) {

  return afl_ijon_fastresume_loaded;

}

void clear_saved_ijon_state(void) {

  memset(&afl_ijon_fastresume_state, 0, sizeof(ijon_fastresume_state_t));
  afl_ijon_fastresume_loaded = 0;

}

// Legacy functions for backward compatibility
void save_ijon_offset_for_fastresume(u32 offset) {

  afl_ijon_fastresume_state.ijon_offset = offset;
  afl_ijon_fastresume_loaded = 1;

}

u32 get_saved_ijon_offset(void) {

  return afl_ijon_fastresume_state.ijon_offset;

}

u8 has_saved_ijon_offset(void) {

  return afl_ijon_fastresume_loaded;

}

// Function prototypes
void ijon_load_existing_state(ijon_min_state *self);

/* Initialize global IJON history limit from environment variable */
static void init_afl_ijon_history_limit(void) {

  if (afl_ijon_history_limit_initialized) return;

  char *history_limit_env = getenv("AFL_IJON_HISTORY_LIMIT");
  afl_ijon_history_limit_global =
      history_limit_env ? atoi(history_limit_env) : 0;
  afl_ijon_history_limit_initialized = true;

}

ijon_input_info *new_ijon_input_info(char *max_dir, int i) {

  ijon_input_info *self = (ijon_input_info *)ck_alloc(sizeof(ijon_input_info));
  self->slot_id = i;
  self->len = 0;

  if (asprintf(&self->filename, "%s/%d", max_dir, i) < 0) {

    FATAL("asprintf() failed");

  }

  return self;

}

ijon_min_state *new_ijon_min_state(char *max_dir) {

  ijon_min_state *self = (ijon_min_state *)ck_alloc(sizeof(ijon_min_state));

  self->max_dir = ck_strdup(max_dir);
  self->num_entries = 0;
  self->num_updates = 0;

  /* Create the IJON max directory if it doesn't exist */
  if (mkdir(max_dir, 0700) && errno != EEXIST) {

    PFATAL("Unable to create IJON max directory '%s'", max_dir);

  }

  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++) {

    self->max_map[i] = 0;
    self->infos[i] = new_ijon_input_info(max_dir, i);

  }

  return self;

}

/* Load existing IJON max values from disk */
void ijon_load_existing_state(ijon_min_state *self) {

  struct stat st;

  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++) {

    // Check if input file exists for this slot
    if (stat(self->infos[i]->filename, &st) == 0 && st.st_size > 0) {

      self->infos[i]->len = st.st_size;
      // We'll set a non-zero value to indicate this slot is active
      // The actual max value will be determined when we first run this input
      self->max_map[i] = 1;  // Placeholder to indicate slot is active
      self->num_entries++;

      /* IJON entry loaded successfully */

    }

  }

  if (self->num_entries > 0) {

    OKF("Loaded %zu existing IJON max entries from %s", self->num_entries,
        self->max_dir);

  }

}

u8 ijon_should_schedule(ijon_min_state *self) {

  if (self->num_entries > 0) {

    /* 80% scheduling probability */
    if (random() % 100 < 80) {

      return 1;  // 80% chance to schedule IJON input

    }

  }

  return 0;

}

ijon_input_info *ijon_get_input(ijon_min_state *self) {

  if (self->num_entries == 0) return NULL;

  uint32_t rnd = random() % self->num_entries;

  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++) {

    if (self->max_map[i] > 0) {

      if (rnd == 0) { return self->infos[i]; }
      rnd--;

    }

  }

  return NULL;

}

void ijon_store_max_input(ijon_min_state *self, int i, uint8_t *data,
                          size_t len) {

  ijon_input_info *inf = self->infos[i];
  inf->len = len;

  // Save input that achieved new maximum for this IJON variable
  /* Store input achieving new max */

  // Store in slot-specific file using atomic write to prevent race conditions
  char temp_filename[512];
  snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", inf->filename);

  int fd = open(temp_filename, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd < 0) {

    WARNF("Failed to open IJON temp file %s: %s", temp_filename,
          strerror(errno));
    return;

  }

  ssize_t written = write(fd, data, len);
  close(fd);

  if (written != (ssize_t)len) {

    WARNF("Failed to write IJON max input to %s: %s", temp_filename,
          strerror(errno));
    unlink(temp_filename);                     /* Clean up failed temp file */
    return;

  }

  /* Atomic rename to prevent race conditions */
  if (rename(temp_filename, inf->filename) != 0) {

    WARNF("Failed to rename IJON temp file %s to %s: %s", temp_filename,
          inf->filename, strerror(errno));
    unlink(temp_filename);                     /* Clean up failed temp file */

  }

  // Store in history file ONLY if this input achieves the best value for
  // variable i
  ijon_store_history_if_best(self, i, data, len);

  self->num_updates++;

}

/* Save to history file for every improvement (no threshold) */
void ijon_store_history_if_best(ijon_min_state *self, int i, uint8_t *data,
                                size_t len) {

  // Save every improvement to rolling history buffer
  ijon_store_history_unconditional(self, i, data, len);

}

/* Unconditional history storage (original logic) */
void ijon_store_history_unconditional(ijon_min_state *self, int i,
                                      uint8_t *data, size_t len) {

  // Rolling history buffer with per-variable guaranteed coverage
  static int history_init = -1;  // -1 = not initialized
  static int global_history_index = 0;
  static int variable_to_index[MAP_SIZE_IJON_ENTRIES];  // Maps variable slot to
                                                        // history index
  static int num_discovered_vars = 0;

  // Initialize history limit from environment variable (once)
  if (unlikely(history_init == -1)) {

    // Initialize variable mapping
    for (int j = 0; j < MAP_SIZE_IJON_ENTRIES; j++) {

      variable_to_index[j] = -1;  // -1 means not assigned

    }

    history_init = 1;

  }

  // Initialize global history limit if not done yet
  init_afl_ijon_history_limit();

  // Store historical input if history is enabled
  if (afl_ijon_history_limit_global > 0) {

    // Check if limit is sufficient for discovered variables (one-time check)
    if (variable_to_index[i] == -1) {

      // New variable discovered - check if limit is sufficient
      if (num_discovered_vars + 1 > afl_ijon_history_limit_global) {

        FATAL(
            "AFL_IJON_HISTORY_LIMIT=%d insufficient for %d variables. Minimum "
            "required: %d. "
            "Either increase limit or disable history (unset "
            "AFL_IJON_HISTORY_LIMIT).",
            afl_ijon_history_limit_global, num_discovered_vars + 1,
            num_discovered_vars + 1);

      }

      // Track this new variable
      variable_to_index[i] = 1;  // Mark as discovered
      num_discovered_vars++;

    }

    // Use global rolling buffer for all finding files
    int idx = global_history_index++ % afl_ijon_history_limit_global;

    char *history_filename = NULL;

    // Use global rolling buffer naming
    int padding = snprintf(NULL, 0, "%d", afl_ijon_history_limit_global - 1);
    if (padding < 3) padding = 3;  // Minimum 3 digits for clean sorting

    if (asprintf(&history_filename, "%s/finding_%0*d.dat", self->max_dir,
                 padding, idx) < 0) {

      WARNF("asprintf() failed for history filename");
      return;

    }

    /* Use atomic write for history files to prevent race conditions */
    char temp_history_filename[512];
    snprintf(temp_history_filename, sizeof(temp_history_filename), "%s.tmp",
             history_filename);

    int fd = open(temp_history_filename, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (likely(fd >= 0)) {

      ssize_t written = write(fd, data, len);
      close(fd);

      if (written != (ssize_t)len) {

        WARNF("Failed to write IJON history input: %s", strerror(errno));
        unlink(temp_history_filename);         /* Clean up failed temp file */

      } else {

        /* Atomic rename to prevent race conditions */
        if (rename(temp_history_filename, history_filename) != 0) {

          WARNF("Failed to rename IJON history temp file %s to %s: %s",
                temp_history_filename, history_filename, strerror(errno));
          unlink(temp_history_filename);       /* Clean up failed temp file */

        }

      }

    } else {

      WARNF("Failed to open IJON history temp file %s: %s",
            temp_history_filename, strerror(errno));
      /* History file open failed */

    }

    ck_free(history_filename);

  }

}

void destroy_ijon_min_state(ijon_min_state *self) {

  if (!self) return;

  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++) {

    if (self->infos[i]) {

      if (self->infos[i]->filename) { ck_free(self->infos[i]->filename); }
      ck_free(self->infos[i]);

    }

  }

  if (self->max_dir) { ck_free(self->max_dir); }

  ck_free(self);

}

dynamic_shared_access_t *setup_dynamic_shared_access(u8 *trace_bits,
                                                     u32 map_size,
                                                     u32 real_map_size) {

  (void)(real_map_size);

  dynamic_shared_access_t *access =
      (dynamic_shared_access_t *)ck_alloc(sizeof(dynamic_shared_access_t));

  /* Calculate IJON offset to match target's __afl_map_size calculation */
  access->ijon_offset = map_size;
  access->ijon_max_area = (u64 *)(trace_bits + map_size);

  return access;

}

void cleanup_dynamic_shared_access(dynamic_shared_access_t *access) {

  if (access) { ck_free(access); }

}

void ijon_update_max_dynamic(ijon_min_state          *self,
                             dynamic_shared_access_t *shared, uint8_t *data,
                             size_t len) {

  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++) {

    if (shared->ijon_max_area[i] > self->max_map[i]) {

      if (self->max_map[i] == 0) { self->num_entries++; }

      self->max_map[i] = shared->ijon_max_area[i];
      self->num_updates++;

      ijon_store_max_input(self, i, data, len);

    }

  }

#ifdef DUMP_IJON_STATE

  static size_t last_num = 0;
  if (last_num == self->num_updates) return;
  last_num = self->num_updates;

  u64   tmp_buf64[MAP_SIZE_IJON_ENTRIES];
  char *file_path = (char *)tmp_buf64;

  int n = snprintf(file_path, sizeof(tmp_buf64), "%s/cur_state", self->max_dir);
  if (n < 0 || (size_t)n >= sizeof(tmp_buf64)) {

    WARNF("state path too long or snprintf error");
    return;

  }

  int fd = open(file_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd < 0) {

    WARNF("Failed to open IJON max state file %s: %s", file_path,
          strerror(errno));
    return;

  }

  int cnt = 0;
  for (int i = 0; i < MAP_SIZE_IJON_ENTRIES; i++)
    if (self->max_map[i]) tmp_buf64[cnt++] = self->max_map[i];

  write(fd, tmp_buf64, cnt * sizeof(u64));
  close(fd);

#endif

}

