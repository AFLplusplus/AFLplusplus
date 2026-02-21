// storfuzz map implementation

#include "afl-fuzz.h"
#include "storfuzz.h"
#include "alloc-inl.h"
#include "debug.h"

#include <stdlib.h>
#include <string.h>

#ifndef USEMMAP
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif

static inline u8 env_truthy(const char *s) {

  if (!s || !*s) return 0;
  if (!strcmp(s, "0")) return 0;
  if (!strcasecmp(s, "false")) return 0;
  if (!strcasecmp(s, "no")) return 0;
  if (!strcasecmp(s, "off")) return 0;
  return 1;

}

#ifndef USEMMAP
static void storfuzz_setup_sysv_shm(afl_state_t *afl) {

  s32 shm_id =
      shmget(IPC_PRIVATE, STORFUZZ_MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) PFATAL("shmget() for StorFuzz map failed");

  u8 *map = (u8 *)shmat(shm_id, NULL, 0);
  if (map == (void *)-1) PFATAL("shmat() for StorFuzz map failed");

  /* mark for deletion once all detach */
  if (shmctl(shm_id, IPC_RMID, 0))
    PFATAL("shmctl(IPC_RMID) for StorFuzz map failed");

  afl->storfuzz.shm_id = shm_id;
  afl->storfuzz.map = map;

  memset(afl->storfuzz.map, 0, STORFUZZ_MAP_SIZE);

  char buf[64];
  snprintf(buf, sizeof(buf), "%d", shm_id);
  setenv(SHM_STOR_ENV_VAR, buf, 1);

}

#else
/* Minimal USEMMAP fallback: disable StorFuzz unless SysV SHM is available. */
static void storfuzz_setup_sysv_shm(afl_state_t *afl) {

  (void)afl;
  FATAL(
      "StorFuzz map requires SysV SHM (shmget/shmat). Rebuild without "
      "USEMMAP.");

}

#endif

void storfuzz_init(afl_state_t *afl) {

  afl->storfuzz.enabled = env_truthy(getenv(AFL_STORFUZZ_ENABLE_ENV));
  afl->storfuzz.shm_id = -1;
  afl->storfuzz.map = NULL;
  afl->storfuzz.virgin = NULL;

  if (!afl->storfuzz.enabled) return;

  /* allocate global “virgin” (all bits unseen) */
  afl->storfuzz.virgin = ck_alloc(STORFUZZ_MAP_SIZE);
  memset(afl->storfuzz.virgin, 0xFF, STORFUZZ_MAP_SIZE);

  storfuzz_setup_sysv_shm(afl);

}

void storfuzz_deinit(afl_state_t *afl) {

  if (!afl->storfuzz.enabled) return;

#ifndef USEMMAP
  if (afl->storfuzz.map) {

    shmdt(afl->storfuzz.map);
    afl->storfuzz.map = NULL;

  }

#endif

  if (afl->storfuzz.virgin) {

    ck_free(afl->storfuzz.virgin);
    afl->storfuzz.virgin = NULL;

  }

  afl->storfuzz.enabled = 0;
  afl->storfuzz.shm_id = -1;

}

void storfuzz_clear_map(afl_state_t *afl) {

  if (!afl->storfuzz.enabled || !afl->storfuzz.map) return;
  memset(afl->storfuzz.map, 0, STORFUZZ_MAP_SIZE);

}

u8 storfuzz_has_new_bits(afl_state_t *afl) {

  if (!afl->storfuzz.enabled || !afl->storfuzz.map || !afl->storfuzz.virgin)
    return 0;

  u8   ret = 0;
  u64 *cur = (u64 *)afl->storfuzz.map;
  u64 *vir = (u64 *)afl->storfuzz.virgin;

  const u32 n = STORFUZZ_MAP_SIZE / sizeof(u64);

  for (u32 i = 0; i < n; i++) {

    u64 v = cur[i] & vir[i];
    if (v) {

      ret = 2;
      vir[i] &= ~cur[i];                           /* clear newly seen bits */

    }

  }

  return ret;

}

