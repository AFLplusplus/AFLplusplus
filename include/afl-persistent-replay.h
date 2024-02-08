#ifndef _HAVE_PERSISTENT_REPLAY_H
#define _HAVE_PERSISTENT_REPLAY_H

#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif

static unsigned short int is_replay_record;
static unsigned int       replay_record;
static unsigned int       replay_record_cnt;
static char               replay_record_path[PATH_MAX];
static char              *replay_record_dir;
static struct dirent    **record_list;

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
static char **record_arg = NULL;
#endif  // AFL_PERSISTENT_REPLAY_ARGPARSE

static int select_files(const struct dirent *dirbuf) {

  char fn[PATH_MAX];

  if (dirbuf->d_name[0] == '.') {

    return 0;

  } else {

    snprintf(fn, sizeof(fn), "RECORD:%06u", replay_record);
    return !!strstr(dirbuf->d_name, fn);

  }

}

static int compare_files(const struct dirent **da, const struct dirent **db) {

  unsigned int c1 = 0, c2 = 0;

  sscanf((*da)->d_name, "RECORD:%*u,cnt:%06u", &c1);
  sscanf((*db)->d_name, "RECORD:%*u,cnt:%06u", &c2);

  return c1 - c2;

}

__attribute__((destructor)) static void __afl_record_replay_destroy(void) {

  for (int i = 0; i < replay_record_cnt; i++) {

    free(record_list[i]);

  }

  free(record_list);

}

__attribute__((constructor)) static void __afl_record_replay_init(
#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
    int argc, char **argv
#endif  // AFL_PERSISTENT_REPLAY_ARGPARSE
) {

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
  char **argp;
#endif  // AFL_PERSISTENT_REPLAY_ARGPARSE

  struct stat sb;

  /* caveat: if harness uses @@ and we don't pass it, it will regardless loop
   * the number of iterations defined for AFL_LOOP (on the same file)*/
  if (!(is_replay_record = !!getenv("AFL_PERSISTENT_REPLAY"))) {

    // printf("[warning] AFL_PERSISTENT_REPLAY not set.\n");
    return;

  }

  replay_record = atoi(getenv("AFL_PERSISTENT_REPLAY"));
  replay_record_dir = getenv("AFL_PERSISTENT_DIR");

  if (!(stat(replay_record_dir, &sb) == 0 && S_ISDIR(sb.st_mode))) {

    fprintf(stderr, "[error] Can't find the requested record directory!\n");
    is_replay_record = 0;
    return;

  }

  replay_record_cnt = scandir(replay_record_dir ? replay_record_dir : "./",
                              &record_list, select_files, compare_files);

  if (!replay_record_cnt) {

    fprintf(stderr, "[error] Can't find the requested record!\n");
    is_replay_record = 0;

  }

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
  argp = argv;
  while (*argp) {

    if (!strcmp(*argp, "@@")) {

      record_arg = argp;
      *record_arg = replay_record_path;
      break;

    }

    ++argp;

  }

#endif  // AFL_PERSISTENT_REPLAY_ARGPARSE

}

#endif  // _HAVE_PERSISTENT_REPLAY_H

