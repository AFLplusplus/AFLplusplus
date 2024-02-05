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

  char fn[4096];

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

/* only used if explictly included for compatibility
   compiling without afl-cc */

#ifdef AFL_COMPAT

  #ifndef PATH_MAX
    #define PATH_MAX 4096
  #endif

  #define FUZZ_BUF_SIZE 1024000

  // extern ssize_t read(int fildes, void *buf, size_t nbyte);

  // extern int __afl_persistent_loop(unsigned int max_cnt);
  // extern unsigned char fuzz_buf[];

  #ifndef __AFL_HAVE_MANUAL_CONTROL
    #define __AFL_HAVE_MANUAL_CONTROL
  #endif

  #define __AFL_FUZZ_TESTCASE_LEN (read(0, fuzz_buf, FUZZ_BUF_SIZE))
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_INIT() sync()
  #define __AFL_LOOP(x) __afl_persistent_loop(x)

unsigned char fuzz_buf[FUZZ_BUF_SIZE];

int __afl_persistent_loop(unsigned int max_cnt) {

  static unsigned int       cycle_cnt = 1;
  static unsigned short int inited = 0;
  char                      tcase[PATH_MAX];

  if (is_replay_record) {

    if (!inited) {

      cycle_cnt = replay_record_cnt;
      inited = 1;

    }

    snprintf(tcase, PATH_MAX, "%s/%s",
             replay_record_dir ? replay_record_dir : "./",
             record_list[replay_record_cnt - cycle_cnt]->d_name);

  #ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
    if (record_arg) {

      *record_arg = tcase;

    } else

  #endif  // AFL_PERSISTENT_REPLAY_ARGPARSE
    {

      int fd = open(tcase, O_RDONLY);
      dup2(fd, 0);
      close(fd);

    }

  } else {

    if (!inited) {

      cycle_cnt = max_cnt;
      inited = 1;

    }

  }

  return cycle_cnt--;

}

#endif  // AFL_COMPAT

#endif  // _HAVE_PERSISTENT_REPLAY_H

