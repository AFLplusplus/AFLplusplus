#ifndef _HAVE_AFL_COMPAT_H
#define _HAVE_AFL_COMPAT_H

#include <afl-persistent-replay.h>

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

  if (is_replay_record && cycle_cnt) {

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

  }

  return cycle_cnt--;

}

#endif  // _HAVE_AFL_COMPAT_H

