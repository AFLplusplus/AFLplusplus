/*
   american fuzzy lop++ - snapshot helpers routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

// From AFL-Snapshot-LKM/include/afl_snapshot.h (must be kept synced)

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define AFL_SNAPSHOT_FILE_NAME "/dev/afl_snapshot"

#define AFL_SNAPSHOT_IOCTL_MAGIC 44313

#define AFL_SNAPSHOT_IOCTL_DO _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 1)
#define AFL_SNAPSHOT_IOCTL_CLEAN _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 2)

static int afl_snapshot_dev_fd;

static int afl_snapshot_init(void) {

  afl_snapshot_dev_fd = open(AFL_SNAPSHOT_FILE_NAME, 0);
  return afl_snapshot_dev_fd;

}

static int afl_snapshot_do() {

  return ioctl(afl_snapshot_dev_fd, AFL_SNAPSHOT_IOCTL_DO);

}

static int afl_snapshot_clean(void) {

  return ioctl(afl_snapshot_dev_fd, AFL_SNAPSHOT_IOCTL_CLEAN);

}

