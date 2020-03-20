/*
   american fuzzy lop++ - android shared memory compatibility layer
   ----------------------------------------------------------------

   Originally written by Michal Zalewski

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

   This header re-defines the shared memory routines used by AFL++
   using the Andoid API.

 */

#ifndef _ANDROID_ASHMEM_H
#define _ANDROID_ASHMEM_H

#include <fcntl.h>
#include <linux/shm.h>
#include <linux/ashmem.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#if __ANDROID_API__ >= 26
#define shmat bionic_shmat
#define shmctl bionic_shmctl
#define shmdt bionic_shmdt
#define shmget bionic_shmget
#endif
#include <sys/shm.h>
#undef shmat
#undef shmctl
#undef shmdt
#undef shmget
#include <stdio.h>

#define ASHMEM_DEVICE "/dev/ashmem"

static inline int shmctl(int __shmid, int __cmd, struct shmid_ds *__buf) {

  int ret = 0;
  if (__cmd == IPC_RMID) {

    int               length = ioctl(__shmid, ASHMEM_GET_SIZE, NULL);
    struct ashmem_pin pin = {0, (unsigned int)length};
    ret = ioctl(__shmid, ASHMEM_UNPIN, &pin);
    close(__shmid);

  }

  return ret;

}

static inline int shmget(key_t __key, size_t __size, int __shmflg) {

  (void)__shmflg;
  int  fd, ret;
  char ourkey[11];

  fd = open(ASHMEM_DEVICE, O_RDWR);
  if (fd < 0) return fd;

  sprintf(ourkey, "%d", __key);
  ret = ioctl(fd, ASHMEM_SET_NAME, ourkey);
  if (ret < 0) goto error;

  ret = ioctl(fd, ASHMEM_SET_SIZE, __size);
  if (ret < 0) goto error;

  return fd;

error:
  close(fd);
  return ret;

}

static inline void *shmat(int __shmid, const void *__shmaddr, int __shmflg) {

  (void)__shmflg;
  int   size;
  void *ptr;

  size = ioctl(__shmid, ASHMEM_GET_SIZE, NULL);
  if (size < 0) { return NULL; }

  ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, __shmid, 0);
  if (ptr == MAP_FAILED) { return NULL; }

  return ptr;

}

#endif

