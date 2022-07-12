/*
   american fuzzy lop++ - afl-untracer skeleton example
   ---------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0


   HOW-TO
   ======

   You only need to change the following:

   1. decide if you want to receive data from stdin [DEFAULT] or file(name)
      -> use_stdin = 0 if via file, and what the maximum input size is
   2. dl load the library you want to fuzz, lookup the functions you need
      and setup the calls to these
   3. in the while loop you call the functions in the necessary order -
      incl the cleanup. the cleanup is important!

   Just look these steps up in the code, look for "// STEP x:"


*/

#define __USE_GNU
#define _GNU_SOURCE

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#if defined(__linux__)
  #include <sys/personality.h>
  #include <sys/ucontext.h>
#elif defined(__APPLE__) && defined(__LP64__)
  #include <mach-o/dyld_images.h>
#elif defined(__FreeBSD__)
  #include <sys/sysctl.h>
  #include <sys/user.h>
  #include <sys/procctl.h>
#else
  #error "Unsupported platform"
#endif

#define MEMORY_MAP_DECREMENT 0x200000000000
#define MAX_LIB_COUNT 128

// STEP 1:

/* here you need to specify the parameter for the target function */
static void *(*o_function)(u8 *buf, int len);

/* use stdin (1) or a file on the commandline (0) */
static u32 use_stdin = 1;

/* This is were the testcase data is written into */
static u8 buf[10000];  // this is the maximum size for a test case! set it!

/* If you want to have debug output set this to 1, can also be set with
   AFL_DEBUG  */
static u32 debug = 0;

// END STEP 1

typedef struct library_list {

  u8 *name;
  u64 addr_start, addr_end;

} library_list_t;

#ifdef __ANDROID__
u32 __afl_map_size = MAP_SIZE;
u32 do_exit;
#else
__thread u32 __afl_map_size = MAP_SIZE;
__thread u32 do_exit;
#endif

static pid_t     pid = 65537;
static pthread_t __afl_thread;
static u8        __afl_dummy[MAP_SIZE];
static u8       *__afl_area_ptr = __afl_dummy;
static u8       *inputfile;  // this will point to argv[1]
static u32       len;

static library_list_t liblist[MAX_LIB_COUNT];
static u32            liblist_cnt;

static void sigtrap_handler(int signum, siginfo_t *si, void *context);
static void fuzz(void);

/* read the library information */
void read_library_information(void) {

#if defined(__linux__)
  FILE *f;
  u8    buf[1024], *b, *m, *e, *n;

  if ((f = fopen("/proc/self/maps", "r")) == NULL)
    FATAL("cannot open /proc/self/maps");

  if (debug) fprintf(stderr, "Library list:\n");
  while (fgets(buf, sizeof(buf), f)) {

    if (strstr(buf, " r-x")) {

      if (liblist_cnt >= MAX_LIB_COUNT) {

        WARNF("too many libraries to old, maximum count of %d reached",
              liblist_cnt);
        return;

      }

      b = buf;
      m = index(buf, '-');
      e = index(buf, ' ');
      if ((n = strrchr(buf, '/')) == NULL) n = strrchr(buf, ' ');
      if (n &&
          ((*n >= '0' && *n <= '9') || *n == '[' || *n == '{' || *n == '('))
        n = NULL;
      else
        n++;
      if (b && m && e && n && *n) {

        *m++ = 0;
        *e = 0;
        if (n[strlen(n) - 1] == '\n') n[strlen(n) - 1] = 0;

        liblist[liblist_cnt].name = strdup(n);
        liblist[liblist_cnt].addr_start = strtoull(b, NULL, 16);
        liblist[liblist_cnt].addr_end = strtoull(m, NULL, 16);
        if (debug)
          fprintf(
              stderr, "%s:%llx (%llx-%llx)\n", liblist[liblist_cnt].name,
              liblist[liblist_cnt].addr_end - liblist[liblist_cnt].addr_start,
              liblist[liblist_cnt].addr_start,
              liblist[liblist_cnt].addr_end - 1);
        liblist_cnt++;

      }

    }

  }

  if (debug) fprintf(stderr, "\n");

#elif defined(__FreeBSD__)
  int    mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid()};
  char  *buf, *start, *end;
  size_t miblen = sizeof(mib) / sizeof(mib[0]);
  size_t len;

  if (debug) fprintf(stderr, "Library list:\n");
  if (sysctl(mib, miblen, NULL, &len, NULL, 0) == -1) { return; }

  len = len * 4 / 3;

  buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (buf == MAP_FAILED) { return; }

  if (sysctl(mib, miblen, buf, &len, NULL, 0) == -1) {

    munmap(buf, len);
    return;

  }

  start = buf;
  end = buf + len;

  while (start < end) {

    struct kinfo_vmentry *region = (struct kinfo_vmentry *)start;
    size_t                size = region->kve_structsize;

    if (size == 0) { break; }

    if ((region->kve_protection & KVME_PROT_READ) &&
        !(region->kve_protection & KVME_PROT_EXEC)) {

      liblist[liblist_cnt].name =
          region->kve_path[0] != '\0' ? strdup(region->kve_path) : 0;
      liblist[liblist_cnt].addr_start = region->kve_start;
      liblist[liblist_cnt].addr_end = region->kve_end;

      if (debug) {

        fprintf(stderr, "%s:%x (%lx-%lx)\n", liblist[liblist_cnt].name,
                liblist[liblist_cnt].addr_end - liblist[liblist_cnt].addr_start,
                liblist[liblist_cnt].addr_start,
                liblist[liblist_cnt].addr_end - 1);

      }

      liblist_cnt++;

    }

    start += size;

  }

#endif

}

library_list_t *find_library(char *name) {

#if defined(__linux__)
  u32 i;

  for (i = 0; i < liblist_cnt; i++)
    if (strncmp(liblist[i].name, name, strlen(name)) == 0) return &liblist[i];
#elif defined(__APPLE__) && defined(__LP64__)
  kern_return_t         err;
  static library_list_t lib;

  // get the list of all loaded modules from dyld
  // the task_info mach API will get the address of the dyld all_image_info
  // struct for the given task from which we can get the names and load
  // addresses of all modules
  task_dyld_info_data_t  task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  err = task_info(mach_task_self(), TASK_DYLD_INFO,
                  (task_info_t)&task_dyld_info, &count);

  const struct dyld_all_image_infos *all_image_infos =
      (const struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;
  const struct dyld_image_info *image_infos = all_image_infos->infoArray;

  for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {

    const char       *image_name = image_infos[i].imageFilePath;
    mach_vm_address_t image_load_address =
        (mach_vm_address_t)image_infos[i].imageLoadAddress;
    if (strstr(image_name, name)) {

      lib.name = name;
      lib.addr_start = (u64)image_load_address;
      lib.addr_end = 0;
      return &lib;

    }

  }

#endif

  return NULL;

}

/* for having an easy breakpoint location after loading the shared library */
// this seems to work for clang too. nice :) requires gcc 4.4+
#pragma GCC push_options
#pragma GCC optimize("O0")
void        breakpoint(void) {

         if (debug) fprintf(stderr, "Breakpoint function \"breakpoint\" reached.\n");

}

#pragma GCC pop_options

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;

}

/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    u32 val = atoi(ptr);
    if (val > 0) __afl_map_size = val;

  }

  if (__afl_map_size > MAP_SIZE) {

    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {

      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);

      }

    } else {

      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);

    }

  }

  if (id_str) {

#ifdef USEMMAP
    const char    *shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, 0, 0);

#endif

    if (__afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. */
inline static void __afl_start_forkserver(void) {

  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  /* Phone home and tell the parent that we're OK. */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) do_exit = 1;
  // fprintf(stderr, "write0 %d\n", do_exit);

}

inline static u32 __afl_next_testcase(u8 *buf, u32 max_len) {

  s32 status;

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &status, 4) != 4) do_exit = 1;
  // fprintf(stderr, "read %d\n", do_exit);

  /* we have a testcase - read it if we read from stdin */
  if (use_stdin) {

    if ((status = read(0, buf, max_len)) <= 0) exit(-1);

  } else

    status = 1;
  // fprintf(stderr, "stdin: %d %d\n", use_stdin, status);

  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &pid, 4) != 4) do_exit = 1;
  // fprintf(stderr, "write1 %d\n", do_exit);

  __afl_area_ptr[0] = 1;  // put something in the map

  return status;

}

inline static void __afl_end_testcase(int status) {

  if (write(FORKSRV_FD + 1, &status, 4) != 4) do_exit = 1;
  // fprintf(stderr, "write2 %d\n", do_exit);
  if (do_exit) exit(0);

}

#ifdef __aarch64__
  #define SHADOW(addr)                                     \
    ((uint64_t *)(((uintptr_t)addr & 0xfffffffffffffff8) - \
                  MEMORY_MAP_DECREMENT -                   \
                  ((uintptr_t)addr & 0x7) * 0x10000000000))
#else
  #define SHADOW(addr)                                     \
    ((uint32_t *)(((uintptr_t)addr & 0xfffffffffffffffc) - \
                  MEMORY_MAP_DECREMENT -                   \
                  ((uintptr_t)addr & 0x3) * 0x10000000000))
#endif

void setup_trap_instrumentation(void) {

  library_list_t *lib_base = NULL;
  size_t          lib_size = 0;
  u8             *lib_addr;
  char           *line = NULL;
  size_t          nread, len = 0;
  char           *filename = getenv("AFL_UNTRACER_FILE");
  if (!filename) filename = getenv("TRAPFUZZ_FILE");
  if (!filename) FATAL("AFL_UNTRACER_FILE environment variable not set");

  FILE *patches = fopen(filename, "r");
  if (!patches) FATAL("Couldn't open AFL_UNTRACER_FILE file %s", filename);

    // Index into the coverage bitmap for the current trap instruction.
#ifdef __aarch64__
  uint64_t bitmap_index = 0;
  #ifdef __APPLE__
  pthread_jit_write_protect_np(0);
  #endif
#else
  uint32_t bitmap_index = 0;
#endif

  while ((nread = getline(&line, &len, patches)) != -1) {

    char *end = line + len;

    char *col = strchr(line, ':');
    if (col) {

      // It's a library:size pair
      *col++ = 0;

      lib_base = find_library(line);
      if (!lib_base) FATAL("Library %s does not appear to be loaded", line);

      // we ignore the defined lib_size
      lib_size = strtoul(col, NULL, 16);
#if (__linux__)
      if (lib_size < lib_base->addr_end - lib_base->addr_start)
        lib_size = lib_base->addr_end - lib_base->addr_start;
#endif
      if (lib_size % 0x1000 != 0)
        WARNF("Invalid library size 0x%zx. Must be multiple of 0x1000",
              lib_size);

      lib_addr = (u8 *)lib_base->addr_start;
      // Make library code writable.
      if (mprotect((void *)lib_addr, lib_size,
                   PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        FATAL("Failed to mprotect library %s writable", line);

        // Create shadow memory.
#ifdef __aarch64__
      for (int i = 0; i < 8; i++) {

#else
      for (int i = 0; i < 4; i++) {

#endif

        void *shadow_addr = SHADOW(lib_addr + i);
        void *shadow = mmap(shadow_addr, lib_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
        if (debug)
          fprintf(stderr, "Shadow: %s %d = %p-%p for %p\n", line, i, shadow,
                  shadow + lib_size - 1, lib_addr);
        if (shadow == MAP_FAILED) FATAL("Failed to mmap shadow memory");

      }

      // Done, continue with next line.
      continue;

    }

    // It's an offset, parse it and do the patching.
    unsigned long offset = strtoul(line, NULL, 16);

    if (offset > lib_size)
      FATAL("Invalid offset: 0x%lx. Current library is 0x%zx bytes large",
            offset, lib_size);

    if (bitmap_index >= __afl_map_size)
      FATAL("Too many basic blocks to instrument");

#ifdef __arch64__
    uint64_t
#else
    uint32_t
#endif
        *shadow = SHADOW(lib_addr + offset);
    if (*shadow != 0) continue;  // skip duplicates

      // Make lookup entry in shadow memory.

#if ((defined(__APPLE__) && defined(__LP64__)) || defined(__x86_64__) || \
     defined(__i386__))

    // this is for Intel x64

    uint8_t orig_byte = lib_addr[offset];
    *shadow = (bitmap_index << 8) | orig_byte;
    lib_addr[offset] = 0xcc;  // replace instruction with debug trap
    if (debug)
      fprintf(stderr,
              "Patch entry: %p[%lx] = %p = %02x -> SHADOW(%p) #%d -> %08x\n",
              lib_addr, offset, lib_addr + offset, orig_byte, shadow,
              bitmap_index, *shadow);

#elif defined(__aarch64__)

    // this is for aarch64

    uint32_t *patch_bytes = (uint32_t *)(lib_addr + offset);
    uint32_t  orig_bytes = *patch_bytes;
    *shadow = (bitmap_index << 32) | orig_bytes;
    *patch_bytes = 0xd4200000;  // replace instruction with debug trap
    if (debug)
      fprintf(stderr,
              "Patch entry: %p[%lx] = %p = %02x -> SHADOW(%p) #%d -> %016x\n",
              lib_addr, offset, lib_addr + offset, orig_bytes, shadow,
              bitmap_index, *shadow);

#else
    // this will be ARM and AARCH64
    // for ARM we will need to identify if the code is in thumb or ARM
  #error "non x86_64/aarch64 not supported yet"
    //__arm__:
    // linux thumb: 0xde01
    // linux arm: 0xe7f001f0
    //__aarch64__:
    // linux aarch64: 0xd4200000
#endif

    bitmap_index++;

  }

  free(line);
  fclose(patches);

  // Install signal handler for SIGTRAP.
  struct sigaction s;
  s.sa_flags = SA_SIGINFO;
  s.sa_sigaction = sigtrap_handler;
  sigemptyset(&s.sa_mask);
  sigaction(SIGTRAP, &s, 0);

  if (debug) fprintf(stderr, "Patched %u locations.\n", bitmap_index);
  __afl_map_size = bitmap_index;
  if (__afl_map_size % 8) __afl_map_size = (((__afl_map_size + 7) >> 3) << 3);

}

/* the signal handler for the traps / debugging interrupts
   No debug output here because this would cost speed      */
static void sigtrap_handler(int signum, siginfo_t *si, void *context) {

  uint64_t addr;
  // Must re-execute the instruction, so decrement PC by one instruction.
  ucontext_t *ctx = (ucontext_t *)context;
#if defined(__APPLE__) && defined(__LP64__)
  #if defined(__x86_64__)
  ctx->uc_mcontext->__ss.__rip -= 1;
  addr = ctx->uc_mcontext->__ss.__rip;
  #else
  ctx->uc_mcontext->__ss.__pc -= 4;
  addr = ctx->uc_mcontext->__ss.__pc;
  #endif
#elif defined(__linux__)
  #if defined(__x86_64__) || defined(__i386__)
  ctx->uc_mcontext.gregs[REG_RIP] -= 1;
  addr = ctx->uc_mcontext.gregs[REG_RIP];
  #elif defined(__aarch64__)
  ctx->uc_mcontext.pc -= 4;
  addr = ctx->uc_mcontext.pc;
  #else
    #error "Unsupported processor"
  #endif
#elif defined(__FreeBSD__) && defined(__LP64__)
  ctx->uc_mcontext.mc_rip -= 1;
  addr = ctx->uc_mcontext.mc_rip;
#else
  #error "Unsupported platform"
#endif

  // fprintf(stderr, "TRAP at context addr = %lx, fault addr = %lx\n", addr,
  // si->si_addr);

  // If the trap didn't come from our instrumentation, then we probably will
  // just segfault here
  uint8_t *faultaddr;
  if (unlikely(si->si_addr))
    faultaddr = (u8 *)si->si_addr - 1;
  else
    faultaddr = (u8 *)addr;
  // if (debug) fprintf(stderr, "Shadow location: %p\n", SHADOW(faultaddr));
  uint32_t shadow = *SHADOW(faultaddr);
  uint8_t  orig_byte = shadow & 0xff;
  uint32_t index = shadow >> 8;

  // if (debug) fprintf(stderr, "shadow data: %x, orig_byte %02x, index %d\n",
  // shadow, orig_byte, index);

  // Index zero is invalid so that it is still possible to catch actual trap
  // instructions in instrumented libraries.
  if (unlikely(index == 0)) abort();

  // Restore original instruction
  *faultaddr = orig_byte;

  __afl_area_ptr[index] = 128;

}

/* the MAIN function */
int main(int argc, char *argv[]) {

#if defined(__linux__)
  (void)personality(ADDR_NO_RANDOMIZE);  // disable ASLR
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1200000
  int no_randomize = PROC_ASLR_FORCE_DISABLE;
  (void)procctl(P_PID, 0, PROC_ASLR_CTL, &no_randomize);
#endif

  pid = getpid();
  if (getenv("AFL_DEBUG")) debug = 1;

  /* by default we use stdin, but also a filename can be passed, in this
     case the input is argv[1] and we have to disable stdin */
  if (argc > 1) {

    use_stdin = 0;
    inputfile = argv[1];

  }

  // STEP 2: load the library you want to fuzz and lookup the functions,
  //         inclusive of the cleanup functions
  //         NOTE: above the main() you have to define the functions!

  void *dl = dlopen("./libtestinstr.so", RTLD_LAZY);
  if (!dl) FATAL("could not find target library");
  o_function = dlsym(dl, "testinstr");
  if (!o_function) FATAL("could not resolve target function from library");
  if (debug) fprintf(stderr, "Function address: %p\n", o_function);

  // END STEP 2

  /* setup instrumentation, shared memory and forkserver */
  breakpoint();
  read_library_information();
  setup_trap_instrumentation();
  __afl_map_shm();
  __afl_start_forkserver();

  while (1) {

    // instead of fork() we could also use the snapshot lkm or do our own mini
    // snapshot feature like in https://github.com/marcinguy/fuzzer
    // -> snapshot.c
    if ((pid = fork()) == -1) PFATAL("fork failed");

    if (pid) {

      u32 status;
      if (waitpid(pid, &status, 0) < 0) exit(1);
      /* report the test case is done and wait for the next */
      __afl_end_testcase(status);

    } else {

      pid = getpid();
      while ((len = __afl_next_testcase(buf, sizeof(buf))) > 0) {

        // in this function the fuzz magic happens, this is STEP 3
        fuzz();

        // we can use _exit which is faster because our target library
        // was loaded via dlopen and therefore cannot have deconstructors
        // registered.
        _exit(0);

      }

    }

  }

  return 0;

}

#ifndef _DEBUG
inline
#endif
    static void
    fuzz(void) {

  // STEP 3: call the function to fuzz, also the functions you might
  //         need to call to prepare the function and - important! -
  //         to clean everything up

  // in this example we use the input file, not stdin!
  (*o_function)(buf, len);

  // normally you also need to cleanup
  //(*o_LibFree)(foo);

  // END STEP 3

}

