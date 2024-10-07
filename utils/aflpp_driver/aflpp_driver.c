//
// afl_driver.cpp - a glue between AFL++ and LLVMFuzzerTestOneInput harnesses
//

/*

 This file allows to fuzz libFuzzer-style target functions
 (LLVMFuzzerTestOneInput) with AFL++ using persistent in-memory fuzzing.

Usage:

# Example target:
$ cat << EOF > test_fuzzer.cc
#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size > 0 && data[0] == 'H')
    if (size > 1 && data[1] == 'I')
       if (size > 2 && data[2] == '!')
       __builtin_trap();
  return 0;

}

EOF

# Build your target with afl-cc -fsanitize=fuzzer
$ afl-c++ -fsanitize=fuzzer -o test_fuzzer test_fuzzer.cc
# Run AFL:
$ mkdir -p in ; echo z > in/foo;
$ afl-fuzz -i in -o out -- ./test_fuzzer

*/

#ifdef __cplusplus
extern "C" {

#endif

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#ifndef __HAIKU__
  #include <sys/syscall.h>
#endif

#include "config.h"
#include "types.h"
#include "cmplog.h"

#ifdef _DEBUG
  #include "hash.h"
#endif

// AFL++ shared memory fuzz cases
int                   __afl_sharedmem_fuzzing = 1;
extern unsigned int  *__afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;

// AFL++ coverage map
extern unsigned char *__afl_area_ptr;
extern unsigned int   __afl_map_size;

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
/* Using the weak attributed on LLVMFuzzerTestOneInput() breaks oss-fuzz but
   on the other hand this is what Google needs to make LLVMFuzzerRunDriver()
   work. Choose your poison Google! */
/*__attribute__((weak))*/ int LLVMFuzzerTestOneInput(const uint8_t *Data,
                                                     size_t         Size);
__attribute__((weak)) int     LLVMFuzzerInitialize(int *argc, char ***argv);
__attribute__((weak)) void    LLVMFuzzerCleanup(void);
__attribute__((weak)) int     LLVMFuzzerRunDriver(
        int *argc, char ***argv, int (*callback)(const uint8_t *data, size_t size));

// Default nop ASan hooks for manual poisoning when not linking the ASan
// runtime
// https://github.com/google/sanitizers/wiki/AddressSanitizerManualPoisoning
__attribute__((weak)) void __asan_poison_memory_region(
    void const volatile *addr, size_t size) {

  (void)addr;
  (void)size;

}

__attribute__((weak)) void __asan_unpoison_memory_region(
    void const volatile *addr, size_t size) {

  (void)addr;
  (void)size;

}

__attribute__((weak)) void *__asan_region_is_poisoned(void *beg, size_t size);

// Notify AFL about persistent mode.
static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
int                  __afl_persistent_loop(unsigned int);

// Notify AFL about deferred forkserver.
static volatile char AFL_DEFER_FORKSVR[] = "##SIG_AFL_DEFER_FORKSRV##";
void                 __afl_manual_init();

// Use this optionally defined function to output sanitizer messages even if
// user asks to close stderr.
__attribute__((weak)) void __sanitizer_set_report_fd(void *);

// Keep track of where stderr content is being written to, so that
// dup_and_close_stderr can use the correct one.
static FILE *output_file;

// Experimental feature to use afl_driver without AFL's deferred mode.
// Needs to run before __afl_auto_init.
__attribute__((constructor(0))) static void __decide_deferred_forkserver(void) {

  if (getenv("AFL_DRIVER_DONT_DEFER")) {

    if (unsetenv("__AFL_DEFER_FORKSRV")) {

      perror("Failed to unset __AFL_DEFER_FORKSRV");
      abort();

    }

  }

}

// If the user asks us to duplicate stderr, then do it.
static void maybe_duplicate_stderr() {

  char *stderr_duplicate_filename =
      getenv("AFL_DRIVER_STDERR_DUPLICATE_FILENAME");

  if (!stderr_duplicate_filename) return;

  FILE *stderr_duplicate_stream =
      freopen(stderr_duplicate_filename, "a+", stderr);

  if (!stderr_duplicate_stream) {

    fprintf(
        stderr,
        "Failed to duplicate stderr to AFL_DRIVER_STDERR_DUPLICATE_FILENAME");
    abort();

  }

  output_file = stderr_duplicate_stream;

}

// Most of these I/O functions were inspired by/copied from libFuzzer's code.
static void discard_output(int fd) {

  FILE *temp = fopen("/dev/null", "w");
  if (!temp) abort();
  dup2(fileno(temp), fd);
  fclose(temp);

}

static void close_stdout() {

  discard_output(STDOUT_FILENO);

}

// Prevent the targeted code from writing to "stderr" but allow sanitizers and
// this driver to do so.
static void dup_and_close_stderr() {

  int output_fileno = fileno(output_file);
  int output_fd = dup(output_fileno);
  if (output_fd <= 0) abort();
  FILE *new_output_file = fdopen(output_fd, "w");
  if (!new_output_file) abort();
  if (!__sanitizer_set_report_fd) return;
  __sanitizer_set_report_fd((void *)(long int)output_fd);
  discard_output(output_fileno);

}

// Close stdout and/or stderr if user asks for it.
static void maybe_close_fd_mask() {

  char *fd_mask_str = getenv("AFL_DRIVER_CLOSE_FD_MASK");
  if (!fd_mask_str) return;
  int fd_mask = atoi(fd_mask_str);
  if (fd_mask & 2) dup_and_close_stderr();
  if (fd_mask & 1) close_stdout();

}

// Define LLVMFuzzerMutate to avoid link failures for targets that use it
// with libFuzzer's LLVMFuzzerCustomMutator.
__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size,
                                              size_t MaxSize) {

  // assert(false && "LLVMFuzzerMutate should not be called from afl_driver");
  return 0;

}

// Execute any files provided as parameters.
static int ExecuteFilesOnyByOne(int argc, char **argv,
                                int (*callback)(const uint8_t *data,
                                                size_t         size)) {

  unsigned char *buf = (unsigned char *)malloc(MAX_FILE);

  __asan_poison_memory_region(buf, MAX_FILE);
  ssize_t prev_length = 0;

  for (int i = 1; i < argc; i++) {

    int fd = 0;

    if (strcmp(argv[i], "-") != 0) { fd = open(argv[i], O_RDONLY); }

    if (fd == -1) { continue; }

#ifndef __HAIKU__
    ssize_t length = syscall(SYS_read, fd, buf, MAX_FILE);
#else
    ssize_t length = _kern_read(fd, buf, MAX_FILE);
#endif  // HAIKU

    if (length > 0) {

      if (length < prev_length) {

        __asan_poison_memory_region(buf + length, prev_length - length);

      } else {

        __asan_unpoison_memory_region(buf + prev_length, length - prev_length);

      }

      prev_length = length;

      printf("Reading %zu bytes from %s\n", length, argv[i]);
      callback(buf, length);
      printf("Execution successful.\n");

    }

    if (fd > 0) { close(fd); }

  }

  free(buf);
  return 0;

}

__attribute__((weak)) int main(int argc, char **argv) {

  // Enable if LLVMFuzzerTestOneInput() has the weak attribute
  /*
    if (!LLVMFuzzerTestOneInput) {

      fprintf(stderr, "Error: function LLVMFuzzerTestOneInput() not found!\n");
      abort();

    }

  */

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0 ||
      strcmp(argv[1], "--help") == 0) {

    printf(
        "============================== INFO ================================\n"
        "This binary is built for afl++.\n"
        "To run the target function on individual input(s) execute:\n"
        "  %s INPUT_FILE1 [INPUT_FILE2 ... ]\n"
        "To fuzz with afl-fuzz execute:\n"
        "  afl-fuzz [afl-flags] -- %s [-N]\n"
        "afl-fuzz will run N iterations before re-spawning the process "
        "(default: "
        "INT_MAX)\n"
        "You can also use AFL_FUZZER_LOOPCOUNT to set N\n"
        "For stdin input processing, pass '-' as single command line option.\n"
        "For file input processing, pass '@@' as single command line option.\n"
        "To use with afl-cmin or afl-cmin.bash pass '-' as single command line "
        "option\n"
        "===================================================================\n",
        argv[0], argv[0]);
    if (argc == 2 &&
        (strncmp(argv[1], "-h", 2) == 0 || strcmp(argv[1], "--help") == 0)) {

      exit(0);

    }

  }

  return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);

}

__attribute__((weak)) int LLVMFuzzerRunDriver(
    int *argcp, char ***argvp,
    int (*callback)(const uint8_t *data, size_t size)) {

  int    argc = *argcp;
  char **argv = *argvp;

  if (getenv("AFL_GDB")) {

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", getpid());
    system(cmd);
    fprintf(stderr, "DEBUG: aflpp_driver pid is %d\n", getpid());
    sleep(1);

  }

  bool in_afl = !(!getenv(SHM_FUZZ_ENV_VAR) || !getenv(SHM_ENV_VAR) ||
                  fcntl(FORKSRV_FD, F_GETFD) == -1 ||
                  fcntl(FORKSRV_FD + 1, F_GETFD) == -1);

  if (!in_afl) { __afl_sharedmem_fuzzing = 0; }

  output_file = stderr;
  maybe_duplicate_stderr();
  maybe_close_fd_mask();

  if (LLVMFuzzerInitialize) {

    fprintf(stderr, "Running LLVMFuzzerInitialize ...\n");
    LLVMFuzzerInitialize(&argc, &argv);
    fprintf(stderr, "continue...\n");

  }

  // Do any other expensive one-time initialization here.

  uint8_t dummy_input[64] = {0};
  memcpy(dummy_input, (void *)AFL_PERSISTENT, sizeof(AFL_PERSISTENT));
  memcpy(dummy_input + 32, (void *)AFL_DEFER_FORKSVR,
         sizeof(AFL_DEFER_FORKSVR));

  int N = INT_MAX;

  if (!in_afl && argc == 2 && !strcmp(argv[1], "-")) {

    __afl_manual_init();
    return ExecuteFilesOnyByOne(argc, argv, callback);

  } else if (argc == 2 && argv[1][0] == '-' && argv[1][1]) {

    N = atoi(argv[1] + 1);

  } else if (argc == 2 && argv[1][0] != '-' && (N = atoi(argv[1])) > 0) {

    printf("WARNING: using the deprecated call style `%s %d`\n", argv[0], N);

  } else if (!in_afl && argc > 1 && argv[1][0] != '-') {

    if (argc == 2) { __afl_manual_init(); }

    return ExecuteFilesOnyByOne(argc, argv, callback);

  } else {

    N = INT_MAX;

  }

  if (getenv("AFL_FUZZER_LOOPCOUNT")) {

    N = atoi(getenv("AFL_FUZZER_LOOPCOUNT"));

  }

  assert(N > 0);

  __afl_manual_init();

  // Call LLVMFuzzerTestOneInput here so that coverage caused by initialization
  // on the first execution of LLVMFuzzerTestOneInput is ignored.
  callback(dummy_input, 4);

  __asan_poison_memory_region(__afl_fuzz_ptr, MAX_FILE);
  size_t prev_length = 0;

  // for speed only insert asan functions if the target is linked with asan
  if (unlikely(__asan_region_is_poisoned)) {

    while (__afl_persistent_loop(N)) {

      size_t length = *__afl_fuzz_len;

      if (likely(length)) {

        if (length < prev_length) {

          __asan_poison_memory_region(__afl_fuzz_ptr + length,
                                      prev_length - length);

        } else if (length > prev_length) {

          __asan_unpoison_memory_region(__afl_fuzz_ptr + prev_length,
                                        length - prev_length);

        }

        prev_length = length;

        if (unlikely(callback(__afl_fuzz_ptr, length) == -1)) {

          memset(__afl_area_ptr, 0, __afl_map_size);
          __afl_area_ptr[0] = 1;

        }

      }

    }

  } else {

    while (__afl_persistent_loop(N)) {

      if (unlikely(callback(__afl_fuzz_ptr, *__afl_fuzz_len) == -1)) {

        memset(__afl_area_ptr, 0, __afl_map_size);
        __afl_area_ptr[0] = 1;

      }

    }

  }

  if (LLVMFuzzerCleanup) {

    fprintf(stderr, "Running LLVMFuzzerCleanup ...\n");
    LLVMFuzzerCleanup();
    fprintf(stderr, "Exiting ...\n");

  }

  return 0;

}

#ifdef __cplusplus

}

#endif

