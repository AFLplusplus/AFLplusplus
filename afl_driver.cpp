#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Platform detection. Copied from FuzzerInternal.h
#ifdef __linux__
#define LIBFUZZER_LINUX 1
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 0
#elif __APPLE__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 1
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 0
#elif __NetBSD__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 1
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 0
#elif __FreeBSD__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 1
#define LIBFUZZER_OPENBSD 0
#elif __OpenBSD__
#define LIBFUZZER_LINUX 0
#define LIBFUZZER_APPLE 0
#define LIBFUZZER_NETBSD 0
#define LIBFUZZER_FREEBSD 0
#define LIBFUZZER_OPENBSD 1
#else
#error "Support for your platform has not been implemented"
#endif

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

// Notify AFL about persistent mode.
static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
int __afl_persistent_loop(unsigned int);
static volatile char suppress_warning2 = AFL_PERSISTENT[0];

// Notify AFL about deferred forkserver.
static volatile char AFL_DEFER_FORKSVR[] = "##SIG_AFL_DEFER_FORKSRV##";
void __afl_manual_init();
static volatile char suppress_warning1 = AFL_DEFER_FORKSVR[0];

// Input buffer.
static const size_t kMaxAflInputSize = 1024000;
static uint8_t AflInputBuf[kMaxAflInputSize];

// Use this optionally defined function to output sanitizer messages even if
// user asks to close stderr.
__attribute__((weak)) void __sanitizer_set_report_fd(void *);

// Keep track of where stderr content is being written to, so that
// dup_and_close_stderr can use the correct one.
static FILE *output_file = stderr;

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

  if (!stderr_duplicate_filename)
    return;

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
  if (!temp)
    abort();
  dup2(fileno(temp), fd);
  fclose(temp);
}

static void close_stdout() { discard_output(STDOUT_FILENO); }

// Prevent the targeted code from writing to "stderr" but allow sanitizers and
// this driver to do so.
static void dup_and_close_stderr() {
  int output_fileno = fileno(output_file);
  int output_fd = dup(output_fileno);
  if (output_fd <= 0)
    abort();
  FILE *new_output_file = fdopen(output_fd, "w");
  if (!new_output_file)
    abort();
  if (!__sanitizer_set_report_fd)
    return;
  __sanitizer_set_report_fd(reinterpret_cast<void *>(output_fd));
  discard_output(output_fileno);
}

// Close stdout and/or stderr if user asks for it.
static void maybe_close_fd_mask() {
  char *fd_mask_str = getenv("AFL_DRIVER_CLOSE_FD_MASK");
  if (!fd_mask_str)
    return;
  int fd_mask = atoi(fd_mask_str);
  if (fd_mask & 2)
    dup_and_close_stderr();
  if (fd_mask & 1)
    close_stdout();
}

// Define LLVMFuzzerMutate to avoid link failures for targets that use it
// with libFuzzer's LLVMFuzzerCustomMutator.
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  assert(false && "LLVMFuzzerMutate should not be called from afl_driver");
  return 0;
}

int main(int argc, char **argv) {
  printf(
      "======================= INFO =========================\n"
      "This binary is built for AFL-fuzz.\n"
      "To run the target function on individual input(s) execute this:\n"
      "  %s < INPUT_FILE\n"
      "To fuzz with afl-fuzz execute this:\n"
      "  afl-fuzz [afl-flags] %s [-N]\n"
      "afl-fuzz will run N iterations before "
      "re-spawning the process (default: 1000)\n"
      "======================================================\n",
          argv[0], argv[0]);

  maybe_duplicate_stderr();
  maybe_close_fd_mask();
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  // Do any other expensive one-time initialization here.

  int N = 100000;
  if (argc == 2 && argv[1][0] == '-')
      N = atoi(argv[1] + 1);
  else if(argc == 2 && (N = atoi(argv[1])) > 0)
      printf("WARNING: using the deprecated call style `%s %d`\n", argv[0], N);

  assert(N > 0);

  if (!getenv("AFL_DRIVER_DONT_DEFER"))
    __afl_manual_init();

  // Call LLVMFuzzerTestOneInput here so that coverage caused by initialization
  // on the first execution of LLVMFuzzerTestOneInput is ignored.
  uint8_t dummy_input[1] = {0};
  LLVMFuzzerTestOneInput(dummy_input, 1);

  while (__afl_persistent_loop(N)) {
    ssize_t n_read = read(0, AflInputBuf, kMaxAflInputSize);
    if (n_read > 0) {
      LLVMFuzzerTestOneInput(AflInputBuf, n_read);
    }
  }

  printf("%s: successfully executed input(s)\n", argv[0]);
}
