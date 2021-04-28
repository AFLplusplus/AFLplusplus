#include <iostream>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dlfcn.h>

#ifdef __ANDROID__
  #include "../include/android-ashmem.h"
#endif

#include <sys/ipc.h>
#include <sys/shm.h>
#include "../config.h"

#include <QBDI.h>

/* NeverZero */

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
  #define INC_AFL_AREA(loc)           \
    asm volatile(                     \
        "addb $1, (%0, %1, 1)\n"      \
        "adcb $0, (%0, %1, 1)\n"      \
        : /* no out */                \
        : "r"(afl_area_ptr), "r"(loc) \
        : "memory", "eax")
#else
  #define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif

using namespace QBDI;

typedef int (*target_func)(char *buf, int size);

static const size_t      STACK_SIZE = 0x100000;  // 1MB
static const QBDI::rword FAKE_RET_ADDR = 0x40000;
target_func              p_target_func = NULL;
rword                    module_base = 0;
rword                    module_end = 0;
static unsigned char
    dummy[MAP_SIZE];         /* costs MAP_SIZE but saves a few instructions */
unsigned char *afl_area_ptr = NULL;           /* Exported for afl_gen_trace */

unsigned long afl_prev_loc = 0;

char input_pathname[PATH_MAX];

/* Set up SHM region and initialize other stuff. */

int afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  int   shm_id;
  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = (unsigned char *)shmat(shm_id, NULL, 0);
    if (afl_area_ptr == (void *)-1) return 0;
    memset(afl_area_ptr, 0, MAP_SIZE);

  }

  return 1;

}

/* Fork server logic, invoked once we hit _start. */
static void afl_forkserver() {

  static unsigned char tmp[4];
  pid_t                child_pid;

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    int status;
    u32 was_killed;
    // wait for afl-fuzz
    if (read(FORKSRV_FD, &was_killed, 4) != 4) exit(2);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      // child return to execute code
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      return;

    }

    // write child pid to afl-fuzz
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    // wait child stop
    if (waitpid(child_pid, &status, 0) < 0) exit(6);

    // send child stop status to afl-fuzz
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

void afl_maybe_log(unsigned long cur_loc) {

  if (afl_area_ptr == NULL) { return; }
  unsigned long afl_idx = cur_loc ^ afl_prev_loc;
  afl_idx &= MAP_SIZE - 1;
  INC_AFL_AREA(afl_idx);
  afl_prev_loc = cur_loc >> 1;

}

char *read_file(char *path, unsigned long *length) {

  unsigned long len;
  char *        buf;

  FILE *fp = fopen(path, "rb");
  fseek(fp, 0, SEEK_END);
  len = ftell(fp);
  buf = (char *)malloc(len);
  rewind(fp);
  fread(buf, 1, len, fp);
  fclose(fp);
  *length = len;
  return buf;

}

QBDI_NOINLINE int fuzz_func() {

  if (afl_setup()) { afl_forkserver(); }

  unsigned long len = 0;
  char *        data = read_file(input_pathname, &len);

  // printf("In fuzz_func\n");
  p_target_func(data, len);
  return 1;

}

static QBDI::VMAction bbcallback(QBDI::VMInstanceRef  vm,
                                 const QBDI::VMState *state,
                                 QBDI::GPRState *     gprState,
                                 QBDI::FPRState *fprState, void *data) {

  // errno = SAVED_ERRNO;

#ifdef __x86_64__
  unsigned long pc = gprState->rip;
#elif defined(i386)
  unsigned long pc = gprState->eip;
#elif defined(__arm__)
  unsigned long pc = gprState->pc;
#endif

  // just log the module path
  if (pc >= module_base && pc <= module_end) {

    unsigned long offset = pc - module_base;
    printf("\toffset:%p\n", offset);
    afl_maybe_log(offset);

  }

  return QBDI::VMAction::CONTINUE;

}

int main(int argc, char **argv) {

  if (argc < 3) {

    puts("usage: ./loader library_path input_file_path");
    exit(0);

  }

  const char *lib_path;
  lib_path = argv[1];
  strcpy(input_pathname, argv[2]);
  void *handle = dlopen(lib_path, RTLD_LAZY);

  if (handle == nullptr) {

    perror("Cannot load library");
    exit(EXIT_FAILURE);

  }

  const char *lib_name = lib_path;
  if (strrchr(lib_name, '/') != nullptr) lib_name = strrchr(lib_name, '/') + 1;

  // printf("library name:%s\n", lib_name);
  // load library module address for log path
  for (MemoryMap &map : getCurrentProcessMaps()) {

    // printf("module:%s\n", map.name.c_str());
    if ((map.permission & PF_EXEC) &&
        strstr(map.name.c_str(), lib_name) != NULL) {

      module_base = map.range.start;
      module_end = map.range.end;

    }

  }

  if (module_base == 0) {

    std::cerr << "Fail to find base address" << std::endl;
    return -1;

  }

  // printf("module base:%p, module end:%p\n", module_base, module_end);
  p_target_func = (target_func)dlsym(handle, "target_func");
  // p_target_func = (target_func)(module_base + 0x61a);
  printf("p_target_func:%p\n", p_target_func);

  VM       vm;
  uint8_t *fakestack = nullptr;

  GPRState *state = vm.getGPRState();
  allocateVirtualStack(state, STACK_SIZE, &fakestack);
  vm.addInstrumentedModuleFromAddr(module_base);
  vm.addInstrumentedModuleFromAddr((rword)&main);

  vm.addVMEventCB(BASIC_BLOCK_ENTRY, bbcallback, nullptr);

  // QBDI::simulateCall(state, FAKE_RET_ADDR);
  // vm.run((rword)&fuzz_func, (rword)FAKE_RET_ADDR);

  rword ret;
  vm.call(&ret, (rword)&fuzz_func, {});

  return 0;

}

