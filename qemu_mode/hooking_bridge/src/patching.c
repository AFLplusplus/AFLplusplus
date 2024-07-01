#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <glib.h>
#include "common.h"
#include "exports.h"

void        *handle;
struct conf *config;
struct conf *(*configure)();
GByteArray *out;
void       *cpu;
char        cbuf[100];

// region GDB Imports
#pragma region GDB Imports
void           cpu_single_step(void *cpu, int enabled);
int            get_sstep_flags(void);
void           gdb_accept_init(int fd);
int            gdb_breakpoint_insert(int type, unsigned long long addr,
                                     unsigned long long len);
int            gdb_breakpoint_remove(int type, unsigned long long addr,
                                     unsigned long long len);
void          *qemu_get_cpu(int index);
int  target_memory_rw_debug(void *cpu, unsigned long long addr, void *ptr,
                            unsigned long long len, char is_write);
int  gdb_read_register(void *cs, GByteArray *mem_buf, int n);
int  gdb_write_register(void *cs, char *mem_buf, int n);
void gdb_set_cpu_pc(unsigned long long pc);
void gdb_continue(void);
#pragma endregion GDB Imports

// region API
int r_mem(unsigned long long addr, unsigned long long len, void *dest) {

  return target_memory_rw_debug(cpu, addr, dest, len, 0);

}

int w_mem(unsigned long long addr, unsigned long long len, void *src) {

  return target_memory_rw_debug(cpu, addr, src, len, 1);

}

int r_reg(unsigned char reg, void *dest) {

  g_byte_array_steal(out, NULL);
  int op = gdb_read_register(cpu, out, reg);
  memcpy(dest, out->data, out->len);
  return op;

}

int w_reg(unsigned char reg, char *src) {

  return gdb_write_register(cpu, src, reg);

}

// region Breakpoint handling
char               single_stepped;
unsigned long long gen_addr;
struct ret *(*hook)();
struct ret *returned;
// Defined and imported gdbstub.c
void set_signal_callback(void (*cb)(int));
// Breakpoints are set here
void patch_block_trans_cb(struct qemu_plugin_tb *tb) {

  unsigned long long addr;
  addr = qemu_plugin_tb_vaddr(tb);

  if (addr == config->entry_addr) {

    // NOTE This means we cannot put a BP in the first basic block
    gdb_accept_init(-1);
    for (int i = 0; i < config->num_hooks; i++) {

      gdb_breakpoint_insert(0, config->hooks[i], 1);

    }

  }

}

void handle_signal_callback(int sig) {

  if (single_stepped) {

    single_stepped = 0;
    gdb_breakpoint_insert(0, gen_addr, 1);
    cpu_single_step(cpu, 0);
    gdb_continue();
    return;

  }

  r_reg(config->IP_reg_num, cbuf);
  gen_addr = *(unsigned long long *)cbuf;

  sprintf(cbuf, "hook_%016llx", gen_addr);
  // TODO maybe find a way to put the hook function pointers in the TCG data
  // structure instead of this dlsym call
  *(unsigned long long **)(&hook) = dlsym(handle, cbuf);
  if (!hook) {

    exit(-1);

  }

  returned = hook();

  if (returned->remove_bp ||
      (returned->addr ==
       gen_addr)) {  //* force removal of bp in returning to the same address,
                     //otherwise hook will be called again
    gdb_breakpoint_remove(0, gen_addr, 1);

  }

  if (returned->addr == gen_addr) {

    single_stepped = 1;
    cpu_single_step(cpu, get_sstep_flags());

  } else {

    //* no need to rexecute the IP instruction
    gdb_set_cpu_pc(returned->addr);

  }

  gdb_continue();

}

// region Constructor/Destructor
void patch_finish_cb(void *userdata) {

  g_byte_array_free(out, 1);
  dlclose(handle);

}

void patch_vpu_init_cb(unsigned int vcpu_index) {

  cpu = qemu_get_cpu(vcpu_index);

}

void patch_init(char *hook_lib) {

  // TODO make OS agnostic, remove dlopen
  handle = dlopen(hook_lib, RTLD_NOW);
  if (!handle) {

    fprintf(stderr, "DLOPEN Error: %s\n", dlerror());
    exit(-1);

  }

  single_stepped = 0;

  *(void **)(&configure) = dlsym(handle, "configure");
  config = configure();

  set_signal_callback(handle_signal_callback);
  out = g_byte_array_new();

}

