#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/shm.h>

#if defined(__linux__)
  #if !defined(__ANDROID__)
    #include <sys/prctl.h>
    #include <sys/syscall.h>
  #else
    #include <linux/ashmem.h>
  #endif
#endif

#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"
#include "ranges.h"
#include "stalker.h"
#include "util.h"

#if defined(__x86_64__)

  #ifndef MAP_FIXED_NOREPLACE
    #ifdef MAP_EXCL
      #define MAP_FIXED_NOREPLACE MAP_EXCL | MAP_FIXED
    #else
      #define MAP_FIXED_NOREPLACE MAP_FIXED
    #endif
  #endif

static GHashTable *coverage_blocks = NULL;

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static gboolean instrument_coverage_in_range(gssize offset) {

  return (offset >= G_MININT32 && offset <= G_MAXINT32);

}

  #ifdef __APPLE__
    #pragma pack(push, 1)

typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  //  mov    QWORD PTR [rsp-0x80],rax
  //  lahf
  //  mov    QWORD PTR [rsp-0x88],rax
  //  mov    QWORD PTR [rsp-0x90],rbx
  //  mov    eax,DWORD PTR [rip+0x333d5a]        # 0x7ffff6ff2740
  //  mov    DWORD PTR [rip+0x333d3c],0x9fbb        # 0x7ffff6ff2740
  //  lea    rax,[rip + 0x103f77]
  //  mov    bl,BYTE PTR [rax]
  //  add    bl,0x1
  //  adc    bl,0x0
  //  mov    BYTE PTR [rax],bl
  //  mov    rbx,QWORD PTR [rsp-0x90]
  //  mov    rax,QWORD PTR [rsp-0x88]
  //  sahf
  //  mov    rax,QWORD PTR [rsp-0x80]

  uint8_t mov_rax_rsp_88[8];
  uint8_t lahf;
  uint8_t mov_rax_rsp_90[8];
  uint8_t mov_rbx_rsp_98[8];

  uint8_t mov_eax_prev_loc[6];
  uint8_t mov_prev_loc_curr_loc_shr1[10];

  uint8_t leax_eax_curr_loc[7];

  uint8_t mov_rbx_ptr_rax[2];
  uint8_t add_bl_1[3];
  uint8_t adc_bl_0[3];
  uint8_t mov_ptr_rax_rbx[2];

  uint8_t mov_rsp_98_rbx[8];
  uint8_t mov_rsp_90_rax[8];
  uint8_t sahf;
  uint8_t mov_rsp_88_rax[8];

} afl_log_code_asm_t;

    #pragma pack(pop)

static const afl_log_code_asm_t template =
    {

        .mov_rax_rsp_88 = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
        .lahf = 0x9f,
        .mov_rax_rsp_90 = {0x48, 0x89, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .mov_rbx_rsp_98 = {0x48, 0x89, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},

        .mov_eax_prev_loc = {0x8b, 0x05},
        .mov_prev_loc_curr_loc_shr1 = {0xc7, 0x05},

        .leax_eax_curr_loc = {0x48, 0x8d, 0x05},
        .mov_rbx_ptr_rax = {0x8a, 0x18},
        .add_bl_1 = {0x80, 0xc3, 0x01},
        .adc_bl_0 = {0x80, 0xd3, 0x00},
        .mov_ptr_rax_rbx = {0x88, 0x18},

        .mov_rsp_98_rbx = {0x48, 0x8B, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},
        .mov_rsp_90_rax = {0x48, 0x8B, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .sahf = 0x9e,
        .mov_rsp_88_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

}

;

  #else
    #pragma pack(push, 1)
typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  //  mov    QWORD PTR [rsp-0x80],rax
  //  lahf
  //  mov    QWORD PTR [rsp-0x88],rax
  //  mov    QWORD PTR [rsp-0x90],rbx
  //  mov    eax,DWORD PTR [rip+0x333d5a]        # 0x7ffff6ff2740
  //  mov    DWORD PTR [rip+0x333d3c],0x9fbb        # 0x7ffff6ff2740
  //  xor    eax,0x103f77
  //  mov    bl,BYTE PTR [rax]
  //  add    bl,0x1
  //  adc    bl,0x0
  //  mov    BYTE PTR [rax],bl
  //  mov    rbx,QWORD PTR [rsp-0x90]
  //  mov    rax,QWORD PTR [rsp-0x88]
  //  sahf
  //  mov    rax,QWORD PTR [rsp-0x80]

  uint8_t mov_rax_rsp_88[8];
  uint8_t lahf;
  uint8_t mov_rax_rsp_90[8];
  uint8_t mov_rbx_rsp_98[8];

  uint8_t mov_eax_prev_loc[6];
  uint8_t mov_prev_loc_curr_loc_shr1[10];

  uint8_t xor_eax_curr_loc[5];

  uint8_t mov_rbx_ptr_rax[2];
  uint8_t add_bl_1[3];
  uint8_t adc_bl_0[3];
  uint8_t mov_ptr_rax_rbx[2];

  uint8_t mov_rsp_98_rbx[8];
  uint8_t mov_rsp_90_rax[8];
  uint8_t sahf;
  uint8_t mov_rsp_88_rax[8];

} afl_log_code_asm_t;

    #pragma pack(pop)

static const afl_log_code_asm_t template =
    {

        .mov_rax_rsp_88 = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
        .lahf = 0x9f,
        .mov_rax_rsp_90 = {0x48, 0x89, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .mov_rbx_rsp_98 = {0x48, 0x89, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},

        .mov_eax_prev_loc = {0x8b, 0x05},
        .mov_prev_loc_curr_loc_shr1 = {0xc7, 0x05},

        .xor_eax_curr_loc = {0x35},
        .mov_rbx_ptr_rax = {0x8a, 0x18},
        .add_bl_1 = {0x80, 0xc3, 0x01},
        .adc_bl_0 = {0x80, 0xd3, 0x00},
        .mov_ptr_rax_rbx = {0x88, 0x18},

        .mov_rsp_98_rbx = {0x48, 0x8B, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},
        .mov_rsp_90_rax = {0x48, 0x8B, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .sahf = 0x9e,
        .mov_rsp_88_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

}

;
  #endif

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

  #ifdef __APPLE__

void instrument_coverage_optimize_init(void) {

}

  #else

static gboolean instrument_coverage_find_low(const GumRangeDetails *details,
                                             gpointer               user_data) {

  static GumAddress last_limit = (64ULL << 10);
  gpointer *        address = (gpointer *)user_data;

  last_limit = GUM_ALIGN_SIZE(last_limit, __afl_map_size);

  if ((details->range->base_address - last_limit) > __afl_map_size) {

    *address = GSIZE_TO_POINTER(last_limit);
    return FALSE;

  }

  if (details->range->base_address > ((2ULL << 30) - __afl_map_size)) {

    return FALSE;

  }

  /*
   * Align our buffer on a 64k boundary so that the low 16-bits of the address
   * are zero, then we can just XOR the base address in, when we XOR with the
   * current block ID.
   */
  last_limit = GUM_ALIGN_SIZE(
      details->range->base_address + details->range->size, __afl_map_size);
  return TRUE;

}

static void instrument_coverage_optimize_map_mmap_anon(gpointer address) {

  __afl_area_ptr =
      mmap(address, __afl_map_size, PROT_READ | PROT_WRITE,
           MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (__afl_area_ptr != address) {

    FATAL("Failed to map mmap __afl_area_ptr: %d", errno);

  }

}

static void instrument_coverage_optimize_map_mmap(char *   shm_file_path,
                                                  gpointer address) {

  int shm_fd = -1;

  if (munmap(__afl_area_ptr, __afl_map_size) != 0) {

    FATAL("Failed to unmap previous __afl_area_ptr");

  }

  __afl_area_ptr = NULL;

    #if !defined(__ANDROID__)
  shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
  if (shm_fd == -1) { FATAL("shm_open() failed\n"); }
    #else
  shm_fd = open("/dev/ashmem", O_RDWR);
  if (shm_fd == -1) { FATAL("open() failed\n"); }
  if (ioctl(shm_fd, ASHMEM_SET_NAME, shm_file_path) == -1) {

    FATAL("ioctl(ASHMEM_SET_NAME) failed");

  }

  if (ioctl(shm_fd, ASHMEM_SET_SIZE, __afl_map_size) == -1) {

    FATAL("ioctl(ASHMEM_SET_SIZE) failed");

  }

    #endif

  __afl_area_ptr = mmap(address, __afl_map_size, PROT_READ | PROT_WRITE,
                        MAP_FIXED_NOREPLACE | MAP_SHARED, shm_fd, 0);
  if (__afl_area_ptr != address) {

    FATAL("Failed to map mmap __afl_area_ptr: %d", errno);

  }

  if (close(shm_fd) != 0) { FATAL("Failed to close shm_fd"); }

}

static void instrument_coverage_optimize_map_shm(guint64  shm_env_val,
                                                 gpointer address) {

  if (shmdt(__afl_area_ptr) != 0) {

    FATAL("Failed to detach previous __afl_area_ptr");

  }

  __afl_area_ptr = shmat(shm_env_val, address, 0);
  if (__afl_area_ptr != address) {

    FATAL("Failed to map shm __afl_area_ptr: %d", errno);

  }

}

void instrument_coverage_optimize_init(void) {

  gpointer low_address = NULL;

  gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, instrument_coverage_find_low,
                               &low_address);

  FVERBOSE("Low address: %p", low_address);

  if (low_address == 0 ||
      GPOINTER_TO_SIZE(low_address) > ((2UL << 30) - __afl_map_size)) {

    FATAL("Invalid low_address: %p", low_address);

  }

  ranges_print_debug_maps();

  char *shm_env = getenv(SHM_ENV_VAR);
  FVERBOSE("SHM_ENV_VAR: %s", shm_env);

  if (shm_env == NULL) {

    FWARNF("SHM_ENV_VAR not set, using anonymous map for debugging purposes");

    instrument_coverage_optimize_map_mmap_anon(low_address);

  } else {

    guint64 shm_env_val = g_ascii_strtoull(shm_env, NULL, 10);

    if (shm_env_val == 0) {

      instrument_coverage_optimize_map_mmap(shm_env, low_address);

    } else {

      instrument_coverage_optimize_map_shm(shm_env_val, low_address);

    }

  }

  FVERBOSE("__afl_area_ptr: %p", __afl_area_ptr);

}

  #endif

static void instrument_coverage_switch(GumStalkerObserver *self,
                                       gpointer            start_address,
                                       const cs_insn *     from_insn,
                                       gpointer *          target) {

  UNUSED_PARAMETER(self);
  UNUSED_PARAMETER(start_address);

  cs_x86 *   x86;
  cs_x86_op *op;
  if (from_insn == NULL) { return; }

  x86 = &from_insn->detail->x86;
  op = x86->operands;

  if (!g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target))) {

    return;

  }

  switch (from_insn->id) {

    case X86_INS_CALL:
    case X86_INS_JMP:
      if (x86->op_count != 1) {

        FATAL("Unexpected operand count: %d", x86->op_count);

      }

      if (op[0].type != X86_OP_IMM) { return; }

      break;
    case X86_INS_RET:
      break;
    default:
      return;

  }

  *target = (guint8 *)*target + sizeof(afl_log_code);

}

static void instrument_coverage_suppress_init(void) {

  static gboolean initialized = false;
  if (initialized) { return; }
  initialized = true;

  GumStalkerObserver *         observer = stalker_get_observer();
  GumStalkerObserverInterface *iface = GUM_STALKER_OBSERVER_GET_IFACE(observer);
  iface->switch_callback = instrument_coverage_switch;

  coverage_blocks = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (coverage_blocks == NULL) {

    FATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  afl_log_code  code = {0};
  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  gsize   map_size_pow2;
  gsize   area_offset_ror;
  GumAddress code_addr = 0;
  if (instrument_previous_pc_addr == NULL) {

    GumAddressSpec spec = {.near_address = cw->code,
                           .max_distance = 1ULL << 30};

    instrument_previous_pc_addr = gum_memory_allocate_near(
        &spec, sizeof(guint64), 0x1000, GUM_PAGE_READ | GUM_PAGE_WRITE);
    *instrument_previous_pc_addr = instrument_hash_zero;
    FVERBOSE("instrument_previous_pc_addr: %p", instrument_previous_pc_addr);
    FVERBOSE("code_addr: %p", cw->code);

  }

  instrument_coverage_suppress_init();

  // gum_x86_writer_put_breakpoint(cw);
  code_addr = cw->pc;
  if (!g_hash_table_add(coverage_blocks, GSIZE_TO_POINTER(cw->code))) {

    FATAL("Failed - g_hash_table_add");

  }

  code.code = template;

  gssize curr_loc_shr_1_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(guint32);

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = util_rotate(area_offset, 1, map_size_pow2);

  *((guint32 *)&code.bytes[curr_loc_shr_1_offset]) = (guint32)(area_offset_ror);

  gssize prev_loc_value =
      GPOINTER_TO_SIZE(instrument_previous_pc_addr) -
      (code_addr + offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
       sizeof(code.code.mov_prev_loc_curr_loc_shr1));
  gssize prev_loc_value_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(gint) -
      sizeof(guint32);
  if (!instrument_coverage_in_range(prev_loc_value)) {

    FATAL("Patch out of range (current_pc_value1): 0x%016lX", prev_loc_value);

  }

  *((gint *)&code.bytes[prev_loc_value_offset]) = (gint)prev_loc_value;

  gssize prev_loc_value2 =
      GPOINTER_TO_SIZE(instrument_previous_pc_addr) -
      (code_addr + offsetof(afl_log_code, code.mov_eax_prev_loc) +
       sizeof(code.code.mov_eax_prev_loc));
  gssize prev_loc_value_offset2 =
      offsetof(afl_log_code, code.mov_eax_prev_loc) +
      sizeof(code.code.mov_eax_prev_loc) - sizeof(gint);
  if (!instrument_coverage_in_range(prev_loc_value)) {

    FATAL("Patch out of range (current_pc_value1): 0x%016lX", prev_loc_value2);

  }

  *((gint *)&code.bytes[prev_loc_value_offset2]) = (gint)prev_loc_value2;

  #ifdef __APPLE__

  gssize xor_curr_loc_offset = offsetof(afl_log_code, code.leax_eax_curr_loc) +
                               sizeof(code.code.leax_eax_curr_loc) -
                               sizeof(guint32);

  gssize xor_curr_loc_value =
      ((GPOINTER_TO_SIZE(__afl_area_ptr) | area_offset) -
       (code_addr + offsetof(afl_log_code, code.mov_eax_prev_loc) +
        sizeof(code.code.mov_eax_prev_loc)));

  if (!instrument_coverage_in_range(xor_curr_loc_value)) {

    FATAL("Patch out of range (xor_curr_loc_value): 0x%016lX",
          xor_curr_loc_value);

  }

  *((guint32 *)&code.bytes[xor_curr_loc_offset]) = xor_curr_loc_value;

  #else

  gssize xor_curr_loc_offset = offsetof(afl_log_code, code.xor_eax_curr_loc) +
                               sizeof(code.code.xor_eax_curr_loc) -
                               sizeof(guint32);

  *((guint32 *)&code.bytes[xor_curr_loc_offset]) =
      (guint32)(GPOINTER_TO_SIZE(__afl_area_ptr) | area_offset);
  #endif

  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

