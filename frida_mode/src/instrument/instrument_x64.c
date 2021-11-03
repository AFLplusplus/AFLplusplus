#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/shm.h>

#if defined(__linux__)
#if !defined(__ANDROID__)
#include <asm/prctl.h>
#include <sys/syscall.h>
#else
#include <linux/ashmem.h>
#endif
#endif

#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "ranges.h"

#if defined(__x86_64__)

#ifndef MAP_FIXED_NOREPLACE
  #ifdef MAP_EXCL
    #define MAP_FIXED_NOREPLACE MAP_EXCL | MAP_FIXED
  #else
    #define MAP_FIXED_NOREPLACE MAP_FIXED
  #endif
#endif

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static gboolean instrument_coverage_in_range(gssize offset) {

  return (offset >= G_MININT32 && offset <= G_MAXINT32);

}

  #pragma pack(push, 1)
typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  // => 0x7ffff6cfb086:      lea    rsp,[rsp-0x80]
  //    0x7ffff6cfb08b:      pushf
  //    0x7ffff6cfb08c:      push   rsi
  //    0x7ffff6cfb08d:      mov    rsi,0x228
  //    0x7ffff6cfb094:      xchg   QWORD PTR [rip+0x3136a5],rsi        # 0x7ffff700e740
  //    0x7ffff6cfb09b:      xor    rsi,0x451
  //    0x7ffff6cfb0a2:      add    BYTE PTR [rsi+0x10000],0x1
  //    0x7ffff6cfb0a9:      adc    BYTE PTR [rsi+0x10000],0x0
  //    0x7ffff6cfb0b0:      pop    rsi
  //    0x7ffff6cfb0b1:      popf
  //    0x7ffff6cfb0b2:      lea    rsp,[rsp+0x80]


  uint8_t lea_rsp_rsp_sub_rz[5];
  uint8_t push_fq;
  uint8_t push_rsi;

  uint8_t mov_rsi_curr_loc_shr_1[7];
  uint8_t xchg_rsi_prev_loc_curr_loc[7];
  uint8_t xor_rsi_curr_loc[7];

  uint8_t add_rsi_1[7];
  uint8_t adc_rsi_0[7];

  uint8_t pop_rsi;
  uint8_t pop_fq;
  uint8_t lsa_rsp_rsp_add_rz[8];

} afl_log_code_asm_t;

  #pragma pack(pop)

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

static const afl_log_code_asm_t template =
    {

        .lea_rsp_rsp_sub_rz = {0x48, 0x8D, 0x64, 0x24, 0x80},
        .push_fq = 0x9c,
        .push_rsi = 0x56,

        .mov_rsi_curr_loc_shr_1 = {0x48, 0xC7, 0xC6},
        .xchg_rsi_prev_loc_curr_loc = {0x48, 0x87, 0x35},
        .xor_rsi_curr_loc = {0x48, 0x81, 0xF6},

        .add_rsi_1 = {0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x01},
        .adc_rsi_0 = {0x80, 0x96, 0x00, 0x00, 0x00, 0x00, 0x00},

        .pop_rsi = 0x5E,
        .pop_fq = 0x9D,
        .lsa_rsp_rsp_add_rz = {0x48, 0x8D, 0xA4, 0x24, 0x80, 0x00, 0x00, 0x00},

}

;

static gboolean instrument_coverage_find_low(const GumRangeDetails *details,
                                             gpointer               user_data) {

  static GumAddress last_limit = (64ULL << 10);
  gpointer *        address = (gpointer *)user_data;

  if ((details->range->base_address - last_limit) > __afl_map_size) {

    *address = GSIZE_TO_POINTER(last_limit);
    return FALSE;

  }

  if (details->range->base_address > ((2ULL << 20) - __afl_map_size)) {

    return FALSE;

  }

  last_limit = details->range->base_address + details->range->size;
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
  if (ioctl(shm_fd, ASHMEM_SET_NAME, shm_file_path) == -1) { FATAL("ioctl(ASHMEM_SET_NAME) failed"); }
  if (ioctl(shm_fd, ASHMEM_SET_SIZE, __afl_map_size) == -1) { FATAL("ioctl(ASHMEM_SET_SIZE) failed"); }

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

  OKF("Low address: %p", low_address);

  if (low_address == 0 ||
      GPOINTER_TO_SIZE(low_address) > ((2UL << 20) - __afl_map_size)) {

    FATAL("Invalid low_address: %p", low_address);

  }

  ranges_print_debug_maps();

  char *shm_env = getenv(SHM_ENV_VAR);
  OKF("SHM_ENV_VAR: %s", shm_env);

  if (shm_env == NULL) {

    WARNF("SHM_ENV_VAR not set, using anonymous map for debugging purposes");

    instrument_coverage_optimize_map_mmap_anon(low_address);

  } else {

    guint64 shm_env_val = g_ascii_strtoull(shm_env, NULL, 10);

    if (shm_env_val == 0) {

      instrument_coverage_optimize_map_mmap(shm_env, low_address);

    } else {

      instrument_coverage_optimize_map_shm(shm_env_val, low_address);

    }

  }

  OKF("__afl_area_ptr: %p", __afl_area_ptr);
  OKF("instrument_previous_pc: %p", &instrument_previous_pc);

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  afl_log_code  code = {0};
  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  GumAddress code_addr = 0;

  // gum_x86_writer_put_breakpoint(cw);
  code_addr = cw->pc;
  code.code = template;

  gssize curr_loc_shr_1_offset =
      offsetof(afl_log_code, code.mov_rsi_curr_loc_shr_1) +
      sizeof(code.code.mov_rsi_curr_loc_shr_1) - sizeof(guint32);

  *((guint32 *)&code.bytes[curr_loc_shr_1_offset]) =
      (guint32)(area_offset >> 1);

  gssize prev_loc_value =
      GPOINTER_TO_SIZE(&instrument_previous_pc) -
      (code_addr + offsetof(afl_log_code, code.xchg_rsi_prev_loc_curr_loc) +
       sizeof(code.code.xchg_rsi_prev_loc_curr_loc));
  gssize prev_loc_value_offset =
      offsetof(afl_log_code, code.xchg_rsi_prev_loc_curr_loc) +
      sizeof(code.code.xchg_rsi_prev_loc_curr_loc) - sizeof(gint);
  if (!instrument_coverage_in_range(prev_loc_value)) {

    FATAL("Patch out of range (current_pc_value1): 0x%016lX", prev_loc_value);

  }

  *((gint *)&code.bytes[prev_loc_value_offset]) = (gint)prev_loc_value;

  gssize xor_curr_loc_offset = offsetof(afl_log_code, code.xor_rsi_curr_loc) +
                               sizeof(code.code.xor_rsi_curr_loc) -
                               sizeof(guint32);

  *((guint32 *)&code.bytes[xor_curr_loc_offset]) = (guint32)(area_offset);

  gssize add_rsi_1_offset = offsetof(afl_log_code, code.add_rsi_1) +
                            sizeof(code.code.add_rsi_1) - sizeof(guint32) - 1;

  *((guint32 *)&code.bytes[add_rsi_1_offset]) =
      (guint32)GPOINTER_TO_SIZE(__afl_area_ptr);

  gssize adc_rsi_0_ffset = offsetof(afl_log_code, code.adc_rsi_0) +
                           sizeof(code.code.adc_rsi_0) - sizeof(guint32) - 1;

  *((guint32 *)&code.bytes[adc_rsi_0_ffset]) =
      (guint32)GPOINTER_TO_SIZE(__afl_area_ptr);

  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

