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

static GHashTable *coverage_blocks = NULL;

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

  // mov    QWORD PTR [rsp-0x88],rax
  // lahf
  // mov    QWORD PTR [rsp-0x90],rax
  // mov    QWORD PTR [rsp-0x98],rbx

  // mov    eax,DWORD PTR [rip+0x1312334]
  // xor    eax,0x3f77

  // lea    rbx,[rip+0x132338]
  // add    rax,rbx

  // mov    bl,BYTE PTR [rax]
  // add    bl,0x1
  // adc    bl,0x0
  // mov    BYTE PTR [rax],bl

  // mov    rbx,QWORD PTR [rsp-0x98]
  // mov    rax,QWORD PTR [rsp-0x90]
  // sahf
  // mov    rax,QWORD PTR [rsp-0x88]

  // mov    DWORD PTR [rip+0x13122f8],0x9fbb

  uint8_t mov_rax_rsp_88[8];
  uint8_t lahf;
  uint8_t mov_rax_rsp_90[8];
  uint8_t mov_rbx_rsp_98[8];

  uint8_t mov_eax_prev_loc[6];
  uint8_t xor_eax_curr_loc[5];

  uint8_t lea_rbx_area_ptr[7];
  uint8_t add_rax_rbx[3];

  uint8_t mov_rbx_ptr_rax[2];
  uint8_t add_bl_1[3];
  uint8_t adc_bl_0[3];
  uint8_t mov_ptr_rax_rbx[2];

  uint8_t mov_rsp_98_rbx[8];
  uint8_t mov_rsp_90_rax[8];
  uint8_t sahf;
  uint8_t mov_rsp_88_rax[8];

  uint8_t mov_prev_loc_curr_loc_shr1[10];

} afl_log_code_asm_t;

  #pragma pack(pop)

static const afl_log_code_asm_t template =
    {

        .mov_rax_rsp_88 = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
        .lahf = 0x9f,
        .mov_rax_rsp_90 = {0x48, 0x89, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .mov_rbx_rsp_98 = {0x48, 0x89, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},

        .mov_eax_prev_loc = {0x8b, 0x05},
        .xor_eax_curr_loc = {0x35},
        .lea_rbx_area_ptr = {0x48, 0x8d, 0x1d},
        .add_rax_rbx = {0x48, 0x01, 0xd8},

        .mov_rbx_ptr_rax = {0x8a, 0x18},
        .add_bl_1 = {0x80, 0xc3, 0x01},
        .adc_bl_0 = {0x80, 0xd3, 0x00},
        .mov_ptr_rax_rbx = {0x88, 0x18},

        .mov_rsp_98_rbx = {0x48, 0x8B, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},
        .mov_rsp_90_rax = {0x48, 0x8B, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .sahf = 0x9e,
        .mov_rsp_88_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

        .mov_prev_loc_curr_loc_shr1 = {0xc7, 0x05},

}

;

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

void instrument_coverage_optimize_init(void) {

  FVERBOSE("__afl_area_ptr: %p", __afl_area_ptr);

}

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

  /* mov_prev_loc_curr_loc_shr1 */

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

  /* mov_eax_prev_loc */

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

  /* xor_eax_curr_loc */

  gssize xor_curr_loc_offset = offsetof(afl_log_code, code.xor_eax_curr_loc) +
                               sizeof(code.code.xor_eax_curr_loc) -
                               sizeof(guint32);

  *((guint32 *)&code.bytes[xor_curr_loc_offset]) = area_offset;

  /* lea_rbx_area_ptr */

  gssize lea_rbx_area_ptr_offset =
      offsetof(afl_log_code, code.lea_rbx_area_ptr) +
      sizeof(code.code.lea_rbx_area_ptr) - sizeof(guint32);

  gssize lea_rbx_area_ptr_value =
      (GPOINTER_TO_SIZE(__afl_area_ptr) -
       (code_addr + offsetof(afl_log_code, code.lea_rbx_area_ptr) +
        sizeof(code.code.lea_rbx_area_ptr)));

  if (!instrument_coverage_in_range(lea_rbx_area_ptr_value)) {

    FATAL("Patch out of range (lea_rbx_area_ptr_value): 0x%016lX",
          lea_rbx_area_ptr_value);

  }

  *((guint32 *)&code.bytes[lea_rbx_area_ptr_offset]) = lea_rbx_area_ptr_value;

  /* mov_prev_loc_curr_loc_shr1 */

  gssize curr_loc_shr_1_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(guint32);

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = util_rotate(area_offset, 1, map_size_pow2);

  *((guint32 *)&code.bytes[curr_loc_shr_1_offset]) = (guint32)(area_offset_ror);

  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

