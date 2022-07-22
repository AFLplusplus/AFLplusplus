#include "frida-gumjs.h"

#include "instrument.h"
#include "stalker.h"
#include "util.h"

#if defined(__i386__)

gboolean instrument_cache_enabled = FALSE;
gsize    instrument_cache_size = 0;

static GHashTable *coverage_blocks = NULL;

  #pragma pack(push, 1)
typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  uint8_t mov_eax_esp_4[4];
  uint8_t lahf;
  uint8_t mov_eax_esp_8[4];
  uint8_t mov_ebx_esp_c[4];

  uint8_t mov_eax_prev_loc[5];
  uint8_t mov_prev_loc_curr_loc_shr1[10];

  uint8_t xor_eax_curr_loc[5];
  uint8_t add_eax_area_ptr[5];

  uint8_t mov_ebx_ptr_eax[2];
  uint8_t add_bl_1[3];
  uint8_t adc_bl_0[3];
  uint8_t mov_ptr_eax_ebx[2];

  uint8_t mov_esp_c_ebx[4];
  uint8_t mov_esp_8_eax[4];
  uint8_t sahf;
  uint8_t mov_esp_4_eax[4];

} afl_log_code_asm_t;

  #pragma pack(pop)

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

static const afl_log_code_asm_t template =
    {

        .mov_eax_esp_4 = {0x89, 0x44, 0x24, 0xFC},
        .lahf = 0x9f,
        .mov_eax_esp_8 = {0x89, 0x44, 0x24, 0xF8},
        .mov_ebx_esp_c = {0x89, 0x5C, 0x24, 0xF4},

        .mov_eax_prev_loc = {0xA1},
        .mov_prev_loc_curr_loc_shr1 = {0xc7, 0x05},

        .xor_eax_curr_loc = {0x35},
        .add_eax_area_ptr = {0x05},
        .mov_ebx_ptr_eax = {0x8a, 0x18},
        .add_bl_1 = {0x80, 0xc3, 0x01},
        .adc_bl_0 = {0x80, 0xd3, 0x00},
        .mov_ptr_eax_ebx = {0x88, 0x18},

        .mov_esp_c_ebx = {0x8B, 0x5C, 0x24, 0xF4},
        .mov_esp_8_eax = {0x8B, 0x44, 0x24, 0xF8},
        .sahf = 0x9e,
        .mov_esp_4_eax = {0x8B, 0x44, 0x24, 0xFC},

}

;

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static void instrument_coverage_switch(GumStalkerObserver *self,
                                       gpointer            from_address,
                                       gpointer            start_address,
                                       const cs_insn      *from_insn,
                                       gpointer           *target) {

  UNUSED_PARAMETER(self);
  UNUSED_PARAMETER(from_address);
  UNUSED_PARAMETER(start_address);

  cs_x86    *x86;
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

  GumStalkerObserver          *observer = stalker_get_observer();
  GumStalkerObserverInterface *iface = GUM_STALKER_OBSERVER_GET_IFACE(observer);
  iface->switch_callback = instrument_coverage_switch;

  coverage_blocks = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (coverage_blocks == NULL) {

    FATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

}

void instrument_coverage_optimize(const cs_insn    *instr,
                                  GumStalkerOutput *output) {

  afl_log_code  code = {0};
  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  gsize   map_size_pow2;
  gsize   area_offset_ror;

  if (instrument_previous_pc_addr == NULL) {

    GumAddressSpec spec = {.near_address = cw->code,
                           .max_distance = 1ULL << 30};

    instrument_previous_pc_addr = gum_memory_allocate_near(
        &spec, sizeof(guint64), 0x1000, GUM_PAGE_READ | GUM_PAGE_WRITE);
    *instrument_previous_pc_addr = instrument_hash_zero;
    FVERBOSE("instrument_previous_pc_addr: %p", instrument_previous_pc_addr);
    FVERBOSE("code_addr: %p", cw->code);

  }

  code.code = template;

  instrument_coverage_suppress_init();

  // gum_x86_writer_put_breakpoint(cw);

  if (!g_hash_table_add(coverage_blocks, GSIZE_TO_POINTER(cw->code))) {

    FATAL("Failed - g_hash_table_add");

  }

  gssize prev_loc_value_offset2 =
      offsetof(afl_log_code, code.mov_eax_prev_loc) +
      sizeof(code.code.mov_eax_prev_loc) - sizeof(gint);

  *((gint *)&code.bytes[prev_loc_value_offset2]) =
      (gint)GPOINTER_TO_SIZE(instrument_previous_pc_addr);

  gssize curr_loc_shr_1_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(guint32);

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = util_rotate(area_offset, 1, map_size_pow2);

  *((guint32 *)&code.bytes[curr_loc_shr_1_offset]) = (guint32)(area_offset_ror);

  gssize prev_loc_value_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(gint) -
      sizeof(guint32);

  *((gint *)&code.bytes[prev_loc_value_offset]) =
      (gint)GPOINTER_TO_SIZE(instrument_previous_pc_addr);

  gssize xor_curr_loc_offset = offsetof(afl_log_code, code.xor_eax_curr_loc) +
                               sizeof(code.code.xor_eax_curr_loc) -
                               sizeof(guint32);

  *((guint32 *)&code.bytes[xor_curr_loc_offset]) = (guint32)area_offset;

  gssize add_area_ptr_offset = offsetof(afl_log_code, code.add_eax_area_ptr) +
                               sizeof(code.code.add_eax_area_ptr) -
                               sizeof(guint32);

  *((guint32 *)&code.bytes[add_area_ptr_offset]) = (guint32)__afl_area_ptr;

  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

}

void instrument_coverage_optimize_insn(const cs_insn    *instr,
                                       GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);

}

void instrument_coverage_optimize_init(void) {

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

void instrument_cache_config(void) {

}

void instrument_cache_init(void) {

}

void instrument_cache_insert(gpointer real_address, gpointer code_address) {

  UNUSED_PARAMETER(real_address);
  UNUSED_PARAMETER(code_address);

}

void instrument_cache(const cs_insn *instr, GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);

}

#endif

