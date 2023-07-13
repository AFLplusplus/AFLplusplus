#include "frida-gumjs.h"

#include "instrument.h"
#include "stalker.h"
#include "util.h"

#if defined(__arm__)

  #define PAGE_MASK (~(GUM_ADDRESS(0xfff)))
  #define PAGE_ALIGNED(x) ((GUM_ADDRESS(x) & PAGE_MASK) == GUM_ADDRESS(x))

gboolean           instrument_cache_enabled = FALSE;
gsize              instrument_cache_size = 0;
static GHashTable *coverage_blocks = NULL;

extern __thread guint64 instrument_previous_pc;

__attribute__((aligned(0x1000))) static guint8 area_ptr_dummy[MAP_INITIAL_SIZE];

  #pragma pack(push, 1)
typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  // str     r0, [sp, #-128] ; 0xffffff80
  // str     r1, [sp, #-132] ; 0xffffff7c
  // ldr     r0, [pc, #-20]  ; 0xf691b29c
  // ldrh    r1, [r0]
  // movw    r0, #33222      ; 0x81c6
  // eor     r0, r0, r1
  // ldr     r1, [pc, #-40]  ; 0xf691b298
  // add     r1, r1, r0
  // ldrb    r0, [r1]
  // add     r0, r0, #1
  // add     r0, r0, r0, lsr #8
  // strb    r0, [r1]
  // movw    r0, #49379      ; 0xc0e3
  // ldr     r1, [pc, #-64]  ; 0xf691b29c
  // strh    r0, [r1]
  // ldr     r1, [sp, #-132] ; 0xffffff7c
  // ldr     r0, [sp, #-128] ; 0xffffff80

  uint32_t  b_code;                                                /* b imm */
  uint8_t  *shared_mem;
  uint64_t *prev_location;

  /* code */

  /* save regs */
  uint32_t str_r0_sp_rz;                         /* str r0, [sp - RED_ZONE] */
  uint32_t str_r1_sp_rz_4;                 /* str r1, [sp - (RED_ZONE + 4)] */

  /* load prev */
  uint32_t ldr_r0_pprev;                                  /* ldr r0, [pc-x] */
  uint32_t ldrh_r1_r0;                                     /* ldrh r1, [r0] */

  /* load curr */
  uint32_t mov_r0_block_id;                               /* mov r0, #imm16 */

  /* calculate new */
  uint32_t eor_r0_r0_r1;                                  /* eor r0, r0, r1 */

  /* load map */
  uint32_t ldr_r1_pmap;                                   /* ldr r1, [pc-x] */

  /* calculate offset */
  uint32_t add_r1_r1_r0;                                  /* add r1, r1, r0 */

  /* Load the value */
  uint32_t ldrb_r0_r1;                                     /* ldrb r0, [r1] */

  /* Increment the value */
  uint32_t add_r0_r0_1;                                   /* add r0, r0, #1 */
  uint32_t add_r0_r0_r0_lsr_8;                    /* add r0, r0, r0, lsr #8 */

  /* Save the value */
  uint32_t strb_r0_r1;                                     /* strb r0, [r1] */

  /* load curr shifted */
  uint32_t mov_r0_block_id_shr_1;                     /* mov r0, #imm16 >> 1*/

  /* Update prev */
  uint32_t ldr_r1_pprev;                                  /* ldr r1, [pc-x] */
  uint32_t strh_r0_r1;                                     /* strh r0, [r1] */

  /* restore regs */
  uint32_t ldr_r1_sp_rz_4;                 /* ldr r1, [sp - (RED_ZONE + 4)] */
  uint32_t ldr_r0_sp_rz;                         /* ldr r0, [sp - RED_ZONE] */

} afl_log_code_asm_t;

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

  #pragma pack(pop)

static const afl_log_code_asm_t template =
    {

        .b_code = GUINT32_TO_LE(0xea000001),
        .shared_mem = (uint8_t *)GUINT32_TO_LE(0xcefaadde),
        .prev_location = (uint64_t *)GUINT32_TO_LE(0xadba0df0),
        .str_r0_sp_rz = GUINT32_TO_LE(0xe50d0080),
        .str_r1_sp_rz_4 = GUINT32_TO_LE(0xe50d1084),
        .ldr_r0_pprev = GUINT32_TO_LE(0xe51f0014),
        .ldrh_r1_r0 = GUINT32_TO_LE(0xe1d010b0),
        .mov_r0_block_id = GUINT32_TO_LE(0xe3000000),
        .eor_r0_r0_r1 = GUINT32_TO_LE(0xe0200001),
        .ldr_r1_pmap = GUINT32_TO_LE(0xe51f1028),
        .add_r1_r1_r0 = GUINT32_TO_LE(0xe0811000),
        .ldrb_r0_r1 = GUINT32_TO_LE(0xe5d10000),
        .add_r0_r0_1 = GUINT32_TO_LE(0xe2800001),
        .add_r0_r0_r0_lsr_8 = GUINT32_TO_LE(0xe0800420),
        .strb_r0_r1 = GUINT32_TO_LE(0xe5c10000),
        .mov_r0_block_id_shr_1 = GUINT32_TO_LE(0xe3000000),
        .ldr_r1_pprev = GUINT32_TO_LE(0xe51f1040),
        .strh_r0_r1 = GUINT32_TO_LE(0xe1c100b0),
        .ldr_r1_sp_rz_4 = GUINT32_TO_LE(0xe51d1084),
        .ldr_r0_sp_rz = GUINT32_TO_LE(0xe51d0080),

}

;

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static void instrument_coverage_switch(GumStalkerObserver *self,
                                       gpointer            from_address,
                                       gpointer start_address, void *from_insn,
                                       gpointer *target) {

  UNUSED_PARAMETER(self);
  UNUSED_PARAMETER(from_address);
  UNUSED_PARAMETER(start_address);
  UNUSED_PARAMETER(from_insn);

  if (!g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target))) {

    return;

  }

  *target =
      (guint8 *)*target + G_STRUCT_OFFSET(afl_log_code_asm_t, str_r0_sp_rz);

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

static void patch_t3_insn(uint32_t *insn, uint16_t val) {

  uint32_t orig = GUINT32_FROM_LE(*insn);
  uint32_t imm12 = (val & 0xfff);
  uint32_t imm4 = (val >> 12);
  orig |= imm12;
  orig |= (imm4 << 16);
  *insn = GUINT32_TO_LE(orig);

}

void instrument_coverage_optimize(const cs_insn    *instr,
                                  GumStalkerOutput *output) {

  afl_log_code  code = {0};
  GumArmWriter *cw = output->writer.arm;
  gpointer      block_start;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  gsize   map_size_pow2;
  gsize   area_offset_ror;

  instrument_coverage_suppress_init();

  block_start = GSIZE_TO_POINTER(GUM_ADDRESS(cw->code));

  if (!g_hash_table_add(coverage_blocks, block_start)) {

    FATAL("Failed - g_hash_table_add");

  }

  code.code = template;

  g_assert(PAGE_ALIGNED(__afl_area_ptr));

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = util_rotate(area_offset, 1, map_size_pow2);

  code.code.shared_mem = __afl_area_ptr;
  code.code.prev_location = instrument_previous_pc_addr;

  patch_t3_insn(&code.code.mov_r0_block_id, (uint16_t)area_offset);
  patch_t3_insn(&code.code.mov_r0_block_id_shr_1, (uint16_t)area_offset_ror);

  // gum_arm_writer_put_breakpoint(cw);
  gum_arm_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

}

void instrument_coverage_optimize_insn(const cs_insn    *instr,
                                       GumStalkerOutput *output) {

  UNUSED_PARAMETER(instr);
  UNUSED_PARAMETER(output);

}

void instrument_coverage_optimize_init(void) {

  char *shm_env = getenv(SHM_ENV_VAR);
  FVERBOSE("SHM_ENV_VAR: %s", shm_env);

  if (shm_env == NULL) {

    FWARNF("SHM_ENV_VAR not set, using dummy for debugging purposes");

    __afl_area_ptr = area_ptr_dummy;
    memset(area_ptr_dummy, '\0', sizeof(area_ptr_dummy));

  }

  FVERBOSE("__afl_area_ptr: %p", __afl_area_ptr);

  if (instrument_previous_pc_addr == NULL) {

    instrument_previous_pc_addr = &instrument_previous_pc;
    *instrument_previous_pc_addr = instrument_hash_zero;
    FVERBOSE("instrument_previous_pc_addr: %p", instrument_previous_pc_addr);

  }

}

void instrument_flush(GumStalkerOutput *output) {

  if (output->encoding == GUM_INSTRUCTION_SPECIAL) {

    gum_thumb_writer_flush(output->writer.thumb);

  } else {

    gum_arm_writer_flush(output->writer.arm);

  }

}

gpointer instrument_cur(GumStalkerOutput *output) {

  gpointer curr = NULL;

  if (output->encoding == GUM_INSTRUCTION_SPECIAL) {

    curr = gum_thumb_writer_cur(output->writer.thumb);

  } else {

    curr = gum_arm_writer_cur(output->writer.arm);

  }

  return curr;

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

void instrument_write_regs(GumCpuContext *cpu_context, gpointer user_data) {

  int fd = (int)user_data;
  instrument_regs_format(fd,
                         "r0 : 0x%08x, r1 : 0x%08x, r2 : 0x%08x, r3 : 0x%08x\n",
                         cpu_context->r[0], cpu_context->r[2],
                         cpu_context->r[1], cpu_context->r[3]);
  instrument_regs_format(fd,
                         "r4 : 0x%08x, r5 : 0x%08x, r6 : 0x%08x, r7 : 0x%08x\n",
                         cpu_context->r[4], cpu_context->r[5],
                         cpu_context->r[6], cpu_context->r[7]);
  instrument_regs_format(
      fd, "r8 : 0x%08x, r9 : 0x%08x, r10: 0x%08x, r11: 0x%08x\n",
      cpu_context->r8, cpu_context->r9, cpu_context->r10, cpu_context->r11);
  instrument_regs_format(
      fd, "r12: 0x%08x, sp : 0x%08x, lr : 0x%08x, pc : 0x%08x\n",
      cpu_context->r12, cpu_context->sp, cpu_context->lr, cpu_context->pc);
  instrument_regs_format(fd, "cpsr: 0x%08x\n\n", cpu_context->cpsr);

}

#endif

