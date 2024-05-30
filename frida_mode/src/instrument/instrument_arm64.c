#include <stddef.h>

#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"
#include "ranges.h"
#include "stalker.h"
#include "util.h"

#define G_MININT33 ((gssize)0xffffffff00000000)
#define G_MAXINT33 ((gssize)0x00000000ffffffff)

#define PAGE_MASK (~(GUM_ADDRESS(0xfff)))
#define PAGE_ALIGNED(x) ((GUM_ADDRESS(x) & PAGE_MASK) == GUM_ADDRESS(x))
#define GUM_RESTORATION_PROLOG_SIZE 4

#if defined(__aarch64__)

gboolean           instrument_cache_enabled = FALSE;
gsize              instrument_cache_size = 0;
static GHashTable *coverage_blocks = NULL;

__attribute__((aligned(0x1000))) static guint8 area_ptr_dummy[MAP_INITIAL_SIZE];

  #pragma pack(push, 1)
typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  // stp     x0, x1, [sp, #-160]
  // adrp    x0, 0x7fb7738000
  // ldr     x1, [x0]
  // mov     x0, #0x18b8
  // eor     x0, x1, x0
  // adrp    x1, 0x7fb7d73000
  // add     x0, x1, x0
  // ldrb    w1, [x0]
  // add     w1, w1, #0x1
  // add     x1, x1, x1, lsr #8
  // strb    w1, [x0]
  // adrp    x0, 0x7fb7738000
  // mov     x1, #0xc5c
  // str     x1, [x0]
  // ldp     x0, x1, [sp, #-160]
  // b       0x7fb6f0dee4
  // ldp     x16, x17, [sp], #144

  uint32_t b_imm8;                                                /* br #68 */
  uint32_t restoration_prolog;                 /* ldp x16, x17, [sp], #0x90 */

  uint32_t stp_x0_x1;                           /* stp x0, x1, [sp, #-0xa0] */

  uint32_t adrp_x0_prev_loc1;                           /* adrp x0, #0xXXXX */
  uint32_t ldr_x1_ptr_x0;                                   /* ldr x1, [x0] */

  uint32_t mov_x0_curr_loc;                             /* movz x0, #0xXXXX */
  uint32_t eor_x0_x1_x0;                                  /* eor x0, x1, x0 */
  uint32_t adrp_x1_area_ptr;                            /* adrp x1, #0xXXXX */
  uint32_t add_x0_x1_x0;                                  /* add x0, x1, x0 */

  uint32_t ldrb_w1_x0;                                     /* ldrb w1, [x0] */
  uint32_t add_w1_w1_1;                                   /* add w1, w1, #1 */
  uint32_t add_w1_w1_w1_lsr_8;                    /* add x1, x1, x1, lsr #8 */

  uint32_t strb_w1_ptr_x0;                                 /* strb w1, [x0] */

  uint32_t adrp_x0_prev_loc2;                           /* adrp x0, #0xXXXX */
  uint32_t mov_x1_curr_loc_shr_1;                       /* movz x1, #0xXXXX */
  uint32_t str_x1_ptr_x0;                                   /* str x1, [x0] */

  uint32_t ldp_x0_x1;                           /* ldp x0, x1, [sp, #-0xa0] */

} afl_log_code_asm_t;

typedef struct {

  uint32_t b_imm8;                                          /* br #XX (end) */

  uint32_t restoration_prolog;                 /* ldp x16, x17, [sp], #0x90 */

  uint32_t stp_x0_x1;                           /* stp x0, x1, [sp, #-0xa0] */

  uint32_t ldr_x0_p_prev_loc_1;                          /* ldr x0, #0xXXXX */
  uint32_t ldr_x1_ptr_x0;                                   /* ldr x1, [x0] */

  uint32_t ldr_x0_p_area_offset;                         /* ldr x0, #0xXXXX */
  uint32_t eor_x0_x1_x0;                                  /* eor x0, x1, x0 */
  uint32_t ldr_x1_p_area_ptr;                            /* ldr x1, #0xXXXX */
  uint32_t add_x0_x1_x0;                                  /* add x0, x1, x0 */

  uint32_t ldrb_w1_x0;                                     /* ldrb w1, [x0] */
  uint32_t add_w1_w1_1;                                   /* add w1, w1, #1 */
  uint32_t add_w1_w1_w1_lsr_8;                    /* add x1, x1, x1, lsr #8 */

  uint32_t strb_w1_ptr_x0;                                 /* strb w1, [x0] */

  uint32_t ldr_x0_p_prev_loc_2;                          /* ldr x0, #0xXXXX */
  uint32_t ldr_x1_p_area_offset_ror;                     /* ldr x1, #0xXXXX */
  uint32_t str_x1_ptr_x0;                                   /* str x1, [x0] */

  uint32_t ldp_x0_x1;                           /* ldp x0, x1, [sp, #-0xa0] */

  uint32_t b_end;                                          /* skip the data */

  uint64_t area_ptr;
  uint64_t prev_loc_ptr;
  uint64_t area_offset;
  uint64_t area_offset_ror;

  uint8_t end[0];

} afl_log_code_asm_long_t;

  #pragma pack(pop)

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

typedef union {

  afl_log_code_asm_long_t code;
  uint8_t                 bytes[0];

} afl_log_code_long;

static const afl_log_code_asm_t template =
    {

        .b_imm8 = 0x14000011,

        .restoration_prolog = 0xa8c947f0,
        .stp_x0_x1 = 0xa93607e0,

        .adrp_x0_prev_loc1 = 0x90000000,
        .ldr_x1_ptr_x0 = 0xf9400001,

        .mov_x0_curr_loc = 0xd2800000,
        .eor_x0_x1_x0 = 0xca000020,

        .adrp_x1_area_ptr = 0x90000001,
        .add_x0_x1_x0 = 0x8b000020,

        .ldrb_w1_x0 = 0x39400001,

        .add_w1_w1_1 = 0x11000421,
        .add_w1_w1_w1_lsr_8 = 0x8b412021,

        .strb_w1_ptr_x0 = 0x39000001,

        .adrp_x0_prev_loc2 = 0x90000000,
        .mov_x1_curr_loc_shr_1 = 0xd2800001,
        .str_x1_ptr_x0 = 0xf9000001,

        .ldp_x0_x1 = 0xa97607e0,

}

;

static const afl_log_code_asm_long_t template_long =
    {.b_imm8 = 0x1400001a,

     .restoration_prolog = 0xa8c947f0,         /* ldp x16, x17, [sp], #0x90 */

     .stp_x0_x1 = 0xa93607e0,                   /* stp x0, x1, [sp, #-0xa0] */

     .ldr_x0_p_prev_loc_1 = 0x58000220,                  /* ldr x0, #0xXXXX */
     .ldr_x1_ptr_x0 = 0xf9400001,                           /* ldr x1, [x0] */

     .ldr_x0_p_area_offset = 0x58000220,                 /* ldr x0, #0xXXXX */
     .eor_x0_x1_x0 = 0xca000020,                          /* eor x0, x1, x0 */
     .ldr_x1_p_area_ptr = 0x58000161,                    /* ldr x1, #0xXXXX */
     .add_x0_x1_x0 = 0x8b000020,                          /* add x0, x1, x0 */

     .ldrb_w1_x0 = 0x39400001,                             /* ldrb w1, [x0] */
     .add_w1_w1_1 = 0x11000421,                           /* add w1, w1, #1 */
     .add_w1_w1_w1_lsr_8 = 0x8b412021,            /* add x1, x1, x1, lsr #8 */

     .strb_w1_ptr_x0 = 0x39000001,                         /* strb w1, [x0] */

     .ldr_x0_p_prev_loc_2 = 0x580000e0,                  /* ldr x0, #0xXXXX */
     .ldr_x1_p_area_offset_ror = 0x58000141,             /* ldr x1, #0xXXXX */
     .str_x1_ptr_x0 = 0xf9000001,                           /* str x1, [x0] */

     .ldp_x0_x1 = 0xa97607e0,                   /* ldp x0, x1, [sp, #-0xa0] */

     .b_end = 0x14000009,                                  /* skip the data */

     .area_ptr = 0x0,
     .prev_loc_ptr = 0x0,
     .area_offset = 0x0,
     .area_offset_ror = 0x0,

     .end = {}

}

;

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static gboolean instrument_is_deterministic(const cs_insn *from_insn) {

  cs_arm64 *arm64;
  arm64_cc  cc;

  if (from_insn == NULL) { return FALSE; }

  arm64 = &from_insn->detail->arm64;
  cc = arm64->cc;

  switch (from_insn->id) {

    case ARM64_INS_B:
    case ARM64_INS_BL:
      if (cc == ARM64_CC_INVALID) { return TRUE; }
      break;

    case ARM64_INS_RET:
    case ARM64_INS_RETAA:
    case ARM64_INS_RETAB:
      if (arm64->op_count == 0) { return TRUE; }
      break;
    default:
      return FALSE;

  }

  return FALSE;

}

cs_insn *instrument_disassemble(gconstpointer address) {

  csh      capstone;
  cs_insn *insn = NULL;

  cs_open(CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &capstone);
  cs_option(capstone, CS_OPT_DETAIL, CS_OPT_ON);

  cs_disasm(capstone, address, 16, GPOINTER_TO_SIZE(address), 1, &insn);

  cs_close(&capstone);

  return insn;

}

static void instrument_coverage_switch(GumStalkerObserver *self,
                                       gpointer            from_address,
                                       gpointer start_address, void *from_insn,
                                       gpointer *target) {

  UNUSED_PARAMETER(self);
  UNUSED_PARAMETER(from_address);
  UNUSED_PARAMETER(start_address);

  cs_insn *insn = NULL;
  gboolean deterministic = FALSE;
  gsize    fixup_offset;

  if (!g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target)) &&
      !g_hash_table_contains(coverage_blocks,
                             GSIZE_TO_POINTER((guint8 *)*target + 4))) {

    return;

  }

  insn = instrument_disassemble(from_insn);
  deterministic = instrument_is_deterministic(insn);
  cs_free(insn, 1);

  /*
   * If the branch is deterministic, then we should start execution at the
   * begining of the block. From here, we will branch and skip the coverage
   * code and jump right to the target code of the instrumented block.
   * Otherwise, if the branch is non-deterministic, then we need to branch
   * part way into the block to where the coverage instrumentation starts.
   */
  if (deterministic) { return; }

  /*
   * Since each block is prefixed with a restoration prologue, we need to be
   * able to begin execution at an offset into the block and execute both this
   * restoration prologue and the instrumented block without the coverage code.
   * We therefore layout our block as follows:
   *
   *  +-----+------------------+-----+--------------------------+-------------+
   *  | LDP | BR <TARGET CODE> | LDP | COVERAGE INSTRUMENTATION | TARGET CODE |
   *  +-----+------------------+-----+--------------------------+-------------+
   *
   *  ^     ^                  ^     ^
   *  |     |                  |     |
   *  A     B                  C     D
   *
   * Without instrumentation suppression, the block is either executed at point
   * (C) if it is reached by an indirect branch (and registers need to be
   * restored) or point (D) if it is reached by an direct branch (and hence the
   * registers don't need restoration). Similarly, we can start execution of the
   * block at points (A) or (B) to achieve the same functionality, but without
   * executing the coverage instrumentation.
   *
   * In either case, Stalker will call us back with the address of the target
   * block to be executed as the destination. We can then check if the branch is
   * a deterministic one and if so branch to point (C) or (D) rather than (A)
   * or (B). We lay the code out in this fashion so that in the event we can't
   * suppress coverage (the most likely), we can vector directly to the coverage
   * instrumentation code and execute entirely without any branches. If we
   * suppress the coverage, we simply branch beyond it instead.
   */
  fixup_offset = GUM_RESTORATION_PROLOG_SIZE +
                 G_STRUCT_OFFSET(afl_log_code_asm_t, restoration_prolog);
  *target = (guint8 *)*target + fixup_offset;

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

static gboolean instrument_coverage_in_range(gssize offset) {

  return (offset >= G_MININT33 && offset <= G_MAXINT33);

}

static bool instrument_patch_ardp(guint32 *patch, GumAddress insn,
                                  GumAddress target) {

  if (!PAGE_ALIGNED(target)) {

    FWARNF("Target not page aligned");
    return false;

  }

  gssize distance = target - (GUM_ADDRESS(insn) & PAGE_MASK);
  if (!instrument_coverage_in_range(distance)) {

    FVERBOSE("Patch out of range 0x%016lX->0x%016lX = 0x%016lX", insn, target,
             distance);
    return false;

  }

  guint32 imm_low = ((distance >> 12) & 0x3) << 29;
  guint32 imm_high = ((distance >> 14) & 0x7FFFF) << 5;
  *patch |= imm_low;
  *patch |= imm_high;
  return true;

}

bool instrument_write_inline(GumArm64Writer *cw, GumAddress code_addr,
                             guint64 area_offset, gsize area_offset_ror) {

  afl_log_code code = {0};
  code.code = template;

  /*
   * Given our map is allocated on a 64KB boundary and our map is a multiple of
   * 64KB in size, then it should also end on a 64 KB boundary. It is followed
   * by our previous_pc, so this too should be 64KB aligned.
   */
  g_assert(PAGE_ALIGNED(instrument_previous_pc_addr));
  g_assert(PAGE_ALIGNED(__afl_area_ptr));

  if (!instrument_patch_ardp(
          &code.code.adrp_x0_prev_loc1,
          code_addr + offsetof(afl_log_code, code.adrp_x0_prev_loc1),
          GUM_ADDRESS(instrument_previous_pc_addr))) {

    return false;

  }

  /*
   * The mov instruction supports up to a 16-bit offset. If our offset is out of
   * range, then it can end up clobbering the op-code portion of the instruction
   * rather than just the operands. So return false and fall back to the
   * alternative instrumentation.
   */
  if (area_offset > UINT16_MAX) { return false; }

  code.code.mov_x0_curr_loc |= area_offset << 5;

  if (!instrument_patch_ardp(
          &code.code.adrp_x1_area_ptr,
          code_addr + offsetof(afl_log_code, code.adrp_x1_area_ptr),
          GUM_ADDRESS(__afl_area_ptr))) {

    return false;

  }

  if (!instrument_patch_ardp(
          &code.code.adrp_x0_prev_loc2,
          code_addr + offsetof(afl_log_code, code.adrp_x0_prev_loc2),
          GUM_ADDRESS(instrument_previous_pc_addr))) {

    return false;

  }

  code.code.mov_x1_curr_loc_shr_1 |= (area_offset_ror << 5);

  if (instrument_suppress) {

    gum_arm64_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

  } else {

    size_t offset = offsetof(afl_log_code, code.stp_x0_x1);
    gum_arm64_writer_put_bytes(cw, &code.bytes[offset],
                               sizeof(afl_log_code) - offset);

  }

  return true;

}

bool instrument_write_inline_long(GumArm64Writer *cw, GumAddress code_addr,
                                  guint64 area_offset, gsize area_offset_ror) {

  afl_log_code_long code = {0};
  code.code = template_long;

  code.code.area_ptr = GUM_ADDRESS(__afl_area_ptr);
  code.code.prev_loc_ptr = GUM_ADDRESS(instrument_previous_pc_addr);
  code.code.area_offset = area_offset;
  code.code.area_offset_ror = GUM_ADDRESS(area_offset_ror);

  if (instrument_suppress) {

    gum_arm64_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code_long));

  } else {

    size_t offset = offsetof(afl_log_code_long, code.stp_x0_x1);
    gum_arm64_writer_put_bytes(cw, &code.bytes[offset],
                               sizeof(afl_log_code_long) - offset);

  }

  return true;

}

void instrument_coverage_optimize(const cs_insn    *instr,
                                  GumStalkerOutput *output) {

  afl_log_code    code = {0};
  GumArm64Writer *cw = output->writer.arm64;
  gpointer        block_start;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  gsize   map_size_pow2;
  gsize   area_offset_ror;
  GumAddress code_addr = 0;

  if (instrument_previous_pc_addr == NULL) {

    GumAddressSpec spec = {.near_address = cw->code,
                           .max_distance = 1ULL << 30};
    guint          page_size = gum_query_page_size();

    instrument_previous_pc_addr = gum_memory_allocate_near(
        &spec, sizeof(guint64), page_size, GUM_PAGE_READ | GUM_PAGE_WRITE);
    *instrument_previous_pc_addr = instrument_hash_zero;
    FVERBOSE("instrument_previous_pc_addr: %p", instrument_previous_pc_addr);
    FVERBOSE("code_addr: %p", cw->code);

  }

  // gum_arm64_writer_put_brk_imm(cw, 0x0);
  // uint32_t jmp_dot = 0x14000000;
  // gum_arm64_writer_put_bytes(cw, (guint8 *)&jmp_dot, sizeof(jmp_dot));

  if (instrument_suppress) { instrument_coverage_suppress_init(); }

  code_addr = cw->pc;

  /*
   * On AARCH64, immediate branches can only be encoded with a 28-bit offset. To
   * make a longer branch, it is necessary to load a register with the target
   * address, this register must be saved beyond the red-zone before the branch
   * is taken. To restore this register each block is prefixed by Stalker with
   * an instruction to load x16,x17 from beyond the red-zone on the stack. A
   * pair of registers are saved/restored because on AARCH64, the stack pointer
   * must be 16 byte aligned. This instruction is emitted into the block before
   * the tranformer (from which we are called) is executed. If is is possible
   * for Stalker to make a direct branch (the target block is close enough), it
   * can forego pushing the registers and instead branch at an offset into the
   * block to skip this restoration prolog.
   */
  block_start =
      GSIZE_TO_POINTER(GUM_ADDRESS(cw->code) - GUM_RESTORATION_PROLOG_SIZE);

  if (instrument_suppress) {

    if (!g_hash_table_add(coverage_blocks, block_start)) {

      FATAL("Failed - g_hash_table_add");

    }

  }

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = util_rotate(area_offset, 1, map_size_pow2);

  code.code = template;

  if (!instrument_write_inline(cw, code_addr, area_offset, area_offset_ror)) {

    if (!instrument_write_inline_long(cw, code_addr, area_offset,
                                      area_offset_ror)) {

      FATAL("Failed to write inline instrumentation");

    }

  }

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

}

void instrument_flush(GumStalkerOutput *output) {

  gum_arm64_writer_flush(output->writer.arm64);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_arm64_writer_cur(output->writer.arm64);

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

  int fd = (int)(size_t)user_data;
  instrument_regs_format(
      fd, "x0 : 0x%016x, x1 : 0x%016x, x2 : 0x%016x, x3 : 0x%016x\n",
      cpu_context->x[0], cpu_context->x[1], cpu_context->x[2],
      cpu_context->x[3]);
  instrument_regs_format(
      fd, "x4 : 0x%016x, x5 : 0x%016x, x6 : 0x%016x, x7 : 0x%016x\n",
      cpu_context->x[4], cpu_context->x[5], cpu_context->x[6],
      cpu_context->x[7]);
  instrument_regs_format(
      fd, "x8 : 0x%016x, x9 : 0x%016x, x10: 0x%016x, x11: 0x%016x\n",
      cpu_context->x[8], cpu_context->x[9], cpu_context->x[10],
      cpu_context->x[11]);
  instrument_regs_format(
      fd, "x12: 0x%016x, x13: 0x%016x, x14: 0x%016x, x15: 0x%016x\n",
      cpu_context->x[12], cpu_context->x[13], cpu_context->x[14],
      cpu_context->x[15]);
  instrument_regs_format(
      fd, "x16: 0x%016x, x17: 0x%016x, x18: 0x%016x, x19: 0x%016x\n",
      cpu_context->x[16], cpu_context->x[17], cpu_context->x[18],
      cpu_context->x[19]);
  instrument_regs_format(
      fd, "x20: 0x%016x, x21: 0x%016x, x22: 0x%016x, x23: 0x%016x\n",
      cpu_context->x[20], cpu_context->x[21], cpu_context->x[22],
      cpu_context->x[23]);
  instrument_regs_format(
      fd, "x24: 0x%016x, x25: 0x%016x, x26: 0x%016x, x27: 0x%016x\n",
      cpu_context->x[24], cpu_context->x[25], cpu_context->x[26],
      cpu_context->x[27]);
  instrument_regs_format(
      fd, "x28: 0x%016x, fp : 0x%016x, lr : 0x%016x, sp : 0x%016x\n",
      cpu_context->x[28], cpu_context->fp, cpu_context->lr, cpu_context->sp);
  instrument_regs_format(fd, "pc : 0x%016x\n\n", cpu_context->pc);

}

#endif

