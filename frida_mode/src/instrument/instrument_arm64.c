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

__attribute__((aligned(0x1000))) static guint8 area_ptr_dummy[MAP_SIZE];

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

  #pragma pack(pop)

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

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

static void instrument_coverage_switch(GumStalkerObserver *self,
                                       gpointer            from_address,
                                       gpointer            start_address,
                                       const cs_insn *     from_insn,
                                       gpointer *          target) {

  UNUSED_PARAMETER(self);
  UNUSED_PARAMETER(from_address);
  UNUSED_PARAMETER(start_address);

  gsize fixup_offset;

  if (!g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target)) &&
      !g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target + 4))) {

    return;

  }

  if (instrument_is_deterministic(from_insn)) { return; }

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
  *target += fixup_offset;

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

static gboolean instrument_coverage_in_range(gssize offset) {

  return (offset >= G_MININT33 && offset <= G_MAXINT33);

}

static void instrument_patch_ardp(guint32 *patch, GumAddress insn,
                                  GumAddress target) {

  if (!PAGE_ALIGNED(target)) { FATAL("Target not page aligned"); }

  gssize distance = target - (GUM_ADDRESS(insn) & PAGE_MASK);
  if (!instrument_coverage_in_range(distance)) {

    FATAL("Patch out of range 0x%016lX->0x%016lX = 0x%016lX", insn, target,
          distance);

  }

  guint32 imm_low = ((distance >> 12) & 0x3) << 29;
  guint32 imm_high = ((distance >> 14) & 0x7FFFF) << 5;
  *patch |= imm_low;
  *patch |= imm_high;

}

void instrument_coverage_optimize(const cs_insn *   instr,
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

    instrument_previous_pc_addr = gum_memory_allocate_near(
        &spec, sizeof(guint64), 0x1000, GUM_PAGE_READ | GUM_PAGE_WRITE);
    *instrument_previous_pc_addr = instrument_hash_zero;
    FVERBOSE("instrument_previous_pc_addr: %p", instrument_previous_pc_addr);
    FVERBOSE("code_addr: %p", cw->code);

  }

  // gum_arm64_writer_put_brk_imm(cw, 0x0);

  instrument_coverage_suppress_init();

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

  if (!g_hash_table_add(coverage_blocks, block_start)) {

    FATAL("Failed - g_hash_table_add");

  }

  code.code = template;

  /*
   * Given our map is allocated on a 64KB boundary and our map is a multiple of
   * 64KB in size, then it should also end on a 64 KB boundary. It is followed
   * by our previous_pc, so this too should be 64KB aligned.
   */
  g_assert(PAGE_ALIGNED(instrument_previous_pc_addr));
  g_assert(PAGE_ALIGNED(__afl_area_ptr));

  instrument_patch_ardp(
      &code.code.adrp_x0_prev_loc1,
      code_addr + offsetof(afl_log_code, code.adrp_x0_prev_loc1),
      GUM_ADDRESS(instrument_previous_pc_addr));

  code.code.mov_x0_curr_loc |= area_offset << 5;

  instrument_patch_ardp(
      &code.code.adrp_x1_area_ptr,
      code_addr + offsetof(afl_log_code, code.adrp_x1_area_ptr),
      GUM_ADDRESS(__afl_area_ptr));

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = util_rotate(area_offset, 1, map_size_pow2);

  instrument_patch_ardp(
      &code.code.adrp_x0_prev_loc2,
      code_addr + offsetof(afl_log_code, code.adrp_x0_prev_loc2),
      GUM_ADDRESS(instrument_previous_pc_addr));

  code.code.mov_x1_curr_loc_shr_1 |= (area_offset_ror << 5);

  gum_arm64_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

}

void instrument_coverage_optimize_insn(const cs_insn *   instr,
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

#endif

