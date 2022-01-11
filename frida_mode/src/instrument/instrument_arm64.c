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

#if defined(__aarch64__)

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

  uint32_t b_imm8;                                                 /* br #8 */
  uint32_t restoration_prolog;                 /* ldp x16, x17, [sp], #0x90 */

} afl_log_code_asm_t;

  #pragma pack(pop)

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

static const afl_log_code_asm_t template =
    {

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

        .b_imm8 = 0x14000002,
        .restoration_prolog = 0xa8c947f0,

}

;

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

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

  code_addr = cw->pc;

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

#endif

