#include <stddef.h>

#include "frida-gumjs.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"

#if defined(__x86_64__)

static GumAddress current_log_impl = GUM_ADDRESS(0);

  #pragma pack(push, 1)

typedef struct {

  /*
   * pushfq
   * push rdx
   * mov rdx, [&previouspc] (rip relative addr)
   * xor rdx, rdi (current_pc)
   * shr rdi. 1
   * mov [&previouspc], rdi
   * lea rsi, [&_afl_area_ptr] (rip relative)
   * add rdx, rsi
   * add byte ptr [rdx], 1
   * adc byte ptr [rdx], 0

   * pop rdx
   * popfq
   */
  uint8_t push_fq;
  uint8_t push_rdx;
  uint8_t mov_rdx_rip_off[7];
  uint8_t xor_rdx_rdi[3];
  uint8_t shr_rdi[3];
  uint8_t mov_rip_off_rdi[7];

  uint8_t lea_rdi_rip_off[7];
  uint8_t add_rdx_rdi[3];
  uint8_t add_byte_ptr_rdx[3];
  uint8_t adc_byte_ptr_rdx[3];

  uint8_t pop_rdx;
  uint8_t pop_fq;
  uint8_t ret;

} afl_log_code_asm_t;

  #pragma pack(pop)

  #pragma pack(push, 8)
typedef struct {

  afl_log_code_asm_t assembly;
  uint64_t           current_pc;

} afl_log_code_t;

  #pragma pack(pop)

typedef union {

  afl_log_code_t data;
  uint8_t        bytes[0];

} afl_log_code;

static const afl_log_code_asm_t template = {

    .push_fq = 0x9c,
    .push_rdx = 0x52,
    .mov_rdx_rip_off =
        {

            0x48, 0x8b, 0x15,
            /* TBC */

        },

    .xor_rdx_rdi =
        {

            0x48,
            0x31,
            0xfa,

        },

    .shr_rdi = {0x48, 0xd1, 0xef},
    .mov_rip_off_rdi = {0x48, 0x89, 0x3d},

    .lea_rdi_rip_off =
        {

            0x48,
            0x8d,
            0x3d,

        },

    .add_rdx_rdi = {0x48, 0x01, 0xfA},

    .add_byte_ptr_rdx =
        {

            0x80,
            0x02,
            0x01,

        },

    .adc_byte_ptr_rdx =
        {

            0x80,
            0x12,
            0x00,

        },

    .pop_rdx = 0x5a,
    .pop_fq = 0x9d,
    .ret = 0xc3};

static guint8 align_pad[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static gboolean instrument_coverage_in_range(gssize offset) {

  return (offset >= G_MININT32 && offset <= G_MAXINT32);

}

static void instrument_coverate_write_function(GumStalkerOutput *output) {

  guint64       misalign = 0;
  GumX86Writer *cw = output->writer.x86;
  GumAddress    code_addr = 0;
  afl_log_code  code = {0};
  guint64       instrument_hash_zero = 0;

  if (current_log_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, current_log_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

    misalign = (cw->pc & 0x7);
    if (misalign != 0) {

      gum_x86_writer_put_bytes(cw, align_pad, 8 - misalign);

    }

    current_log_impl = cw->pc;
    // gum_x86_writer_put_breakpoint(cw);
    code_addr = cw->pc;

    code.data.assembly = template;
    code.data.current_pc = instrument_get_offset_hash(0);

    gssize current_pc_value1 =
        GPOINTER_TO_SIZE(&instrument_previous_pc) -
        (code_addr + offsetof(afl_log_code, data.assembly.mov_rdx_rip_off) +
         sizeof(code.data.assembly.mov_rdx_rip_off));
    gssize patch_offset1 =
        offsetof(afl_log_code, data.assembly.mov_rdx_rip_off) +
        sizeof(code.data.assembly.mov_rdx_rip_off) - sizeof(gint);
    if (!instrument_coverage_in_range(current_pc_value1)) {

      FATAL("Patch out of range (current_pc_value1): 0x%016lX",
            current_pc_value1);

    }

    *((gint *)&code.bytes[patch_offset1]) = (gint)current_pc_value1;

    gssize current_pc_value2 =
        GPOINTER_TO_SIZE(&instrument_previous_pc) -
        (code_addr + offsetof(afl_log_code, data.assembly.mov_rip_off_rdi) +
         sizeof(code.data.assembly.mov_rip_off_rdi));
    gssize patch_offset2 =
        offsetof(afl_log_code, data.assembly.mov_rip_off_rdi) +
        sizeof(code.data.assembly.mov_rip_off_rdi) - sizeof(gint);

    if (!instrument_coverage_in_range(current_pc_value2)) {

      FATAL("Patch out of range (current_pc_value2): 0x%016lX",
            current_pc_value2);

    }

    *((gint *)&code.bytes[patch_offset2]) = (gint)current_pc_value2;

    gsize afl_area_ptr_value =
        GPOINTER_TO_SIZE(__afl_area_ptr) -
        (code_addr + offsetof(afl_log_code, data.assembly.lea_rdi_rip_off) +
         sizeof(code.data.assembly.lea_rdi_rip_off));
    gssize afl_area_ptr_offset =
        offsetof(afl_log_code, data.assembly.lea_rdi_rip_off) +
        sizeof(code.data.assembly.lea_rdi_rip_off) - sizeof(gint);

    if (!instrument_coverage_in_range(afl_area_ptr_value)) {

      FATAL("Patch out of range (afl_area_ptr_value): 0x%016lX",
            afl_area_ptr_value);

    }

    *((gint *)&code.bytes[afl_area_ptr_offset]) = (gint)afl_area_ptr_value;

    gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));

    gum_x86_writer_put_label(cw, after_log_impl);

  }

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  instrument_coverate_write_function(output);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDI, area_offset);
  gum_x86_writer_put_call_address(cw, current_log_impl);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        GUM_RED_ZONE_SIZE);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

