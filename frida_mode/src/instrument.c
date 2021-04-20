#include "frida-gum.h"
#include "config.h"
#include "debug.h"
#include "prefetch.h"
#include "ranges.h"
#include "unistd.h"

extern uint8_t *__afl_area_ptr;
extern u32      __afl_map_size;

uint64_t __thread previous_pc = 0;
GumAddress current_log_impl = GUM_ADDRESS(0);

static gboolean tracing = false;
static gboolean optimize = false;
static gboolean strict = false;

#if defined(__x86_64__)
static const guint8 afl_log_code[] = {

    0x9c,                                                         /* pushfq */
    0x50,                                                       /* push rax */
    0x51,                                                       /* push rcx */
    0x52,                                                       /* push rdx */

    0x48, 0x8d, 0x05, 0x27,
    0x00, 0x00, 0x00,                     /* lea rax, sym._afl_area_ptr_ptr */
    0x48, 0x8b, 0x00,                               /* mov rax, qword [rax] */
    0x48, 0x8b, 0x00,                               /* mov rax, qword [rax] */
    0x48, 0x8d, 0x0d, 0x22,
    0x00, 0x00, 0x00,                       /* lea rcx, sym.previous_pc     */
    0x48, 0x8b, 0x11,                               /* mov rdx, qword [rcx] */
    0x48, 0x8b, 0x12,                               /* mov rdx, qword [rdx] */
    0x48, 0x31, 0xfa,                                       /* xor rdx, rdi */
    0xfe, 0x04, 0x10,                               /* inc byte [rax + rdx] */
    0x48, 0xd1, 0xef,                                         /* shr rdi, 1 */
    0x48, 0x8b, 0x01,                               /* mov rax, qword [rcx] */
    0x48, 0x89, 0x38,                               /* mov qword [rax], rdi */

    0x5a,                                                        /* pop rdx */
    0x59,                                                        /* pop rcx */
    0x58,                                                        /* pop rax */
    0x9d,                                                          /* popfq */

    0xc3,                                                            /* ret */

    /* Read-only data goes here: */
    /* uint8_t** afl_area_ptr_ptr */
    /* uint64_t* afl_prev_loc_ptr */

};

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  guint64 current_pc = instr->address;
  guint64 area_offset = (current_pc >> 4) ^ (current_pc << 8);
  area_offset &= MAP_SIZE - 1;
  GumX86Writer *cw = output->writer.x86;

  if (current_log_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, current_log_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

    current_log_impl = cw->pc;
    gum_x86_writer_put_bytes(cw, afl_log_code, sizeof(afl_log_code));

    uint8_t **afl_area_ptr_ptr = &__afl_area_ptr;
    uint64_t *afl_prev_loc_ptr = &previous_pc;
    gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_area_ptr_ptr,
                             sizeof(afl_area_ptr_ptr));
    gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                             sizeof(afl_prev_loc_ptr));

    gum_x86_writer_put_label(cw, after_log_impl);

  }

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDI, area_offset);
  gum_x86_writer_put_call_address(cw, current_log_impl);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        GUM_RED_ZONE_SIZE);

}

#elif defined(__aarch64__)
static const guint8 afl_log_code[] = {

    // __afl_area_ptr[current_pc ^ previous_pc]++;
    // previous_pc = current_pc >> 1;
    0xE1, 0x0B, 0xBF, 0xA9,  // stp x1, x2, [sp, -0x10]!
    0xE3, 0x13, 0xBF, 0xA9,  // stp x3, x4, [sp, -0x10]!

    // x0 = current_pc
    0xc1, 0x01, 0x00, 0x58,  // ldr x1, #0x38, =&__afl_area_ptr
    0x21, 0x00, 0x40, 0xf9,  // ldr x1, [x1] (=__afl_area_ptr)

    0xc2, 0x01, 0x00, 0x58,  // ldr x2, #0x38, =&previous_pc
    0x42, 0x00, 0x40, 0xf9,  // ldr x2, [x2] (=previous_pc)

    // __afl_area_ptr[current_pc ^ previous_pc]++;
    0x42, 0x00, 0x00, 0xca,  // eor x2, x2, x0
    0x23, 0x68, 0x62, 0xf8,  // ldr x3, [x1, x2]
    0x63, 0x04, 0x00, 0x91,  // add x3, x3, #1
    0x23, 0x68, 0x22, 0xf8,  // str x3, [x1, x2]

    // previous_pc = current_pc >> 1;
    0xe0, 0x07, 0x40, 0x8b,  // add x0, xzr, x0, LSR #1
    0xe2, 0x00, 0x00, 0x58,  // ldr x2, #0x1c, =&previous_pc
    0x40, 0x00, 0x00, 0xf9,  // str x0, [x2]

    0xE3, 0x13, 0xc1, 0xA8,  // ldp x3, x4, [sp], #0x10
    0xE1, 0x0B, 0xc1, 0xA8,  // ldp x1, x2, [sp], #0x10
    0xC0, 0x03, 0x5F, 0xD6,  // ret

    // &afl_area_ptr_ptr
    // &afl_prev_loc_ptr

};

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  guint64 current_pc = instr->address;
  guint64 area_offset = (current_pc >> 4) ^ (current_pc << 8);
  area_offset &= MAP_SIZE - 1;
  GumArm64Writer *cw = output->writer.arm64;

  if (current_log_impl == 0 ||
      !gum_arm64_writer_can_branch_directly_between(cw, cw->pc,
                                                    current_log_impl) ||
      !gum_arm64_writer_can_branch_directly_between(cw, cw->pc + 128,
                                                    current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_arm64_writer_put_b_label(cw, after_log_impl);

    current_log_impl = cw->pc;
    gum_arm64_writer_put_bytes(cw, afl_log_code, sizeof(afl_log_code));

    uint8_t **afl_area_ptr_ptr = &__afl_area_ptr;
    uint64_t *afl_prev_loc_ptr = &previous_pc;
    gum_arm64_writer_put_bytes(cw, (const guint8 *)&afl_area_ptr_ptr,
                               sizeof(afl_area_ptr_ptr));
    gum_arm64_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                               sizeof(afl_prev_loc_ptr));

    gum_arm64_writer_put_label(cw, after_log_impl);

  }

  gum_arm64_writer_put_stp_reg_reg_reg_offset(
      cw, ARM64_REG_LR, ARM64_REG_X0, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X0, area_offset);
  gum_arm64_writer_put_bl_imm(cw, current_log_impl);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset(
      cw, ARM64_REG_LR, ARM64_REG_X0, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

}

#endif

static void on_basic_block(GumCpuContext *context, gpointer user_data) {

  /*
   * This function is performance critical as it is called to instrument every
   * basic block. By moving our print buffer to a global, we avoid it affecting
   * the critical path with additional stack adjustments if tracing is not
   * enabled. If tracing is enabled, then we're printing a load of diagnostic
   * information so this overhead is unlikely to be noticeable.
   */
  static char buffer[200];
  int         len;
  guint64     current_pc = (guint64)user_data;
  if (tracing) {

    /* Avoid any functions which may cause an allocation since the target app
     * may already be running inside malloc and it isn't designed to be
     * re-entrant on a single thread */
    len = snprintf(buffer, sizeof(buffer),
                   "current_pc: 0x%016" G_GINT64_MODIFIER
                   "x, previous_pc: 0x%016" G_GINT64_MODIFIER "x\n",
                   current_pc, previous_pc);

    write(STDOUT_FILENO, buffer, len + 1);

  }

  current_pc = (current_pc >> 4) ^ (current_pc << 8);
  current_pc &= MAP_SIZE - 1;

  __afl_area_ptr[current_pc ^ previous_pc]++;
  previous_pc = current_pc >> 1;

}

void instr_basic_block(GumStalkerIterator *iterator, GumStalkerOutput *output,
                       gpointer user_data) {

  const cs_insn *instr;
  gboolean       begin = TRUE;
  while (gum_stalker_iterator_next(iterator, &instr)) {

    if (begin) {

      prefetch_write((void *)instr->address);
      if (!strict || !range_is_excluded((void *)instr->address)) {

        if (optimize) {

          instrument_coverage_optimize(instr, output);

        } else {

          gum_stalker_iterator_put_callout(iterator, on_basic_block,
                                           (gpointer)instr->address, NULL);

        }

      }

      begin = FALSE;

    }

    gum_stalker_iterator_keep(iterator);

  }

}

void instrument_init() {

  optimize = (getenv("AFL_FRIDA_INST_NO_OPTIMIZE") == NULL);
  tracing = (getenv("AFL_FRIDA_INST_TRACE") != NULL);
  strict = (getenv("AFL_FRIDA_INST_STRICT") != NULL);

#if !defined(__x86_64__) && !defined(__aarch64__)
  optimize = false;
#endif

  OKF("Instrumentation - optimize [%c]", optimize ? 'X' : ' ');
  OKF("Instrumentation - tracing [%c]", tracing ? 'X' : ' ');
  OKF("Instrumentation - strict [%c]", strict ? 'X' : ' ');

  if (tracing && optimize) {

    FATAL("AFL_FRIDA_INST_OPTIMIZE and AFL_FRIDA_INST_TRACE are incompatible");

  }

  if (__afl_map_size != 0x10000) {

    FATAL("Bad map size: 0x%08x", __afl_map_size);

  }

}

