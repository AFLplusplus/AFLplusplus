#include <sys/mman.h>
#include <sys/resource.h>

#include "instrument.h"
#include "util.h"

#if defined(__x86_64__)

  #define INVALID 1
  #define DEFAULT_CACHE_SIZE (256ULL << 20)

gboolean         instrument_cache_enabled = TRUE;
gsize            instrument_cache_size = DEFAULT_CACHE_SIZE;
static gpointer *map_base = MAP_FAILED;

void instrument_cache_config(void) {

  instrument_cache_enabled = (getenv("AFL_FRIDA_INST_NO_CACHE") == NULL);

  if (getenv("AFL_FRIDA_INST_CACHE_SIZE") != NULL) {

    if (!instrument_cache_enabled) {

      FFATAL(
          "AFL_FRIDA_INST_CACHE_SIZE incomatible with "
          "AFL_FRIDA_INST_NO_CACHE");

    }

    instrument_cache_size =
        util_read_address("AFL_FRIDA_INST_CACHE_SIZE", DEFAULT_CACHE_SIZE);
    util_log2(instrument_cache_size);

  }

}

void instrument_cache_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "cache:" cYEL " [%c]",
       instrument_cache_enabled ? 'X' : ' ');
  if (!instrument_cache_enabled) { return; }

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "cache size:" cYEL " [0x%016lX]",
       instrument_cache_size);

  const struct rlimit data_limit = {.rlim_cur = RLIM_INFINITY,
                                    .rlim_max = RLIM_INFINITY};

  if (setrlimit(RLIMIT_AS, &data_limit) != 0) {

    FFATAL("Failed to setrlimit: %d", errno);

  }

  map_base =
      gum_memory_allocate(NULL, instrument_cache_size, instrument_cache_size,
                          GUM_PAGE_READ | GUM_PAGE_WRITE);
  if (map_base == MAP_FAILED) { FFATAL("Failed to map segment: %d", errno); }

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "cache addr:" cYEL " [0x%016lX]",
       GUM_ADDRESS(map_base));

}

static gpointer *instrument_cache_get_addr(gpointer addr) {

  gsize mask = (instrument_cache_size / sizeof(gpointer)) - 1;
  return &map_base[GPOINTER_TO_SIZE(addr) & mask];

}

void instrument_cache_insert(gpointer real_address, gpointer code_address) {

  if (!instrument_cache_enabled) { return; }

  gpointer *target = instrument_cache_get_addr(real_address);
  if (*target == code_address) {

    return;

  } else if (*target == NULL) {

    *target = code_address;

  } else {

    *target = GSIZE_TO_POINTER(INVALID);

  }

}

static gboolean instrument_cache_relocate(GumAddress old_pc, GumAddress new_pc,
                                          gint32  old_offset,
                                          gint32 *new_offset) {

  guint64 old_target = old_pc + old_offset;
  gint64  relocated = old_target - new_pc;

  if (relocated > G_MAXINT32 || relocated < G_MININT32) { return FALSE; }

  *new_offset = relocated;
  return TRUE;

}

static void instrument_cache_rewrite_branch_insn(const cs_insn    *instr,
                                                 GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  cs_x86       *x86 = &instr->detail->x86;
  guint8        modified[sizeof(instr->bytes)] = {0};
  guint8        offset = 0;
  guint8        skip = 0;

  g_assert(sizeof(x86->prefix) == 4);
  g_assert(sizeof(x86->opcode) == 4);

  /*
   * If the target is simply RAX, we can skip writing the code to load the
   * RIP
   */
  if (x86->operands[0].type == X86_OP_REG ||
      x86->operands[0].reg == X86_REG_RAX) {

    return;

  }

  /* Write the prefix */
  for (gsize i = 0; i < sizeof(x86->prefix); i++) {

    if (x86->prefix[i] != 0) {

      if (x86->prefix[i] == 0xf2) {

        skip++;

      } else {

        modified[offset++] = x86->prefix[i];
        skip++;

      }

    }

  }

  /* Write the REX */
  if (x86->rex == 0) {

    /*
     * CALL (near) and JMP (near) default to 64-bit operands, MOV does not,
     * write REX.W
     */
    modified[offset++] = 0x48;

  } else {

    if ((x86->rex & 0xF8) != 0x40) {

      FATAL("Unexpected REX byte: 0x%02x", x86->rex);

    }

    modified[offset++] = x86->rex | 0x08;
    skip++;

  }

  /*
   * CALL is FF /2, JMP is FF /4. The remaining op-code fields should thus be
   * unused
   */

  if (x86->opcode[0] != 0xFF || x86->opcode[1] != 0x00 ||
      x86->opcode[2] != 0x00 || x86->opcode[3] != 0x00) {

    FFATAL("Unexpected Op-code: 0x%02x 0x%02x 0x%02x 0x%02x", x86->opcode[0],
           x86->opcode[1], x86->opcode[2], x86->opcode[3]);

  }

  /* The reg field of the ModRM should be set to 2 for CALL and 4 for JMP */
  guint8 reg = (x86->modrm >> 3) & 7;
  if (reg != 0x4 && reg != 0x2) {

    FFATAL("Unexpected Reg: 0x%02x, ModRM: 0x%02x", reg, x86->modrm);

  }

  /* MOV */
  modified[offset++] = 0x8b;
  skip++;

  /* Clear the reg field (RAX) */
  modified[offset++] = x86->modrm & 0xc7;
  skip++;

  /* Operands */
  guint8 op_len = instr->size - skip;

  /* If our branch was RIP relative, we'll need to fix-up the offset */
  if (x86->operands[0].type == X86_OP_MEM &&
      x86->operands[0].mem.base == X86_REG_RIP) {

    /* RIP relative offsets should be 32-bits */
    if (op_len != sizeof(gint32)) {

      FFATAL("Unexpected operand length: %d\n", op_len);

    }

    gint32 old_offset = *(gint32 *)&instr->bytes[skip];
    gint32 new_offset = 0;
    if (instrument_cache_relocate(instr->address, cw->pc, old_offset,
                                  &new_offset)) {

      gint32 *output = (gint32 *)&modified[offset];
      *output = new_offset;
      offset += sizeof(gint32);

    } else {

      GumAddress target = instr->address + old_offset;
      gum_x86_writer_put_mov_reg_address(cw, GUM_X86_RAX, target);
      gum_x86_writer_put_mov_reg_reg_ptr(cw, GUM_X86_RAX, GUM_X86_RAX);
      return;

    }

  } else {

    for (int i = 0; i < op_len; i++) {

      guint8 val = instr->bytes[i + skip];
      modified[offset++] = val;

    }

  }

  gum_x86_writer_put_bytes(cw, modified, offset);

}

static void instrument_cache_write_push_frame(GumX86Writer *cw) {

  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_XSP, -(GUM_RED_ZONE_SIZE + (1 * sizeof(gpointer))),
      GUM_X86_XAX);
  gum_x86_writer_put_lahf(cw);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_XSP, -(GUM_RED_ZONE_SIZE + (2 * sizeof(gpointer))),
      GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_XSP, -(GUM_RED_ZONE_SIZE + (3 * sizeof(gpointer))),
      GUM_X86_XBX);

}

static void instrument_cache_write_pop_frame(GumX86Writer *cw) {

  gum_x86_writer_put_mov_reg_reg_offset_ptr(
      cw, GUM_X86_XBX, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (3 * sizeof(gpointer))));
  gum_x86_writer_put_mov_reg_reg_offset_ptr(
      cw, GUM_X86_XAX, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (2 * sizeof(gpointer))));
  gum_x86_writer_put_sahf(cw);
  gum_x86_writer_put_mov_reg_reg_offset_ptr(
      cw, GUM_X86_XAX, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (1 * sizeof(gpointer))));

}

static void instrument_cache_write_lookup(GumX86Writer *cw) {

  /* &map_base[GPOINTER_TO_SIZE(addr) & MAP_MASK]; */

  gsize mask = (instrument_cache_size / sizeof(gpointer)) - 1;
  gum_x86_writer_put_mov_reg_u64(cw, GUM_X86_XBX, mask);
  gum_x86_writer_put_and_reg_reg(cw, GUM_X86_XAX, GUM_X86_XBX);
  gum_x86_writer_put_shl_reg_u8(cw, GUM_X86_XAX, util_log2(sizeof(gpointer)));
  gum_x86_writer_put_mov_reg_u64(cw, GUM_X86_XBX, GPOINTER_TO_SIZE(map_base));
  gum_x86_writer_put_add_reg_reg(cw, GUM_X86_XAX, GUM_X86_XBX);

  /* Read the return address lookup */
  gum_x86_writer_put_mov_reg_reg_ptr(cw, GUM_X86_XAX, GUM_X86_XAX);

}

void instrument_cache_jmp_call(const cs_insn *instr, GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  cs_x86       *x86 = &instr->detail->x86;

  if (x86->op_count != 1) { FFATAL("Unexpected operand count"); }

  if (x86->operands[0].type == X86_OP_IMM) { return; }

  gconstpointer null = cw->code;

  instrument_cache_write_push_frame(cw);

  /*
   * We are about to re-write the CALL or JMP instruction, but replace the
   * op-code with that for a MOV into RAX. Since we are keeping the operand from
   * the JMP exactly the same, it is imperative that the target register state
   * be exactly the same as how the target left it. Since `LAHF` spoils `RAX` we
   * must restore it from the stack. We also must avoid adjusting `RSP`, so we
   * use `MOV` instructions to store our context into the stack beyond the
   * red-zone.
   */
  gum_x86_writer_put_mov_reg_reg_offset_ptr(
      cw, GUM_X86_XAX, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (1 * sizeof(gpointer))));

  instrument_cache_rewrite_branch_insn(instr, output);

  instrument_cache_write_lookup(cw);

  /* Test if its set*/
  gum_x86_writer_put_cmp_reg_i32(cw, GUM_X86_XAX, INVALID);
  gum_x86_writer_put_jcc_short_label(cw, X86_INS_JLE, null, GUM_UNLIKELY);

  /* If it's set, then stash the address beyond the red-zone */
  gum_x86_writer_put_mov_reg_offset_ptr_reg(
      cw, GUM_X86_XSP, -(GUM_RED_ZONE_SIZE + (4 * sizeof(gpointer))),
      GUM_X86_XAX);

  if (instr->id == X86_INS_JMP) {

    instrument_cache_write_pop_frame(cw);
    gum_x86_writer_put_jmp_reg_offset_ptr(
        cw, GUM_X86_XSP, -(GUM_RED_ZONE_SIZE + (4 * sizeof(gpointer))));

  } else {

    gum_x86_writer_put_mov_reg_address(
        cw, GUM_X86_XAX, GUM_ADDRESS(instr->address + instr->size));
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_X86_XSP,
                                              -sizeof(gpointer), GUM_X86_XAX);

    instrument_cache_write_pop_frame(cw);

    gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XSP, GUM_X86_XSP,
                                          -sizeof(gpointer));
    gum_x86_writer_put_jmp_reg_offset_ptr(
        cw, GUM_X86_XSP, -(GUM_RED_ZONE_SIZE + ((4 - 1) * sizeof(gpointer))));

  }

  /* Tidy up our mess and let FRIDA handle it */
  gum_x86_writer_put_label(cw, null);
  instrument_cache_write_pop_frame(cw);

}

void instrument_cache_ret(const cs_insn *instr, GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  cs_x86       *x86 = &instr->detail->x86;
  guint16       n = 0;

  if (x86->op_count != 0) {

    if (x86->operands[0].type != X86_OP_IMM) {

      FFATAL("Unexpected operand type");

    }

    n = x86->operands[0].imm;

  }

  gconstpointer null = cw->code;

  instrument_cache_write_push_frame(cw);

  gum_x86_writer_put_mov_reg_reg_ptr(cw, GUM_X86_XAX, GUM_X86_XSP);

  instrument_cache_write_lookup(cw);

  /* Test if its set*/
  gum_x86_writer_put_cmp_reg_i32(cw, GUM_X86_XAX, INVALID);
  gum_x86_writer_put_jcc_short_label(cw, X86_INS_JLE, null, GUM_UNLIKELY);

  /* If it's set, then overwrite our return address and return */
  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_X86_XSP, GUM_X86_XAX);
  instrument_cache_write_pop_frame(cw);

  if (n == 0) {

    gum_x86_writer_put_ret(cw);

  } else {

    gum_x86_writer_put_ret_imm(cw, n);

  }

  /* Tidy up our mess and let FRIDA handle it */
  gum_x86_writer_put_label(cw, null);
  instrument_cache_write_pop_frame(cw);

}

void instrument_cache(const cs_insn *instr, GumStalkerOutput *output) {

  if (!instrument_cache_enabled) { return; }

  switch (instr->id) {

    case X86_INS_RET:
      instrument_cache_ret(instr, output);
      break;

    case X86_INS_CALL:
    case X86_INS_JMP:
      instrument_cache_jmp_call(instr, output);
      break;

    default:
      return;

  }

}

#endif

