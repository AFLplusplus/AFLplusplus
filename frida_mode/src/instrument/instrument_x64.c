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

enum jcc_opcodes {

  OPC_JO = 0x70,
  OPC_JNO = 0x71,
  OPC_JB = 0x72,
  OPC_JAE = 0x73,
  OPC_JE = 0x74,
  OPC_JNE = 0x75,
  OPC_JBE = 0x76,
  OPC_JA = 0x77,
  OPC_JS = 0x78,
  OPC_JNS = 0x79,
  OPC_JP = 0x7a,
  OPC_JNP = 0x7b,
  OPC_JL = 0x7c,
  OPC_JGE = 0x7d,
  OPC_JLE = 0x7e,
  OPC_JG = 0x7f,

};

typedef union {

  struct {

    uint8_t opcode;
    uint8_t distance;

  };

  uint8_t bytes[0];

} jcc_insn;

static GHashTable *coverage_blocks = NULL;
static GHashTable *coverage_blocks_long = NULL;

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

typedef struct {

  // cur_location = (block_address >> 4) ^ (block_address << 8);
  // shared_mem[cur_location ^ prev_location]++;
  // prev_location = cur_location >> 1;

  // mov    QWORD PTR [rsp-0x88],rax
  // lahf
  // mov    QWORD PTR [rsp-0x90],rax
  // mov    QWORD PTR [rsp-0x98],rbx

  // mov    rax, 0xXXXXXXXXXXXXXXXXX                          /* p_prev_loc */
  // mov    eax, dword ptr [rax]                                /* prev_loc */
  // xor    eax,0x3f77                                           /* cur_loc */

  // mov    rbx, 0xXXXXXXXXXXXXXXXXX                                 /* map */
  // add    rax,rbx

  // mov    bl,BYTE PTR [rax]
  // add    bl,0x1
  // adc    bl,0x0
  // mov    BYTE PTR [rax],bl

  // mov    rax, 0xXXXXXXXXXXXXXXXXX                          /* p_prev_loc */
  // mov    dword ptr [rax], 0xXXXXXXXXX                        /* prev_loc */

  // mov    rbx,QWORD PTR [rsp-0x98]
  // mov    rax,QWORD PTR [rsp-0x90]
  // sahf
  // mov    rax,QWORD PTR [rsp-0x88]

  uint8_t mov_rax_rsp_88[8];
  uint8_t lahf;
  uint8_t mov_rax_rsp_90[8];
  uint8_t mov_rbx_rsp_98[8];

  uint8_t mov_rax_prev_loc_ptr1[10];
  uint8_t mov_eax_prev_loc[2];
  uint8_t xor_eax_curr_loc[5];

  uint8_t mov_rbx_map_ptr[10];
  uint8_t add_rax_rbx[3];

  uint8_t mov_rbx_ptr_rax[2];
  uint8_t add_bl_1[3];
  uint8_t adc_bl_0[3];
  uint8_t mov_ptr_rax_rbx[2];

  uint8_t mov_rax_prev_loc_ptr2[10];
  uint8_t mov_prev_loc_curr_loc_shr1[6];

  uint8_t mov_rsp_98_rbx[8];
  uint8_t mov_rsp_90_rax[8];
  uint8_t sahf;
  uint8_t mov_rsp_88_rax[8];

} afl_log_code_asm_long_t;

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

static const afl_log_code_asm_long_t template_long =
    {

        .mov_rax_rsp_88 = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
        .lahf = 0x9f,
        .mov_rax_rsp_90 = {0x48, 0x89, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .mov_rbx_rsp_98 = {0x48, 0x89, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},

        .mov_rax_prev_loc_ptr1 = {0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xFF, 0xFF, 0xFF},
        .mov_eax_prev_loc = {0x8b, 0x00},
        .xor_eax_curr_loc = {0x35},

        .mov_rbx_map_ptr = {0x48, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF},
        .add_rax_rbx = {0x48, 0x01, 0xd8},

        .mov_rbx_ptr_rax = {0x8a, 0x18},
        .add_bl_1 = {0x80, 0xc3, 0x01},
        .adc_bl_0 = {0x80, 0xd3, 0x00},
        .mov_ptr_rax_rbx = {0x88, 0x18},

        .mov_rax_prev_loc_ptr2 = {0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xFF, 0xFF, 0xFF},
        .mov_prev_loc_curr_loc_shr1 = {0xc7, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},

        .mov_rsp_98_rbx = {0x48, 0x8B, 0x9C, 0x24, 0x68, 0xFF, 0xFF, 0xFF},
        .mov_rsp_90_rax = {0x48, 0x8B, 0x84, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
        .sahf = 0x9e,
        .mov_rsp_88_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

}

;

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

typedef union {

  afl_log_code_asm_long_t code;
  uint8_t                 bytes[0];

} afl_log_code_long;

void instrument_coverage_optimize_init(void) {

  FVERBOSE("__afl_area_ptr: %p", __afl_area_ptr);

}

static void instrument_coverage_switch_insn(GumStalkerObserver *self,
                                            gpointer            from_address,
                                            gpointer            start_address,
                                            const cs_insn      *from_insn,
                                            gpointer           *target) {

  UNUSED_PARAMETER(self);
  UNUSED_PARAMETER(from_address);

  cs_x86    *x86;
  cs_x86_op *op;
  bool       is_short = false;
  bool       is_long = false;

  if (from_insn == NULL) { return; }

  x86 = &from_insn->detail->x86;
  op = x86->operands;

  is_short = g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target));
  is_long =
      g_hash_table_contains(coverage_blocks_long, GSIZE_TO_POINTER(*target));

  if (!is_short && !is_long) { return; }

  switch (from_insn->id) {

    case X86_INS_CALL:
    case X86_INS_JMP:
      if (x86->op_count != 1) {

        FATAL("Unexpected operand count: %d", x86->op_count);

      }

      if (op[0].type != X86_OP_IMM) {

        instrument_cache_insert(start_address, *target);
        return;

      }

      break;
    case X86_INS_RET:
      if (is_short) {

        instrument_cache_insert(start_address,
                                (guint8 *)*target + sizeof(afl_log_code));

      } else if (is_long) {

        instrument_cache_insert(start_address,
                                (guint8 *)*target + sizeof(afl_log_code_long));

      } else {

        FATAL("Something has gone wrong here!");

      }

      break;
    default:
      return;

  }

  if (is_short) {

    *target = (guint8 *)*target + sizeof(afl_log_code);

  } else if (is_long) {

    *target = (guint8 *)*target + sizeof(afl_log_code_long);

  } else {

    FATAL("Something has gone wrong here!");

  }

}

cs_insn *instrument_disassemble(gconstpointer address) {

  csh      capstone;
  cs_insn *insn = NULL;

  cs_open(CS_ARCH_X86, GUM_CPU_MODE, &capstone);
  cs_option(capstone, CS_OPT_DETAIL, CS_OPT_ON);

  cs_disasm(capstone, address, 16, GPOINTER_TO_SIZE(address), 1, &insn);

  cs_close(&capstone);

  return insn;

}

static void instrument_coverage_switch(GumStalkerObserver *self,
                                       gpointer            from_address,
                                       gpointer start_address, void *from_insn,
                                       gpointer *target) {

  if (from_insn == NULL) { return; }
  cs_insn *insn = instrument_disassemble(from_insn);
  instrument_coverage_switch_insn(self, from_address, start_address, insn,
                                  target);
  cs_free(insn, 1);

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

  coverage_blocks_long = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (coverage_blocks_long == NULL) {

    FATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

}

bool instrument_write_inline(GumX86Writer *cw, GumAddress code_addr,
                             guint32 area_offset, guint32 area_offset_ror) {

  afl_log_code code = {0};

  code.code = template;

  gssize prev_loc_value =
      GPOINTER_TO_SIZE(instrument_previous_pc_addr) -
      (code_addr + offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
       sizeof(code.code.mov_prev_loc_curr_loc_shr1));
  gssize prev_loc_value_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(gint) -
      sizeof(guint32);
  if (!instrument_coverage_in_range(prev_loc_value)) { return false; }

  *((gint *)&code.bytes[prev_loc_value_offset]) = (gint)prev_loc_value;

  /* mov_eax_prev_loc */

  gssize prev_loc_value2 =
      GPOINTER_TO_SIZE(instrument_previous_pc_addr) -
      (code_addr + offsetof(afl_log_code, code.mov_eax_prev_loc) +
       sizeof(code.code.mov_eax_prev_loc));
  gssize prev_loc_value_offset2 =
      offsetof(afl_log_code, code.mov_eax_prev_loc) +
      sizeof(code.code.mov_eax_prev_loc) - sizeof(gint);
  if (!instrument_coverage_in_range(prev_loc_value)) { return false; }

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

  if (!instrument_coverage_in_range(lea_rbx_area_ptr_value)) { return false; }

  *((guint32 *)&code.bytes[lea_rbx_area_ptr_offset]) = lea_rbx_area_ptr_value;

  /* mov_prev_loc_curr_loc_shr1 */

  gssize curr_loc_shr_1_offset =
      offsetof(afl_log_code, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(guint32);

  *((guint32 *)&code.bytes[curr_loc_shr_1_offset]) = (guint32)(area_offset_ror);

  if (instrument_suppress) {

    if (!g_hash_table_add(coverage_blocks, GSIZE_TO_POINTER(cw->code))) {

      FATAL("Failed - g_hash_table_add");

    }

  }

  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));
  return true;

}

bool instrument_write_inline_long(GumX86Writer *cw, guint32 area_offset,
                                  guint32 area_offset_ror) {

  afl_log_code_long code = {0};
  code.code = template_long;

  /* mov_rax_prev_loc_ptr1 */
  gssize mov_rax_prev_loc_ptr1_offset =
      offsetof(afl_log_code_long, code.mov_rax_prev_loc_ptr1) +
      sizeof(code.code.mov_rax_prev_loc_ptr1) - sizeof(gsize);
  *((gsize *)&code.bytes[mov_rax_prev_loc_ptr1_offset]) =
      GPOINTER_TO_SIZE(instrument_previous_pc_addr);

  /* xor_eax_curr_loc */
  gssize xor_eax_curr_loc_offset =
      offsetof(afl_log_code_long, code.xor_eax_curr_loc) +
      sizeof(code.code.xor_eax_curr_loc) - sizeof(guint32);
  *((guint32 *)&code.bytes[xor_eax_curr_loc_offset]) = area_offset;

  /* mov_rbx_map_ptr */
  gsize mov_rbx_map_ptr_offset =
      offsetof(afl_log_code_long, code.mov_rbx_map_ptr) +
      sizeof(code.code.mov_rbx_map_ptr) - sizeof(gsize);
  *((gsize *)&code.bytes[mov_rbx_map_ptr_offset]) =
      GPOINTER_TO_SIZE(__afl_area_ptr);

  /* mov_rax_prev_loc_ptr2 */
  gssize mov_rax_prev_loc_ptr2_offset =
      offsetof(afl_log_code_long, code.mov_rax_prev_loc_ptr2) +
      sizeof(code.code.mov_rax_prev_loc_ptr2) - sizeof(gsize);
  *((gsize *)&code.bytes[mov_rax_prev_loc_ptr2_offset]) =
      GPOINTER_TO_SIZE(instrument_previous_pc_addr);

  /* mov_prev_loc_curr_loc_shr1 */
  gssize mov_prev_loc_curr_loc_shr1_offset =
      offsetof(afl_log_code_long, code.mov_prev_loc_curr_loc_shr1) +
      sizeof(code.code.mov_prev_loc_curr_loc_shr1) - sizeof(guint32);
  *((guint32 *)&code.bytes[mov_prev_loc_curr_loc_shr1_offset]) =
      (guint32)(area_offset_ror);

  if (instrument_suppress) {

    if (!g_hash_table_add(coverage_blocks_long, GSIZE_TO_POINTER(cw->code))) {

      FATAL("Failed - g_hash_table_add");

    }

  }

  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code_long));
  return true;

}

static void instrument_coverage_write(GumAddress        address,
                                      GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64       area_offset = (guint32)instrument_get_offset_hash(address);
  gsize         map_size_pow2;
  guint32       area_offset_ror;
  GumAddress    code_addr = cw->pc;

  map_size_pow2 = util_log2(__afl_map_size);
  area_offset_ror = (guint32)util_rotate(instrument_get_offset_hash(address), 1,
                                         map_size_pow2);

  if (!instrument_write_inline(cw, code_addr, area_offset, area_offset_ror)) {

    if (!instrument_write_inline_long(cw, area_offset, area_offset_ror)) {

      FATAL("Failed to write inline instrumentation");

    }

  }

}

void instrument_coverage_optimize(const cs_insn    *instr,
                                  GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
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

  if (instrument_suppress) { instrument_coverage_suppress_init(); }

  instrument_coverage_write(GUM_ADDRESS(instr->address), output);

}

void instrument_coverage_optimize_insn(const cs_insn    *instr,
                                       GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  jcc_insn      taken, not_taken;

  switch (instr->id) {

    case X86_INS_CMOVA:
      taken.opcode = OPC_JA;
      not_taken.opcode = OPC_JBE;
      break;
    case X86_INS_CMOVAE:
      taken.opcode = OPC_JAE;
      not_taken.opcode = OPC_JB;
      break;
    case X86_INS_CMOVB:
      taken.opcode = OPC_JB;
      not_taken.opcode = OPC_JAE;
      break;
    case X86_INS_CMOVBE:
      taken.opcode = OPC_JBE;
      not_taken.opcode = OPC_JA;
      break;
    case X86_INS_CMOVE:
      taken.opcode = OPC_JE;
      not_taken.opcode = OPC_JNE;
      break;
    case X86_INS_CMOVG:
      taken.opcode = OPC_JG;
      not_taken.opcode = OPC_JLE;
      break;
    case X86_INS_CMOVGE:
      taken.opcode = OPC_JGE;
      not_taken.opcode = OPC_JL;
      break;
    case X86_INS_CMOVL:
      taken.opcode = OPC_JL;
      not_taken.opcode = OPC_JGE;
      break;
    case X86_INS_CMOVLE:
      taken.opcode = OPC_JLE;
      not_taken.opcode = OPC_JG;
      break;
    case X86_INS_CMOVNE:
      taken.opcode = OPC_JNE;
      not_taken.opcode = OPC_JE;
      break;
    case X86_INS_CMOVNO:
      taken.opcode = OPC_JNO;
      not_taken.opcode = OPC_JO;
      break;
    case X86_INS_CMOVNP:
      taken.opcode = OPC_JNP;
      not_taken.opcode = OPC_JP;
      break;
    case X86_INS_CMOVNS:
      taken.opcode = OPC_JNS;
      not_taken.opcode = OPC_JS;
      break;
    case X86_INS_CMOVO:
      taken.opcode = OPC_JO;
      not_taken.opcode = OPC_JNO;
      break;
    case X86_INS_CMOVP:
      taken.opcode = OPC_JP;
      not_taken.opcode = OPC_JNP;
      break;
    case X86_INS_CMOVS:
      taken.opcode = OPC_JS;
      not_taken.opcode = OPC_JNS;
      break;
    default:
      return;

  }

  taken.distance = sizeof(afl_log_code);
  not_taken.distance = sizeof(afl_log_code);

  // gum_x86_writer_put_breakpoint(cw);

  gum_x86_writer_put_bytes(cw, taken.bytes, sizeof(jcc_insn));
  instrument_coverage_write(GUM_ADDRESS(instr->address), output);

  gum_x86_writer_put_bytes(cw, not_taken.bytes, sizeof(jcc_insn));
  instrument_coverage_write(GUM_ADDRESS(instr->address + instr->size), output);

  FVERBOSE("Instrument - 0x%016lx: %s %s", instr->address, instr->mnemonic,
           instr->op_str);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

void instrument_write_regs(GumCpuContext *cpu_context, gpointer user_data) {

  int fd = (int)(size_t)user_data;
  instrument_regs_format(
      fd, "rax: 0x%016x, rbx: 0x%016x, rcx: 0x%016x, rdx: 0x%016x\n",
      cpu_context->rax, cpu_context->rbx, cpu_context->rcx, cpu_context->rdx);
  instrument_regs_format(
      fd, "rdi: 0x%016x, rsi: 0x%016x, rbp: 0x%016x, rsp: 0x%016x\n",
      cpu_context->rdi, cpu_context->rsi, cpu_context->rbp, cpu_context->rsp);
  instrument_regs_format(
      fd, "r8 : 0x%016x, r9 : 0x%016x, r10: 0x%016x, r11: 0x%016x\n",
      cpu_context->r8, cpu_context->r9, cpu_context->r10, cpu_context->r11);
  instrument_regs_format(
      fd, "r12: 0x%016x, r13: 0x%016x, r14: 0x%016x, r15: 0x%016x\n",
      cpu_context->r12, cpu_context->r13, cpu_context->r14, cpu_context->r15);
  instrument_regs_format(fd, "rip: 0x%016x\n\n", cpu_context->rip);

}

#endif

