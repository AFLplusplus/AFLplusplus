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

  // add    byte ptr [rip+0x132338], 1
  // adc    byte ptr [rip+0x132338], 0

  // sahf
  // mov    rax,QWORD PTR [rsp-0x88]

  uint8_t mov_rax_rsp_88[8];
  uint8_t lahf;

  struct {

    uint8_t  add_ptr_1_prefix[2];
    uint32_t add_ptr_1_index;
    uint8_t  add_ptr_1_const[1];

  };

  struct {

    uint8_t  adc_ptr_0_prefix[2];
    uint32_t adc_ptr_0_index;
    uint8_t  adc_ptr_0_const[1];

  };

  uint8_t sahf;
  uint8_t mov_rsp_88_rax[8];

} afl_log_code_asm_t;

  #pragma pack(pop)

static const afl_log_code_asm_t template =
    {

        .mov_rax_rsp_88 = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
        .lahf = 0x9f,

        .add_ptr_1_prefix = {0x80, 0x05},
        .add_ptr_1_index = 0xdeadface,
        .add_ptr_1_const = {0x1},

        .adc_ptr_0_prefix = {0x80, 0x15},
        .adc_ptr_0_index = 0xdeadface,
        .adc_ptr_0_const = {0x0},

        .sahf = 0x9e,
        .mov_rsp_88_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

}

;

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

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

  if (!g_hash_table_contains(coverage_blocks, GSIZE_TO_POINTER(*target))) {

    return;

  }

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
      instrument_cache_insert(start_address,
                              (guint8 *)*target + sizeof(afl_log_code));

      break;
    default:
      return;

  }

  *target = (guint8 *)*target + sizeof(afl_log_code);

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
                             guint32 area_offset) {

  afl_log_code code = {0};

  code.code = template;

  gssize add_ptr_1_value =
      (GPOINTER_TO_SIZE(__afl_area_ptr) -
       (code_addr + offsetof(afl_log_code, code.add_ptr_1_prefix) +
        sizeof(code.code.add_ptr_1_prefix))) +
      area_offset;

  if (!instrument_coverage_in_range(add_ptr_1_value)) { return false; }

  code.code.add_ptr_1_index = add_ptr_1_value;

  gssize adc_ptr_0_value =
      (GPOINTER_TO_SIZE(__afl_area_ptr) -
       (code_addr + offsetof(afl_log_code, code.adc_ptr_0_prefix) +
        sizeof(code.code.adc_ptr_0_prefix))) +
      area_offset;

  if (!instrument_coverage_in_range(adc_ptr_0_value)) { return false; }

  code.code.adc_ptr_0_index = adc_ptr_0_value;

  if (instrument_suppress) {

    if (!g_hash_table_add(coverage_blocks, GSIZE_TO_POINTER(cw->code))) {

      FATAL("Failed - g_hash_table_add");

    }

  }

  // gum_x86_writer_put_breakpoint(cw);
  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));
  return true;

}

static guint32 instrument_block_idx() {

  static guint32 idx = 0;
  gsize          map_size_pow2 = util_log2(__afl_map_size);
  return idx++ & ((1 << map_size_pow2) - 1);

}

static void instrument_coverage_write(GumAddress        address,
                                      GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64       area_offset = instrument_block_idx();
  GumAddress    code_addr = cw->pc;

  if (!instrument_write_inline(cw, code_addr, area_offset)) {

    FATAL("Failed to write inline instrumentation");

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

