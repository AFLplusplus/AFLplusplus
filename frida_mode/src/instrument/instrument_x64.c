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
#include "persistent.h"
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

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static gboolean instrument_coverage_in_range(gssize offset) {

  return (offset >= G_MININT32 && offset <= G_MAXINT32);

}

  #pragma pack(push, 1)

  #define LOG_SIZE 1024

typedef void (*fnPurgeBlockLog)(void);

typedef struct {

  void           *bitmap;
  fnPurgeBlockLog fn_purge;
  uint32_t        remain;
  uint32_t        log[LOG_SIZE];

} block_log_t;

extern void instrument_purge(void);

asm("instrument_purge:\n"
    ".global instrument_purge\n"
    /* RAX points at our remaining count */
    // "int $0x3\n"

    /* TODO: Process block log and update __afl_area_map*/
    "pushf \n"

    /* rax = block_log_t */
    "push %rbx\n"                                             /* prev block */
    /* rcx = loop count */
    "push %rdx\n"                                             /* curr block */

    "push %rsi\n"                                                 /* bitmap */
    "push %rdi\n"                                             /* map offset */
    "push %r8\n"                                                /* map byte */

    /* Get bitmap address */
    "mov -16(%rax), %rsi\n"
    "mov (%rsi), %rsi\n"

    /* Set loop counter (BLOCK_SIZE) */
    "movl $1024, %ecx\n"

    /* Calculate the first prev map index */
    "movl (%rax,%rcx,4), %ebx\n"
    "shr $0x1, %ebx\n"
    "dec %rcx\n"

    "1:\n"
    "movl (%rax,%rcx,4), %edx\n"

    /* Calculate the map offset */
    "mov %rdx, %rdi\n"
    "xor %rbx, %rdi\n"

    /* Update the map */
    "movb (%rsi,%rdi), %r8b\n"
    "add $0x1, %r8b\n"
    "adc $0x0, %r8b\n"
    "movb %r8b, (%rsi,%rdi)\n"

    /* Calculate the prev map index */
    "mov %edx, %ebx\n"
    "shr $0x1, %ebx\n"

    "dec %ecx\n"
    "jnz 1b\n"

    /* Move the last entry written (index 0) into the last position */
    "mov %ebx, 0x4000(%rax)\n"

    "pop %r8\n"
    "pop %rdi\n"
    "pop %rsi\n"
    "pop %rdx\n"
    "pop %rbx\n"
    "popf\n"

    /* Reset .remain BLOCK_SIZE - 1*/
    "movl $1023, %ecx\n"
    "ret\n");

block_log_t block_log = {

    .bitmap = &__afl_area_ptr,
    .fn_purge = instrument_purge,
    .remain = LOG_SIZE + 1,
    .log = {0}};

typedef struct {

  uint8_t push_rax[8];
  uint8_t push_rcx[8];

  union {

    uint8_t mov_rax_data[10];
    struct {

      uint8_t  mov_rax_data_code[2];
      uint64_t mov_rax_data_addr;

    };

  };

  uint8_t read_count[2];
  uint8_t loop[2];

  uint8_t push_stack[8];
  uint8_t call_purge[3];
  uint8_t pop_stack[8];

  uint8_t write_count[2];
  union {

    uint8_t store_block_id[7];
    struct {

      uint8_t  store_block_code[3];
      uint32_t store_block_data;

    };

  };

  uint8_t pop_rcx[8];
  uint8_t pop_rax[8];

} afl_log_code_asm_t;

typedef struct {

  uint8_t push_rax[8];

  union {

    uint8_t mov_rax_data[10];
    struct {

      uint8_t  mov_rax_data_code[2];
      uint64_t mov_rax_data_addr;

    };

  };

  union {

    uint8_t store_count[6];
    struct {

      uint8_t  store_count_code[2];
      uint32_t store_count_data;

    };

  };

  uint8_t pop_rax[8];

} afl_init_code_asm_t;

  #pragma pack(pop)

// mov qword ptr [rsp-0x88], rax
//    48 89 84 24 78 FF FF FF
// mov qword ptr [rsp-0x90], rcx
//    48 89 8C 24 70 FF FF FF
// mov rax, 0xb00bd00dfacedead
//    48 B8 AD DE CE FA 0D D0 0B B0
// mov ecx, dword ptr [rax]
//    8B 08
// loop 0x13
//    E2 13
// lea rsp, qword ptr [rsp - 0x98]
//    48 8D A4 24 68 FF FF FF
// call qword ptr [rax - 0x8]
//    FF 50 F8
// lea rsp, qword ptr [rsp + 0x98]
//    48 8D A4 24 98 00 00 00
// mov dword ptr [rax], ecx
//    89 08
// mov dword ptr [rax + rcx * 4], 0xdeadface
//    C7 04 88 CE FA AD DE
// mov rcx, qword ptr [rsp-0x90]
//    48 8B 8C 24 70 FF FF FF
// mov rax, qword ptr [rsp-0x88]
//    48 8B 84 24 78 FF FF FF

static const afl_log_code_asm_t template = {

    .push_rax = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
    .push_rcx = {0x48, 0x89, 0x8C, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
    .mov_rax_data = {0x48, 0xB8, 0xAD, 0xDE, 0xCE, 0xFA, 0x0D, 0xD0, 0x0B,
                     0xB0},

    .read_count = {0x8B, 0x08},
    .loop = {0xE2, 0x13},

    .push_stack = {0x48, 0x8D, 0xA4, 0x24, 0x68, 0xFF, 0xFF, 0xFF},
    .call_purge = {0xFF, 0x50, 0xF8},
    .pop_stack = {0x48, 0x8D, 0xA4, 0x24, 0x98, 0x00, 0x00, 0x00},

    .write_count = {0x89, 0x08},
    .store_block_id = {0xC7, 0x04, 0x88, 0xCE, 0xFA, 0xAD, 0xDE},

    .pop_rcx = {0x48, 0x8B, 0x8C, 0x24, 0x70, 0xFF, 0xFF, 0xFF},
    .pop_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

};

static const afl_init_code_asm_t init_template = {

    .push_rax = {0x48, 0x89, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},
    .mov_rax_data = {0x48, 0xB8, 0xAD, 0xDE, 0xCE, 0xFA, 0x0D, 0xD0, 0x0B,
                     0xB0},
    .store_count = {0xC7, 0x00, 0xCE, 0xFA, 0xAD, 0xDE},
    .pop_rax = {0x48, 0x8B, 0x84, 0x24, 0x78, 0xFF, 0xFF, 0xFF},

};

typedef union {

  afl_log_code_asm_t code;
  uint8_t            bytes[0];

} afl_log_code;

typedef union {

  afl_init_code_asm_t code;
  uint8_t             bytes[0];

} afl_init_code;

void instrument_coverage_optimize_init(void) {

  FVERBOSE("__afl_area_ptr: %p", __afl_area_ptr);
  FVERBOSE("__afl_map_size: 0x%08x\n", __afl_map_size);

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

}

static bool instrument_write(GumX86Writer *cw, guint32 area_offset) {

  afl_log_code code = {0};
  code.code = template;

  code.code.mov_rax_data_addr = (uint64_t)&block_log.remain;
  code.code.store_block_data = area_offset;

  if (instrument_suppress) {

    if (!g_hash_table_add(coverage_blocks, GSIZE_TO_POINTER(cw->code))) {

      FATAL("Failed - g_hash_table_add");

    }

  }

  // gum_x86_writer_put_breakpoint(cw);
  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_log_code));
  return true;

};

static void instrument_coverage_write(GumAddress        address,
                                      GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64       area_offset = (guint32)instrument_get_offset_hash(address);

  if (!instrument_write(cw, area_offset)) {

    FATAL("Failed to write inline instrumentation");

  }

}

void instrument_coverage_persistent_start_arch(GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  afl_init_code code = {0};
  code.code = init_template;

  code.code.mov_rax_data_addr = (uint64_t)&block_log.remain;
  code.code.store_count_data = LOG_SIZE + 1;

  // gum_x86_writer_put_breakpoint(cw);
  gum_x86_writer_put_bytes(cw, code.bytes, sizeof(afl_init_code));

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

