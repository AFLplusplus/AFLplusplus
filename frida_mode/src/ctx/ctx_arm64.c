#include "frida-gumjs.h"

#include "ctx.h"
#include "util.h"

#if defined(__aarch64__)

  #define ARM64_REG_8(LABEL, REG) \
    case LABEL: {                 \
                                  \
      return REG & GUM_INT8_MASK; \
                                  \
    }

  #define ARM64_REG_16(LABEL, REG)   \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT16_MASK); \
                                     \
    }

  #define ARM64_REG_32(LABEL, REG)   \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT32_MASK); \
                                     \
    }

  #define ARM64_REG_64(LABEL, REG) \
    case LABEL: {                  \
                                   \
      return (REG);                \
                                   \
    }

gsize ctx_read_reg(GumArm64CpuContext *ctx, arm64_reg reg) {

  switch (reg) {

    case ARM64_REG_WZR:
    case ARM64_REG_XZR:
      return 0;

      ARM64_REG_8(ARM64_REG_B0, ctx->x[0])
      ARM64_REG_8(ARM64_REG_B1, ctx->x[1])
      ARM64_REG_8(ARM64_REG_B2, ctx->x[2])
      ARM64_REG_8(ARM64_REG_B3, ctx->x[3])
      ARM64_REG_8(ARM64_REG_B4, ctx->x[4])
      ARM64_REG_8(ARM64_REG_B5, ctx->x[5])
      ARM64_REG_8(ARM64_REG_B6, ctx->x[6])
      ARM64_REG_8(ARM64_REG_B7, ctx->x[7])
      ARM64_REG_8(ARM64_REG_B8, ctx->x[8])
      ARM64_REG_8(ARM64_REG_B9, ctx->x[9])
      ARM64_REG_8(ARM64_REG_B10, ctx->x[10])
      ARM64_REG_8(ARM64_REG_B11, ctx->x[11])
      ARM64_REG_8(ARM64_REG_B12, ctx->x[12])
      ARM64_REG_8(ARM64_REG_B13, ctx->x[13])
      ARM64_REG_8(ARM64_REG_B14, ctx->x[14])
      ARM64_REG_8(ARM64_REG_B15, ctx->x[15])
      ARM64_REG_8(ARM64_REG_B16, ctx->x[16])
      ARM64_REG_8(ARM64_REG_B17, ctx->x[17])
      ARM64_REG_8(ARM64_REG_B18, ctx->x[18])
      ARM64_REG_8(ARM64_REG_B19, ctx->x[19])
      ARM64_REG_8(ARM64_REG_B20, ctx->x[20])
      ARM64_REG_8(ARM64_REG_B21, ctx->x[21])
      ARM64_REG_8(ARM64_REG_B22, ctx->x[22])
      ARM64_REG_8(ARM64_REG_B23, ctx->x[23])
      ARM64_REG_8(ARM64_REG_B24, ctx->x[24])
      ARM64_REG_8(ARM64_REG_B25, ctx->x[25])
      ARM64_REG_8(ARM64_REG_B26, ctx->x[26])
      ARM64_REG_8(ARM64_REG_B27, ctx->x[27])
      ARM64_REG_8(ARM64_REG_B28, ctx->x[28])
      ARM64_REG_8(ARM64_REG_B29, ctx->fp)
      ARM64_REG_8(ARM64_REG_B30, ctx->lr)
      ARM64_REG_8(ARM64_REG_B31, ctx->sp)

      ARM64_REG_16(ARM64_REG_H0, ctx->x[0])
      ARM64_REG_16(ARM64_REG_H1, ctx->x[1])
      ARM64_REG_16(ARM64_REG_H2, ctx->x[2])
      ARM64_REG_16(ARM64_REG_H3, ctx->x[3])
      ARM64_REG_16(ARM64_REG_H4, ctx->x[4])
      ARM64_REG_16(ARM64_REG_H5, ctx->x[5])
      ARM64_REG_16(ARM64_REG_H6, ctx->x[6])
      ARM64_REG_16(ARM64_REG_H7, ctx->x[7])
      ARM64_REG_16(ARM64_REG_H8, ctx->x[8])
      ARM64_REG_16(ARM64_REG_H9, ctx->x[9])
      ARM64_REG_16(ARM64_REG_H10, ctx->x[10])
      ARM64_REG_16(ARM64_REG_H11, ctx->x[11])
      ARM64_REG_16(ARM64_REG_H12, ctx->x[12])
      ARM64_REG_16(ARM64_REG_H13, ctx->x[13])
      ARM64_REG_16(ARM64_REG_H14, ctx->x[14])
      ARM64_REG_16(ARM64_REG_H15, ctx->x[15])
      ARM64_REG_16(ARM64_REG_H16, ctx->x[16])
      ARM64_REG_16(ARM64_REG_H17, ctx->x[17])
      ARM64_REG_16(ARM64_REG_H18, ctx->x[18])
      ARM64_REG_16(ARM64_REG_H19, ctx->x[19])
      ARM64_REG_16(ARM64_REG_H20, ctx->x[20])
      ARM64_REG_16(ARM64_REG_H21, ctx->x[21])
      ARM64_REG_16(ARM64_REG_H22, ctx->x[22])
      ARM64_REG_16(ARM64_REG_H23, ctx->x[23])
      ARM64_REG_16(ARM64_REG_H24, ctx->x[24])
      ARM64_REG_16(ARM64_REG_H25, ctx->x[25])
      ARM64_REG_16(ARM64_REG_H26, ctx->x[26])
      ARM64_REG_16(ARM64_REG_H27, ctx->x[27])
      ARM64_REG_16(ARM64_REG_H28, ctx->x[28])
      ARM64_REG_16(ARM64_REG_H29, ctx->fp)
      ARM64_REG_16(ARM64_REG_H30, ctx->lr)
      ARM64_REG_16(ARM64_REG_H31, ctx->sp)

      ARM64_REG_32(ARM64_REG_W0, ctx->x[0])
      ARM64_REG_32(ARM64_REG_W1, ctx->x[1])
      ARM64_REG_32(ARM64_REG_W2, ctx->x[2])
      ARM64_REG_32(ARM64_REG_W3, ctx->x[3])
      ARM64_REG_32(ARM64_REG_W4, ctx->x[4])
      ARM64_REG_32(ARM64_REG_W5, ctx->x[5])
      ARM64_REG_32(ARM64_REG_W6, ctx->x[6])
      ARM64_REG_32(ARM64_REG_W7, ctx->x[7])
      ARM64_REG_32(ARM64_REG_W8, ctx->x[8])
      ARM64_REG_32(ARM64_REG_W9, ctx->x[9])
      ARM64_REG_32(ARM64_REG_W10, ctx->x[10])
      ARM64_REG_32(ARM64_REG_W11, ctx->x[11])
      ARM64_REG_32(ARM64_REG_W12, ctx->x[12])
      ARM64_REG_32(ARM64_REG_W13, ctx->x[13])
      ARM64_REG_32(ARM64_REG_W14, ctx->x[14])
      ARM64_REG_32(ARM64_REG_W15, ctx->x[15])
      ARM64_REG_32(ARM64_REG_W16, ctx->x[16])
      ARM64_REG_32(ARM64_REG_W17, ctx->x[17])
      ARM64_REG_32(ARM64_REG_W18, ctx->x[18])
      ARM64_REG_32(ARM64_REG_W19, ctx->x[19])
      ARM64_REG_32(ARM64_REG_W20, ctx->x[20])
      ARM64_REG_32(ARM64_REG_W21, ctx->x[21])
      ARM64_REG_32(ARM64_REG_W22, ctx->x[22])
      ARM64_REG_32(ARM64_REG_W23, ctx->x[23])
      ARM64_REG_32(ARM64_REG_W24, ctx->x[24])
      ARM64_REG_32(ARM64_REG_W25, ctx->x[25])
      ARM64_REG_32(ARM64_REG_W26, ctx->x[26])
      ARM64_REG_32(ARM64_REG_W27, ctx->x[27])
      ARM64_REG_32(ARM64_REG_W28, ctx->x[28])
      ARM64_REG_32(ARM64_REG_W29, ctx->fp)
      ARM64_REG_32(ARM64_REG_W30, ctx->lr)

      ARM64_REG_64(ARM64_REG_X0, ctx->x[0])
      ARM64_REG_64(ARM64_REG_X1, ctx->x[1])
      ARM64_REG_64(ARM64_REG_X2, ctx->x[2])
      ARM64_REG_64(ARM64_REG_X3, ctx->x[3])
      ARM64_REG_64(ARM64_REG_X4, ctx->x[4])
      ARM64_REG_64(ARM64_REG_X5, ctx->x[5])
      ARM64_REG_64(ARM64_REG_X6, ctx->x[6])
      ARM64_REG_64(ARM64_REG_X7, ctx->x[7])
      ARM64_REG_64(ARM64_REG_X8, ctx->x[8])
      ARM64_REG_64(ARM64_REG_X9, ctx->x[9])
      ARM64_REG_64(ARM64_REG_X10, ctx->x[10])
      ARM64_REG_64(ARM64_REG_X11, ctx->x[11])
      ARM64_REG_64(ARM64_REG_X12, ctx->x[12])
      ARM64_REG_64(ARM64_REG_X13, ctx->x[13])
      ARM64_REG_64(ARM64_REG_X14, ctx->x[14])
      ARM64_REG_64(ARM64_REG_X15, ctx->x[15])
      ARM64_REG_64(ARM64_REG_X16, ctx->x[16])
      ARM64_REG_64(ARM64_REG_X17, ctx->x[17])
      ARM64_REG_64(ARM64_REG_X18, ctx->x[18])
      ARM64_REG_64(ARM64_REG_X19, ctx->x[19])
      ARM64_REG_64(ARM64_REG_X20, ctx->x[20])
      ARM64_REG_64(ARM64_REG_X21, ctx->x[21])
      ARM64_REG_64(ARM64_REG_X22, ctx->x[22])
      ARM64_REG_64(ARM64_REG_X23, ctx->x[23])
      ARM64_REG_64(ARM64_REG_X24, ctx->x[24])
      ARM64_REG_64(ARM64_REG_X25, ctx->x[25])
      ARM64_REG_64(ARM64_REG_X26, ctx->x[26])
      ARM64_REG_64(ARM64_REG_X27, ctx->x[27])
      ARM64_REG_64(ARM64_REG_X28, ctx->x[28])
      ARM64_REG_64(ARM64_REG_FP, ctx->fp)
      ARM64_REG_64(ARM64_REG_LR, ctx->lr)
      ARM64_REG_64(ARM64_REG_SP, ctx->sp)

    default:
      FFATAL("Failed to read register: %d", reg);
      return 0;

  }

}

size_t ctx_get_size(const cs_insn *instr, cs_arm64_op *operand) {

  uint8_t num_registers;
  uint8_t count_byte;
  char    vas_digit;
  size_t  mnemonic_len;

  switch (instr->id) {

    case ARM64_INS_STP:
    case ARM64_INS_STXP:
    case ARM64_INS_STNP:
    case ARM64_INS_STLXP:
    case ARM64_INS_LDP:
    case ARM64_INS_LDXP:
    case ARM64_INS_LDNP:
      num_registers = 2;
      break;
    default:
      num_registers = 1;
      break;

  }

  mnemonic_len = strlen(instr->mnemonic);
  if (mnemonic_len == 0) { FFATAL("No mnemonic found"); };

  char last = instr->mnemonic[mnemonic_len - 1];
  switch (last) {

    case 'b':
      return 1;
    case 'h':
      return 2;
    case 'w':
      return 4 * num_registers;

  }

  if (operand->vas == ARM64_VAS_INVALID) {

    if (operand->type == ARM64_OP_REG) {

      switch (operand->reg) {

        case ARM64_REG_WZR:
        case ARM64_REG_WSP:
        case ARM64_REG_W0 ... ARM64_REG_W30:
        case ARM64_REG_S0 ... ARM64_REG_S31:
          return 4 * num_registers;
        case ARM64_REG_D0 ... ARM64_REG_D31:
          return 8 * num_registers;
        case ARM64_REG_Q0 ... ARM64_REG_Q31:
          return 16;
        default:
          return 8 * num_registers;
          ;

      }

    }

    return 8 * num_registers;

  }

  if (g_str_has_prefix(instr->mnemonic, "st") ||
      g_str_has_prefix(instr->mnemonic, "ld")) {

    if (mnemonic_len < 3) {

      FFATAL("VAS Mnemonic too short: %s\n", instr->mnemonic);

    }

    vas_digit = instr->mnemonic[2];
    if (vas_digit < '0' || vas_digit > '9') {

      FFATAL("VAS Mnemonic digit out of range: %s\n", instr->mnemonic);

    }

    count_byte = vas_digit - '0';

  } else {

    count_byte = 1;

  }

  switch (operand->vas) {

    case ARM64_VAS_1B:
      return 1 * count_byte;
    case ARM64_VAS_1H:
      return 2 * count_byte;
    case ARM64_VAS_4B:
    case ARM64_VAS_1S:
    case ARM64_VAS_1D:
    case ARM64_VAS_2H:
      return 4 * count_byte;
    case ARM64_VAS_8B:
    case ARM64_VAS_4H:
    case ARM64_VAS_2S:
    case ARM64_VAS_2D:
    case ARM64_VAS_1Q:
      return 8 * count_byte;
    case ARM64_VAS_8H:
    case ARM64_VAS_4S:
    case ARM64_VAS_16B:
      return 16 * count_byte;
    default:
      FFATAL("Unexpected VAS type: %s %d", instr->mnemonic, operand->vas);

  }

}

#endif

