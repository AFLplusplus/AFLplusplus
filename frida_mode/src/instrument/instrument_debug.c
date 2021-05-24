#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "frida-gum.h"

#include "util.h"

#ifdef FRIDA_DEBUG

static gpointer instrument_gen_start = NULL;

static void instrument_debug(char *format, ...) {

  va_list ap;
  char    buffer[4096] = {0};

  va_start(ap, format);

  vsnprintf(buffer, sizeof(buffer) - 1, format, ap);
  va_end(ap);

  IGNORED_RETURN(write(STDOUT_FILENO, buffer, sizeof(buffer)));

}

static void instrument_disasm(guint8 *code, guint size) {

  csh      capstone;
  cs_err   err;
  cs_insn *insn;
  size_t   count, i;

  err = cs_open(GUM_DEFAULT_CS_ARCH,
                GUM_DEFAULT_CS_MODE | GUM_DEFAULT_CS_ENDIAN, &capstone);
  g_assert(err == CS_ERR_OK);

  count = cs_disasm(capstone, code, size, GPOINTER_TO_SIZE(code), 0, &insn);
  g_assert(insn != NULL);

  for (i = 0; i != count; i++) {

    instrument_debug("\t0x%" G_GINT64_MODIFIER "x\t%s %s\n", insn[i].address,
                     insn[i].mnemonic, insn[i].op_str);

  }

  cs_free(insn, count);

  cs_close(&capstone);

}

static gpointer instrument_cur(GumStalkerOutput *output) {

  #if defined(__i386__) || defined(__x86_64__)
  return gum_x86_writer_cur(output->writer.x86);
  #elif defined(__aarch64__)
  return gum_arm64_writer_cur(output->writer.arm64);
  #elif defined(__arm__)
  return gum_arm_writer_cur(output->writer.arm);
  #else
    #error "Unsupported architecture"
  #endif

}

void instrument_debug_start(uint64_t address, GumStalkerOutput *output) {

  GumDebugSymbolDetails details;

  instrument_gen_start = instrument_cur(output);

  if (gum_symbol_details_from_address(GSIZE_TO_POINTER(address), &details)) {

    instrument_debug("\n\n***\n\nCreating block for 0x%" G_GINT64_MODIFIER
                     "x (%s!%s):\n",
                     address, details.module_name, details.symbol_name);

  } else {

    instrument_debug(
        "\n\n***\n\nCreating block for 0x%" G_GINT64_MODIFIER "x:\n", address);

  }

}

void instrument_debug_instruction(uint64_t address, uint16_t size) {

  uint8_t *start = (uint8_t *)GSIZE_TO_POINTER(address);
  instrument_disasm(start, size);

}

void instrument_debug_end(GumStalkerOutput *output) {

  gpointer instrument_gen_end = instrument_cur(output);
  uint16_t size = GPOINTER_TO_SIZE(instrument_gen_end) -
                  GPOINTER_TO_SIZE(instrument_gen_start);

  instrument_debug("\nGenerated block %p\n", instrument_gen_start);
  instrument_disasm(instrument_gen_start, size);

}

#else
void instrument_debug_start(void *address) {

  UNUSED_PARAMETER(address);

}

void instrument_debug_instruction(uint64_t address, uint16_t size) {

  UNUSED_PARAMETER(address);
  UNUSED_PARAMETER(size);

}

void instrument_debug_end(GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);

}

#endif

