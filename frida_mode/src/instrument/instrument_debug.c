#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "instrument.h"
#include "util.h"

static int      debugging_fd = -1;
static gpointer instrument_gen_start = NULL;

char *instrument_debug_filename = NULL;

static void instrument_debug(char *format, ...) {

  va_list ap;
  char    buffer[4096] = {0};
  int     ret;
  int     len;

  va_start(ap, format);
  ret = vsnprintf(buffer, sizeof(buffer) - 1, format, ap);
  va_end(ap);

  if (ret < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));

  IGNORED_RETURN(write(debugging_fd, buffer, len));

}

static void instrument_disasm(guint8 *start, guint8 *end,
                              GumStalkerOutput *output) {

#if !defined(__arm__)
  UNUSED_PARAMETER(output);
#endif

  csh      capstone;
  cs_err   err;
  cs_mode  mode;
  uint16_t size;
  cs_insn *insn;
  size_t   count = 0;
  size_t   i;
  uint16_t len;

  mode = GUM_DEFAULT_CS_MODE | GUM_DEFAULT_CS_ENDIAN;

#if defined(__arm__)
  if (output->encoding == GUM_INSTRUCTION_SPECIAL) { mode |= CS_MODE_THUMB; }
#endif

  err = cs_open(GUM_DEFAULT_CS_ARCH, mode, &capstone);
  g_assert(err == CS_ERR_OK);

  size = GPOINTER_TO_SIZE(end) - GPOINTER_TO_SIZE(start);

  for (guint8 *curr = start; curr < end; curr += len, size -= len, len = 0) {

    count = cs_disasm(capstone, curr, size, GPOINTER_TO_SIZE(curr), 0, &insn);
    if (insn == NULL) {

      instrument_debug("\t0x%" G_GINT64_MODIFIER "x\t* 0x%016" G_GSIZE_MODIFIER
                       "x\n",
                       curr, *(size_t *)curr);

      len += sizeof(size_t);
      continue;

    }

    for (i = 0; i != count; i++) {

      instrument_debug("\t0x%" G_GINT64_MODIFIER "x\t%s %s\n", insn[i].address,
                       insn[i].mnemonic, insn[i].op_str);

      len += insn[i].size;

    }

  }

  cs_free(insn, count);

  cs_close(&capstone);

}

void instrument_debug_config(void) {

  instrument_debug_filename = getenv("AFL_FRIDA_INST_DEBUG_FILE");

}

void instrument_debug_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "debugging:" cYEL " [%s]",
       instrument_debug_filename == NULL ? " " : instrument_debug_filename);

  if (instrument_debug_filename == NULL) { return; }

  char *path =
      g_canonicalize_filename(instrument_debug_filename, g_get_current_dir());

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "path:" cYEL " [%s]", path);

  debugging_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (debugging_fd < 0) { FFATAL("Failed to open stats file '%s'", path); }

  g_free(path);

}

void instrument_debug_start(uint64_t address, GumStalkerOutput *output) {

  if (likely(debugging_fd < 0)) { return; }

  instrument_gen_start = instrument_cur(output);

  instrument_debug("\n\n***\n\nCreating block for 0x%" G_GINT64_MODIFIER "x:\n",
                   address);

}

void instrument_debug_instruction(uint64_t address, uint16_t size,
                                  GumStalkerOutput *output) {

  if (likely(debugging_fd < 0)) { return; }
  uint8_t *start = (uint8_t *)GSIZE_TO_POINTER(address);
  instrument_disasm(start, start + size, output);

}

void instrument_debug_end(GumStalkerOutput *output) {

  if (likely(debugging_fd < 0)) { return; }
  gpointer instrument_gen_end = instrument_cur(output);

  instrument_debug("\nGenerated block %p-%p\n", instrument_gen_start,
                   instrument_gen_end);
  instrument_disasm(instrument_gen_start, instrument_gen_end, output);

}

