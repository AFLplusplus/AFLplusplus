#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "frida-gum.h"

#include "debug.h"

#include "util.h"

static int      debugging_fd = -1;
static gpointer instrument_gen_start = NULL;

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

void instrument_debug_init(void) {

  char *filename = getenv("AFL_FRIDA_INST_DEBUG_FILE");
  OKF("Instrumentation debugging - enabled [%c]", filename == NULL ? ' ' : 'X');

  if (filename == NULL) { return; }

  OKF("Instrumentation debugging - file [%s]", filename);

  if (filename == NULL) { return; }

  char *path = g_canonicalize_filename(filename, g_get_current_dir());

  OKF("Instrumentation debugging - path [%s]", path);

  debugging_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (debugging_fd < 0) { FATAL("Failed to open stats file '%s'", path); }

  g_free(path);

}

void instrument_debug_start(uint64_t address, GumStalkerOutput *output) {

  if (likely(debugging_fd < 0)) { return; }

  instrument_gen_start = instrument_cur(output);

  instrument_debug("\n\n***\n\nCreating block for 0x%" G_GINT64_MODIFIER "x:\n",
                   address);

}

void instrument_debug_instruction(uint64_t address, uint16_t size) {

  if (likely(debugging_fd < 0)) { return; }
  uint8_t *start = (uint8_t *)GSIZE_TO_POINTER(address);
  instrument_disasm(start, size);

}

void instrument_debug_end(GumStalkerOutput *output) {

  if (likely(debugging_fd < 0)) { return; }
  gpointer instrument_gen_end = instrument_cur(output);
  uint16_t size = GPOINTER_TO_SIZE(instrument_gen_end) -
                  GPOINTER_TO_SIZE(instrument_gen_start);

  instrument_debug("\nGenerated block %p\n", instrument_gen_start);
  instrument_disasm(instrument_gen_start, size);

}

