#ifndef __APPLE__
  #include <elf.h>
  #include <fcntl.h>
  #include <limits.h>
  #include <stdio.h>
  #include <sys/mman.h>
  #include <unistd.h>

  #include "frida-gumjs.h"

  #include "lib.h"
  #include "util.h"

  #if defined(__arm__) || defined(__i386__)
    #define ELFCLASS ELFCLASS32
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Addr Elf_Addr;
  #elif defined(__aarch64__) || defined(__x86_64__)
    #define ELFCLASS ELFCLASS64
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Addr Elf_Addr;
  #else
    #error "Unsupported platform"
  #endif

typedef struct {

  gchar      name[PATH_MAX + 1];
  gchar      path[PATH_MAX + 1];
  GumAddress base_address;
  gsize      size;

} lib_details_t;

static guint64 text_base = 0;
static guint64 text_limit = 0;

static void lib_validate_hdr(Elf_Ehdr *hdr) {

  if (hdr->e_ident[0] != ELFMAG0) FFATAL("Invalid e_ident[0]");
  if (hdr->e_ident[1] != ELFMAG1) FFATAL("Invalid e_ident[1]");
  if (hdr->e_ident[2] != ELFMAG2) FFATAL("Invalid e_ident[2]");
  if (hdr->e_ident[3] != ELFMAG3) FFATAL("Invalid e_ident[3]");
  if (hdr->e_ident[4] != ELFCLASS) FFATAL("Invalid class");

}

static void lib_read_text_section(lib_details_t *lib_details, Elf_Ehdr *hdr) {

  Elf_Phdr *phdr;
  gboolean  found_preferred_base = FALSE;
  Elf_Addr  preferred_base;
  Elf_Shdr *shdr;
  Elf_Shdr *shstrtab;
  char     *shstr;
  char     *section_name;
  Elf_Shdr *curr;
  char      text_name[] = ".text";

  phdr = (Elf_Phdr *)((char *)hdr + hdr->e_phoff);
  for (size_t i = 0; i < hdr->e_phnum; i++) {

    if (phdr[i].p_type == PT_LOAD) {

      preferred_base = phdr[i].p_vaddr;
      found_preferred_base = TRUE;
      break;

    }

  }

  if (!found_preferred_base) {

    FFATAL("Failed to find preferred load address");

  }

  FVERBOSE("\tpreferred load address: 0x%016" G_GSIZE_MODIFIER "x",
           preferred_base);

  shdr = (Elf_Shdr *)((char *)hdr + hdr->e_shoff);
  shstrtab = &shdr[hdr->e_shstrndx];
  shstr = (char *)hdr + shstrtab->sh_offset;

  FVERBOSE("\tshdr:                   %p", shdr);
  FVERBOSE("\tshstrtab:               %p", shstrtab);
  FVERBOSE("\tshstr:                  %p", shstr);

  FVERBOSE("Sections:");
  for (size_t i = 0; i < hdr->e_shnum; i++) {

    curr = &shdr[i];

    if (curr->sh_name == 0) continue;

    section_name = &shstr[curr->sh_name];
    FVERBOSE("\t%2" G_GSIZE_MODIFIER "u - base: 0x%016" G_GSIZE_MODIFIER
             "X size: 0x%016" G_GSIZE_MODIFIER "X %s",
             i, curr->sh_addr, curr->sh_size, section_name);
    if (memcmp(section_name, text_name, sizeof(text_name)) == 0 &&
        text_base == 0) {

      text_base = lib_details->base_address + curr->sh_addr - preferred_base;
      text_limit = text_base + curr->sh_size;

    }

  }

  FVERBOSE(".text\n");
  FVERBOSE("\taddr: 0x%016" G_GINT64_MODIFIER "X", text_base);
  FVERBOSE("\tlimit: 0x%016" G_GINT64_MODIFIER "X", text_limit);

}

static void lib_get_text_section(lib_details_t *details) {

  int       fd = -1;
  off_t     len;
  Elf_Ehdr *hdr;

  fd = open(details->path, O_RDONLY);
  if (fd < 0) { FFATAL("Failed to open %s", details->path); }

  len = lseek(fd, 0, SEEK_END);

  if (len == (off_t)-1) { FFATAL("Failed to lseek %s", details->path); }

  FVERBOSE("\tlength:                 %ld", len);

  hdr = (Elf_Ehdr *)mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (hdr == MAP_FAILED) { FFATAL("Failed to map %s", details->path); }

  lib_validate_hdr(hdr);
  lib_read_text_section(details, hdr);

  munmap(hdr, len);
  close(fd);

}

void lib_config(void) {

}

void lib_init(void) {

  /*
   * gum_process_enumerate_modules() does not guarantee that the main
   * executable is the first module reported (and under FRIDA 17.x it isn't —
   * the injected afl-frida-trace.so wins). Ask for the main module
   * explicitly, otherwise we end up using the .text range of the FRIDA
   * library and the target's basic blocks get excluded from instrumentation
   * (no coverage map updates).
   */
  GumModule *main_module = gum_process_get_main_module();
  if (main_module == NULL) FFATAL("Failed to resolve main module");

  const gchar          *name = gum_module_get_name(main_module);
  const gchar          *path = gum_module_get_path(main_module);
  const GumMemoryRange *range = gum_module_get_range(main_module);

  lib_details_t lib_details;
  strncpy(lib_details.name, name, PATH_MAX);
  strncpy(lib_details.path, path, PATH_MAX);
  lib_details.name[PATH_MAX] = '\0';
  lib_details.path[PATH_MAX] = '\0';
  lib_details.base_address = range->base_address;
  lib_details.size = range->size;

  FVERBOSE("Image");
  FVERBOSE("\tbase:                   0x%016" G_GINT64_MODIFIER "x",
           lib_details.base_address);
  FVERBOSE("\tpath:                   %s", lib_details.path);
  lib_get_text_section(&lib_details);

}

guint64 lib_get_text_base(void) {

  if (text_base == 0) FFATAL("Lib not initialized");
  return text_base;

}

guint64 lib_get_text_limit(void) {

  if (text_limit == 0) FFATAL("Lib not initialized");
  return text_limit;

}

#endif

