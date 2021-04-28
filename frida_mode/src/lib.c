#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "frida-gum.h"

#include "debug.h"

#include "lib.h"

#if defined(__arm__) || defined(__i386__)
  #define ELFCLASS ELFCLASS32
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
#elif defined(__aarch64__) || defined(__x86_64__)
  #define ELFCLASS ELFCLASS64
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
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

static gboolean lib_find_exe(const GumModuleDetails *details,
                             gpointer                user_data) {

  lib_details_t *lib_details = (lib_details_t *)user_data;

  memcpy(lib_details->name, details->name, PATH_MAX);
  memcpy(lib_details->path, details->path, PATH_MAX);
  lib_details->base_address = details->range->base_address;
  lib_details->size = details->range->size;
  return FALSE;

}

static gboolean lib_is_little_endian(void) {

  int probe = 1;
  return *(char *)&probe;

}

static void lib_validate_hdr(Elf_Ehdr *hdr) {

  if (hdr->e_ident[0] != ELFMAG0) FATAL("Invalid e_ident[0]");
  if (hdr->e_ident[1] != ELFMAG1) FATAL("Invalid e_ident[1]");
  if (hdr->e_ident[2] != ELFMAG2) FATAL("Invalid e_ident[2]");
  if (hdr->e_ident[3] != ELFMAG3) FATAL("Invalid e_ident[3]");
  if (hdr->e_ident[4] != ELFCLASS) FATAL("Invalid class");
/*
  if (hdr->e_ident[5] != (lib_is_little_endian() ? ELFDATA2LSB : ELFDATA2MSB))
    FATAL("Invalid endian");
  if (hdr->e_ident[6] != EV_CURRENT) FATAL("Invalid version");
  if (hdr->e_type != ET_DYN) FATAL("Invalid type");
  if (hdr->e_version != EV_CURRENT) FATAL("Invalid e_version");
  if (hdr->e_phoff != sizeof(Elf_Ehdr)) FATAL("Invalid e_phoff");
  if (hdr->e_ehsize != sizeof(Elf_Ehdr)) FATAL("Invalid e_ehsize");
  if (hdr->e_phentsize != sizeof(Elf_Phdr)) FATAL("Invalid e_phentsize");
  if (hdr->e_shentsize != sizeof(Elf_Shdr)) FATAL("Invalid e_shentsize");
*/

}

static void lib_read_text_section(lib_details_t *lib_details, Elf_Ehdr *hdr) {

  Elf_Shdr *shdr;
  Elf_Shdr *shstrtab;
  char *    shstr;
  char *    section_name;
  Elf_Shdr *curr;
  char      text_name[] = ".text";

  shdr = (Elf_Shdr *)((char *)hdr + hdr->e_shoff);
  shstrtab = &shdr[hdr->e_shstrndx];
  shstr = (char *)hdr + shstrtab->sh_offset;

  OKF("shdr: %p", shdr);
  OKF("shstrtab: %p", shstrtab);
  OKF("shstr: %p", shstr);

  for (size_t i = 0; i < hdr->e_shnum; i++) {

    curr = &shdr[i];

    if (curr->sh_name == 0) continue;

    section_name = &shstr[curr->sh_name];
    OKF("Section: %2lu - base: 0x%016lX size: 0x%016lX %s", i, curr->sh_addr,
        curr->sh_size, section_name);
    if (memcmp(section_name, text_name, sizeof(text_name)) == 0 &&
        text_base == 0) {

      text_base = lib_details->base_address + curr->sh_addr;
      text_limit = lib_details->base_address + curr->sh_addr + curr->sh_size;
      OKF("> text_addr: 0x%016lX", text_base);
      OKF("> text_limit: 0x%016lX", text_limit);

    }

  }

}

static void lib_get_text_section(lib_details_t *details) {

  int       fd = -1;
  off_t     len;
  Elf_Ehdr *hdr;

  fd = open(details->path, O_RDONLY);
  if (fd < 0) { FATAL("Failed to open %s", details->path); }

  len = lseek(fd, 0, SEEK_END);

  if (len == (off_t)-1) { FATAL("Failed to lseek %s", details->path); }

  OKF("len: %ld", len);

  hdr = (Elf_Ehdr *)mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (hdr == MAP_FAILED) { FATAL("Failed to map %s", details->path); }

  lib_validate_hdr(hdr);
  lib_read_text_section(details, hdr);

  munmap(hdr, len);
  close(fd);

}

void lib_init(void) {

  lib_details_t lib_details;
  gum_process_enumerate_modules(lib_find_exe, &lib_details);
  OKF("Executable: 0x%016lx - %s", lib_details.base_address, lib_details.path);
  lib_get_text_section(&lib_details);

}

guint64 lib_get_text_base(void) {

  if (text_base == 0) FATAL("Lib not initialized");
  return text_base;

}

guint64 lib_get_text_limit(void) {

  if (text_limit == 0) FATAL("Lib not initialized");
  return text_limit;

}

