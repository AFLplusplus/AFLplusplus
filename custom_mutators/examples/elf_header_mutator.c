/*
   AFL++ Custom Mutator for ELF Headers
   Written by @echel0n <melih.sahin@protonmail.com>
   based on libgolf.h by @xcellerator
   $ gcc -O3 -fPIC -shared -o elf_mutator.so -I ~/AFLplusplus/include/
 */
#include "afl-fuzz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <linux/elf.h>

/* EI_ABIVERSION isn't used anymore and elf.h defines EI_PAD to be 0x09 */
#define EI_ABIVERSION 0x08
#define EI_PAD 0x09
/* Define the Architecture and ISA constants to match those in <linux/elf.h> */
#define X86_64 EM_X86_64
#define ARM32 EM_ARM
#define AARCH64 EM_AARCH64
#define uchar unsigned char
#define DATA_SIZE 0x100

/*
 * The ELF and Program headers are different sizes depending on 32- and 64-bit
 * architectures
 * taken from libgolf.h
 */
#define EHDR_T(x) Elf##x##_Ehdr
#define PHDR_T(x) Elf##x##_Phdr
#define EHDR(x) ehdr##x
#define PHDR(x) phdr##x
#define GET_EHDR(x) (&(elf_ptr->EHDR(x)));
#define GET_PHDR(x) (&(elf_ptr->PHDR(x)));
#define REF_EHDR(b, x) ((Elf##b##_Ehdr *)ehdr)->x
#define REF_PHDR(b, x) ((Elf##b##_Phdr *)phdr)->x
int ehdr_size;
int phdr_size;
/*
 * This struct holds the bytes that will be executed, and the size.
 */
typedef struct text_segment {

  size_t         text_size;
  unsigned char *text_segment;

} TextSegment;

// example shellcode that exits
// taken from libgolf.h
unsigned char buf[] = {0xb0, 0x3c, 0x31, 0xff, 0x0f, 0x05};

/*
 * This is the raw ELF file
 * - EHDR(xx) is the ELF header
 * - PHDR(xx) is the program header
 * - text is the text segment
 * - filename is the name of the golf'd binary
 * - isa is the target architecture (X86_64, ARM32, AARCH64)
 * taken from libgolf.h
 */
typedef struct rawbinary_t {

  EHDR_T(32) EHDR(32);
  PHDR_T(32) PHDR(32);
  EHDR_T(64) EHDR(64);
  PHDR_T(64) PHDR(64);
  TextSegment text;
  char       *filename;
  int         isa;

} RawBinary;

/*
 * Copy an E_IDENT array into the corresponding fields in the ELF header
 * Called by populate_ehdr()
 * taken from libgolf.h
 */
int populate_e_ident(RawBinary *elf_ptr, unsigned char e_ident[]) {

  int i;
  /* Depending on whether the target ISA is 32- or 64-bit, set e_ident */
  switch (elf_ptr->isa) {

    case X86_64:
    case AARCH64:
      for (i = 0; i < EI_NIDENT; i++)
        elf_ptr->EHDR(64).e_ident[i] = e_ident[i];
      break;
    case ARM32:
      for (i = 0; i < EI_NIDENT; i++)
        elf_ptr->EHDR(32).e_ident[i] = e_ident[i];
      break;
    default:
      exit(1);

  }

  return 0;

}

/*
 * Copy bytes from buf[] array into text_segment in ELF struct
 * taken from libgolf.h
 */
int copy_text_segment(RawBinary *elf_ptr, unsigned char buf[], int text_size) {

  int i;

  /* Set size of text segment and allocate the buffer */
  elf_ptr->text.text_size = text_size;
  elf_ptr->text.text_segment =
      malloc(elf_ptr->text.text_size * sizeof(unsigned char));

  /* Copy the bytes into the text segment buffer */
  for (i = 0; i < elf_ptr->text.text_size; i++) {

    elf_ptr->text.text_segment[i] = buf[i];

  }

}

/*
 * Populate the ELF Header with sane values
 * Returns a pointer to an EHDR struct
 * taken from libgolf.h
 */
void *populate_ehdr(RawBinary *elf_ptr) {

  /*
   * Set ehdr_size and phdr_size. Determined by whether target ISA is 32- or
   * 64-bit.
   */
  switch (elf_ptr->isa) {

    case X86_64:
    case AARCH64:
      ehdr_size = sizeof(EHDR_T(64));
      phdr_size = sizeof(PHDR_T(64));
      break;
    case ARM32:
      ehdr_size = sizeof(EHDR_T(32));
      phdr_size = sizeof(PHDR_T(32));
      break;
    default:
      exit(1);

  };

  /* Start with the E_IDENT area at the top of the file */
  unsigned char e_ident[EI_NIDENT] = {0};

  /* Magic Bytes */
  e_ident[EI_MAG0] = 0x7F;
  e_ident[EI_MAG1] = 0x45;  // E
  e_ident[EI_MAG2] = 0x4C;  // L
  e_ident[EI_MAG3] = 0x46;  // F

  /*
   * EI_CLASS denotes the architecture:
   * ELFCLASS32: 0x01
   * ELFCLASS64: 0x02
   */
  switch (elf_ptr->isa) {

    case X86_64:
    case AARCH64:
      e_ident[EI_CLASS] = ELFCLASS64;
      break;
    case ARM32:
      e_ident[EI_CLASS] = ELFCLASS32;
      break;
    default:
      exit(1);

  }

  /*
   * EI_DATA denotes the endianness:
   * ELFDATA2LSB:   0x01
   * ELFDATA2MSB:   0x02
   */
  e_ident[EI_DATA] = ELFDATA2LSB;

  /* EI_VERSION is always 0x01 */
  e_ident[EI_VERSION] = EV_CURRENT;

  /*
   * EI_OSABI defines the target OS. Ignored by most modern ELF parsers.
   */
  e_ident[EI_OSABI] = ELFOSABI_NONE;

  /* EI_ABIVERSION was for sub-classification. Un-defined since Linux 2.6 */
  e_ident[EI_ABIVERSION] = 0x00;

  /* EI_PAD is currently unused */
  e_ident[EI_PAD] = 0x00;

  /* Copy the E_IDENT section to the ELF struct */
  populate_e_ident(elf_ptr, e_ident);

  /*
   * The remainder of the ELF header following E_IDENT follows.
   *
   * ehdr is a pointer to either an Elf32_Edhr, or Elf64_Ehdr struct.
   */
  void *ehdr = NULL;
  switch (elf_ptr->isa) {

    case X86_64:
    case AARCH64:
      ehdr = (&(elf_ptr->EHDR(64)));
      break;
    case ARM32:
      ehdr = (&(elf_ptr->EHDR(32)));
      break;
    default:
      exit(1);

  }

  /*
   * Depending on whether the ISA is 32- or 64-bit determines the size of
   * many of the fields in the ELF Header. This switch case deals with it.
   */
  switch (elf_ptr->isa) {

    // 64-Bit ISAs
    case X86_64:
    case AARCH64:
      /*
       * e_type specifies what kind of ELF file this is:
       * ET_NONE:         0x00    // Unknown Type
       * ET_REL:          0x01    // Relocatable
       * ET_EXEC:         0x02    // Executable File
       * ET_DYN:          0x03    // Shared Object
       * ET_CORE:         0x04    // Core Dump
       */
      REF_EHDR(64, e_type) = ET_EXEC;  // 0x0002

      /* e_machine specifies the target ISA */
      REF_EHDR(64, e_machine) = elf_ptr->isa;

      /* e_version is always set of 0x01 for the original ELF spec */
      REF_EHDR(64, e_version) = EV_CURRENT;  // 0x00000001

      /*
       * e_entry is the memory address of the entry point
       * Set by set_entry_point() after p_vaddr is set in the phdr
       */
      REF_EHDR(64, e_entry) = 0x0;

      /*
       * e_phoff points to the start of the program header, which
       * immediately follows the ELF header
       */
      REF_EHDR(64, e_phoff) = ehdr_size;

      /* e_shoff points to the start of the section header table */
      REF_EHDR(64, e_shoff) = 0x00;

      /* e_flags is architecture dependent */
      REF_EHDR(64, e_flags) = 0x0;

      /* e_ehsize contains the size of the ELF header */
      REF_EHDR(64, e_ehsize) = ehdr_size;

      /* e_phentsize is the size of the program header */
      REF_EHDR(64, e_phentsize) = phdr_size;

      /*
       * e_phnum contains the number of entries in the program header
       * e_phnum * e_phentsize = size of program header table
       */
      REF_EHDR(64, e_phnum) = 0x1;

      /* e_shentsize contains the size of a section header entry */
      REF_EHDR(64, e_shentsize) = 0x0;

      /*
       * e_shnum contains the number of entries in the section header
       * e_shnum * e_shentsize = size of section header table
       */
      REF_EHDR(64, e_shnum) = 0x0;

      /*
       * e_shstrndx contains the index of the section header table that
       * contains the section names
       */
      REF_EHDR(64, e_shstrndx) = 0x0;

      break;
    // 32-Bit ISAs
    case ARM32:
      /*
       * e_type specifies what kind of ELF file this is:
       * ET_NONE:         0x00    // Unknown Type
       * ET_REL:          0x01    // Relocatable
       * ET_EXEC:         0x02    // Executable File
       * ET_DYN:          0x03    // Shared Object
       * ET_CORE:         0x04    // Core Dump
       */
      REF_EHDR(32, e_type) = ET_EXEC;  // 0x0002

      /* e_machine specifies the target ISA */
      REF_EHDR(32, e_machine) = elf_ptr->isa;

      /* e_version is always set of 0x01 for the original ELF spec */
      REF_EHDR(32, e_version) = EV_CURRENT;  // 0x00000001

      /*
       * e_entry is the memory address of the entry point
       * Set by set_entry_point() after p_vaddr is set in the phdr
       */
      REF_EHDR(32, e_entry) = 0x0;

      /*
       * e_phoff points to the start of the program header, which
       * immediately follows the ELF header
       */
      REF_EHDR(32, e_phoff) = ehdr_size;

      /* e_shoff points to the start of the section header table */
      REF_EHDR(32, e_shoff) = 0x0i;

      /* e_flags is architecture dependent */
      REF_EHDR(32, e_flags) = 0x0;

      /* e_ehsize contains the size of the ELF header */
      REF_EHDR(32, e_ehsize) = ehdr_size;

      /* e_phentsize is the size of the program header */
      REF_EHDR(32, e_phentsize) = phdr_size;

      /*
       * e_phnum contains the number of entries in the program header
       * e_phnum * e_phentsize = size of program header table
       */
      REF_EHDR(32, e_phnum) = 0x1;

      /* e_shentsize contains the size of a section header entry */
      REF_EHDR(32, e_shentsize) = 0x0;

      /*
       * e_shnum contains the number of entries in the section header
       * e_shnum * e_shentsize = size of section header table
       */
      REF_EHDR(32, e_shnum) = 0x0;

      /*
       * e_shstrndx contains the index of the section header table that
       * contains the section names
       */
      REF_EHDR(32, e_shnum) = 0x0;

      break;

  }

  return ehdr;

}

/*
 * Populate the program headers with sane values
 * Returns a pointer to a PHDR struct
 * taken from libgolf.h
 */
void *populate_phdr(RawBinary *elf_ptr) {

  /*
   * All offsets are relative to the start of the program header (0x40)
   *
   * phdr is a pointer to either an Elf32_Phdr, or Elf64_Phdr struct.
   */
  void *phdr = NULL;
  switch (elf_ptr->isa) {

    case X86_64:
    case AARCH64:
      phdr = (&(elf_ptr->PHDR(64)));
      break;
    case ARM32:
      phdr = (&(elf_ptr->PHDR(32)));
      break;
    default:
      exit(1);

  }

  /*
   * Depending on whether the ISA is 32- or 64-bit determines the size of
   * many of the fields in the Progra Header. This switch case deals with it.
   */
  switch (elf_ptr->isa) {

    // 64-Bit ISAs
    case X86_64:
    case AARCH64:
      /*
       * p_type identifies what type of segment this is
       * PT_NULL:         0x0     // Unused
       * PT_LOAD:         0x1     // Loadable Segment
       * PT_DYNAMIC:      0x2     // Dynamic Linker Information
       * PT_INTERP:       0x3     // Interpreter Information
       * PT_NOTE:         0x4     // Auxiliary Information
       * PT_SHLIB:        0x5     // Reserved
       * PT_PHDR:         0x6     // Segment with Program Header
       * PT_TLS:          0x7     // Thread Local Storage
       */
      REF_PHDR(64, p_type) = PT_LOAD;  // 0x1

      /*
       * p_flags defines permissions for this section
       * PF_R:    0x4     // Read
       * PF_W:    0x2     // Write
       * PF_X:    0x1     // Execute
       */
      REF_PHDR(64, p_flags) = PF_R | PF_X;  // 0x5

      /*
       * p_offset is the offset in the file image (relative to the start
       * of the program header) for this segment.
       */
      REF_PHDR(64, p_offset) = 0x0;

      /*
       * p_vaddr is the virtual address where this segment should be loaded
       * p_paddr is for the physical address (unused by System V)
       */
      REF_PHDR(64, p_vaddr) = 0x400000;
      REF_PHDR(64, p_paddr) = 0x400000;

      /*
       * p_filesz is the size of the segment in the file image
       * p_memsz is the size of the segment in memory
       *
       * Note: p_filesz doesn't have to equal p_memsz
       */
      REF_PHDR(64, p_filesz) = elf_ptr->text.text_size;
      REF_PHDR(64, p_memsz) = elf_ptr->text.text_size;

      break;
    // 32-Bit ISAs
    case ARM32:
      /*
       * p_type identifies what type of segment this is
       * PT_NULL:         0x0     // Unused
       * PT_LOAD:         0x1     // Loadable Segment
       * PT_DYNAMIC:      0x2     // Dynamic Linker Information
       * PT_INTERP:       0x3     // Interpreter Information
       * PT_NOTE:         0x4     // Auxiliary Information
       * PT_SHLIB:        0x5     // Reserved
       * PT_PHDR:         0x6     // Segment with Program Header
       * PT_TLS:          0x7     // Thread Local Storage
       */
      REF_PHDR(32, p_type) = PT_LOAD;  // 0x1

      /*
       * p_flags defines permissions for this section
       * PF_R:    0x4     // Read
       * PF_W:    0x2     // Write
       * PF_X:    0x1     // Execute
       */
      REF_PHDR(32, p_flags) = PF_R | PF_X;  // 0x5

      /*
       * p_offset is the offset in the file image (relative to the start
       * of the program header) for this segment.
       */
      REF_PHDR(32, p_offset) = 0x0;

      /*
       * p_vaddr is the virtual address where this segment should be loaded
       * p_paddr is for the physical address (unused by System V)
       */
      REF_PHDR(32, p_vaddr) = 0x10000;
      REF_PHDR(32, p_paddr) = 0x10000;

      /*
       * p_filesz is the size of the segment in the file image
       * p_memsz is the size of the segment in memory
       *
       * Note: p_filesz doesn't have to equal p_memsz
       */
      REF_PHDR(32, p_filesz) = elf_ptr->text.text_size;
      REF_PHDR(32, p_memsz) = elf_ptr->text.text_size;

      break;
    default:
      exit(1);

  }

  /*
   * p_align is the memory alignment
   *
   * Note: p_vaddr = p_offset % p_align
   */
  switch (elf_ptr->isa) {

    case X86_64:
      REF_PHDR(64, p_align) = 0x400000;
      break;
    case ARM32:
      REF_PHDR(32, p_align) = 0x10000;
      break;
    case AARCH64:
      REF_PHDR(64, p_align) = 0x400000;
      break;

  }

  return phdr;

}

/*
 * e_entry depends on p_vaddr, so has to be set after populate_ehdr()
 * and populate_phdr() have been called.
 * taken from libgolf.h
 */
int set_entry_point(RawBinary *elf_ptr) {

  /*
   * Once the whole ELF file is copied into memory, control is handed to
   * e_entry. Relative to the process's virtual memory address, the .text
   * segment will be located immediately after the ELF and program header.
   *
   * ehdr and phdr are pointers to the ELF and Program headers respectively.
   * The switch case casts and assigns them to the correct fields of the ELF
   * struct, then sets ehdr->e_entry.
   */
  void *ehdr, *phdr;

  switch (elf_ptr->isa) {

    case X86_64:
    case AARCH64:
      ehdr = GET_EHDR(64);
      phdr = GET_PHDR(64);
      REF_EHDR(64, e_entry) = REF_PHDR(64, p_vaddr) + ehdr_size + phdr_size;
      break;
    case ARM32:
      ehdr = GET_EHDR(32);
      phdr = GET_PHDR(32);
      REF_EHDR(32, e_entry) = REF_PHDR(32, p_vaddr) + ehdr_size + phdr_size;
      break;
    default:
      exit(1);

  }

  return 0;

}

typedef struct my_mutator {

  afl_state_t *afl;
  size_t       trim_size_current;
  int          trimmming_steps;
  int          cur_step;
  u8          *mutated_out, *post_process_buf, *trim_buf;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);  // needed also by surgical_havoc_mutate()
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutated_out = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  if ((data->post_process_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  if ((data->trim_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  data->afl = afl;
  return data;

}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *in_buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {

  RawBinary  elf_obj;
  RawBinary *elf = &elf_obj;
  elf->isa = 62;
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  copy_text_segment(elf, buf, sizeof(buf));
  ehdr = populate_ehdr(elf);
  phdr = populate_phdr(elf);
  set_entry_point(elf);

  size_t mutated_size = ehdr_size + phdr_size + elf->text.text_size;
  int    pos = 0;
  // example fields
  ehdr->e_ident[EI_CLASS] = (uint8_t *)(in_buf + pos++);
  ehdr->e_ident[EI_DATA] = (uint8_t *)(in_buf + pos++);
  ehdr->e_ident[EI_VERSION] = (uint8_t *)(in_buf + pos++);
  ehdr->e_ident[EI_OSABI] = (uint8_t *)(in_buf + pos++);
  for (int i = 0x8; i < 0x10; ++i) {

    (ehdr->e_ident)[i] = (uint8_t *)(in_buf + pos++);

  }

  ehdr->e_version = (uint32_t *)(in_buf + pos);
  pos += 4;
  // sections headers
  ehdr->e_shoff = (uint64_t *)(in_buf + pos);
  pos += 8;
  ehdr->e_shentsize = (uint16_t *)(in_buf + pos);
  pos += 2;
  ehdr->e_shnum = (uint16_t *)(in_buf + pos);
  pos += 2;
  ehdr->e_shstrndx = (uint16_t *)(in_buf + pos);
  pos += 2;
  ehdr->e_flags = (uint32_t *)(in_buf + pos);
  pos += 4;
  // physical addr
  phdr->p_paddr = (uint64_t *)(in_buf + pos);
  pos += 8;
  phdr->p_align = (uint64_t *)(in_buf + pos);
  pos += 8;

  /* mimic GEN_ELF()
   * Write:
   * - ELF Header
   * - Program Header
   * - Text Segment
   */
  memcpy(data->mutated_out, ehdr, ehdr_size);
  memcpy(data->mutated_out + ehdr_size, phdr, phdr_size);
  memcpy(data->mutated_out + ehdr_size + phdr_size, elf->text.text_segment,
         elf->text.text_size);

  *out_buf = data->mutated_out;
  return mutated_size;

}

void afl_custom_deinit(my_mutator_t *data) {

  free(data->post_process_buf);
  free(data->mutated_out);
  free(data->trim_buf);
  free(data);

}

