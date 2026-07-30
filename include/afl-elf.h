/*
   american fuzzy lop++ - vendored ELF format definitions
   -----------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

   Just enough of the ELF format to walk the section and program headers of a
   32- or 64-bit, little- or big-endian object. Deliberately self-contained:
   AFL++ must not gain a dependency on the system <elf.h>, which does not
   exist on every platform we build on.

 */

#ifndef _HAVE_AFL_ELF_H
#define _HAVE_AFL_ELF_H

#include "types.h"

#define AFL_EI_NIDENT 16

#define AFL_EI_MAG0 0
#define AFL_EI_MAG1 1
#define AFL_EI_MAG2 2
#define AFL_EI_MAG3 3
#define AFL_EI_CLASS 4
#define AFL_EI_DATA 5

#define AFL_ELFCLASS32 1
#define AFL_ELFCLASS64 2

#define AFL_ELFDATA2LSB 1
#define AFL_ELFDATA2MSB 2

#define AFL_ET_EXEC 2
#define AFL_ET_DYN 3

/* e_machine, only those we need to tell apart. On a CISC target a wide
   immediate is one contiguous field in the instruction stream; on a RISC target
   it is assembled from pieces and never appears as a whole. */

#define AFL_EM_386 3
#define AFL_EM_MIPS 8
#define AFL_EM_PPC64 21
#define AFL_EM_ARM 40
#define AFL_EM_X86_64 62
#define AFL_EM_AARCH64 183
#define AFL_EM_RISCV 243

#define AFL_SHT_NULL 0
#define AFL_SHT_PROGBITS 1
#define AFL_SHT_STRTAB 3
#define AFL_SHT_NOBITS 8

#define AFL_SHF_ALLOC 0x2
#define AFL_SHF_EXECINSTR 0x4

#define AFL_PT_LOAD 1

#define AFL_PF_X 0x1
#define AFL_PF_W 0x2
#define AFL_PF_R 0x4

#define AFL_SHN_UNDEF 0

typedef struct {

  u8  e_ident[AFL_EI_NIDENT];
  u16 e_type;
  u16 e_machine;
  u32 e_version;
  u32 e_entry;
  u32 e_phoff;
  u32 e_shoff;
  u32 e_flags;
  u16 e_ehsize;
  u16 e_phentsize;
  u16 e_phnum;
  u16 e_shentsize;
  u16 e_shnum;
  u16 e_shstrndx;

} afl_elf32_ehdr;

typedef struct {

  u8  e_ident[AFL_EI_NIDENT];
  u16 e_type;
  u16 e_machine;
  u32 e_version;
  u64 e_entry;
  u64 e_phoff;
  u64 e_shoff;
  u32 e_flags;
  u16 e_ehsize;
  u16 e_phentsize;
  u16 e_phnum;
  u16 e_shentsize;
  u16 e_shnum;
  u16 e_shstrndx;

} afl_elf64_ehdr;

typedef struct {

  u32 sh_name;
  u32 sh_type;
  u32 sh_flags;
  u32 sh_addr;
  u32 sh_offset;
  u32 sh_size;
  u32 sh_link;
  u32 sh_info;
  u32 sh_addralign;
  u32 sh_entsize;

} afl_elf32_shdr;

typedef struct {

  u32 sh_name;
  u32 sh_type;
  u64 sh_flags;
  u64 sh_addr;
  u64 sh_offset;
  u64 sh_size;
  u32 sh_link;
  u32 sh_info;
  u64 sh_addralign;
  u64 sh_entsize;

} afl_elf64_shdr;

typedef struct {

  u32 p_type;
  u32 p_offset;
  u32 p_vaddr;
  u32 p_paddr;
  u32 p_filesz;
  u32 p_memsz;
  u32 p_flags;
  u32 p_align;

} afl_elf32_phdr;

typedef struct {

  u32 p_type;
  u32 p_flags;
  u64 p_offset;
  u64 p_vaddr;
  u64 p_paddr;
  u64 p_filesz;
  u64 p_memsz;
  u64 p_align;

} afl_elf64_phdr;

/* The layouts above are naturally packed on every ABI we support, so a plain
   memcpy() from the mapped file into one of these is a faithful read. Pin that
   assumption down rather than trusting it. */

_Static_assert(sizeof(afl_elf32_ehdr) == 52, "afl_elf32_ehdr layout");
_Static_assert(sizeof(afl_elf64_ehdr) == 64, "afl_elf64_ehdr layout");
_Static_assert(sizeof(afl_elf32_shdr) == 40, "afl_elf32_shdr layout");
_Static_assert(sizeof(afl_elf64_shdr) == 64, "afl_elf64_shdr layout");
_Static_assert(sizeof(afl_elf32_phdr) == 32, "afl_elf32_phdr layout");
_Static_assert(sizeof(afl_elf64_phdr) == 56, "afl_elf64_phdr layout");

#endif                                                   /* _HAVE_AFL_ELF_H */

