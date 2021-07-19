"""
    unicorn_loader.py

    Loads a process context dumped created using a
    Unicorn Context Dumper script into a Unicorn Engine
    instance. Once this is performed emulation can be
    started.
"""

import argparse
import binascii
from collections import namedtuple
import datetime
import hashlib
import json
import os
import signal
import struct
import time
import zlib

# Unicorn imports
from unicornafl import *
from unicornafl.arm_const import *
from unicornafl.arm64_const import *
from unicornafl.x86_const import *
from unicornafl.mips_const import *

# If Capstone libraries are availible (only check once)
try:
    from capstone import *

    CAPSTONE_EXISTS = 1
except:
    CAPSTONE_EXISTS = 0

# Name of the index file
INDEX_FILE_NAME = "_index.json"

# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Max allowable segment size (1G)
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024

# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE - 1)

# ---------------------------------------
# ---- Unicorn-based heap implementation


class UnicornSimpleHeap(object):
    """Use this class to provide a simple heap implementation. This should
    be used if malloc/free calls break things during emulation. This heap also
    implements basic guard-page capabilities which enable immediate notice of
    heap overflow and underflows.
    """

    # Helper data-container used to track chunks
    class HeapChunk(object):
        def __init__(self, actual_addr, total_size, data_size):
            self.total_size = (
                total_size  # Total size of the chunk (including padding and guard page)
            )
            self.actual_addr = actual_addr  # Actual start address of the chunk
            self.data_size = (
                data_size  # Size requested by the caller of actual malloc call
            )
            self.data_addr = (
                actual_addr + UNICORN_PAGE_SIZE
            )  # Address where data actually starts

        # Returns true if the specified buffer is completely within the chunk, else false
        def is_buffer_in_chunk(self, addr, size):
            if addr >= self.data_addr and (
                (addr + size) <= (self.data_addr + self.data_size)
            ):
                return True
            else:
                return False

    # Skip the zero-page to avoid weird potential issues with segment registers
    HEAP_MIN_ADDR = 0x00002000
    HEAP_MAX_ADDR = 0xFFFFFFFF

    _uc = None  # Unicorn engine instance to interact with
    _chunks = []  # List of all known chunks
    _debug_print = False  # True to print debug information

    def __init__(self, uc, debug_print=False):
        self._uc = uc
        self._debug_print = debug_print

        # Add the watchpoint hook that will be used to implement psuedo-guard page support
        self._uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__check_mem_access)

    def malloc(self, size):
        # Figure out the overall size to be allocated/mapped
        #    - Allocate at least 1 4k page of memory to make Unicorn happy
        #    - Add guard pages at the start and end of the region
        total_chunk_size = UNICORN_PAGE_SIZE + ALIGN_PAGE_UP(size) + UNICORN_PAGE_SIZE
        # Gross but efficient way to find space for the chunk:
        chunk = None
        for addr in range(self.HEAP_MIN_ADDR, self.HEAP_MAX_ADDR, UNICORN_PAGE_SIZE):
            try:
                self._uc.mem_map(addr, total_chunk_size, UC_PROT_READ | UC_PROT_WRITE)
                chunk = self.HeapChunk(addr, total_chunk_size, size)
                if self._debug_print:
                    print(
                        "Allocating 0x{0:x}-byte chunk @ 0x{1:016x}".format(
                            chunk.data_size, chunk.data_addr
                        )
                    )
                break
            except UcError as e:
                continue
        # Something went very wrong
        if chunk == None:
            return 0
        self._chunks.append(chunk)
        return chunk.data_addr

    def calloc(self, size, count):
        # Simple wrapper around malloc with calloc() args
        return self.malloc(size * count)

    def realloc(self, ptr, new_size):
        # Wrapper around malloc(new_size) / memcpy(new, old, old_size) / free(old)
        if self._debug_print:
            print(
                "Reallocating chunk @ 0x{0:016x} to be 0x{1:x} bytes".format(
                    ptr, new_size
                )
            )
        old_chunk = None
        for chunk in self._chunks:
            if chunk.data_addr == ptr:
                old_chunk = chunk
        new_chunk_addr = self.malloc(new_size)
        if old_chunk != None:
            self._uc.mem_write(
                new_chunk_addr,
                str(self._uc.mem_read(old_chunk.data_addr, old_chunk.data_size)),
            )
            self.free(old_chunk.data_addr)
        return new_chunk_addr

    def free(self, addr):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, 1):
                if self._debug_print:
                    print(
                        "Freeing 0x{0:x}-byte chunk @ 0x{0:016x}".format(
                            chunk.req_size, chunk.data_addr
                        )
                    )
                self._uc.mem_unmap(chunk.actual_addr, chunk.total_size)
                self._chunks.remove(chunk)
                return True
        return False

    # Implements basic guard-page functionality
    def __check_mem_access(self, uc, access, address, size, value, user_data):
        for chunk in self._chunks:
            if address >= chunk.actual_addr and (
                (address + size) <= (chunk.actual_addr + chunk.total_size)
            ):
                if chunk.is_buffer_in_chunk(address, size) == False:
                    if self._debug_print:
                        print(
                            "Heap over/underflow attempting to {0} 0x{1:x} bytes @ {2:016x}".format(
                                "write" if access == UC_MEM_WRITE else "read",
                                size,
                                address,
                            )
                        )
                    # Force a memory-based crash
                    uc.force_crash(UcError(UC_ERR_READ_PROT))


# ---------------------------
# ---- Loading function


class AflUnicornEngine(Uc):
    def __init__(self, context_directory, enable_trace=False, debug_print=False):
        """
        Initializes an AflUnicornEngine instance, which extends standard the UnicornEngine
        with a bunch of helper routines that are useful for creating afl-unicorn test harnesses.

        Parameters:
          - context_directory: Path to the directory generated by one of the context dumper scripts
          - enable_trace: If True trace information will be printed to STDOUT
          - debug_print: If True debugging information will be printed while loading the context
        """

        # Make sure the index file exists and load it
        index_file_path = os.path.join(context_directory, INDEX_FILE_NAME)
        if not os.path.isfile(index_file_path):
            raise Exception(
                "Index file not found. Expected it to be at {}".format(index_file_path)
            )

        # Load the process context from the index file
        if debug_print:
            print("Loading process context index from {}".format(index_file_path))
        index_file = open(index_file_path, "r")
        context = json.load(index_file)
        index_file.close()

        # Check the context to make sure we have the basic essential components
        if "arch" not in context:
            raise Exception("Couldn't find architecture information in index file")
        if "regs" not in context:
            raise Exception("Couldn't find register information in index file")
        if "segments" not in context:
            raise Exception("Couldn't find segment/memory information in index file")

        # Set the UnicornEngine instance's architecture and mode
        self._arch_str = context["arch"]["arch"]
        arch, mode = self.__get_arch_and_mode(self._arch_str)
        Uc.__init__(self, arch, mode)

        # Load the registers
        regs = context["regs"]
        reg_map = self.__get_register_map(self._arch_str)
        self.__load_registers(regs, reg_map, debug_print)
        # If we have extra FLOATING POINT regs, load them in!
        if "regs_extended" in context:
            if context["regs_extended"]:
                regs_extended = context["regs_extended"]
                reg_map = self.__get_registers_extended(self._arch_str)
                self.__load_registers(regs_extended, reg_map, debug_print)

        # For ARM, sometimes the stack pointer is erased ??? (I think I fixed this (issue with ordering of dumper.py, I'll keep the write anyways)
        if self.__get_arch_and_mode(self.get_arch_str())[0] == UC_ARCH_ARM:
            self.reg_write(UC_ARM_REG_SP, regs["sp"])

        # Setup the memory map and load memory content
        self.__map_segments(context["segments"], context_directory, debug_print)

        if enable_trace:
            self.hook_add(UC_HOOK_BLOCK, self.__trace_block)
            self.hook_add(UC_HOOK_CODE, self.__trace_instruction)
            self.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__trace_mem_access)
            self.hook_add(
                UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID,
                self.__trace_mem_invalid_access,
            )

        if debug_print:
            print("Done loading context.")

    def get_arch(self):
        return self._arch

    def get_mode(self):
        return self._mode

    def get_arch_str(self):
        return self._arch_str

    def force_crash(self, uc_error):
        """This function should be called to indicate to AFL that a crash occurred during emulation.
        You can pass the exception received from Uc.emu_start
        """
        mem_errors = [
            UC_ERR_READ_UNMAPPED,
            UC_ERR_READ_PROT,
            UC_ERR_READ_UNALIGNED,
            UC_ERR_WRITE_UNMAPPED,
            UC_ERR_WRITE_PROT,
            UC_ERR_WRITE_UNALIGNED,
            UC_ERR_FETCH_UNMAPPED,
            UC_ERR_FETCH_PROT,
            UC_ERR_FETCH_UNALIGNED,
        ]
        if uc_error.errno in mem_errors:
            # Memory error - throw SIGSEGV
            os.kill(os.getpid(), signal.SIGSEGV)
        elif uc_error.errno == UC_ERR_INSN_INVALID:
            # Invalid instruction - throw SIGILL
            os.kill(os.getpid(), signal.SIGILL)
        else:
            # Not sure what happened - throw SIGABRT
            os.kill(os.getpid(), signal.SIGABRT)

    def dump_regs(self):
        """ Dumps the contents of all the registers to STDOUT """
        for reg in sorted(
            self.__get_register_map(self._arch_str).items(), key=lambda reg: reg[0]
        ):
            print(">>> {0:>4}: 0x{1:016x}".format(reg[0], self.reg_read(reg[1])))

    def dump_regs_extended(self):
        """ Dumps the contents of all the registers to STDOUT """
        try:
            for reg in sorted(
                self.__get_registers_extended(self._arch_str).items(),
                key=lambda reg: reg[0],
            ):
                print(">>> {0:>4}: 0x{1:016x}".format(reg[0], self.reg_read(reg[1])))
        except Exception as e:
            print("ERROR: Are extended registers loaded?")

    # TODO: Make this dynamically get the stack pointer register and pointer width for the current architecture
    """
    def dump_stack(self, window=10):
        arch = self.get_arch()
        mode = self.get_mode()
        # Get stack pointers and bit sizes for given architecture
        if arch == UC_ARCH_X86 and mode == UC_MODE_64:
            stack_ptr_addr = self.reg_read(UC_X86_REG_RSP)
            bit_size = 8
        elif arch == UC_ARCH_X86 and mode == UC_MODE_32:
            stack_ptr_addr = self.reg_read(UC_X86_REG_ESP)
            bit_size = 4
        elif arch == UC_ARCH_ARM64:
            stack_ptr_addr = self.reg_read(UC_ARM64_REG_SP)
            bit_size = 8
        elif arch == UC_ARCH_ARM:
            stack_ptr_addr = self.reg_read(UC_ARM_REG_SP)
            bit_size = 4
        elif arch == UC_ARCH_ARM and mode == UC_MODE_THUMB:
            stack_ptr_addr = self.reg_read(UC_ARM_REG_SP)
            bit_size = 4
        elif arch == UC_ARCH_MIPS:
            stack_ptr_addr = self.reg_read(UC_MIPS_REG_SP)
            bit_size = 4
        print("")
        print(">>> Stack:")
        stack_ptr_addr = self.reg_read(UC_X86_REG_RSP)
        for i in xrange(-window, window + 1):
            addr = stack_ptr_addr + (i*8)
            print("{0}0x{1:016x}: 0x{2:016x}".format( \
               'SP->' if i == 0 else '    ', addr, \
                struct.unpack('<Q', self.mem_read(addr, 8))[0]))
    """

    # -----------------------------
    # ---- Loader Helper Functions

    def __load_registers(self, regs, reg_map, debug_print):
        for register, value in regs.items():
            if debug_print:
                print("Reg {0} = {1}".format(register, value))
            if register.lower() not in reg_map:
                if debug_print:
                    print("Skipping Reg: {}".format(register))
            else:
                reg_write_retry = True
                try:
                    self.reg_write(reg_map[register.lower()], value)
                    reg_write_retry = False
                except Exception as e:
                    if debug_print:
                        print(
                            "ERROR writing register: {}, value: {} -- {}".format(
                                register, value, repr(e)
                            )
                        )

                if reg_write_retry:
                    if debug_print:
                        print("Trying to parse value ({}) as hex string".format(value))
                    try:
                        self.reg_write(reg_map[register.lower()], int(value, 16))
                    except Exception as e:
                        if debug_print:
                            print(
                                "ERROR writing hex string register: {}, value: {} -- {}".format(
                                    register, value, repr(e)
                                )
                            )

    def __map_segment(self, name, address, size, perms, debug_print=False):
        # - size is unsigned and must be != 0
        # - starting address must be aligned to 4KB
        # - map size must be multiple of the page size (4KB)
        mem_start = address
        mem_end = address + size
        mem_start_aligned = ALIGN_PAGE_DOWN(mem_start)
        mem_end_aligned = ALIGN_PAGE_UP(mem_end)
        if debug_print:
            if mem_start_aligned != mem_start or mem_end_aligned != mem_end:
                print("Aligning segment to page boundary:")
                print("  name:  {}".format(name))
                print(
                    "  start: {0:016x} -> {1:016x}".format(mem_start, mem_start_aligned)
                )
                print("  end:   {0:016x} -> {1:016x}".format(mem_end, mem_end_aligned))
            print(
                "Mapping segment from {0:016x} - {1:016x} with perm={2}: {3}".format(
                    mem_start_aligned, mem_end_aligned, perms, name
                )
            )
        if mem_start_aligned < mem_end_aligned:
            self.mem_map(mem_start_aligned, mem_end_aligned - mem_start_aligned, perms)

    def __map_segments(self, segment_list, context_directory, debug_print=False):
        for segment in segment_list:

            # Get the segment information from the index
            name = segment["name"]
            seg_start = segment["start"]
            seg_end = segment["end"]
            perms = (
                (UC_PROT_READ if segment["permissions"]["r"] == True else 0)
                | (UC_PROT_WRITE if segment["permissions"]["w"] == True else 0)
                | (UC_PROT_EXEC if segment["permissions"]["x"] == True else 0)
            )

            if debug_print:
                print("Handling segment {}".format(name))

            # Check for any overlap with existing segments. If there is, it must
            # be consolidated and merged together before mapping since Unicorn
            # doesn't allow overlapping segments.
            found = False
            overlap_start = False
            overlap_end = False
            tmp = 0
            for (mem_start, mem_end, mem_perm) in self.mem_regions():
                mem_end = mem_end + 1
                if seg_start >= mem_start and seg_end < mem_end:
                    found = True
                    break
                if seg_start >= mem_start and seg_start < mem_end:
                    overlap_start = True
                    tmp = mem_end
                    break
                if seg_end >= mem_start and seg_end < mem_end:
                    overlap_end = True
                    tmp = mem_start
                    break

            # Map memory into the address space if it is of an acceptable size.
            if (seg_end - seg_start) > MAX_ALLOWABLE_SEG_SIZE:
                if debug_print:
                    print(
                        "Skipping segment (LARGER THAN {0}) from {1:016x} - {2:016x} with perm={3}: {4}".format(
                            MAX_ALLOWABLE_SEG_SIZE, seg_start, seg_end, perms, name
                        )
                    )
                continue
            elif not found:  # Make sure it's not already mapped
                if overlap_start:  # Partial overlap (start)
                    self.__map_segment(name, tmp, seg_end - tmp, perms, debug_print)
                elif overlap_end:  # Patrial overlap (end)
                    self.__map_segment(
                        name, seg_start, tmp - seg_start, perms, debug_print
                    )
                else:  # Not found
                    self.__map_segment(
                        name, seg_start, seg_end - seg_start, perms, debug_print
                    )
            else:
                if debug_print:
                    print("Segment {} already mapped. Moving on.".format(name))

            # Load the content (if available)
            if "content_file" in segment and len(segment["content_file"]) > 0:
                content_file_path = os.path.join(
                    context_directory, segment["content_file"]
                )
                if not os.path.isfile(content_file_path):
                    raise Exception(
                        "Unable to find segment content file. Expected it to be at {}".format(
                            content_file_path
                        )
                    )
                # if debug_print:
                #    print("Loading content for segment {} from {}".format(name, segment['content_file']))
                content_file = open(content_file_path, "rb")
                compressed_content = content_file.read()
                content_file.close()
                self.mem_write(seg_start, zlib.decompress(compressed_content))

            else:
                if debug_print:
                    print(
                        "No content found for segment {0} @ {1:016x}".format(
                            name, seg_start
                        )
                    )
                self.mem_write(seg_start, b"\x00" * (seg_end - seg_start))

    def __get_arch_and_mode(self, arch_str):
        arch_map = {
            "x64": [UC_X86_REG_RIP, UC_ARCH_X86, UC_MODE_64],
            "x86": [UC_X86_REG_EIP, UC_ARCH_X86, UC_MODE_32],
            "arm64be": [
                UC_ARM64_REG_PC,
                UC_ARCH_ARM64,
                UC_MODE_ARM | UC_MODE_BIG_ENDIAN,
            ],
            "arm64le": [
                UC_ARM64_REG_PC,
                UC_ARCH_ARM64,
                UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN,
            ],
            "armbe": [UC_ARM_REG_PC, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN],
            "armle": [UC_ARM_REG_PC, UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN],
            "armbethumb": [
                UC_ARM_REG_PC,
                UC_ARCH_ARM,
                UC_MODE_THUMB | UC_MODE_BIG_ENDIAN,
            ],
            "armlethumb": [
                UC_ARM_REG_PC,
                UC_ARCH_ARM,
                UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN,
            ],
            "mips": [UC_MIPS_REG_PC, UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN],
            "mipsel": [
                UC_MIPS_REG_PC,
                UC_ARCH_MIPS,
                UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN,
            ],
        }
        return (arch_map[arch_str][1], arch_map[arch_str][2])

    def __get_register_map(self, arch):
        if arch == "arm64le" or arch == "arm64be":
            arch = "arm64"
        elif arch == "armle" or arch == "armbe" or "thumb" in arch:
            arch = "arm"
        elif arch == "mipsel":
            arch = "mips"

        registers = {
            "x64": {
                "rax": UC_X86_REG_RAX,
                "rbx": UC_X86_REG_RBX,
                "rcx": UC_X86_REG_RCX,
                "rdx": UC_X86_REG_RDX,
                "rsi": UC_X86_REG_RSI,
                "rdi": UC_X86_REG_RDI,
                "rbp": UC_X86_REG_RBP,
                "rsp": UC_X86_REG_RSP,
                "r8": UC_X86_REG_R8,
                "r9": UC_X86_REG_R9,
                "r10": UC_X86_REG_R10,
                "r11": UC_X86_REG_R11,
                "r12": UC_X86_REG_R12,
                "r13": UC_X86_REG_R13,
                "r14": UC_X86_REG_R14,
                "r15": UC_X86_REG_R15,
                "rip": UC_X86_REG_RIP,
                "efl": UC_X86_REG_EFLAGS,
                "cs": UC_X86_REG_CS,
                "ds": UC_X86_REG_DS,
                "es": UC_X86_REG_ES,
                "fs": UC_X86_REG_FS,
                "gs": UC_X86_REG_GS,
                "ss": UC_X86_REG_SS,
            },
            "x86": {
                "eax": UC_X86_REG_EAX,
                "ebx": UC_X86_REG_EBX,
                "ecx": UC_X86_REG_ECX,
                "edx": UC_X86_REG_EDX,
                "esi": UC_X86_REG_ESI,
                "edi": UC_X86_REG_EDI,
                "ebp": UC_X86_REG_EBP,
                "eip": UC_X86_REG_EIP,
                "esp": UC_X86_REG_ESP,
                "efl": UC_X86_REG_EFLAGS,
                # Segment registers removed...
                # They caused segfaults (from unicorn?) when they were here
            },
            "arm": {
                "r0": UC_ARM_REG_R0,
                "r1": UC_ARM_REG_R1,
                "r2": UC_ARM_REG_R2,
                "r3": UC_ARM_REG_R3,
                "r4": UC_ARM_REG_R4,
                "r5": UC_ARM_REG_R5,
                "r6": UC_ARM_REG_R6,
                "r7": UC_ARM_REG_R7,
                "r8": UC_ARM_REG_R8,
                "r9": UC_ARM_REG_R9,
                "r10": UC_ARM_REG_R10,
                "r11": UC_ARM_REG_R11,
                "r12": UC_ARM_REG_R12,
                "pc": UC_ARM_REG_PC,
                "sp": UC_ARM_REG_SP,
                "lr": UC_ARM_REG_LR,
                "cpsr": UC_ARM_REG_CPSR,
            },
            "arm64": {
                "x0": UC_ARM64_REG_X0,
                "x1": UC_ARM64_REG_X1,
                "x2": UC_ARM64_REG_X2,
                "x3": UC_ARM64_REG_X3,
                "x4": UC_ARM64_REG_X4,
                "x5": UC_ARM64_REG_X5,
                "x6": UC_ARM64_REG_X6,
                "x7": UC_ARM64_REG_X7,
                "x8": UC_ARM64_REG_X8,
                "x9": UC_ARM64_REG_X9,
                "x10": UC_ARM64_REG_X10,
                "x11": UC_ARM64_REG_X11,
                "x12": UC_ARM64_REG_X12,
                "x13": UC_ARM64_REG_X13,
                "x14": UC_ARM64_REG_X14,
                "x15": UC_ARM64_REG_X15,
                "x16": UC_ARM64_REG_X16,
                "x17": UC_ARM64_REG_X17,
                "x18": UC_ARM64_REG_X18,
                "x19": UC_ARM64_REG_X19,
                "x20": UC_ARM64_REG_X20,
                "x21": UC_ARM64_REG_X21,
                "x22": UC_ARM64_REG_X22,
                "x23": UC_ARM64_REG_X23,
                "x24": UC_ARM64_REG_X24,
                "x25": UC_ARM64_REG_X25,
                "x26": UC_ARM64_REG_X26,
                "x27": UC_ARM64_REG_X27,
                "x28": UC_ARM64_REG_X28,
                "pc": UC_ARM64_REG_PC,
                "sp": UC_ARM64_REG_SP,
                "fp": UC_ARM64_REG_FP,
                "lr": UC_ARM64_REG_LR,
                "nzcv": UC_ARM64_REG_NZCV,
                "cpsr": UC_ARM_REG_CPSR,
            },
            "mips": {
                "0": UC_MIPS_REG_ZERO,
                "at": UC_MIPS_REG_AT,
                "v0": UC_MIPS_REG_V0,
                "v1": UC_MIPS_REG_V1,
                "a0": UC_MIPS_REG_A0,
                "a1": UC_MIPS_REG_A1,
                "a2": UC_MIPS_REG_A2,
                "a3": UC_MIPS_REG_A3,
                "t0": UC_MIPS_REG_T0,
                "t1": UC_MIPS_REG_T1,
                "t2": UC_MIPS_REG_T2,
                "t3": UC_MIPS_REG_T3,
                "t4": UC_MIPS_REG_T4,
                "t5": UC_MIPS_REG_T5,
                "t6": UC_MIPS_REG_T6,
                "t7": UC_MIPS_REG_T7,
                "t8": UC_MIPS_REG_T8,
                "t9": UC_MIPS_REG_T9,
                "s0": UC_MIPS_REG_S0,
                "s1": UC_MIPS_REG_S1,
                "s2": UC_MIPS_REG_S2,
                "s3": UC_MIPS_REG_S3,
                "s4": UC_MIPS_REG_S4,
                "s5": UC_MIPS_REG_S5,
                "s6": UC_MIPS_REG_S6,
                "s7": UC_MIPS_REG_S7,
                "s8": UC_MIPS_REG_S8,
                "k0": UC_MIPS_REG_K0,
                "k1": UC_MIPS_REG_K1,
                "gp": UC_MIPS_REG_GP,
                "pc": UC_MIPS_REG_PC,
                "sp": UC_MIPS_REG_SP,
                "fp": UC_MIPS_REG_FP,
                "ra": UC_MIPS_REG_RA,
                "hi": UC_MIPS_REG_HI,
                "lo": UC_MIPS_REG_LO,
            },
        }
        return registers[arch]

    def __get_registers_extended(self, arch):
        # Similar to __get_register_map, but for ARM floating point registers
        if arch == "arm64le" or arch == "arm64be":
            arch = "arm64"
        elif arch == "armle" or arch == "armbe" or "thumb" in arch:
            arch = "arm"
        elif arch == "mipsel":
            arch = "mips"

        registers = {
            "arm": {
                "d0": UC_ARM_REG_D0,
                "d1": UC_ARM_REG_D1,
                "d2": UC_ARM_REG_D2,
                "d3": UC_ARM_REG_D3,
                "d4": UC_ARM_REG_D4,
                "d5": UC_ARM_REG_D5,
                "d6": UC_ARM_REG_D6,
                "d7": UC_ARM_REG_D7,
                "d8": UC_ARM_REG_D8,
                "d9": UC_ARM_REG_D9,
                "d10": UC_ARM_REG_D10,
                "d11": UC_ARM_REG_D11,
                "d12": UC_ARM_REG_D12,
                "d13": UC_ARM_REG_D13,
                "d14": UC_ARM_REG_D14,
                "d15": UC_ARM_REG_D15,
                "d16": UC_ARM_REG_D16,
                "d17": UC_ARM_REG_D17,
                "d18": UC_ARM_REG_D18,
                "d19": UC_ARM_REG_D19,
                "d20": UC_ARM_REG_D20,
                "d21": UC_ARM_REG_D21,
                "d22": UC_ARM_REG_D22,
                "d23": UC_ARM_REG_D23,
                "d24": UC_ARM_REG_D24,
                "d25": UC_ARM_REG_D25,
                "d26": UC_ARM_REG_D26,
                "d27": UC_ARM_REG_D27,
                "d28": UC_ARM_REG_D28,
                "d29": UC_ARM_REG_D29,
                "d30": UC_ARM_REG_D30,
                "d31": UC_ARM_REG_D31,
                "fpscr": UC_ARM_REG_FPSCR,
            }
        }

        return registers[arch]

    # ---------------------------
    # Callbacks for tracing

    # TODO: Extra mode for Capstone (i.e. Cs(cs_arch, cs_mode + cs_extra) not implemented

    def __trace_instruction(self, uc, address, size, user_data):
        if CAPSTONE_EXISTS == 1:
            # If Capstone is installed then we'll dump disassembly, otherwise just dump the binary.
            arch = self.get_arch()
            mode = self.get_mode()
            bit_size = self.bit_size_arch()
            # Map current arch to capstone labeling
            if arch == UC_ARCH_X86 and mode == UC_MODE_64:
                cs_arch = CS_ARCH_X86
                cs_mode = CS_MODE_64
            elif arch == UC_ARCH_X86 and mode == UC_MODE_32:
                cs_arch = CS_ARCH_X86
                cs_mode = CS_MODE_32
            elif arch == UC_ARCH_ARM64:
                cs_arch = CS_ARCH_ARM64
                cs_mode = CS_MODE_ARM
            elif arch == UC_ARCH_ARM and mode == UC_MODE_THUMB:
                cs_arch = CS_ARCH_ARM
                cs_mode = CS_MODE_THUMB
            elif arch == UC_ARCH_ARM:
                cs_arch = CS_ARCH_ARM
                cs_mode = CS_MODE_ARM
            elif arch == UC_ARCH_MIPS:
                cs_arch = CS_ARCH_MIPS
                cs_mode = CS_MODE_MIPS32  # No other MIPS supported in program

            cs = Cs(cs_arch, cs_mode)
            mem = uc.mem_read(address, size)
            if bit_size == 4:
                for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
                    bytes(mem), size
                ):
                    print(
                        "    Instr: {:#08x}:\t{}\t{}".format(
                            address, cs_mnemonic, cs_opstr
                        )
                    )
            else:
                for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
                    bytes(mem), size
                ):
                    print(
                        "    Instr: {:#16x}:\t{}\t{}".format(
                            address, cs_mnemonic, cs_opstr
                        )
                    )
        else:
            print("    Instr: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))

    def __trace_block(self, uc, address, size, user_data):
        print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))

    def __trace_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(
                "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                    address, size, value
                )
            )
        else:
            print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))

    def __trace_mem_invalid_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE_UNMAPPED:
            print(
                "        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                    address, size, value
                )
            )
        else:
            print(
                "        >>> INVALID Read: addr=0x{0:016x} size={1}".format(
                    address, size
                )
            )

    def bit_size_arch(self):
        arch = self.get_arch()
        mode = self.get_mode()
        # Get bit sizes for given architecture
        if arch == UC_ARCH_X86 and mode == UC_MODE_64:
            bit_size = 8
        elif arch == UC_ARCH_X86 and mode == UC_MODE_32:
            bit_size = 4
        elif arch == UC_ARCH_ARM64:
            bit_size = 8
        elif arch == UC_ARCH_ARM:
            bit_size = 4
        elif arch == UC_ARCH_MIPS:
            bit_size = 4
        return bit_size
