#!/usr/bin/env python3
""" 
    Simple test harness for AFL's Unicorn Mode.

    This loads the speedtest target binary (precompiled X64 code) into
    Unicorn's memory map for emulation, places the specified input into
    Argv, and executes main.
    There should not be any crashes - it's a speedtest against Rust and c.

    Before running this harness, call make in the parent folder.

    Run under AFL as follows:

    $ cd <afl_path>/unicorn_mode/samples/speedtest/python
    $ ../../../../afl-fuzz -U -i ../sample_inputs -o ./output -- python3 harness.py @@
"""

import argparse
import os
import struct

from unicornafl import *
from unicorn.unicorn_const import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RDI,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

# Memory map for the code to be tested
BASE_ADDRESS = 0x0  # Arbitrary address where the (PIE) target binary will be loaded to
CODE_SIZE_MAX = 0x00010000  # Max size for the code (64kb)
INPUT_ADDRESS = 0x00100000  # where we put our stuff
INPUT_MAX = 0x00100000  # max size for our input
HEAP_ADDRESS = 0x00200000  # Heap addr
HEAP_SIZE_MAX = 0x000F0000  # Maximum allowable size for the heap
STACK_ADDRESS = 0x00400000  # Address of the stack (arbitrarily chosen)
STACK_SIZE = 0x000F0000  # Size of the stack (arbitrarily chosen)

target_path = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)
target_bin = os.path.join(target_path, "target")


def get_offsets_for(name):
    full_path = os.path.join(target_path, f"target.offsets.{name}")
    with open(full_path) as f:
        return [int(x, 16) + BASE_ADDRESS for x in f.readlines()]


# Read all offsets from our objdump file
main_offset = get_offsets_for("main")[0]
main_ends = get_offsets_for("main_ends")
malloc_callsites = get_offsets_for("malloc")
free_callsites = get_offsets_for("free")
magicfn_callsites = get_offsets_for("magicfn")
# Joke's on me: strlen got inlined by my compiler
strlen_callsites = get_offsets_for("strlen")

try:
    # If Capstone is installed then we'll dump disassembly, otherwise just dump the binary.
    from capstone import *

    cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)

    def unicorn_debug_instruction(uc, address, size, user_data):
        mem = uc.mem_read(address, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
            bytes(mem), size
        ):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))


except ImportError:

    def unicorn_debug_instruction(uc, address, size, user_data):
        print("    Instr: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))


def unicorn_debug_block(uc, address, size, user_data):
    print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))


def unicorn_debug_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))


def unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            "        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print(
            "        >>> INVALID Read: addr=0x{0:016x} size={1}".format(address, size)
        )


already_allocated = False


def malloc_hook(uc, address, size, user_data):
    """
    We use a very simple malloc/free stub here, that only works for exactly one allocation at a time.
    """
    global already_allocated
    if already_allocated:
        print("Double malloc, not supported right now!")
        os.abort()
    # read the first param
    malloc_size = uc.reg_read(UC_X86_REG_RDI)
    if malloc_size > HEAP_SIZE_MAX:
        print(
            f"Tried to allocate {malloc_size} bytes, aint't nobody got space for that! (We may only allocate up to {HEAP_SIZE_MAX})"
        )
        os.abort()
    uc.reg_write(UC_X86_REG_RAX, HEAP_ADDRESS)
    uc.reg_write(UC_X86_REG_RIP, address + size)
    already_allocated = True


def free_hook(uc, address, size, user_data):
    """
    No real free, just set the "used"-flag to false.
    """
    global already_allocated
    if not already_allocated:
        print("Double free detected. Real bug?")
        os.abort()
    # read the first param
    free_ptr = uc.reg_read(UC_X86_REG_RDI)
    if free_ptr != HEAP_ADDRESS:
        print(
            f"Tried to free wrong mem region: {hex(free_ptr)} at code loc {hex(address)}"
        )
        os.abort()
    uc.reg_write(UC_X86_REG_RIP, address + size)
    already_allocated = False


# def strlen_hook(uc, address, size, user_data):
#     """
#     No real strlen, we know the len is == our input.
#     This completely ignores '\0', but for this target, do we really care?
#     """
#     global input_len
#     print(f"Returning len {input_len}")
#     uc.reg_write(UC_X86_REG_RAX, input_len)
#     uc.reg_write(UC_X86_REG_RIP, address + size)


def magicfn_hook(uc, address, size, user_data):
    """
    This is a fancy print function that we're just going to skip for fuzzing.
    """
    uc.reg_write(UC_X86_REG_RIP, address + size)


def main():

    parser = argparse.ArgumentParser(description="Test harness for simple_target.bin")
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the file containing the mutated input to load",
    )
    parser.add_argument(
        "-t",
        "--trace",
        default=False,
        action="store_true",
        help="Enables debug tracing",
    )
    args = parser.parse_args()

    # Instantiate a MIPS32 big endian Unicorn Engine instance
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    if args.trace:
        uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
        uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, unicorn_debug_mem_access)
        uc.hook_add(
            UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID,
            unicorn_debug_mem_invalid_access,
        )

    print("The input testcase is set to {}".format(args.input_file))

    # ---------------------------------------------------
    # Load the binary to emulate and map it into memory
    with open(target_bin, "rb") as f:
        binary_code = f.read()

    # Apply constraints to the mutated input
    if len(binary_code) > CODE_SIZE_MAX:
        print("Binary code is too large (> {} bytes)".format(CODE_SIZE_MAX))
        return

    # Write the binary to its place in mem
    uc.mem_map(BASE_ADDRESS, CODE_SIZE_MAX)
    uc.mem_write(BASE_ADDRESS, binary_code)

    # Set the program counter to the start of the code
    uc.reg_write(UC_X86_REG_RIP, main_offset)

    # Setup the stack.
    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    # Setup the stack pointer, but allocate two pointers for the pointers to input.
    uc.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 16)

    # Setup our input space, and push the pointer to it in the function params
    uc.mem_map(INPUT_ADDRESS, INPUT_MAX)
    # We have argc = 2
    uc.reg_write(UC_X86_REG_RDI, 2)
    # RSI points to our little 2 QWORD space at the beginning of the stack...
    uc.reg_write(UC_X86_REG_RSI, STACK_ADDRESS + STACK_SIZE - 16)
    # ... which points to the Input. Write the ptr to mem in little endian.
    uc.mem_write(STACK_ADDRESS + STACK_SIZE - 16, struct.pack("<Q", INPUT_ADDRESS))

    for addr in malloc_callsites:
        uc.hook_add(UC_HOOK_CODE, malloc_hook, begin=addr, end=addr)

    for addr in free_callsites:
        uc.hook_add(UC_HOOK_CODE, free_hook, begin=addr, end=addr)

    if len(strlen_callsites):
        # strlen got inlined for my compiler.
        print(
            "Oops, your compiler emitted strlen as function. You may have to change the harness."
        )
    # for addr in strlen_callsites:
    #     uc.hook_add(UC_HOOK_CODE, strlen_hook, begin=addr, end=addr)

    for addr in magicfn_callsites:
        uc.hook_add(UC_HOOK_CODE, magicfn_hook, begin=addr, end=addr + 1)

    # -----------------------------------------------------
    # Set up a callback to place input data (do little work here, it's called for every single iteration! This code is *HOT*)
    # We did not pass in any data and don't use persistent mode, so we can ignore these params.
    # Be sure to check out the docstrings for the uc.afl_* functions.
    def place_input_callback(uc, input, persistent_round, data):
        # Apply constraints to the mutated input
        input_len = len(input)
        # global input_len
        if input_len > INPUT_MAX:
            # print("Test input is too long (> {} bytes)")
            return False

        # print(f"Placing input: {input} in round {persistent_round}")

        # Make sure the string is always 0-terminated (as it would be "in the wild")
        input[-1] = b"\0"

        # Write the mutated command into the data buffer
        uc.mem_write(INPUT_ADDRESS, input)
        # uc.reg_write(UC_X86_REG_RIP, main_offset)

    print(f"Starting to fuzz. Running from addr {main_offset} to one of {main_ends}")
    # Start the fuzzer.
    uc.afl_fuzz(args.input_file, place_input_callback, main_ends, persistent_iters=1000)


if __name__ == "__main__":
    main()
