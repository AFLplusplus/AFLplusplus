#!/usr/bin/env python
"""
   Simple test harness for AFL's Unicorn Mode.

   This loads the compcov_target.bin binary (precompiled as MIPS code) into
   Unicorn's memory map for emulation, places the specified input into
   compcov_target's buffer (hardcoded to be at 0x300000), and executes 'main()'.
   If any crashes occur during emulation, this script throws a matching signal
   to tell AFL that a crash occurred.

   Run under AFL as follows:

   $ cd <afl_path>/unicorn_mode/samples/simple/
   $ AFL_COMPCOV_LEVEL=2 ../../../afl-fuzz -U -m none -i ./sample_inputs -o ./output -- python compcov_test_harness.py @@
"""

import argparse
import os
import signal

from unicornafl import *
from unicornafl.x86_const import *

# Path to the file containing the binary to emulate
BINARY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "compcov_target.bin"
)

# Memory map for the code to be tested
CODE_ADDRESS = 0x00100000  # Arbitrary address where code to test will be loaded
CODE_SIZE_MAX = 0x00010000  # Max size for the code (64kb)
STACK_ADDRESS = 0x00200000  # Address of the stack (arbitrarily chosen)
STACK_SIZE = 0x00010000  # Size of the stack (arbitrarily chosen)
DATA_ADDRESS = 0x00300000  # Address where mutated data will be placed
DATA_SIZE_MAX = 0x00010000  # Maximum allowable size of mutated data

try:
    # If Capstone is installed then we'll dump disassembly, otherwise just dump the binary.
    from capstone import *

    cs = Cs(CS_ARCH_X86, CS_MODE_64)

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


def main():

    parser = argparse.ArgumentParser(description="Test harness for compcov_target.bin")
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

    # ---------------------------------------------------
    # Load the binary to emulate and map it into memory

    print("Loading data input from {}".format(args.input_file))
    binary_file = open(BINARY_FILE, "rb")
    binary_code = binary_file.read()
    binary_file.close()

    # Apply constraints to the mutated input
    if len(binary_code) > CODE_SIZE_MAX:
        print("Binary code is too large (> {} bytes)".format(CODE_SIZE_MAX))
        return

    # Write the mutated command into the data buffer
    uc.mem_map(CODE_ADDRESS, CODE_SIZE_MAX)
    uc.mem_write(CODE_ADDRESS, binary_code)

    # Set the program counter to the start of the code
    start_address = CODE_ADDRESS  # Address of entry point of main()
    end_address = CODE_ADDRESS + 0x55  # Address of last instruction in main()
    uc.reg_write(UC_X86_REG_RIP, start_address)

    # -----------------
    # Setup the stack

    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    uc.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE)

    # Mapping a location to write our buffer to
    uc.mem_map(DATA_ADDRESS, DATA_SIZE_MAX)

    # -----------------------------------------------
    # Load the mutated input and map it into memory

    def place_input_callback(uc, input, _, data):
        """
        Callback that loads the mutated input into memory.
        """
        # Apply constraints to the mutated input
        if len(input) > DATA_SIZE_MAX:
            return

        # Write the mutated command into the data buffer
        uc.mem_write(DATA_ADDRESS, input)

    # ------------------------------------------------------------
    # Emulate the code, allowing it to process the mutated input

    print("Starting the AFL fuzz")
    uc.afl_fuzz(
        input_file=args.input_file,
        place_input_callback=place_input_callback,
        exits=[end_address],
        persistent_iters=1,
    )


if __name__ == "__main__":
    main()
