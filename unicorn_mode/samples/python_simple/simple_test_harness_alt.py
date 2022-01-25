#!/usr/bin/env python
""" 
   Alternative simple test harness for Unicornafl.
   It is slower but compatible with anything that uses unicorn.

   Have a look at `unicornafl.monkeypatch()` for an easy way to fuzz unicorn projects.

   This loads the simple_target.bin binary (precompiled as MIPS code) into
   Unicorn's memory map for emulation, places the specified input into
   simple_target's buffer (hardcoded to be at 0x300000), and executes 'main()'.
   If any crashes occur during emulation, this script throws a matching signal
   to tell AFL that a crash occurred.

   Run under AFL as follows:

   $ cd <afl_path>/unicorn_mode/samples/python_simple
   $ ../../../afl-fuzz -U -m none -i ./sample_inputs -o ./output -- python simple_test_harness_alt.py @@ 
"""

import argparse
import os
import signal

from unicornafl import *
from unicornafl.mips_const import *

# Path to the file containing the binary to emulate
BINARY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "simple_target.bin"
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


def force_crash(uc_error):
    # This function should be called to indicate to AFL that a crash occurred during emulation.
    # Pass in the exception received from Uc.emu_start()
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


def main():

    parser = argparse.ArgumentParser(description="Test harness for simple_target.bin")
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the file containing the mutated input to load",
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
        help="Enables debug tracing",
    )
    args = parser.parse_args()

    # Instantiate a MIPS32 big endian Unicorn Engine instance
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)

    if args.debug:
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
    end_address = CODE_ADDRESS + 0xF4  # Address of last instruction in main()
    uc.reg_write(UC_MIPS_REG_PC, start_address)

    # -----------------
    # Setup the stack

    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    uc.reg_write(UC_MIPS_REG_SP, STACK_ADDRESS + STACK_SIZE)

    # reserve some space for data
    uc.mem_map(DATA_ADDRESS, DATA_SIZE_MAX)

    # -----------------------------------------------------
    #   Kick off AFL's fork server
    #   THIS MUST BE DONE BEFORE LOADING USER DATA!
    #   If this isn't done every single run, the AFL fork server
    #   will not be started appropriately and you'll get erratic results!

    print("Starting the AFL forkserver")

    afl_mode = uc.afl_forkserver_start([end_address])
    if afl_mode != UC_AFL_RET_NO_AFL:
        # Disable prints for speed
        out = lambda x, y: None
    else:
        out = lambda x, y: print(x.format(y))

    # -----------------------------------------------
    # Load the mutated input and map it into memory

    # Load the mutated input from disk
    out("Loading data input from {}", args.input_file)
    input_file = open(args.input_file, "rb")
    input = input_file.read()
    input_file.close()

    # Apply constraints to the mutated input
    if len(input) > DATA_SIZE_MAX:
        out("Test input is too long (> {} bytes)", DATA_SIZE_MAX)
        return

    # Write the mutated command into the data buffer
    uc.mem_write(DATA_ADDRESS, input)

    # ------------------------------------------------------------
    # Emulate the code, allowing it to process the mutated input

    out("Executing until a crash or execution reaches 0x{0:016x}", end_address)
    try:
        uc.emu_start(uc.reg_read(UC_MIPS_REG_PC), end_address, timeout=0, count=0)
    except UcError as e:
        out("Execution failed with error: {}", e)
        force_crash(e)

    # UC_AFL_RET_ERROR = 0
    # UC_AFL_RET_CHILD = 1
    # UC_AFL_RET_NO_AFL = 2
    # UC_AFL_RET_FINISHED = 3
    out("Done. AFL Mode is {}", afl_mode)


if __name__ == "__main__":
    main()
