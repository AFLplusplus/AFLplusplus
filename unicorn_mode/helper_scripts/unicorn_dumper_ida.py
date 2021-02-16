"""
    unicorn_dumper_ida.py
    
    When run with IDA (<v7) sitting at a debug breakpoint, 
    dumps the current state (registers/memory/etc) of
    the process to a directory consisting of an index 
    file with register and segment information and 
    sub-files containing all actual process memory.
    
    The output of this script is expected to be used 
    to initialize context for Unicorn emulation.
"""

import datetime
import hashlib
import json
import os
import sys
import time
import zlib

# IDA Python SDK
from idaapi import *
from idc import *

# Maximum segment size that we'll store
# Yep, this could break stuff pretty quickly if we
# omit something that's used during emulation.
MAX_SEG_SIZE = 128 * 1024 * 1024

# Name of the index file
INDEX_FILE_NAME = "_index.json"

# ----------------------
# ---- Helper Functions


def get_arch():
    if ph.id == PLFM_386 and ph.flag & PR_USE64:
        return "x64"
    elif ph.id == PLFM_386 and ph.flag & PR_USE32:
        return "x86"
    elif ph.id == PLFM_ARM and ph.flag & PR_USE64:
        if cvar.inf.is_be():
            return "arm64be"
        else:
            return "arm64le"
    elif ph.id == PLFM_ARM and ph.flag & PR_USE32:
        if cvar.inf.is_be():
            return "armbe"
        else:
            return "armle"
    else:
        return ""


def get_register_list(arch):
    if arch == "arm64le" or arch == "arm64be":
        arch = "arm64"
    elif arch == "armle" or arch == "armbe":
        arch = "arm"

    registers = {
        "x64": [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
            "rsp",
            "efl",
            "cs",
            "ds",
            "es",
            "fs",
            "gs",
            "ss",
        ],
        "x86": [
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "eip",
            "esp",
            "efl",
            "cs",
            "ds",
            "es",
            "fs",
            "gs",
            "ss",
        ],
        "arm": [
            "R0",
            "R1",
            "R2",
            "R3",
            "R4",
            "R5",
            "R6",
            "R7",
            "R8",
            "R9",
            "R10",
            "R11",
            "R12",
            "PC",
            "SP",
            "LR",
            "PSR",
        ],
        "arm64": [
            "X0",
            "X1",
            "X2",
            "X3",
            "X4",
            "X5",
            "X6",
            "X7",
            "X8",
            "X9",
            "X10",
            "X11",
            "X12",
            "X13",
            "X14",
            "X15",
            "X16",
            "X17",
            "X18",
            "X19",
            "X20",
            "X21",
            "X22",
            "X23",
            "X24",
            "X25",
            "X26",
            "X27",
            "X28",
            "PC",
            "SP",
            "FP",
            "LR",
            "CPSR"
            #    "NZCV",
        ],
    }
    return registers[arch]


# -----------------------
# ---- Dumping functions


def dump_arch_info():
    arch_info = {}
    arch_info["arch"] = get_arch()
    return arch_info


def dump_regs():
    reg_state = {}
    for reg in get_register_list(get_arch()):
        reg_state[reg] = GetRegValue(reg)
    return reg_state


def dump_process_memory(output_dir):
    # Segment information dictionary
    segment_list = []

    # Loop over the segments, fill in the info dictionary
    for seg_ea in Segments():
        seg_start = SegStart(seg_ea)
        seg_end = SegEnd(seg_ea)
        seg_size = seg_end - seg_start

        seg_info = {}
        seg_info["name"] = SegName(seg_ea)
        seg_info["start"] = seg_start
        seg_info["end"] = seg_end

        perms = getseg(seg_ea).perm
        seg_info["permissions"] = {
            "r": False if (perms & SEGPERM_READ) == 0 else True,
            "w": False if (perms & SEGPERM_WRITE) == 0 else True,
            "x": False if (perms & SEGPERM_EXEC) == 0 else True,
        }

        if (perms & SEGPERM_READ) and seg_size <= MAX_SEG_SIZE and isLoaded(seg_start):
            try:
                # Compress and dump the content to a file
                seg_content = get_many_bytes(seg_start, seg_end - seg_start)
                if seg_content == None:
                    print(
                        "Segment empty: {0}@0x{1:016x} (size:UNKNOWN)".format(
                            SegName(seg_ea), seg_ea
                        )
                    )
                    seg_info["content_file"] = ""
                else:
                    print(
                        "Dumping segment {0}@0x{1:016x} (size:{2})".format(
                            SegName(seg_ea), seg_ea, len(seg_content)
                        )
                    )
                    compressed_seg_content = zlib.compress(seg_content)
                    md5_sum = hashlib.md5(compressed_seg_content).hexdigest() + ".bin"
                    seg_info["content_file"] = md5_sum

                    # Write the compressed contents to disk
                    out_file = open(os.path.join(output_dir, md5_sum), "wb")
                    out_file.write(compressed_seg_content)
                    out_file.close()
            except:
                print("Exception reading segment: {}".format(sys.exc_info()[0]))
                seg_info["content_file"] = ""
        else:
            print("Skipping segment {0}@0x{1:016x}".format(SegName(seg_ea), seg_ea))
            seg_info["content_file"] = ""

        # Add the segment to the list
        segment_list.append(seg_info)

    return segment_list


"""
    TODO: FINISH IMPORT DUMPING
def import_callback(ea, name, ord):
    if not name:
    else:
    
    # True -> Continue enumeration
    # False -> End enumeration
    return True
    
def dump_imports():
    import_dict = {}
    
    for i in xrange(0, number_of_import_modules):
        enum_import_names(i, import_callback)
    
    return import_dict
"""

# ----------
# ---- Main


def main():

    try:
        print("----- Unicorn Context Dumper -----")
        print("You must be actively debugging before running this!")
        print(
            "If it fails, double check that you are actively debugging before running."
        )

        # Create the output directory
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime(
            "%Y%m%d_%H%M%S"
        )
        output_path = os.path.dirname(os.path.abspath(GetIdbPath()))
        output_path = os.path.join(output_path, "UnicornContext_" + timestamp)
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        print("Process context will be output to {}".format(output_path))

        # Get the context
        context = {
            "arch": dump_arch_info(),
            "regs": dump_regs(),
            "segments": dump_process_memory(output_path),
            # "imports": dump_imports(),
        }

        # Write the index file
        index_file = open(os.path.join(output_path, INDEX_FILE_NAME), "w")
        index_file.write(json.dumps(context, indent=4))
        index_file.close()
        print("Done.")

    except Exception, e:
        print("!!! ERROR:\n\t{}".format(str(e)))


if __name__ == "__main__":
    main()
