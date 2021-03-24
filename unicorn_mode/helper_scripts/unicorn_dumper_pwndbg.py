"""
    unicorn_dumper_pwndbg.py
    
    When run with GDB sitting at a debug breakpoint, this
    dumps the current state (registers/memory/etc) of
    the process to a directory consisting of an index 
    file with register and segment information and 
    sub-files containing all actual process memory.
    
    The output of this script is expected to be used 
    to initialize context for Unicorn emulation.

    -----------

    In order to run this script, PWNDBG needs to be running in the GDB session (gdbinit.py)
    # HELPERS from: https://github.com/pwndbg/pwndbg
    It can be loaded with:
      source <path_to_pwndbg>/gdbinit.py

    Call this function when at a breakpoint in your process with:
      source unicorn_dumper_pwndbg.py

    -----------


"""

import datetime
import hashlib
import json
import os
import sys
import time
import zlib
import traceback

# GDB Python SDK
import gdb

pwndbg_loaded = False

try:
    import pwndbg.arch
    import pwndbg.regs
    import pwndbg.vmmap
    import pwndbg.memory

    pwndbg_loaded = True

except ImportError:
    print("!!! PWNGDB not running in GDB.  Please run gdbinit.py by executing:")
    print('\tpython execfile ("<path_to_pwndbg>/gdbinit.py")')

# Maximum segment size that we'll store
# Yep, this could break stuff pretty quickly if we
# omit something that's used during emulation.
MAX_SEG_SIZE = 128 * 1024 * 1024

# Name of the index file
INDEX_FILE_NAME = "_index.json"

# ----------------------
# ---- Helper Functions


def map_arch():
    arch = pwndbg.arch.current  # from PWNDBG
    if "x86_64" in arch or "x86-64" in arch:
        return "x64"
    elif "x86" in arch or "i386" in arch:
        return "x86"
    elif "aarch64" in arch or "arm64" in arch:
        return "arm64le"
    elif "aarch64_be" in arch:
        return "arm64be"
    elif "arm" in arch:
        cpsr = pwndbg.regs["cpsr"]
        # check endianess
        if pwndbg.arch.endian == "big":
            # check for THUMB mode
            if cpsr & (1 << 5):
                return "armbethumb"
            else:
                return "armbe"
        else:
            # check for THUMB mode
            if cpsr & (1 << 5):
                return "armlethumb"
            else:
                return "armle"
    elif "mips" in arch:
        if pwndbg.arch.endian == "little":
            return "mipsel"
        else:
            return "mips"
    else:
        return ""


# -----------------------
# ---- Dumping functions


def dump_arch_info():
    arch_info = {}
    arch_info["arch"] = map_arch()
    return arch_info


def dump_regs():
    reg_state = {}
    for reg in pwndbg.regs.all:
        reg_val = pwndbg.regs[reg]
        # current dumper script looks for register values to be hex strings
        #         reg_str = "0x{:08x}".format(reg_val)
        #         if "64" in get_arch():
        #             reg_str = "0x{:016x}".format(reg_val)
        #         reg_state[reg.strip().strip('$')] = reg_str
        reg_state[reg.strip().strip("$")] = reg_val
    return reg_state


def dump_process_memory(output_dir):
    # Segment information dictionary
    final_segment_list = []

    # PWNDBG:
    vmmap = pwndbg.vmmap.get()

    # Pointer to end of last dumped memory segment
    segment_last_addr = 0x0

    start = None
    end = None

    if not vmmap:
        print("No address mapping information found")
        return final_segment_list

    # Assume segment entries are sorted by start address
    for entry in vmmap:
        if entry.start == entry.end:
            continue

        start = entry.start
        end = entry.end

        if segment_last_addr > entry.start:  # indicates overlap
            if (
                segment_last_addr > entry.end
            ):  # indicates complete overlap, so we skip the segment entirely
                continue
            else:
                start = segment_last_addr

        seg_info = {
            "start": start,
            "end": end,
            "name": entry.objfile,
            "permissions": {"r": entry.read, "w": entry.write, "x": entry.execute},
            "content_file": "",
        }

        # "(deleted)" may or may not be valid, but don't push it.
        if entry.read and not "(deleted)" in entry.objfile:
            try:
                # Compress and dump the content to a file
                seg_content = pwndbg.memory.read(start, end - start)
                if seg_content == None:
                    print(
                        "Segment empty: @0x{0:016x} (size:UNKNOWN) {1}".format(
                            entry.start, entry.objfile
                        )
                    )
                else:
                    print(
                        "Dumping segment @0x{0:016x} (size:0x{1:x}): {2} [{3}]".format(
                            entry.start,
                            len(seg_content),
                            entry.objfile,
                            repr(seg_info["permissions"]),
                        )
                    )
                    compressed_seg_content = zlib.compress(str(seg_content))
                    md5_sum = hashlib.md5(compressed_seg_content).hexdigest() + ".bin"
                    seg_info["content_file"] = md5_sum

                    # Write the compressed contents to disk
                    out_file = open(os.path.join(output_dir, md5_sum), "wb")
                    out_file.write(compressed_seg_content)
                    out_file.close()

            except Exception as e:
                traceback.print_exc()
                print(
                    "Exception reading segment ({}): {}".format(
                        entry.objfile, sys.exc_info()[0]
                    )
                )
        else:
            print("Skipping segment {0}@0x{1:016x}".format(entry.objfile, entry.start))

        segment_last_addr = end

        # Add the segment to the list
        final_segment_list.append(seg_info)

    return final_segment_list


# ----------
# ---- Main


def main():
    print("----- Unicorn Context Dumper -----")
    print("You must be actively debugging before running this!")
    print("If it fails, double check that you are actively debugging before running.")

    try:

        # Create the output directory
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime(
            "%Y%m%d_%H%M%S"
        )
        output_path = "UnicornContext_" + timestamp
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        print("Process context will be output to {}".format(output_path))

        # Get the context
        context = {
            "arch": dump_arch_info(),
            "regs": dump_regs(),
            "segments": dump_process_memory(output_path),
        }

        # Write the index file
        index_file = open(os.path.join(output_path, INDEX_FILE_NAME), "w")
        index_file.write(json.dumps(context, indent=4))
        index_file.close()
        print("Done.")

    except Exception as e:
        print("!!! ERROR:\n\t{}".format(repr(e)))


if __name__ == "__main__" and pwndbg_loaded:
    main()
