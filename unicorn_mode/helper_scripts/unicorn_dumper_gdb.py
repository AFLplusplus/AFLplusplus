"""
    unicorn_dumper_gdb.py

    When run with GDB sitting at a debug breakpoint, this
    dumps the current state (registers/memory/etc) of
    the process to a directory consisting of an index
    file with register and segment information and
    sub-files containing all actual process memory.

    The output of this script is expected to be used
    to initialize context for Unicorn emulation.

    -----------

    In order to run this script, GEF needs to be running in the GDB session (gef.py)
    # HELPERS from: https://github.com/hugsy/gef/blob/master/gef.py
    It can be loaded with:
      source <path_to_gef>/gef.py

    Call this function when at a breakpoint in your process with:
      source unicorn_dumper_gdb.py

    -----------


"""

import datetime
import hashlib
import json
import os
import sys
import time
import zlib

# GDB Python SDK
import gdb

# Maximum segment size that we'll store
# Yep, this could break stuff pretty quickly if we
# omit something that's used during emulation.
MAX_SEG_SIZE = 128 * 1024 * 1024

# Name of the index file
INDEX_FILE_NAME = "_index.json"


# ----------------------
# ---- Helper Functions


def map_arch():
    arch = get_arch()  # from GEF
    if "x86_64" in arch or "x86-64" in arch:
        return "x64"
    elif "x86" in arch or "i386" in arch:
        return "x86"
    elif "aarch64" in arch or "arm64" in arch:
        return "arm64le"
    elif "aarch64_be" in arch:
        return "arm64be"
    elif "armeb" in arch:
        # check for THUMB mode
        cpsr = get_register("$cpsr")
        if cpsr & (1 << 5):
            return "armbethumb"
        else:
            return "armbe"
    elif "arm" in arch:
        # check for THUMB mode
        cpsr = get_register("$cpsr")
        if cpsr & (1 << 5):
            return "armlethumb"
        else:
            return "armle"
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
    for reg in gef.arch.registers:
        reg_val = gef.arch.register(reg)
        reg_state[reg.strip().strip("$")] = reg_val

    return reg_state


def dump_process_memory(output_dir):
    # Segment information dictionary
    final_segment_list = []

    # GEF:
    vmmap = gef.memory.maps
    memory = GefMemoryManager()
    
    if not vmmap:
        print("No address mapping information found")
        return final_segment_list

    for entry in vmmap:
        if entry.page_start == entry.page_end:
            continue

        seg_info = {
            "start": entry.page_start,
            "end": entry.page_end,
            "name": entry.path,
            "permissions": {
                "r": entry.is_readable() > 0,
                "w": entry.is_writable() > 0,
                "x": entry.is_executable() > 0,
            },
            "content_file": "",
        }

        # "(deleted)" may or may not be valid, but don't push it.
        if entry.is_readable() and not "(deleted)" in entry.path:
            try:
                # Compress and dump the content to a file
                seg_content = memory.read(entry.page_start, entry.size)
                if seg_content == None:
                    print(
                        "Segment empty: @0x{0:016x} (size:UNKNOWN) {1}".format(
                            entry.page_start, entry.path
                        )
                    )
                else:
                    print(
                        "Dumping segment @0x{0:016x} (size:0x{1:x}): {2} [{3}]".format(
                            entry.page_start,
                            len(seg_content),
                            entry.path,
                            repr(seg_info["permissions"]),
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
                print(
                    "Exception reading segment ({}): {}".format(
                        entry.path, sys.exc_info()[0]
                    )
                )
        else:
            print(
                "Skipping segment {0}@0x{1:016x}".format(entry.path, entry.page_start)
            )

        # Add the segment to the list
        final_segment_list.append(seg_info)

    return final_segment_list


# ---------------------------------------------
# ---- ARM Extention (dump floating point regs)


def dump_float(rge=32):
    reg_convert = ""
    if (
        map_arch() == "armbe"
        or map_arch() == "armle"
        or map_arch() == "armbethumb"
        or map_arch() == "armbethumb"
    ):
        reg_state = {}
        for reg_num in range(32):
            value = gdb.selected_frame().read_register("d" + str(reg_num))
            reg_state["d" + str(reg_num)] = int(str(value["u64"]), 16)
        value = gdb.selected_frame().read_register("fpscr")
        reg_state["fpscr"] = int(str(value), 16)

        return reg_state


# ----------
# ---- Main


def main():
    print("----- Unicorn Context Dumper -----")
    print("You must be actively debugging before running this!")
    print("If it fails, double check that you are actively debugging before running.")
    try:
        GEF_TEST = set_arch()
    except Exception as e:
        print("!!! GEF not running in GDB.  Please run gef.py by executing:")
        print('\tpython execfile ("<path_to_gef>/gef.py")')
        return

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
            "regs_extended": dump_float(),
            "segments": dump_process_memory(output_path),
        }

        # Write the index file
        index_file = open(os.path.join(output_path, INDEX_FILE_NAME), "w")
        index_file.write(json.dumps(context, indent=4))
        index_file.close()
        print("Done.")

    except Exception as e:
        print("!!! ERROR:\n\t{}".format(repr(e)))


if __name__ == "__main__":
    main()
