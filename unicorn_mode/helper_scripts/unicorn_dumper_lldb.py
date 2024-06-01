"""
    unicorn_dumper_lldb.py
    
    When run with LLDB sitting at a debug breakpoint, this
    dumps the current state (registers/memory/etc) of
    the process to a directory consisting of an index 
    file with register and segment information and 
    sub-files containing all actual process memory.
    
    The output of this script is expected to be used 
    to initialize context for Unicorn emulation.

    -----------

    Call this function when at a breakpoint in your process with:
      command script import -r unicorn_dumper_lldb

    If there is trouble with "split on a NoneType", issue the following command:
      script lldb.target.triple

    and try to import the script again.

    -----------

"""

from copy import deepcopy
import datetime
import hashlib
import json
import os
import sys
import time
import zlib

# LLDB Python SDK
import lldb

# Maximum segment size that we'll store
# Yep, this could break stuff pretty quickly if we
# omit something that's used during emulation.
MAX_SEG_SIZE = 128 * 1024 * 1024

# Name of the index file
INDEX_FILE_NAME = "_index.json"
DEBUG_MEM_FILE_NAME = "_memory.json"

# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE - 1)

# ----------------------
# ---- Helper Functions


def overlap_alignments(segments, memory):
    final_list = []
    curr_seg_idx = 0
    curr_end_addr = 0
    curr_node = None
    current_segment = None
    sorted_segments = sorted(segments, key=lambda k: (k["start"], k["end"]))
    if curr_seg_idx < len(sorted_segments):
        current_segment = sorted_segments[curr_seg_idx]
    for mem in sorted(memory, key=lambda k: (k["start"], -k["end"])):
        if curr_node is None:
            if current_segment is not None and current_segment["start"] == mem["start"]:
                curr_node = deepcopy(current_segment)
                curr_node["permissions"] = mem["permissions"]
            else:
                curr_node = deepcopy(mem)

            curr_end_addr = curr_node["end"]

        while curr_end_addr <= mem["end"]:
            if curr_node["end"] == mem["end"]:
                if (
                    current_segment is not None
                    and current_segment["start"] > curr_node["start"]
                    and current_segment["start"] < curr_node["end"]
                ):
                    curr_node["end"] = current_segment["start"]
                    if curr_node["end"] > curr_node["start"]:
                        final_list.append(curr_node)
                    curr_node = deepcopy(current_segment)
                    curr_node["permissions"] = mem["permissions"]
                    curr_end_addr = curr_node["end"]
                else:
                    if curr_node["end"] > curr_node["start"]:
                        final_list.append(curr_node)
                    # if curr_node is a segment
                    if (
                        current_segment is not None
                        and current_segment["end"] == mem["end"]
                    ):
                        curr_seg_idx += 1
                        if curr_seg_idx < len(sorted_segments):
                            current_segment = sorted_segments[curr_seg_idx]
                        else:
                            current_segment = None

                    curr_node = None
                    break
            # could only be a segment
            else:
                if curr_node["end"] < mem["end"]:
                    # check for remaining segments and valid segments
                    if curr_node["end"] > curr_node["start"]:
                        final_list.append(curr_node)

                    curr_seg_idx += 1
                    if curr_seg_idx < len(sorted_segments):
                        current_segment = sorted_segments[curr_seg_idx]
                    else:
                        current_segment = None

                    if (
                        current_segment is not None
                        and current_segment["start"] <= curr_end_addr
                        and current_segment["start"] < mem["end"]
                    ):
                        curr_node = deepcopy(current_segment)
                        curr_node["permissions"] = mem["permissions"]
                    else:
                        # no more segments
                        curr_node = deepcopy(mem)

                    curr_node["start"] = curr_end_addr
                    curr_end_addr = curr_node["end"]

    return final_list


# https://github.com/llvm-mirror/llvm/blob/master/include/llvm/ADT/Triple.h
def get_arch():
    arch, arch_vendor, arch_os, *arch_remains = lldb.debugger.GetSelectedTarget().GetTriple().split("-")
    if arch == "x86_64":
        return "x64"
    elif arch == "x86" or arch == "i386":
        return "x86"
    elif arch == "aarch64" or arch == "arm64":
        return "arm64le"
    elif arch == "aarch64_be":
        return "arm64be"
    elif arch == "armeb":
        return "armbe"
    elif arch == "arm":
        return "armle"
    else:
        return ""


# -----------------------
# ---- Dumping functions


def dump_arch_info():
    arch_info = {}
    arch_info["arch"] = get_arch()
    return arch_info


def dump_regs():
    reg_state = {}
    for reg_list in lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame().GetRegisters():
        if "general purpose registers" in reg_list.GetName().lower():
            for reg in reg_list:
                reg_state[reg.GetName()] = int(reg.GetValue(), 16)
    return reg_state


def get_section_info(sec):
    name = sec.name if sec.name is not None else ""
    if sec.GetParent().name is not None:
        name = sec.GetParent().name + "." + sec.name

    module_name = sec.addr.module.file.GetFilename()
    module_name = module_name if module_name is not None else ""
    long_name = module_name + "." + name
    load_addr = sec.addr.GetLoadAddress(lldb.debugger.GetSelectedTarget())

    return load_addr, (load_addr + sec.size), sec.size, long_name


def dump_process_memory(output_dir):
    # Segment information dictionary
    raw_segment_list = []
    raw_memory_list = []

    # 1st pass:
    # Loop over the segments, fill in the segment info dictionary
    for module in lldb.debugger.GetSelectedTarget().module_iter():
        for seg_ea in module.section_iter():
            seg_info = {"module": module.file.GetFilename()}
            (
                seg_info["start"],
                seg_info["end"],
                seg_size,
                seg_info["name"],
            ) = get_section_info(seg_ea)
            # TODO: Ugly hack for -1 LONG address on 32-bit
            if seg_info["start"] >= sys.maxsize or seg_size <= 0:
                print ("Throwing away page: {}".format(seg_info["name"]))
                continue

            # Page-align segment
            seg_info["start"] = ALIGN_PAGE_DOWN(seg_info["start"])
            seg_info["end"] = ALIGN_PAGE_UP(seg_info["end"])
            print ("Appending: {}".format(seg_info["name"]))
            raw_segment_list.append(seg_info)

    # Add the stack memory region (just hardcode 0x1000 around the current SP)
    sp = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame().GetSP()
    start_sp = ALIGN_PAGE_DOWN(sp)
    raw_segment_list.append(
        {"start": start_sp, "end": start_sp + 0x1000, "name": "STACK"}
    )

    # Write the original memory to file for debugging
    index_file = open(os.path.join(output_dir, DEBUG_MEM_FILE_NAME), "w")
    index_file.write(json.dumps(raw_segment_list, indent=4))
    index_file.close()

    # Loop over raw memory regions
    mem_info = lldb.SBMemoryRegionInfo()
    start_addr = -1
    next_region_addr = 0
    while next_region_addr > start_addr:
        err = lldb.debugger.GetSelectedTarget().GetProcess().GetMemoryRegionInfo(next_region_addr, mem_info)
        # TODO: Should check err.success.  If False, what do we do?
        if not err.success:
            break
        next_region_addr = mem_info.GetRegionEnd()
        if next_region_addr >= sys.maxsize:
            break

        start_addr = mem_info.GetRegionBase()
        end_addr = mem_info.GetRegionEnd()

        # Unknown region name
        region_name = "UNKNOWN"

        # Ignore regions that aren't even mapped
        if mem_info.IsMapped() and mem_info.IsReadable():
            mem_info_obj = {
                "start": start_addr,
                "end": end_addr,
                "name": region_name,
                "permissions": {
                    "r": mem_info.IsReadable(),
                    "w": mem_info.IsWritable(),
                    "x": mem_info.IsExecutable(),
                },
            }

            raw_memory_list.append(mem_info_obj)

    final_segment_list = overlap_alignments(raw_segment_list, raw_memory_list)

    for seg_info in final_segment_list:
        try:
            seg_info["content_file"] = ""
            start_addr = seg_info["start"]
            end_addr = seg_info["end"]
            region_name = seg_info["name"]
            # Compress and dump the content to a file
            err = lldb.SBError()
            seg_content = lldb.debugger.GetSelectedTarget().GetProcess().ReadMemory(
                start_addr, end_addr - start_addr, err
            )
            if seg_content == None:
                print (
                    "Segment empty: @0x{0:016x} (size:UNKNOWN) {1}".format(
                        start_addr, region_name
                    )
                )
                seg_info["content_file"] = ""
            else:
                print (
                    "Dumping segment @0x{0:016x} (size:0x{1:x}): {2} [{3}]".format(
                        start_addr,
                        len(seg_content),
                        region_name,
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
            print (
                "Exception reading segment ({}): {}".format(
                    region_name, sys.exc_info()[0]
                )
            )

    return final_segment_list


# ----------
# ---- Main


def main():

    try:
        print ("----- Unicorn Context Dumper -----")
        print ("You must be actively debugging before running this!")
        print (
            "If it fails, double check that you are actively debugging before running."
        )

        # Create the output directory
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime(
            "%Y%m%d_%H%M%S"
        )
        output_path = "UnicornContext_" + timestamp
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        print ("Process context will be output to {}".format(output_path))

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
        print ("Done.")

    except Exception as e:
        print ("!!! ERROR:\n\t{}".format(repr(e)))


if __name__ == "__main__":
    lldb.debugger = lldb.SBDebugger.Create()
    main()
elif lldb.debugger:
    main()
