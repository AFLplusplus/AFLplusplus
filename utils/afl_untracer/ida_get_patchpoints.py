#
# IDAPython script for IDA Pro
# Slightly modified from https://github.com/googleprojectzero/p0tools/blob/master/TrapFuzz/findPatchPoints.py
#

import idautils
import idaapi
import ida_nalt
import idc

# See https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml

from os.path import expanduser

home = expanduser("~")

patchpoints = set()

max_offset = 0
for seg_ea in idautils.Segments():
    name = idc.get_segm_name(seg_ea)
    # print("Segment: " + name)
    if name != "__text" and name != ".text":
        continue

    start = idc.get_segm_start(seg_ea)
    end = idc.get_segm_end(seg_ea)
    first = 0
    subtract_addr = 0
    # print("Start: " + hex(start) + " End: " + hex(end))
    for func_ea in idautils.Functions(start, end):
        f = idaapi.get_func(func_ea)
        if not f:
            continue
        for block in idaapi.FlowChart(f):
            if start <= block.start_ea < end:
                if first == 0:
                    if block.start_ea >= 0x1000:
                        subtract_addr = 0x1000
                        first = 1

                max_offset = max(max_offset, block.start_ea)
                patchpoints.add(block.start_ea - subtract_addr)
            # else:
            #    print("Warning: broken CFG?")

# Round up max_offset to page size
size = max_offset
rem = size % 0x1000
if rem != 0:
    size += 0x1000 - rem

print("Writing to " + home + "/Desktop/patches.txt")

with open(home + "/Desktop/patches.txt", "w") as f:
    f.write(ida_nalt.get_root_filename() + ":" + hex(size) + "\n")
    f.write("\n".join(map(hex, sorted(patchpoints))))
    f.write("\n")

print("Done, found {} patchpoints".format(len(patchpoints)))

# For headless script running remove the comment from the next line
# ida_pro.qexit()
