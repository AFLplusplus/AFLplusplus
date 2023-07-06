# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import struct
import sys
import subprocess
import json
import os

def read_modinfo(file):
    modinfo = {}
    with open(file, 'r') as f:
        for x in f.readlines():
            fn, start, stop = x.rsplit(" ", 2)
            modinfo[fn] = (int(start), int(stop))
    return modinfo


def get_line_cluster(line_clusters, name, line):
    if not line_clusters or name not in line_clusters:
        return [line]
    for x in line_clusters[name]:
        if line in x:
            return x
    return [line]


def read_pointers(file):
    pointer_list = []
    with open(file, 'rb') as f:
        while True:
            pointer = f.read(8)
            if not pointer:
                break
            pointer = struct.unpack('<Q', pointer)[0]
            pointer += 1
            pointer_list.append(hex(pointer))
    return pointer_list


def read_bitmap(file):
    bitmap = []
    with open(file, 'rb') as f:
        while True:
            bit8 = f.read(1)
            if not bit8:
                break
            bit8 = struct.unpack('<B', bit8)[0]
            bitmap.append(bit8)
    return bitmap


def main():
    line_clusters = None

    if len(sys.argv) != 5:
        print("Usage: %s /path/to/workdir/dump/ build_prefix scm_rev outfile" % os.path.basename(sys.argv[0]))
        sys.exit(1)

    dump_folder = sys.argv[1]
    prefix = sys.argv[2]
    rev = sys.argv[3]
    outfile = sys.argv[4]

    if not prefix.endswith("/"):
        prefix += "/"

    pointers_file = os.path.join(dump_folder, "pcmap.dump")
    bitmap_file = os.path.join(dump_folder, "covmap.dump")
    modinfo_file = os.path.join(dump_folder, "modinfo.txt")
    lineclusters_file = os.path.join(dump_folder, "lineclusters.json")

    pointers = read_pointers(pointers_file)
    bitmap = read_bitmap(bitmap_file)
    modinfo = read_modinfo(modinfo_file)

    if len(pointers) != len(bitmap):
        print("ERROR: Length mismatch: len(pointers) != len(bitmap)", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(lineclusters_file):
        with open(lineclusters_file, 'r') as fd:
            line_clusters = json.load(fd)

    merged_locations = [''] * len(bitmap)

    unresolved = 0
    covered = 0

    for mod_path in modinfo:
        start_idx = modinfo[mod_path][0]
        stop_idx = modinfo[mod_path][1]


        symbolize = []

        for idx, pointer in enumerate(pointers):
            if start_idx <= idx < stop_idx:
                if pointer == "0x0":
                    unresolved += 1
                    # Important to be able to match entries to original bitmap by index
                    symbolize.append("")
                else:
                    symbolize.append("%s" % pointer)
                    if bitmap[idx] > 0:
                        covered += 1

        addr2line = subprocess.Popen(
            ['llvm-addr2line', '-C', '-e', mod_path],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        locations = addr2line.communicate(input="\n".join(symbolize).encode())[0].decode().split("\n")

        for idx, location in enumerate(locations):
            merged_locations[start_idx + idx] = location

    print("Total unresolved: %s" % unresolved, file=sys.stderr)
    print("Total covered: %s" % covered, file=sys.stderr)
    print("Total uncovered: %s" % (len(bitmap) - covered), file=sys.stderr)

    covobj = {
        "source_files": [],
        "git": {"head": {"id": rev}, "branch": "main"}
    }

    name2obj = {}

    for idx, location in enumerate(merged_locations):
        # Check if this is an unresolvable location
        if not location:
            continue

        try:
            name, line = location.rsplit(":", 1)
        except:
            print("WARNING: Failed to split line number: %s" % location)
            continue

        name = name.replace(prefix, "", 1)
        if name.startswith("objdir"):
            continue

        try:
            line = int(line)
        except:
            print("WARNING: Failed to convert line number: %s" % location)
            continue

        if name not in name2obj:
            source_file = {
                "name": name,
                "coverage": [None] * line
            }

            name2obj[name] = source_file
            covobj["source_files"].append(source_file)

        lines = get_line_cluster(line_clusters, name, line)

        for line in lines:
            while len(name2obj[name]["coverage"]) <= line:
                name2obj[name]["coverage"].append(None)
            name2obj[name]["coverage"][line - 1] = bitmap[idx]

    with open(outfile, "w") as fd:
        json.dump(covobj, fd)


if __name__ == "__main__":
    main()

