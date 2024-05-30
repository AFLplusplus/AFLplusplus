# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Written by Christian Holler <decoder at mozilla dot com>

import json
import os
import sys
import subprocess

if len(sys.argv) != 2:
    print("Usage: %s binfile" % os.path.basename(sys.argv[0]))
    sys.exit(1)

binfile = sys.argv[1]

addr2len = {}
addrs = []

output = subprocess.check_output(["objdump", "-t", binfile]).decode("utf-8")
for line in output.splitlines():
    line = line.replace("\t", " ")
    components = [x for x in line.split(" ") if x]
    if not components:
        continue
    try:
        start_addr = int(components[0], 16)
    except ValueError:
        continue

    # Length has variable position in objdump output
    length = None
    for comp in components[1:]:
        if len(comp) == 16:
            try:
                length = int(comp, 16)
                break
            except:
                continue

    if length is None:
        print("ERROR: Couldn't determine function section length: %s" % line)

    func = components[-1]
    
    addrs.append(start_addr)
    addr2len[str(hex(start_addr))] = str(length)

# The search implementation in the AFL runtime expects everything sorted.
addrs.sort()
addrs = [str(hex(addr)) for addr in addrs]

# We symbolize in one go to speed things up with large binaries.
output = subprocess.check_output([
    "llvm-addr2line",
    "--output-style=JSON",
    "-f", "-C", "-a", "-e",
    binfile],
    input="\n".join(addrs).encode("utf-8")).decode("utf-8")

output = output.strip().splitlines()
for line in output:
    output = json.loads(line)
    if "Symbol" in output and output["Address"] in addr2len:
        final_output = [
            output["Address"],
            addr2len[output["Address"]],
            os.path.basename(output["ModuleName"]),
            output["Symbol"][0]["FileName"],
            output["Symbol"][0]["FunctionName"]
        ]
        print("\t".join(final_output))
