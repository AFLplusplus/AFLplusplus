#!/usr/bin/env python3

"""This simple script uses objdump to parse important addresses from the target"""
import shlex
import subprocess

objdump_output = subprocess.check_output(
    shlex.split("objdump -M intel -D target")
).decode()
main_loc = None
main_ends = []
main_ended = False
magicfn_calls = []
malloc_calls = []
free_calls = []
strlen_calls = []


def line2addr(line):
    return "0x" + line.split(":", 1)[0].strip()


last_line = None
for line in objdump_output.split("\n"):
    line = line.strip()

    def read_addr_if_endswith(findme, list_to):
        """
        Look, for example, for the addr like:
        12a9:       e8 f2 fd ff ff          call   10a0 <free@plt>
        """
        if line.endswith(findme):
            list_to.append(line2addr(line))

    if main_loc is not None and main_ended is False:
        # We want to know where main ends. An empty line in objdump.
        if len(line) == 0:
            main_ends.append(line2addr(last_line))
            main_ended = True
        elif "ret" in line:
            main_ends.append(line2addr(line))

    if "<main>:" in line:
        if main_loc is not None:
            raise Exception("Found multiple main functions, odd target!")
        # main_loc is the label, so it's parsed differntly (i.e. `0000000000001220 <main>:`)
        main_loc = "0x" + line.strip().split(" ", 1)[0].strip()
    else:
        [
            read_addr_if_endswith(*x)
            for x in [
                ("<free@plt>", free_calls),
                ("<malloc@plt>", malloc_calls),
                ("<strlen@plt>", strlen_calls),
                ("<magicfn>", magicfn_calls),
            ]
        ]

    last_line = line

if main_loc is None:
    raise Exception(
        "Could not find main in ./target! Make sure objdump is installed and the target is compiled."
    )

with open("target.offsets.main", "w") as f:
    f.write(main_loc)
with open("target.offsets.main_ends", "w") as f:
    f.write("\n".join(main_ends))
with open("target.offsets.magicfn", "w") as f:
    f.write("\n".join(magicfn_calls))
with open("target.offsets.malloc", "w") as f:
    f.write("\n".join(malloc_calls))
with open("target.offsets.free", "w") as f:
    f.write("\n".join(free_calls))
with open("target.offsets.strlen", "w") as f:
    f.write("\n".join(strlen_calls))
