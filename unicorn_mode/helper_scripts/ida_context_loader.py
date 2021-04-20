# Copyright (c) 2021 Brandon Miller (zznop)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""IDA script for loading state that was dumped from a running process using unicorn AFL's GDB
plugin (unicorn_dumper_gdb.py). The dumper script can be found in the AFL++ repository at:
https://github.com/AFLplusplus/AFLplusplus/blob/stable/unicorn_mode/helper_scripts/unicorn_dumper_gdb.py
"""

import json
from pathlib import Path, PurePath
import zlib
import idaapi
import ida_bytes
import ida_kernwin
import ida_nalt
import ida_segment


class ContextLoaderError(Exception):
    """Base "catch all" exception for this script"""


class ArchNotSupportedError(ContextLoaderError):
    """Exception raised if the input file CPU architecture isn't supported fully"""


def parse_mapping_index(filepath: str):
    """Open and unmarshal the _index.json file

    :param filepath: Path to the JSON file
    :return: Dict representing index file contents
    """

    if filepath is None:
        raise ContextLoaderError("_index.json file was not selected")

    try:
        with open(filepath, "rb") as _file:
            return json.load(_file)
    except Exception as ex:
        raise ContextLoaderError(
            "Failed to parse json file {}".format(filepath)
        ) from ex


def get_input_name():
    """Get the name of the input file

    :retrun: Name of the input file
    """

    input_filepath = ida_nalt.get_input_file_path()
    return Path(input_filepath).name


def write_segment_bytes(start: int, filepath: str):
    """ "Read data from context file and write it to the IDA segment

    :param start: Start address
    :param filepath: Path to context file
    """

    with open(filepath, "rb") as _file:
        data = _file.read()

    decompressed_data = zlib.decompress(data)
    ida_bytes.put_bytes(start, decompressed_data)


def create_segment(context_dir: str, segment: dict, is_be: bool):
    """Create segment in IDA and map in the data from the file

    :param context_dir: Parent directory of the context files
    :param segment: Segment information from _index.json
    :param is_be: True if processor is big endian, otherwise False
    """

    input_name = get_input_name()
    if Path(segment["name"]).name != input_name:
        ida_seg = idaapi.segment_t()
        ida_seg.start_ea = segment["start"]
        ida_seg.end_ea = segment["end"]
        ida_seg.bitness = 1 if is_be else 0
        if segment["permissions"]["r"]:
            ida_seg.perm |= ida_segment.SEGPERM_READ
        if segment["permissions"]["w"]:
            ida_seg.perm |= ida_segment.SEGPERM_WRITE
        if segment["permissions"]["x"]:
            ida_seg.perm |= ida_segment.SEGPERM_EXEC
            idaapi.add_segm_ex(
                ida_seg, Path(segment["name"]).name, "CODE", idaapi.ADDSEG_OR_DIE
            )
        else:
            idaapi.add_segm_ex(
                ida_seg, Path(segment["name"]).name, "DATA", idaapi.ADDSEG_OR_DIE
            )

    if segment["content_file"]:
        write_segment_bytes(
            segment["start"], PurePath(context_dir, segment["content_file"])
        )


def create_segments(index: dict, context_dir: str):
    """Iterate segments in index JSON, create the segment in IDA, and map in the data from the file

    :param index: _index.json JSON data
    :param context_dir: Parent directory of the context files
    """

    info = idaapi.get_inf_structure()
    is_be = info.is_be()
    for segment in index["segments"]:
        create_segment(context_dir, segment, is_be)


def rebase_program(index: dict):
    """Rebase the program to the offset specified in the context _index.json

    :param index: _index.json JSON data
    """

    input_name = get_input_name()
    new_base = None
    for segment in index["segments"]:
        if not segment["name"]:
            continue

        segment_name = Path(segment["name"]).name
        if input_name == segment_name:
            new_base = segment["start"]
            break

    if not new_base:
        raise ContextLoaderError("Input file is not in _index.json")

    current_base = idaapi.get_imagebase()
    ida_segment.rebase_program(new_base - current_base, 8)


def get_pc_by_arch(index: dict) -> int:
    """Queries the input file CPU architecture and attempts to lookup the address of the program
    counter in the _index.json by register name

    :param index: _index.json JSON data
    :return: Program counter value or None
    """

    progctr = None
    info = idaapi.get_inf_structure()
    if info.procname == "metapc":
        if info.is_64bit():
            progctr = index["regs"]["rax"]
        elif info.is_32bit():
            progctr = index["regs"]["eax"]
    return progctr


def write_reg_info(index: dict):
    """Write register info as line comment at instruction pointed to by the program counter and
    change focus to that location

    :param index: _index.json JSON data
    """

    cmt = ""
    for reg, val in index["regs"].items():
        cmt += f"{reg.ljust(6)} : {hex(val)}\n"

    progctr = get_pc_by_arch(index)
    if progctr is None:
        raise ArchNotSupportedError(
            "Architecture not fully supported, skipping register status comment"
        )
    ida_bytes.set_cmt(progctr, cmt, 0)
    ida_kernwin.jumpto(progctr)


def main(filepath):
    """Main - parse _index.json input and map context files into the database

    :param filepath: Path to the _index.json file
    """

    try:
        index = parse_mapping_index(filepath)
        context_dir = Path(filepath).parent
        rebase_program(index)
        create_segments(index, context_dir)
        write_reg_info(index)
    except ContextLoaderError as ex:
        print(ex)


if __name__ == "__main__":
    main(ida_kernwin.ask_file(1, "*.json", "Import file name"))
