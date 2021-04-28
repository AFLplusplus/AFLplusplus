#!/usr/bin/env python3
import argparse
from elftools.elf.elffile import ELFFile


def process_file(file, section, base):
    with open(file, "rb") as f:
        for sect in ELFFile(f).iter_sections():
            if sect.name == section:
                start = base + sect.header["sh_offset"]
                end = start + sect.header["sh_size"]
                print("0x%016x-0x%016x" % (start, end))
                return

    print("Section '%s' not found in '%s'" % (section, file))


def hex_value(x):
    return int(x, 16)


def main():
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument(
        "-f", "--file", dest="file", type=str, help="elf file name", required=True
    )
    parser.add_argument(
        "-s",
        "--section",
        dest="section",
        type=str,
        help="elf section name",
        required=True,
    )
    parser.add_argument(
        "-b",
        "--base",
        dest="base",
        type=hex_value,
        help="elf base address",
        required=True,
    )

    args = parser.parse_args()
    process_file(args.file, args.section, args.base)


if __name__ == "__main__":
    main()
