#!/usr/bin/python3
import argparse
from elftools.elf.elffile import ELFFile

def process_file(file, symbol, base):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        mains = symtab.get_symbol_by_name(symbol)
        if len(mains) != 1:
            print ("Failed to find main")
            return 1

        main_addr = mains[0]['st_value']
        main = base + main_addr
        print ("0x%016x" % main)
        return 0

def hex_value(x):
    return int(x, 16)

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-f', '--file', dest='file', type=str,
                    help='elf file name', required=True)
    parser.add_argument('-s', '--symbol', dest='symbol', type=str,
                    help='symbol name', required=True)
    parser.add_argument('-b', '--base', dest='base', type=hex_value,
                    help='elf base address', required=True)

    args = parser.parse_args()
    return process_file (args.file, args.symbol, args.base)

if __name__ == "__main__":
    ret = main()
    exit(ret)
