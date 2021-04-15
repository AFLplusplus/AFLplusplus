#!/usr/bin/env python3
# Autodict-QL - Optimal token generation for fuzzing
# Part of AFL++ Project
# Author : Microsvuln - Arash.vre@gmail.com
import string
import os
import binascii
import codecs
import struct
import errno
import argparse
import re
import base64
from binascii import unhexlify


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Helper - Specify input file to analysis and output folder to save corpdirus for constants in the overall project -------  Example usage : python2 thisfile.py outdir o.txt"
        )
    )
    parser.add_argument(
        "corpdir", help="The path to the corpus directory to generate files."
    )
    parser.add_argument(
        "infile",
        help="Specify file output of codeql analysis - ex. ooo-hex.txt, analysis take place on this file, example : python2 thisfile.py outdir out.txt",
    )
    return parser.parse_args()


def ensure_dir(dir):
    try:
        os.makedirs(dir)
    except OSError as e:
        if e.errno == errno.EEXIST:
            # print "[-] Directory exists, specify another directory"
            exit(1)


def do_analysis1(corpdir, infile):
    with open(infile, "rb") as f:
        lines = f.readlines()[1:]
        f.close()
        new_lst = []
        n = 1
        for i, num in enumerate(lines):
            if i != 0:
                new_lst.append(num)
                str1 = str(num)
                print("num is " + str1)
                str1 = str1.rstrip("\n\n")
                # str1 = str1.replace("0x","");
                str1 = str1.replace("|", "")
                str1 = str1.rstrip("\r\n")
                str1 = str1.rstrip("\n")
                str1 = str1.replace(" ", "")
                # str1 = str1.translate(None, string.punctuation)
                translator = str.maketrans("", "", string.punctuation)
                str1 = str1.translate(translator)
                str1 = str1[1:]
                str1 = str1[:-1]
                print("After cleanup : " + str1)
                if (
                    (str1 != "0")
                    and (str1 != "ffffffff")
                    and (str1 != "fffffffe")
                    or (len(str1) == 4)
                    or (len(str1) == 8)
                ):
                    print("first : " + str1)
                    if len(str1) > 8:
                        str1 = str1[:-1]
                    elif len(str1) == 5:
                        str1 = str1 = "0"
                    try:
                        # str1 = str1.decode("hex")
                        with open(corpdir + "/lit-seed{0}".format(n), "w") as file:
                            str1 = str1.replace("0x", "")
                            print(str1)
                            str1 = int(str1, base=16)
                            str1 = str1.to_bytes(4, byteorder="little")
                            file.write(str(str1))
                            file.close()
                            with open(corpdir + "/lit-seed{0}".format(n), "r") as q:
                                a = q.readline()
                                a = a[1:]
                                print(
                                    "AFL++ Autodict-QL by Microsvuln : Writing Token :"
                                    + str(a)
                                )
                                q.close()
                                with open(
                                    corpdir + "/lit-seed{0}".format(n), "w"
                                ) as w1:
                                    w1.write(str(a))
                                    print("Done!")
                                    w1.close()
                    except:
                        print("Error!")
                    n = n + 1


def main():
    args = parse_args()
    ensure_dir(args.corpdir)
    do_analysis1(args.corpdir, args.infile)


if __name__ == "__main__":
    main()
