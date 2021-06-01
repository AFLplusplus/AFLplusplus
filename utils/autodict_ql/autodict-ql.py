#!/usr/bin/env python3
# AutoDict-QL - Optimal Token Generation for Fuzzing
# Part of AFL++ Project
# Developed and Maintained by Arash Ale Ebrahim (@Microsvuln)
# Usage : python3 autodict-ql.py [CURRECT_DIR] [CODEQL_DATABASE_PATH] [TOKEN_PATH]
# CURRENT_DIR = full of your current Dir
# CODEQL_DATABASE_PATH = Full path to your CodeQL database
# TOKEN_PATH = Folder name of the newly generated tokens
# Example : python3 autodict-ql.py /home/user/libxml/automate /home/user/libxml/libxml-db tokens
# Just pass the tokens folder to the -x flag of your fuzzer

import os
import string
import binascii
import codecs
import errno
import struct
import argparse
import shutil
import subprocess

from binascii import unhexlify


def ensure_dir(dir):
    try:
        os.makedirs(dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Helper - Specify input file analysis and output folder to save corpus for strings in the overall project ---------------------------------------------------------------------------  Example usage : python2 thisfile.py outdir str.txt"
        )
    )

    # parser.add_argument("tokenpath",
    # help="Destination directory for tokens")
    parser.add_argument("cur", help="Current Path")
    parser.add_argument("db", help="CodeQL database Path")
    parser.add_argument("tokenpath", help="Destination directory for tokens")

    return parser.parse_args()


def static_analysis(file, file2, cur, db):
    with open(cur + "/" + file, "w") as f:
        print(cur + "/" + file)
        stream = os.popen("codeql query run " + cur + "/" + file2 + " -d " + db)
        output = stream.read()
        f.write(output)
        f.close()


def copy_tokens(cur, tokenpath):
    subprocess.call(
        ["mv " + cur + "/" + "strcmp-strs/*" + " " + cur + "/" + tokenpath + "/."],
        shell=True,
    )
    subprocess.call(
        ["mv " + cur + "/" + "strncmp-strs/*" + " " + cur + "/" + tokenpath + "/."],
        shell=True,
    )
    subprocess.call(
        ["mv " + cur + "/" + "memcmp-strs/*" + " " + cur + "/" + tokenpath + "/."],
        shell=True,
    )
    subprocess.call(
        ["mv " + cur + "/" + "lits/*" + " " + cur + "/" + tokenpath + "/."], shell=True
    )
    subprocess.call(
        ["mv " + cur + "/" + "strtool-strs/*" + " " + cur + "/" + tokenpath + "/."],
        shell=True,
    )
    subprocess.call(
        ["rm -rf strcmp-strs memcmp-strs strncmp-strs lits strtool-strs"], shell=True
    )
    subprocess.call(["rm *.out"], shell=True)
    subprocess.call(["find " + tokenpath + " -size 0 -delete"], shell=True)


def codeql_analysis(cur, db):
    static_analysis("litout.out", "litool.ql", cur, db)
    static_analysis("strcmp-strings.out", "strcmp-str.ql", cur, db)
    static_analysis("strncmp-strings.out", "strncmp-str.ql", cur, db)
    static_analysis("memcmp-strings.out", "memcmp-str.ql", cur, db)
    static_analysis("strtool-strings.out", "strtool.ql", cur, db)
    start_autodict(0, cur)


def start_autodict(tokenpath, cur):
    command = ["python3", cur + "/litan.py", cur + "/lits/", cur + "/litout.out"]
    worker1 = subprocess.Popen(command)
    print(worker1.communicate())

    command1 = [
        "python3",
        cur + "/strcmp-strings.py",
        cur + "/strcmp-strs/",
        cur + "/strcmp-strings.out",
    ]
    worker2 = subprocess.Popen(command1)
    print(worker2.communicate())

    command2 = [
        "python3",
        cur + "/strncmp-strings.py",
        cur + "/strncmp-strs/",
        cur + "/strncmp-strings.out",
    ]
    worker3 = subprocess.Popen(command2)
    print(worker3.communicate())

    command5 = [
        "python3",
        cur + "/memcmp-strings.py",
        cur + "/memcmp-strs/",
        cur + "/memcmp-strings.out",
    ]
    worker6 = subprocess.Popen(command5)
    print(worker6.communicate())

    command8 = [
        "python3",
        cur + "/stan-strings.py",
        cur + "/strtool-strs/",
        cur + "/strtool-strings.out",
    ]
    worker9 = subprocess.Popen(command8)
    print(worker9.communicate())


def main():
    args = parse_args()
    ensure_dir(args.tokenpath)
    # copy_tokens(args.cur, args.tokenpath)
    codeql_analysis(args.cur, args.db)
    copy_tokens(args.cur, args.tokenpath)
    # start_autodict(args.tokenpath, args.cur)


if __name__ == "__main__":
    main()
