#!/usr/bin/env python3
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
    parser = argparse.ArgumentParser(description=(
        "Helper - Specify input file analysis and output folder to save corpus for strings in the overall project ---------------------------------------------------------------------------  Example usage : python2 thisfile.py outdir str.txt"    ))
    
    #parser.add_argument("tokenpath",
        #help="Destination directory for tokens")
    parser.add_argument("cur",
            help = "Current Path")
    parser.add_argument("db",
            help = "CodeQL database Path")
    parser.add_argument("tokenpath",
            help="Destination directory for tokens")

    return parser.parse_args()

def static_analysis(file,file2,cur,db) :
    with open(cur+"/"+file, "w") as f:
        print(cur+"/"+file)
        stream = os.popen("codeql query run " + cur +"/"+ file2 +  " -d " + db )
        output = stream.read()
        f.write(output)
        f.close()

def copy_tokens(cur, tokenpath) :
    subprocess.call(["cp " + cur  + "/" + "arrays-lits/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "strstr-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "strcmp-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "strncmp-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "local-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "memcmp-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "global-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "lits/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "arrays-lits/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "arrays-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    subprocess.call(["cp " + cur  + "/" + "strtool-strs/*" + " " + cur + "/" + tokenpath + "/."] ,shell=True)
    #strtool-strs


def codeql_analysis(cur, db) :
    static_analysis("litout.out","litool.ql", cur, db)
    static_analysis("strcmp-strings.out","strcmp-str.ql", cur, db)
    static_analysis("strncmp-strings.out","strncmp-str.ql", cur, db)
    static_analysis("strstr-strings.out","strstr-str.ql", cur, db)
    static_analysis("memcmp-strings.out","memcmp-str.ql", cur, db)
    static_analysis("global-values-strings.out","globals-values.ql", cur, db)
    static_analysis("local-strings.out","locals-strs.ql", cur, db)
    static_analysis("strtool-strings.out","strtool.ql", cur, db)
    static_analysis("arrays.out","array-literals.ql", cur, db)
    start_aflql(0,cur)
    #command1 = [
    #       'codeql','query', 'run',
    #       cur + '/litool.ql',
    #       '-d',
    #       db, '>','fff.txt'
    #    ]
    #with open("litool2.log", "w") as f:
    #    stream = os.popen("codeql query run litool.ql -d " + db )
    #    output = stream.read()
    #    f.write(output)
    #    f.close()
    #worker1 = subprocess.Popen(command1)
    #print(worker1.communicate())


def start_aflql(tokenpath, cur):
    command = [
           'python3',
           cur + '/litan.py',
           cur+'/lits/',
           cur+'/litout.out'
        ]
    worker1 = subprocess.Popen(command)
    print(worker1.communicate())
    
    command1 = [
           'python3',
           cur + '/strcmp-strings.py',
           cur + '/strcmp-strs/',
           cur + '/strcmp-strings.out'
        ]
    worker2 = subprocess.Popen(command1)
    print(worker2.communicate())

    command2 = [
           'python3',
           cur + '/strncmp-strings.py',
           cur + '/strncmp-strs/',
           cur + '/strncmp-strings.out'
        ]
    worker3 = subprocess.Popen(command2)
    print(worker3.communicate())

    command3 = [
           'python3',
           cur + '/array-lits.py',
           cur + '/arrays-lits/',
           cur + '/arrays.out'
        ]
    worker4 = subprocess.Popen(command3)
    print(worker4.communicate())

    command4 = [
           'python3',
           cur + '/array-strings.py',
           cur + '/arrays-strs/',
           cur + '/arrays.out'
        ]
    worker5 = subprocess.Popen(command4)
    print(worker5.communicate())


    command5 = [
           'python3',
           cur + '/memcmp-strings.py',
           cur + '/memcmp-strs/',
           cur + '/memcmp-strings.out'
        ]
    worker6 = subprocess.Popen(command5)
    print(worker6.communicate())

    command6 = [
           'python3',
           cur + '/globals-strings.py',
           cur + '/global-strs/',
           cur + '/global-values-strings.out'
        ]
    worker7 = subprocess.Popen(command6)
    print(worker7.communicate())

    command7 = [
           'python3',
           cur + '/strstr-strings.py',
           cur + '/strstr-strs/',
           cur + '/strstr-strings.out'
        ]
    worker8 = subprocess.Popen(command7)
    print(worker8.communicate())


    #strtool-strings.out

    command8 = [
           'python3',
           cur + '/stan-strings.py',
           cur + '/strtool-strs/',
           cur + '/strtool-strings.out'
        ]
    worker9 = subprocess.Popen(command8)
    print(worker9.communicate())

    command9 = [
           'python3',
           cur + '/local-strings.py',
           cur + '/local-strs/',
           cur + '/local-strings.out'
        ]
    worker10 = subprocess.Popen(command9)
    print(worker10.communicate())

def main():
    args = parse_args()    
    ensure_dir(args.tokenpath)
    #copy_tokens(args.cur, args.tokenpath)
    codeql_analysis(args.cur, args.db)
    copy_tokens(args.cur, args.tokenpath)
    #start_aflql(args.tokenpath, args.cur)
if __name__ == '__main__':
    main()