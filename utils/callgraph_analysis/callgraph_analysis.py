#!/usr/bin/env python3
#
# american fuzzy lop++ - callgraph analysis script
# ------------------------------------------------
#
# (c) 2021 Marc Heuse <mh@mh-sec.de>
#
# python script a single parameter: fuzz.cg
#   fuzz.cg is generated with with afl-clang-lto + AFL_LLVM_LTO_CALLGRAPH=1
#
# 1. run c++filt on both .cg inputs
# 2. parse fuzz-harness.cg, remove all functions that just have on external call
#    keep an array of it's functions and the one it is calling
# 3. parse fuzz.cg, remove all functions that just have an external call.
# 4. loop on fuzz-harness.cg array, look for these functions in fuzz.cg,
#    remove them from both fuzz-harness.cg and fuzz.cg array when found and
#    add the callers into fuzz-harness.cg array instead.
# 5. resulting functions in fuzz-harness.cg array are unreachable
#

import subprocess
import sys
import os
import re

new_function = re.compile('^Call graph node for function:')
is_external = re.compile('calls external')
is_call = re.compile('calls function')
is_empty = re.compile('^\s*$')

all_functions = []
entries = []
calls = []
entry = { 'caller': '', 'calls': [''] }
func = ''
i = 0

print()
print('Analysing ' + sys.argv[1] + " for unreachable functions...")

with open(sys.argv[1]) as f:
    for line in f:
        #print(line)
        if new_function.match(line):
            if not len(func) == 0:
                print('Error: invalid input: ' + line)
                exit(1)
            func = line.split("'")[1]
            if len(func) > 0:
                all_functions.append(func)
            calls.clear()
        elif is_call.search(line):
            if len(func) > 0:
                call = line.split("'")[1]
                calls.append(call);
        elif is_empty.match(line):
            if len(calls) > 0 and len(func) > 0:
                calls_u = list(dict.fromkeys(calls))
                entry = { 'func' : func, 'calls' : calls_u }
                entries.append(entry)
            func = ''
            calls.clear()
        elif not is_external.search(line):
            #print('Ignoring line: ' + line)
            i += 1 # ignored

found = 0
for entry in entries:
    if entry['func'] == 'main':
        found = 1
        break
if found:
    follow = ['main']
else:
    follow = ['LLVMFuzzerInitialize', 'LLVMFuzzerTestOneInput']

for f in follow:
    for entry in entries:
        if entry['func'] == f:
            #print('follow: ' + f + ' => ' + str(entry['calls']))
            for call in entry['calls']:
                follow.append(call)
            entries.remove(entry)
            break

print('Analysis done, printing results.')
print('Note that CTORs/DTORs/callbacks-only functions will be in the unreachable list.')
print()

for entry in entries:
    print('Unreachable: ' + entry['func'])
