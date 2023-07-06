# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import struct
import sys
import glob
import logging
import json

GCOV_TAG_FUNCTION = b'\x00\x00\x00\x01'
GCOV_TAG_BLOCKS = b'\x00\x00\x41\x01'
GCOV_TAG_ARCS = b'\x00\x00\x43\x01'
GCOV_TAG_LINES = b'\x00\x00\x45\x01'
GCOV_TAG_COUNTER_ARCS = b'\x00\x00\xa1\x01'
GCOV_TAG_OBJECT_SUMMARY = b'\x00\x00\x00\xa1'
GCOV_TAG_PROGRAM_SUMMARY = b'\x00\x00\x00\xa3'
GCOV_TAG_END = b'\x00\x00\x00\x00'

global_blocks = {}

#logging.basicConfig(level=logging.DEBUG)

def read_gcno_file(filename, target_file = None):
    with open(filename, 'rb') as f:
        magic_number = f.read(4)
        version = f.read(4)
        checksum = f.read(4)


        local_blocks = {}

        blocks = []
        src_file = None
        blocks_recorded = False

        while True:
            tag, length = read_tag(f)
            # Function 
            if tag == GCOV_TAG_FUNCTION:
                f.read(length * 4)
            elif tag == GCOV_TAG_BLOCKS:
                # Reset blocks and src file
                blocks = []
                src_file = None

                for i in range(length):
                    read_counter(f)
                    blocks.append({'no': i, 'lines': []})
                logging.debug("Read %s blocks" % len(blocks))
                blocks_recorded = False
            elif tag == GCOV_TAG_ARCS:
                f.read(length * 4)
            elif tag == GCOV_TAG_LINES:
                logging.debug("Reading GCOV_TAG_LINES")
                block_no = read_counter(f)
                block_offset = 0
                logging.debug("Block %s" % block_no)
                lines = []
                if block_no < len(blocks):
                    while True:
                        line_no = read_counter(f)
                        if line_no > 0:
                            if not src_file:
                                logging.error("No source file in block?")
                                sys.exit(1)
                            if target_file is None or src_file.endswith(target_file):
                                blocks[block_no]['lines'].append(line_no)
                        else:
                            src_file = read_string(f)
                            if not src_file:
                                break

                            if not blocks_recorded and (target_file is None or src_file.endswith(target_file)):

                                if not src_file in local_blocks:
                                    local_blocks[src_file] = [ blocks ]
                                    logging.info("Reading block for %s, expecting %s blocks" % (src_file, len(blocks)))
                                elif src_file in local_blocks:
                                    logging.info("Got another src_file for %s, now expecting %s blocks" % (src_file, len(blocks)))
                                    local_blocks[src_file].append(blocks)
                            
                                # This loop actually alternates between reading lines and reading strings.
                                # That means, it reads the same file string multiple times without actually
                                # entering a new `GCOV_TAG_BLOCKS` section. We must avoid adding `blocks`
                                # times or we end up duplicating a lot of lines.
                                blocks_recorded = True

                            elif blocks_recorded:
                                if len(blocks) != len(local_blocks[src_file][-1]):
                                    logging.error("ERROR: Size mismatch?!")
                                    sys.exit(1)

                else:
                    raise ValueError('Invalid block number: %s' % block_no)

            elif tag == GCOV_TAG_COUNTER_ARCS:
                f.read(length * 4)
            elif tag == GCOV_TAG_OBJECT_SUMMARY:
                f.read(length * 4)
            elif tag == GCOV_TAG_PROGRAM_SUMMARY:
                f.read(length * 4)
            elif tag == GCOV_TAG_END:
                break
            else:
                raise ValueError('Invalid tag: %s' % tag)

        for src_file in local_blocks:
            if not src_file in global_blocks:
                global_blocks[src_file] = []
            for blocks in local_blocks[src_file]:
                for x in blocks:
                    if x['lines']:
                        global_blocks[src_file].append(tuple(x['lines']))

def read_tag(f):
    tag = f.read(4)
    length_bytes = f.read(4)
    length = struct.unpack('<I', length_bytes)[0]
    return tag, length

def read_counter(f):
    counter_bytes = f.read(4)
    counter = struct.unpack('<I', counter_bytes)[0]
    return counter

def read_string(f):
    len_bytes = f.read(4)
    len_str = struct.unpack('<I', len_bytes)[0] * 4
    return f.read(len_str).decode().rstrip('\x00')

def read_block(f):
    flags_bytes = f.read(4)
    flags = struct.unpack('<I', flags_bytes)[0]
    block_num_bytes = f.read(4)
    block_num = struct.unpack('<I', block_num_bytes)[0]
    num_lines_bytes = f.read(4)
    num_lines = struct.unpack('<I', num_lines_bytes)[0]
    lines = []
    for i in range(num_lines):
        line_bytes = f.read(4)
        line = struct.unpack('<I', line_bytes)[0]
        lines.append(line)
    block = {'flags': flags, 'block_num': block_num, 'num_lines': num_lines, 'lines': lines}
    return block

def read_line_counts(f):
    line_counts = []
    while True:
        count_bytes = f.read(4)
        count = struct.unpack('<I', count_bytes)[0]
        if count == 0:
            break
        line_counts.append(count)
    return line_counts

def read_lines(f, count):
    lines = set()
    for i in range(count):
        line_bytes = f.read(4)
        line = struct.unpack('<I', line_bytes)[0]
        lines.add(line)
    return lines

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: %s outfile (path/to/dir|path/to/file.gcno) prefix [target_source_file]" % os.path.basename(sys.argv[0]))
        sys.exit(1)

    outfile = sys.argv[1]
    target = sys.argv[2]
    prefix = sys.argv[3]

    if target.endswith(".gcno"):
        # Single gcno file for debugging
        logging.basicConfig(level=logging.WARN)
        target_file = None
        if len(sys.argv) == 5:
            target_file = sys.argv[4]
        read_gcno_file(target, target_file)
    else:
        # Whole tree
        for filename in glob.glob(target + '**/*.gcno', recursive=True):
            logging.debug(filename)
            read_gcno_file(filename)

    global_blocks_processed = {}

    for src_file in global_blocks:
        new_src_file = src_file.replace(prefix, "", 1)
        global_blocks_processed[new_src_file] = list(set(global_blocks[src_file]))

    data = json.dumps(global_blocks_processed, indent=4)

    with open(outfile, 'w') as fd:
        print(data, file=fd)
