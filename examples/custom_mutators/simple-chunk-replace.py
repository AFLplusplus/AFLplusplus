#!/usr/bin/env python
# encoding: utf-8
'''
Simple Chunk Cross-Over Replacement Module for AFLFuzz

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''

import random


def init(seed):
    '''
    Called once when AFLFuzz starts up. Used to seed our RNG.

    @type seed: int
    @param seed: A 32-bit random value
    '''
    # Seed our RNG
    random.seed(seed)


def fuzz(buf, add_buf, max_size):
    '''
    Called per fuzzing iteration.

    @type buf: bytearray
    @param buf: The buffer that should be mutated.

    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.

    @type max_size: int
    @param max_size: Maximum size of the mutated output. The mutation must not
        produce data larger than max_size.

    @rtype: bytearray
    @return: A new bytearray containing the mutated data
    '''
    # Make a copy of our input buffer for returning
    ret = bytearray(buf)

    # Take a random fragment length between 2 and 32 (or less if add_buf is shorter)
    fragment_len = random.randint(1, min(len(add_buf), 32))

    # Determine a random source index where to take the data chunk from
    rand_src_idx = random.randint(0, len(add_buf) - fragment_len)

    # Determine a random destination index where to put the data chunk
    rand_dst_idx = random.randint(0, len(buf))

    # Make the chunk replacement
    ret[rand_dst_idx:rand_dst_idx + fragment_len] = add_buf[rand_src_idx:rand_src_idx + fragment_len]

    # Return data
    return ret
