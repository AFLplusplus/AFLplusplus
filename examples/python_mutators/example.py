#!/usr/bin/env python
# encoding: utf-8
'''
Example Python Module for AFLFuzz

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
    random.seed(seed)
    return 0

def fuzz(buf, add_buf):
    '''
    Called per fuzzing iteration.
    
    @type buf: bytearray
    @param buf: The buffer that should be mutated.
    
    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.
    
    @rtype: bytearray
    @return: A new bytearray containing the mutated data
    '''
    ret = bytearray(buf)
    # Do something interesting with ret

    return ret

# Uncomment and implement the following methods if you want to use a custom
# trimming algorithm. See also the documentation for a better API description.

# def init_trim(buf):
#     '''
#     Called per trimming iteration.
#     
#     @type buf: bytearray
#     @param buf: The buffer that should be trimmed.
#     
#     @rtype: int
#     @return: The maximum number of trimming steps.
#     '''
#     global ...
#     
#     # Initialize global variables
#     
#     # Figure out how many trimming steps are possible.
#     # If this is not possible for your trimming, you can
#     # return 1 instead and always return 0 in post_trim
#     # until you are done (then you return 1).
#         
#     return steps
# 
# def trim():
#     '''
#     Called per trimming iteration.
# 
#     @rtype: bytearray
#     @return: A new bytearray containing the trimmed data.
#     '''
#     global ...
#     
#     # Implement the actual trimming here
#     
#     return bytearray(...)
# 
# def post_trim(success):
#     '''
#     Called after each trimming operation.
#     
#     @type success: bool
#     @param success: Indicates if the last trim operation was successful.
#     
#     @rtype: int
#     @return: The next trim index (0 to max number of steps) where max
#              number of steps indicates the trimming is done.
#     '''
#     global ...
# 
#     if not success:
#         # Restore last known successful input, determine next index
#     else:
#         # Just determine the next index, based on what was successfully
#         # removed in the last step
#     
#     return next_index
