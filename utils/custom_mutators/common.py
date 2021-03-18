#!/usr/bin/env python
# encoding: utf-8
"""
Module containing functions shared between multiple AFL modules

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
"""

from __future__ import print_function
import random
import os
import re


def randel(l):
    if not l:
        return None
    return l[random.randint(0, len(l) - 1)]


def randel_pop(l):
    if not l:
        return None
    return l.pop(random.randint(0, len(l) - 1))


def write_exc_example(data, exc):
    exc_name = re.sub(r"[^a-zA-Z0-9]", "_", repr(exc))

    if not os.path.exists(exc_name):
        with open(exc_name, "w") as f:
            f.write(data)
