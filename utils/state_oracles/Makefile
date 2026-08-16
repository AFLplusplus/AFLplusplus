#
# american fuzzy lop++ - optional oracle helpers
# ----------------------------------------------
#
# Written by Marc Heuse <mh@mh-sec.de>
#
# Copyright 2019-2026 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#

CC       ?= cc
CFLAGS   ?= -O2 -g -Wall -Wextra
LDFLAGS  ?=

# The self-tests are built at -O0 with -fno-builtin on purpose: a leak
# self-test once reported "clean" at -O1 because the compiler deleted the
# leak. A detector never seen to fire is not known to work.
TEST_CFLAGS = -O0 -g -fno-builtin -Wall -Wextra

TESTS = tests/roundtrip_good tests/roundtrip_bad \
        tests/exactbuf_good  tests/exactbuf_bad  \
        tests/allocfail_good tests/allocfail_bad \
        tests/perturb_good   tests/perturb_bad

.PHONY: all tests selftest clean

all: afl_allocfail.so

tests: $(TESTS)

afl_allocfail.so: afl_allocfail.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl

tests/%: tests/%.c afl-oracles.h
	$(CC) $(TEST_CFLAGS) -o $@ $<

selftest: all tests
	./tests/run-selftests.sh

clean:
	rm -f afl_allocfail.so $(TESTS)
