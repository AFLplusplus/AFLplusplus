#!/bin/bash
# Test for cmplog buffer over-read bug
cd "$(dirname "$0")/.."
AFL_LLVM_CMPLOG=1 ./afl-clang-fast -o test/test-cmplog-overread test/test-cmplog-overread.c || exit 1
AFL_CMPLOG_DEBUG=1 ./test/test-cmplog-overread
