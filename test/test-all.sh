#!/bin/sh

source ./test-pre.sh

source ./test-basic.sh

source ./test-llvm.sh

source ./test-llvm-lto.sh

source ./test-gcc-plugin.sh

source ./test-compcov.sh

source ./test-qemu-mode.sh

source ./test-unicorn-mode.sh

source ./test-custom-mutators.sh

source ./test-unittests.sh

source ./test-post.sh
