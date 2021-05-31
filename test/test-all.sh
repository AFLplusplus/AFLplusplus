#!/bin/sh

. ./test-pre.sh

. ./test-basic.sh

. ./test-llvm.sh

. ./test-llvm-lto.sh

. ./test-gcc-plugin.sh

. ./test-libextensions.sh

. ./test-qemu-mode.sh

. ./test-frida-mode.sh

. ./test-unicorn-mode.sh

. ./test-custom-mutators.sh

. ./test-unittests.sh

. ./test-post.sh
