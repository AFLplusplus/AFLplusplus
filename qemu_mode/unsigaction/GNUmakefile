#
# american fuzzy lop++ - unsigaction
# --------------------------------
#
# Written by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2019-2020 Andrea Fioraldi. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

ifndef AFL_NO_X86

all: lib_i386 lib_amd64

lib_i386:
	@$(CC) -m32 -fPIC -shared unsigaction.c -o unsigaction32.so 2>/dev/null ; if [ "$$?" = "0" ]; then echo "unsigaction32 build success"; else echo "unsigaction32 build failure (that's fine)"; fi

lib_amd64:
	$(CC) -fPIC -shared unsigaction.c -o unsigaction64.so

clean:
	rm -f unsigaction32.so unsigaction64.so

else

all:
	@echo "[!] Note: skipping compilation of unsigaction (AFL_NO_X86 set)."

endif
