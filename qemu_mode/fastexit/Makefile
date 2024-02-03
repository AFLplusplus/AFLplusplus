#
# american fuzzy lop++ - fastexit
# --------------------------------
#
# Written by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2019-2024 Andrea Fioraldi. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

TARGETS=fastexit.so fastexit32.so fastexit64.so

all:  $(TARGETS)

fastexit.so: fastexit.c
	@if $(CC) -fPIC -shared fastexit.c -o fastexit.so 2>/dev/null ; then echo "fastexit build success"; else echo "fastexit build failure (that's fine)"; fi

fastexit32.so: fastexit.c
	@if $(CC) -fPIC -m32 -shared fastexit.c -o fastexit32.so 2>/dev/null ; then echo "fastexit32 build success"; else echo "fastexit32 build failure (that's fine)"; fi

fastexit64.so: fastexit.c
	@if $(CC) -fPIC -m64 -shared fastexit.c -o fastexit64.so 2>/dev/null ; then echo "fastexit64 build success"; else echo "fastexit64 build failure (that's fine)"; fi

clean:
	rm -f fastexit.so
