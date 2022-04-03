#
# american fuzzy lop++ - unsigaction
# --------------------------------
#
# Written by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2019-2022 Andrea Fioraldi. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

TARGETS=unsigaction.so unsigaction32.so unsigaction64.so

all:  $(TARGETS)

unsigaction.so: unsigaction.c
	@if $(CC) -fPIC -shared unsigaction.c -o unsigaction.so 2>/dev/null ; then echo "unsigaction build success"; else echo "unsigaction build failure (that's fine)"; fi

unsigaction32.so: unsigaction.c
	@if $(CC) -fPIC -m32 -shared unsigaction.c -o unsigaction32.so 2>/dev/null ; then echo "unsigaction32 build success"; else echo "unsigaction32 build failure (that's fine)"; fi

unsigaction64.so: unsigaction.c
	@if $(CC) -fPIC -m64 -shared unsigaction.c -o unsigaction64.so 2>/dev/null ; then echo "unsigaction64 build success"; else echo "unsigaction64 build failure (that's fine)"; fi

clean:
	rm -f unsigaction.so
