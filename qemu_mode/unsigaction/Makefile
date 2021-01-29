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
.POSIX:

_UNIQ=_QINU_

TARGETCANDIDATES=unsigaction.so
_TARGETS=$(_UNIQ)$(AFL_NO_X86)$(_UNIQ)
__TARGETS=$(_TARGETS:$(_UNIQ)1$(_UNIQ)=)
TARGETS=$(__TARGETS:$(_UNIQ)$(_UNIQ)=$(TARGETCANDIDATES))

all:  $(TARGETS)

unsigaction.so: unsigaction.c
	@if $(CC) -fPIC -shared unsigaction.c -o unsigaction.so 2>/dev/null ; then echo "unsigaction build success"; else echo "unsigaction build failure (that's fine)"; fi

clean:
	rm -f unsigaction.so
