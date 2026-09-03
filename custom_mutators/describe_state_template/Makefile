#
# describe_state_template - report operation counts to afl-fuzz
#
# SO_CC rather than CC: afl-fuzz dlopens mutators with RTLD_NOW, and an
# instrumented .so needs __afl_area_ptr from the target, so building this with
# afl-clang-fast would abort every instance at startup. Overriding CC in the
# environment must not be able to reach it.
#

CFLAGS ?= -Wall -Wextra
SO_CC ?= cc

all: describe_state_template.so

describe_state_template.so: describe_state_template.c
	$(SO_CC) $(CFLAGS) -D_FORTIFY_SOURCE=2 -O3 -fPIC -shared -g \
	    -I ../../include describe_state_template.c -o describe_state_template.so

clean:
	rm -f describe_state_template.so

.PHONY: all clean
