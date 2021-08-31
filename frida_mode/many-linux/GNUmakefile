PWD:=$(shell pwd)/
ROOT:=$(PWD)../../
BUILD_DIR:=$(PWD)build/

.PHONY: all clean shell

all:
	docker build --tag many-afl-frida .
	docker run --rm \
		-v $(ROOT):/AFLplusplus \
		many-afl-frida \
		make -C /AFLplusplus/frida_mode clean all

$(BUILD_DIR):
	mkdir -p $@

clean:
	docker images --filter 'dangling=true' -q --no-trunc | xargs -L1 docker rmi --force

shell:
	docker run -ti --rm many-afl-frida /bin/bash
